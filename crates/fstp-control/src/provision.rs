//! Provisioning a cell (design section 9.2, ADR-011 "Provisioning a cell
//! in SaaS").
//!
//! This module holds the parts of `provision-cell` that decide: the mode
//! rule over the clusters' current cells, and the ordered `fstp-pgagent`
//! jobs of steps 4, 6 and 7 for one placement. Every job comes from the
//! role plan of [`crate::pg::cell_role_plan`], so SaaS and the
//! self-hosted install run the same jobs.

use fstp_cp_proto::{CellId, ScramVerifier};

use crate::ControlError;
use crate::pg::CellDatabase;
use crate::pgagent::{DbIdent, PgagentJob, RoleIdent};
use crate::placement::{ClusterId, Placement};

/// How a cell shares clusters (design section 9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CellMode {
    /// The cell shares clusters with other shared cells.
    Shared,
    /// The cell's clusters hold no other cell.
    Dedicated,
}

/// Why the mode rule refused a placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    /// A dedicated cell asked for a cluster that holds another cell.
    ClusterNotEmpty(ClusterId),
    /// A shared cell asked for a cluster that holds a dedicated cell.
    ClusterDedicated(ClusterId),
}

/// The mode rule: a dedicated cell takes clusters that hold no other cell,
/// and a shared cell takes clusters that hold no dedicated cell.
/// `others(cluster)` gives the modes of the cells already on a cluster.
///
/// # Errors
///
/// [`ControlError::Mode`] naming the first cluster that breaks the rule,
/// the application cluster first.
pub fn check_mode(
    placement: &Placement,
    mode: CellMode,
    others: impl Fn(ClusterId) -> Vec<CellMode>,
) -> Result<(), ControlError> {
    let (app, vault) = placement.clusters();
    for cluster in [app, vault] {
        let on = others(cluster);
        match mode {
            CellMode::Dedicated if !on.is_empty() => {
                return Err(ControlError::Mode(ModeError::ClusterNotEmpty(cluster)));
            }
            CellMode::Shared if on.contains(&CellMode::Dedicated) => {
                return Err(ControlError::Mode(ModeError::ClusterDedicated(cluster)));
            }
            CellMode::Shared | CellMode::Dedicated => {}
        }
    }
    Ok(())
}

/// The jobs of step 4 for `cell` on `placement`, each with the cluster
/// that runs it, in order. On each cluster, [`PgagentJob::HardenCluster`]
/// comes first, then the database, its roles as NOLOGIN with CONNECT on
/// their own database, and the revocations. `HardenCluster` may repeat,
/// so a cluster that holds other cells takes it again unchanged. The
/// application database goes only to the application cluster and the
/// vault database only to the vault cluster (I-83).
pub fn database_jobs(cell: CellId, placement: &Placement) -> Vec<(ClusterId, PgagentJob)> {
    let (app, vault) = placement.clusters();
    let mut out = Vec::new();
    for (cluster, db) in [(app, CellDatabase::App), (vault, CellDatabase::Vault)] {
        let d = DbIdent::new(db, cell);
        out.push((cluster, PgagentJob::HardenCluster));
        out.push((cluster, PgagentJob::CreateCellDatabase(d)));
        out.push((cluster, PgagentJob::CreateRoles(d)));
        out.push((cluster, PgagentJob::ApplyRevocations(d)));
    }
    out
}

/// The job of step 6 for one role credential that a cell component sent,
/// with the cluster that runs it.
///
/// # Errors
///
/// [`ControlError::RoleOutsideDatabase`] for a role of the other
/// database's set.
pub fn credential_job(
    cell: CellId,
    placement: &Placement,
    db: CellDatabase,
    role: fstp_cp_proto::RoleName,
    verifier: ScramVerifier,
) -> Result<(ClusterId, PgagentJob), ControlError> {
    let (app, vault) = placement.clusters();
    let cluster = match db {
        CellDatabase::App => app,
        CellDatabase::Vault => vault,
    };
    let role = RoleIdent::new(DbIdent::new(db, cell), role)?;
    Ok((cluster, PgagentJob::SetRoleCredential { role, verifier }))
}

/// The jobs of step 7, after both migration sets ran: the grant rows of
/// each database, with the cluster that runs them.
pub fn grant_jobs(cell: CellId, placement: &Placement) -> Vec<(ClusterId, PgagentJob)> {
    let (app, vault) = placement.clusters();
    vec![
        (
            app,
            PgagentJob::ApplyGrants(DbIdent::new(CellDatabase::App, cell)),
        ),
        (
            vault,
            PgagentJob::ApplyGrants(DbIdent::new(CellDatabase::Vault, cell)),
        ),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::placement::{Cluster, ClusterKind};

    fn placement() -> Placement {
        Placement::new(
            &Cluster {
                id: ClusterId([1; 16]),
                kind: ClusterKind::Application,
            },
            &Cluster {
                id: ClusterId([2; 16]),
                kind: ClusterKind::Vault,
            },
        )
        .unwrap()
    }

    /// I-83: every database job of the application database runs on the
    /// application cluster, and every vault job on the vault cluster.
    #[test]
    fn i83_database_jobs_go_to_the_cluster_of_their_kind() {
        let p = placement();
        let (app, vault) = p.clusters();
        for (cluster, job) in database_jobs(CellId([5; 16]), &p) {
            let db = match job {
                PgagentJob::HardenCluster => continue,
                PgagentJob::CreateCellDatabase(d)
                | PgagentJob::CreateRoles(d)
                | PgagentJob::ApplyRevocations(d) => d.database(),
                other => panic!("unexpected job {other:?}"),
            };
            let want = match db {
                CellDatabase::App => app,
                CellDatabase::Vault => vault,
            };
            assert_eq!(cluster, want);
        }
    }

    /// I-82, G14, design section 4.1: provisioning hardens each cluster
    /// before anything else runs on it, so `postgres` and `template1` are
    /// closed before the cell's databases copy `template1`.
    #[test]
    fn i82_database_jobs_harden_each_cluster_first() {
        let p = placement();
        let (app, vault) = p.clusters();
        let jobs = database_jobs(CellId([6; 16]), &p);
        for cluster in [app, vault] {
            let first = jobs.iter().find(|(c, _)| *c == cluster).map(|(_, j)| j);
            assert_eq!(first, Some(&PgagentJob::HardenCluster), "{cluster:?}");
        }
    }

    /// Design section 9.2: the mode rule keeps dedicated cells alone.
    #[test]
    fn i83_mode_rule_keeps_dedicated_cells_alone() {
        let p = placement();
        let none = |_: ClusterId| Vec::new();
        let shared = |_: ClusterId| vec![CellMode::Shared];
        let dedicated = |_: ClusterId| vec![CellMode::Dedicated];
        assert_eq!(check_mode(&p, CellMode::Dedicated, none), Ok(()));
        assert_eq!(check_mode(&p, CellMode::Shared, shared), Ok(()));
        assert!(check_mode(&p, CellMode::Dedicated, shared).is_err());
        assert!(check_mode(&p, CellMode::Shared, dedicated).is_err());
    }
}

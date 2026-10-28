//! Placement of a cell's application and vault databases (I-83, design
//! section 9.2).

use crate::ControlError;

/// A cluster, by random id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClusterId(pub [u8; 16]);

/// What a cluster serves. Immutable once registered (I-83). The kind
/// travels in `cp.cluster.kind` and in the subject OU of the cluster's
/// server certificate (design sections 1.3 and 4.1).
///
/// Under Daniel's Q3 C answer the control-plane databases (`cp`,
/// `licence`) are provider-managed, while the witness database stays
/// self-operated. A `Control` cluster is therefore never a `fstp-pgagent`
/// target, and the witness has its own kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterKind {
    /// Application databases (`c_<cell>`), self-operated.
    Application,
    /// Vault databases (`v_<cell>`), self-operated.
    Vault,
    /// Control-plane databases (`cp`, `licence`), provider-managed (Q3 C).
    /// Never a `fstp-pgagent` target.
    Control,
    /// The witness database (`witness`), self-operated (Q3 C).
    Witness,
}

/// A registered cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cluster {
    /// The id.
    pub id: ClusterId,
    /// The kind.
    pub kind: ClusterKind,
}

/// Why a placement was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    /// The application cluster is not of kind application.
    NotAnApplicationCluster,
    /// The vault cluster is not of kind vault.
    NotAVaultCluster,
    /// One cluster for both roles.
    SameCluster,
    /// The check is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// A checked placement. Its fields are private, so no placement exists
/// that mixes kinds (I-83).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    app: ClusterId,
    vault: ClusterId,
}

impl Placement {
    /// Places a cell on `app` and `vault`.
    pub fn new(app: &Cluster, vault: &Cluster) -> Result<Placement, PlacementError> {
        let _ = (app, vault);
        Err(PlacementError::NotImplemented(
            "fstp_control::placement::Placement::new",
        ))
    }

    /// The application and vault clusters.
    pub fn clusters(&self) -> (ClusterId, ClusterId) {
        (self.app, self.vault)
    }
}

/// Runs the control plane service until shutdown.
pub fn run() -> Result<(), ControlError> {
    Err(ControlError::NotImplemented("fstp_control::run"))
}

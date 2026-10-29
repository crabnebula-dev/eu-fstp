//! I-83: identity vault databases never share a cluster with application
//! databases (design section 14.4, T-DB-ISO, B8).
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until `fstp_control::placement` and `cell_role_plan` (lane W2h), the cp
//! migrations (lane W2h), the vault and cell start checks (lanes W2d and
//! W3a), the cell runtime (lane W3a) and the M-PLACE tripwire count (lane
//! W4) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::place_model::db::{self, MigrationSet};
use fstp_celltest::mc::place_model::{
    Mode, Mutant, PlaceAction, PlaceBackend, PlaceDefect, PlaceModel, Production, Reference,
    cluster, cluster_id, ids, properties, reference_places,
};
use fstp_celltest::mc::tripwires::{M_PLACE, NOT_MEASURED, tripwire};
use fstp_celltest::world::{ClusterHandle, DbMode, VaultLayout, World, WorldSpec, kind_label};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement, PlacementError};
use fstp_domain_testkit::harness::teeth::{expect_unreachable, expect_violation};
use fstp_mc::{Config, check, explore};
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

fn bound() -> Config {
    assert_ne!(
        M_PLACE, NOT_MEASURED,
        "the M-PLACE tripwire is not recorded yet (lane W4); \
         i83_m_place_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_PLACE))
}

fn outcome_of<B: PlaceBackend>(
    backend: B,
) -> fstp_mc::Outcome<
    fstp_celltest::mc::place_model::PlaceState,
    fstp_celltest::mc::place_model::PlaceAction,
> {
    let model = PlaceModel::new(backend);
    let props = properties(&model);
    check(&model, &props, &bound())
}

fn passes<B: PlaceBackend>(backend: B) {
    let outcome = outcome_of(backend);
    assert!(
        outcome.exhaustive,
        "M-PLACE did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn caught<B: PlaceBackend>(backend: B, id: &str) {
    let outcome = outcome_of(backend);
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-PLACE production backend: {e}"))
}

const ALL_KINDS: [ClusterKind; 4] = [
    ClusterKind::Application,
    ClusterKind::Vault,
    ClusterKind::Control,
    ClusterKind::Witness,
];

fn spec(cells: u8, mode: DbMode, self_hosted: bool) -> WorldSpec {
    WorldSpec {
        cells,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted,
        process_mode: false,
    }
}

fn world(cells: u8, mode: DbMode, self_hosted: bool) -> World {
    World::start(spec(cells, mode, self_hosted))
        .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn cp_set() -> MigrationSet {
    db::migration_sets()
        .into_iter()
        .find(|s| s.set == "cp")
        .unwrap()
}

/// A fresh control-plane database with the cp migrations applied.
fn cp_database() -> (ClusterHandle, String) {
    let control = ClusterHandle::start(ClusterKind::Control).unwrap();
    let name = db::migrated(control.server(), &cp_set()).unwrap_or_else(|e| panic!("{e}"));
    (control, name)
}

// ---------------------------------------------------------------------------
// Production against the reference.

/// I-83, design section 9.2: `Placement::new` accepts exactly an
/// application cluster and a different vault cluster, for every pair of
/// kinds, and the placement names the clusters it was given.
#[test]
fn i83_placement_never_mixes_kinds() {
    fstp_prop::check("i83_placement_never_mixes_kinds", |g: &mut Gen| {
        let app = Cluster {
            id: ClusterId([g.u8_in(0..=3); 16]),
            kind: *g.pick(&ALL_KINDS),
        };
        let vault = Cluster {
            id: ClusterId([g.u8_in(0..=3); 16]),
            kind: *g.pick(&ALL_KINDS),
        };
        let want = reference_places(&app, &vault);
        match Placement::new(&app, &vault) {
            Err(PlacementError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
            Ok(p) => {
                prop_assert_eq!(want, true, "placed {app:?} and {vault:?}");
                prop_assert_eq!(p.clusters(), (app.id, vault.id));
                Ok(())
            }
            Err(e) => {
                prop_assert_eq!(want, false, "refused {app:?} and {vault:?} with {e:?}");
                Ok(())
            }
        }
    });
}

/// I-83, design section 9.2: each refusal names its reason: a wrong
/// application kind, a wrong vault kind, or one cluster for both.
///
/// Design section 9.2 does not order the three checks, so each case
/// breaks exactly one rule. The wrong-kind cases use two distinct
/// clusters, and the one-cluster case uses the right kinds.
#[test]
fn i83_placement_refusals_name_their_reason() {
    let app = cluster(0).unwrap();
    let vault = cluster(1).unwrap();
    let control = cluster(2).unwrap();
    let other = |kind| Cluster {
        id: ClusterId([0xE7; 16]),
        kind,
    };
    let cases = [
        (
            other(ClusterKind::Vault),
            vault,
            PlacementError::NotAnApplicationCluster,
        ),
        (control, vault, PlacementError::NotAnApplicationCluster),
        (
            app,
            other(ClusterKind::Application),
            PlacementError::NotAVaultCluster,
        ),
        (app, control, PlacementError::NotAVaultCluster),
        (
            app,
            Cluster {
                id: app.id,
                kind: ClusterKind::Vault,
            },
            PlacementError::SameCluster,
        ),
    ];
    for (a, v, want) in cases {
        match Placement::new(&a, &v) {
            Err(PlacementError::NotImplemented(op)) => panic!("{op} is NotImplemented"),
            got => assert_eq!(got, Err(want), "{a:?} and {v:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// M-PLACE.

/// I-83 and I-82, M-PLACE over production: every placement keeps the
/// kinds apart, no plan reaches two cells' databases, and every witness is
/// reachable.
#[test]
fn i83_m_place() {
    passes(production());
}

/// I-83 and I-82, M-PLACE over the reference: every property and witness
/// holds.
#[test]
fn i83_m_place_on_the_reference() {
    passes(Reference);
}

/// I-83, design section 14.1: the recorded tripwire count is the measured
/// state count of M-PLACE over the reference.
#[test]
fn i83_m_place_tripwire_records_the_measured_count() {
    let space = explore(&PlaceModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-PLACE over the reference did not finish"
    );
    assert_eq!(
        M_PLACE,
        space.len(),
        "record the measured M-PLACE count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-83 teeth, design section 14.2: a placement that takes the first free
/// cluster without a kind check breaks I-83.
#[test]
fn i83_teeth_first_free_cluster_is_caught() {
    caught(
        Mutant::new(production(), PlaceDefect::FirstFreeCluster),
        ids::I83,
    );
}

/// I-83 teeth: the same defect is caught on the reference.
#[test]
fn i83_teeth_first_free_cluster_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, PlaceDefect::FirstFreeCluster),
        ids::I83,
    );
}

/// I-82 teeth, M-PLACE `I-82-plan`: a plan that names another cell is
/// caught.
#[test]
fn i82_teeth_m_place_plan_for_another_cell_is_caught() {
    caught(
        Mutant::new(production(), PlaceDefect::PlanForFirstCell),
        ids::I82_PLAN,
    );
}

/// I-82 teeth: the same defect is caught on the reference.
#[test]
fn i82_teeth_m_place_plan_for_another_cell_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, PlaceDefect::PlanForFirstCell),
        ids::I82_PLAN,
    );
}

/// An over-denial mutant: it refuses every placement.
#[derive(Clone, Copy, Debug)]
struct RefusesAll<B>(B);

impl<B: PlaceBackend> PlaceBackend for RefusesAll<B> {
    fn place(
        &self,
        registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, fstp_celltest::NotImplemented> {
        self.0.place(registry, app, vault)?;
        Ok(None)
    }

    fn plan(
        &self,
        cell: fstp_cp_proto::CellId,
    ) -> Result<fstp_celltest::mc::place_model::PlanView, fstp_celltest::NotImplemented> {
        self.0.plan(cell)
    }
}

/// I-83 teeth, design section 14.1 two-way postconditions: a placement that
/// refuses everything keeps I-83 but loses the shared-cell witness.
#[test]
fn i83_teeth_refusing_every_placement_loses_the_witness() {
    let outcome = outcome_of(RefusesAll(Reference));
    if let Err(e) = expect_unreachable(&outcome, ids::W_SHARED) {
        panic!("{e}\n{outcome}");
    }
}

/// I-83: the model offers the mixed requests that the witnesses need: a
/// vault cluster asked for as the application cluster.
#[test]
fn i83_m_place_offers_mixed_requests() {
    let model = PlaceModel::new(Reference);
    let mut out = Vec::new();
    fstp_mc::Model::actions(
        &model,
        &fstp_celltest::mc::place_model::PlaceState::genesis(),
        &mut out,
    );
    assert!(out.contains(&PlaceAction::Provision {
        cell: 0,
        app: 1,
        vault: 0,
        mode: Mode::Shared,
    }));
    assert_eq!(cluster(1).map(|c| c.id), Some(cluster_id(1)));
}

// ---------------------------------------------------------------------------
// The control-plane database (design section 4.4).

/// I-83, design section 4.4: `cp.cluster.kind` cannot change once
/// registered. The trigger refuses an UPDATE of the kind, even by the
/// superuser.
#[test]
fn i83_cluster_kind_is_immutable() {
    let (control, name) = cp_database();
    let s = control.server();
    s.psql(
        &name,
        "INSERT INTO cp.cluster (cluster_id, kind, region, endpoint, server_spki, created_at) \
         VALUES ('\\x000102030405060708090a0b0c0d0e0f', 1, 1, 'app1.example:5432', '\\x00', 1)",
    )
    .unwrap();
    let err = s
        .psql(
            &name,
            "UPDATE cp.cluster SET kind = 2 WHERE cluster_id = '\\x000102030405060708090a0b0c0d0e0f'",
        )
        .expect_err("the kind of a registered cluster changed");
    assert!(err.to_string().contains("ERROR"), "{err}");
    let kind = s.psql(&name, "SELECT kind FROM cp.cluster").unwrap();
    assert_eq!(kind, "1");
}

/// I-83, design section 4.4: a database CHECK refuses one cluster for both
/// the application and the vault database of a cell.
#[test]
fn i83_cp_cell_refuses_one_cluster_for_both_databases() {
    let (control, name) = cp_database();
    let s = control.server();
    s.psql(
        &name,
        "INSERT INTO cp.cluster (cluster_id, kind, region, endpoint, server_spki, created_at) \
         VALUES ('\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', 1, 1, 'app1.example:5432', '\\x00', 1)",
    )
    .unwrap();
    let err = s
        .psql(
            &name,
            "INSERT INTO cp.cell (cell_id, status, mode, app_cluster, vault_cluster, \
             app_backend, vault_backend, org_ref, created_at) VALUES \
             ('\\x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 1, 1, \
              '\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', '\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', \
              1, 1, '\\x00', 1)",
        )
        .expect_err("one cluster took both databases of a cell");
    assert!(err.to_string().contains("check"), "{err}");
}

// ---------------------------------------------------------------------------
// Start checks (design section 9.2).

/// What a database looks like to a process at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    /// `fstp_meta.placement.kind` of the database: 1 application, 2 vault.
    marker: u8,
    /// The kind in the server certificate's subject OU.
    ou: ClusterKind,
    /// The kind the server SPKI is registered for.
    spki: ClusterKind,
}

/// The reference start rule of design section 9.2: a process accepts a
/// database only when the marker, the OU and the registered SPKI all name
/// its own kind.
fn reference_accepts(own: ClusterKind, t: Target) -> bool {
    let marker = match own {
        ClusterKind::Application => 1,
        ClusterKind::Vault => 2,
        ClusterKind::Control | ClusterKind::Witness => 0,
    };
    t.marker == marker && t.ou == own && t.spki == own
}

fn targets() -> Vec<Target> {
    let mut out = Vec::new();
    for marker in [1, 2] {
        for ou in [ClusterKind::Application, ClusterKind::Vault] {
            for spki in [ClusterKind::Application, ClusterKind::Vault] {
                out.push(Target { marker, ou, spki });
            }
        }
    }
    out
}

/// A start-check verdict: whether the process accepts the database, or
/// why the check could not run.
type StartVerdict = Result<bool, fstp_celltest::NotImplemented>;

/// The vault start check of design section 9.2 for one target.
///
/// Gap, reported by lane W1f and raised to the lead for lane W2d:
/// `fstp-vault` exposes only `run()`, which runs the service until
/// shutdown, and no start check that takes the marker, the OU and the
/// registered SPKI kind. This seam is the one place to wire such an entry
/// point, for example `fstp_vault::start_check(marker, ou, spki)`. Until
/// then it refuses with `NotImplemented`, and the test stays red on that
/// refusal, never on a fixed panic.
fn vault_start_check(t: Target) -> StartVerdict {
    let _ = t;
    Err(fstp_celltest::NotImplemented::new(
        "fstp_vault start check over (placement marker, server OU, registered SPKI) \
         (lane W2d; design gap raised by lane W1f)",
    ))
}

/// The cell start check of design section 9.2 for one target, the mirror
/// of [`vault_start_check`].
///
/// Gap, reported by lane W1f and raised to the lead for lane W3a, as for
/// the vault: `fstp-cell` exposes only `run()`.
fn cell_start_check(t: Target) -> StartVerdict {
    let _ = t;
    Err(fstp_celltest::NotImplemented::new(
        "fstp_cell start check over (placement marker, server OU, registered SPKI) \
         (lane W3a; design gap raised by lane W1f)",
    ))
}

/// Every target where `check` disagrees with the reference rule for a
/// process of kind `own`, or could not run, one line each.
fn start_check_mismatches(own: ClusterKind, check: fn(Target) -> StartVerdict) -> Vec<String> {
    let mut out = Vec::new();
    for t in targets() {
        let want = reference_accepts(own, t);
        match check(t) {
            Ok(got) if got == want => {}
            Ok(got) => out.push(format!(
                "{t:?}: the {own:?} start check accepted: {got}, the reference: {want}"
            )),
            Err(e) => out.push(format!("{t:?}: {e}")),
        }
    }
    out
}

/// I-83, design section 9.2: `fstp-vault` refuses a database whose
/// placement marker is not vault, whose server certificate OU is not
/// `vault`, or whose SPKI is registered for an application cluster. It
/// accepts the one target where all three name the vault kind. Every
/// target is compared with the reference rule.
#[test]
fn i83_vault_refuses_an_application_cluster() {
    let found = start_check_mismatches(ClusterKind::Vault, vault_start_check);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-83, design section 9.2: `fstp-cell` makes the mirror checks, refuses
/// a vault cluster and accepts only an application target. Every target
/// is compared with the reference rule.
#[test]
fn i83_cell_refuses_a_vault_cluster() {
    let found = start_check_mismatches(ClusterKind::Application, cell_start_check);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-83 teeth: the start-check comparison reports a check that accepts
/// every target, and one that ignores the SPKI. The reference rule itself
/// gives no mismatch.
#[test]
fn i83_teeth_start_check_comparison_catches_a_lax_check() {
    let all = start_check_mismatches(ClusterKind::Vault, |_| Ok(true));
    assert_eq!(all.len(), targets().len() - 1, "{all:#?}");
    let no_spki = start_check_mismatches(ClusterKind::Vault, |t| {
        Ok(t.marker == 2 && t.ou == ClusterKind::Vault)
    });
    assert_eq!(no_spki.len(), 1, "{no_spki:#?}");
    let exact = start_check_mismatches(ClusterKind::Application, |t| {
        Ok(reference_accepts(ClusterKind::Application, t))
    });
    assert!(exact.is_empty(), "{exact:#?}");
}

/// I-83: the reference start rule accepts one target per kind, and never
/// the other kind's.
#[test]
fn i83_reference_start_rule_accepts_only_its_own_kind() {
    let accepted = |own| {
        targets()
            .into_iter()
            .filter(|t| reference_accepts(own, *t))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        accepted(ClusterKind::Vault),
        vec![Target {
            marker: 2,
            ou: ClusterKind::Vault,
            spki: ClusterKind::Vault
        }]
    );
    assert_eq!(
        accepted(ClusterKind::Application),
        vec![Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Application
        }]
    );
}

// ---------------------------------------------------------------------------
// Worlds.

/// I-83, R-NF-01, design section 1.4: a self-hosted cell runs two
/// PostgreSQL instances with separate data directories, ports and cluster
/// CAs. Its application database lives only on the application instance
/// and its vault database only on the vault instance.
#[test]
fn i83_self_hosted_layout_runs_two_instances() {
    let w = world(1, DbMode::Shared, true);
    let clusters = w.clusters();
    assert_eq!(clusters.len(), 2, "{clusters:?}");
    let (a, v) = (&clusters[0], &clusters[1]);
    assert_eq!(
        (a.kind(), v.kind()),
        (ClusterKind::Application, ClusterKind::Vault)
    );
    assert_ne!(a.server().port(), v.server().port());
    assert_ne!(a.server().dir(), v.server().dir());
    assert_ne!(
        a.server().cluster_ca().map(|c| c.cert_pem().to_vec()),
        v.server().cluster_ca().map(|c| c.cert_pem().to_vec())
    );
    let dbs = w.databases().unwrap();
    let on = |prefix: &str| {
        dbs.iter()
            .filter(|d| db::cell_of(&d.name).is_some() && d.name.starts_with(prefix))
            .map(|d| d.kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(on("c_"), vec![ClusterKind::Application], "{dbs:?}");
    assert_eq!(on("v_"), vec![ClusterKind::Vault], "{dbs:?}");
}

/// I-83, B8: in a SaaS world in shared and in dedicated mode, every vault
/// database sits on a vault cluster and every application database on an
/// application cluster.
#[test]
fn t_db_iso_i83_cell_databases_sit_on_clusters_of_their_kind() {
    for mode in [DbMode::Shared, DbMode::Dedicated] {
        let w = world(3, mode, false);
        let dbs = w.databases().unwrap();
        let cells: Vec<_> = dbs
            .iter()
            .filter(|d| db::cell_of(&d.name).is_some())
            .collect();
        assert_eq!(cells.len(), 6, "{mode:?}: {dbs:?}");
        for d in cells {
            let want = if d.name.starts_with("v_") {
                ClusterKind::Vault
            } else {
                ClusterKind::Application
            };
            assert_eq!(
                d.kind,
                want,
                "{mode:?}: {} on {} ({})",
                d.name,
                d.cluster,
                kind_label(d.kind)
            );
        }
    }
}

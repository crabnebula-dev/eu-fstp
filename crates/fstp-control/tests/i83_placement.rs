//! I-83, design section 9.2, ADR-011 "Provisioning a cell in SaaS" step 2:
//! `fstp_control::placement::Placement::new`.
//!
//! A placement takes an application cluster of kind application and a
//! vault cluster of kind vault, and they differ. It refuses equal
//! clusters, wrong kinds, and every control or witness cluster. A refusal
//! names its reason. Where exactly one condition fails, the variant is the
//! one for that condition.
//!
//! The model check M-PLACE and the database CHECK live in `fstp-celltest`
//! (`i83_m_place`, `i83_cp_cell_refuses_one_cluster_for_both_databases`,
//! lane W1f). These tests pin the constructor on its own.
//!
//! Lane W2h test author. Red until lane W2h writes the check:
//! `Placement::new` is a W0 stub that refuses with
//! `PlacementError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement, PlacementError};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

const KINDS: [ClusterKind; 4] = [
    ClusterKind::Application,
    ClusterKind::Vault,
    ClusterKind::Control,
    ClusterKind::Witness,
];

fn cluster(id: u8, kind: ClusterKind) -> Cluster {
    Cluster {
        id: ClusterId([id; 16]),
        kind,
    }
}

/// Whether `e` is a refusal whose condition holds for `app` and `vault`.
fn reason_holds(e: PlacementError, app: &Cluster, vault: &Cluster) -> Result<(), String> {
    #[allow(
        unreachable_patterns,
        reason = "lane W2h may add refusal variants, each needing a reason here"
    )]
    match e {
        PlacementError::NotImplemented(op) => Err(format!("{op} is NotImplemented")),
        PlacementError::NotAnApplicationCluster if app.kind != ClusterKind::Application => Ok(()),
        PlacementError::NotAVaultCluster if vault.kind != ClusterKind::Vault => Ok(()),
        PlacementError::SameCluster if app.id == vault.id => Ok(()),
        other => Err(format!("{other:?} does not hold for {app:?} and {vault:?}")),
    }
}

/// I-83, design section 9.2: over random cluster ids, equal or not, and
/// every pair of kinds, a placement exists exactly when the application
/// cluster is of kind application, the vault cluster of kind vault, and
/// the two differ. It keeps both ids. Every refusal names a reason that
/// holds.
#[test]
fn i83_placement_accepts_only_an_application_and_a_distinct_vault_cluster() {
    fstp_prop::check(
        "i83_placement_accepts_only_an_application_and_a_distinct_vault_cluster",
        |g: &mut Gen| {
            let a = g.bytes(16..=16);
            let b = if g.bool() {
                a.clone()
            } else {
                g.bytes(16..=16)
            };
            let app = Cluster {
                id: ClusterId(a.try_into().unwrap()),
                kind: *g.pick(&KINDS),
            };
            let vault = Cluster {
                id: ClusterId(b.try_into().unwrap()),
                kind: *g.pick(&KINDS),
            };
            let want = app.kind == ClusterKind::Application
                && vault.kind == ClusterKind::Vault
                && app.id != vault.id;
            match Placement::new(&app, &vault) {
                Ok(p) => {
                    prop_assert!(want, "placed {app:?} and {vault:?}");
                    prop_assert_eq!(p.clusters(), (app.id, vault.id));
                    Ok(())
                }
                Err(e) => {
                    reason_holds(e, &app, &vault)?;
                    prop_assert!(!want, "refused {app:?} and {vault:?} with {e:?}");
                    Ok(())
                }
            }
        },
    );
}

/// I-83, ADR-011: a control or witness cluster is never placed, in either
/// role. With the other cluster right, the refusal names the wrong one.
#[test]
fn i83_placement_refuses_control_and_witness_clusters() {
    let app = cluster(1, ClusterKind::Application);
    let vault = cluster(2, ClusterKind::Vault);
    let mut failures = Vec::new();
    for kind in [ClusterKind::Control, ClusterKind::Witness] {
        let other = cluster(3, kind);
        match Placement::new(&other, &vault) {
            Err(PlacementError::NotAnApplicationCluster) => {}
            r => failures.push(format!("{kind:?} as application cluster: {r:?}")),
        }
        match Placement::new(&app, &other) {
            Err(PlacementError::NotAVaultCluster) => {}
            r => failures.push(format!("{kind:?} as vault cluster: {r:?}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// I-83, B8: a vault database never lands on an application cluster, and
/// an application database never on a vault cluster. With the other
/// cluster right, the refusal names the wrong one.
#[test]
fn i83_placement_refuses_swapped_kinds() {
    let app = cluster(1, ClusterKind::Application);
    let vault = cluster(2, ClusterKind::Vault);
    let other_app = cluster(3, ClusterKind::Application);
    let other_vault = cluster(4, ClusterKind::Vault);
    let mut failures = Vec::new();
    match Placement::new(&app, &other_app) {
        Err(PlacementError::NotAVaultCluster) => {}
        r => failures.push(format!("two application clusters: {r:?}")),
    }
    match Placement::new(&other_vault, &vault) {
        Err(PlacementError::NotAnApplicationCluster) => {}
        r => failures.push(format!("two vault clusters: {r:?}")),
    }
    match Placement::new(&vault, &app) {
        Err(PlacementError::NotAnApplicationCluster | PlacementError::NotAVaultCluster) => {}
        r => failures.push(format!("swapped clusters: {r:?}")),
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// I-83, design section 4.4: one cluster id for both roles is refused as
/// the same cluster, even when the two values carry the right kinds. A
/// registry that held two kinds under one id is itself broken, and the
/// placement must not trust it.
#[test]
fn i83_placement_refuses_one_cluster_for_both_roles() {
    let app = cluster(7, ClusterKind::Application);
    let vault = cluster(7, ClusterKind::Vault);
    assert_eq!(
        Placement::new(&app, &vault),
        Err(PlacementError::SameCluster)
    );
}

/// I-83: the one right placement of a fixed pair keeps both ids in order.
#[test]
fn i83_placement_keeps_the_application_and_vault_ids() {
    let app = cluster(1, ClusterKind::Application);
    let vault = cluster(2, ClusterKind::Vault);
    let p = Placement::new(&app, &vault).unwrap();
    assert_eq!(p.clusters(), (app.id, vault.id));
}

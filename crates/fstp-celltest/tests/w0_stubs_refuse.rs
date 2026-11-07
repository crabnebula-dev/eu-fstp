//! Lane W0 (`docs/handoff/m3-design.md` section 19): every new crate starts
//! as a stub whose operations refuse with a typed `NotImplemented` error,
//! never with a panic.
//!
//! Each test calls one operation that the design names with a byte-slice
//! or empty input, so it needs no other type of the crate. The error's
//! `Debug` output must name `NotImplemented`. These tests turn green only
//! while the stubs stand. Each production lane replaces its test with the
//! real behaviour tests of its own step, and the W4 registry then drops it.
//!
//! The parsers are fuzz targets of design section 15, so each stub must
//! also refuse arbitrary input without panicking.
//!
//! Lane W2h implemented `fstp_control::pg::cell_role_plan` and
//! `fstp_control::isolation_audit::privilege_graph`, so their W0 tests are
//! gone. The plan's real behaviour, for every cell, is tested by
//! `i82_role_plan_matches_design_section_4_1` (`i82_role_plan.rs`) and by
//! `i82_role_plan_names_its_cell_and_the_adr011_roles` and
//! `i82_role_plan_rows_do_not_depend_on_the_cell` (`fstp-control`,
//! `i82_role_plan_rows.rs`). The graph's real behaviour over generated and
//! live catalogues is tested in `fstp-control` (`i82_privilege_graph.rs`,
//! from `i82_privilege_graph_holds_every_membership_edge` on). Its
//! behaviour on the W0 input, an empty catalogue, is tested below.
//!
//! Lane W3a implemented `fstp_cell::egress::connect`, so its W0 test is
//! replaced by `adr009_cell_egress_connect_builds_the_closed_set_only`
//! below. `i38_only_egress_reaches_crabnebula_hosts` (`i38_egress.rs`)
//! drives the same connector at the CrabNebula hosts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Debug;

/// Asserts that `r` is an error whose `Debug` output names `NotImplemented`.
fn refuses<T, E: Debug>(what: &str, r: Result<T, E>) {
    match r {
        Ok(_) => panic!("{what}: the stub accepted the input"),
        Err(e) => {
            let shown = format!("{e:?}");
            assert!(
                shown.contains("NotImplemented"),
                "{what}: refused with {shown}, not NotImplemented"
            );
        }
    }
}

/// I-82, design section 9.3: `fstp_control::isolation_audit::privilege_graph`
/// over an empty catalogue, the W0 input, gives a graph with no edge. The
/// graph holds only edges that catalogue rows give, so no path between
/// cells is ever invented.
#[test]
fn i82_privilege_graph_of_an_empty_catalogue_has_no_edge() {
    let graph = fstp_control::isolation_audit::privilege_graph(
        &fstp_control::isolation_audit::CatalogueRows::default(),
    )
    .unwrap();
    assert_eq!(graph.edges, Vec::new());
}

/// B4, I-16, ADR-009 "Outbound destinations": `fstp_cell::egress::connect`
/// builds each destination of the closed set at the host its own
/// definition fixes, a CrabNebula call at the host it names. It refuses
/// only `KeystoreSnapshots`, which ADR-012 proposes and Daniel has not
/// decided. Every variant is listed, so a new one fails to compile here.
#[test]
fn adr009_cell_egress_connect_builds_the_closed_set_only() {
    use fstp_cell::egress::{Destination, EgressRefusal};
    use fstp_release::egress::{Channel, CnCall, LicenceRefresh, ProductVersion, UpdateCheck};
    let version = ProductVersion(0, 3, 0);
    let calls = [
        CnCall::Update(UpdateCheck {
            version,
            channel: Channel::Stable,
        }),
        CnCall::Licence(LicenceRefresh {
            licence: fstp_release::licence::LicenceId([0x5A; 16]),
            version,
        }),
    ];
    for d in [
        Destination::AppDatabase,
        Destination::Vault,
        Destination::Custody,
        Destination::ControlPlane,
        Destination::Witness,
        Destination::CrabNebula(calls[0]),
        Destination::CrabNebula(calls[1]),
        Destination::KeystoreSnapshots,
        Destination::MailSubmission {
            host: fstp_cell::egress::MailHost::parse("smtp.relay.example").unwrap(),
        },
    ] {
        let want = match d {
            Destination::AppDatabase
            | Destination::Vault
            | Destination::Custody
            | Destination::ControlPlane
            | Destination::Witness
            | Destination::CrabNebula(_)
            | Destination::MailSubmission { .. } => Ok(()),
            Destination::KeystoreSnapshots => {
                Err(fstp_cell::CellError::Egress(EgressRefusal::PendingDecision))
            }
        };
        assert_eq!(fstp_cell::egress::connect(&d), want, "{d:?}");
    }
}

/// B4a, ADR-009: the vault connector opens nothing until lane W2d writes
/// it.
#[test]
fn w0_vault_egress_connect_refuses() {
    refuses(
        "fstp_vault::egress::connect",
        fstp_vault::egress::connect(&fstp_vault::VaultDestination::Witness),
    );
}

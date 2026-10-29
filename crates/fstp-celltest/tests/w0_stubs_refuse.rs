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

/// Inputs every stub parser must refuse without a panic.
const INPUTS: [&[u8]; 4] = [b"", b"\x00", b"\xff\xff\xff\xff", b"{\"a\":1}"];

/// TH-26, design section 3.2: `fstp_keys::envelope::decode_sealed_key`.
#[test]
fn w0_keys_decode_sealed_key_refuses() {
    for input in INPUTS {
        refuses(
            "decode_sealed_key",
            fstp_keys::envelope::decode_sealed_key(input),
        );
    }
}

/// TH-26, design section 3.2: `fstp_keys::envelope::decode_sealed_blob`.
#[test]
fn w0_keys_decode_sealed_blob_refuses() {
    for input in INPUTS {
        refuses(
            "decode_sealed_blob",
            fstp_keys::envelope::decode_sealed_blob(input),
        );
    }
}

/// TH-26, design section 9.4: `fstp_edge::parse_client_hello_sni`.
#[test]
fn w0_edge_parse_client_hello_sni_refuses() {
    for input in INPUTS {
        refuses(
            "parse_client_hello_sni",
            fstp_edge::parse_client_hello_sni(input),
        );
    }
}

/// TH-26, design section 9.4: `fstp_edge::decode_tunnel_header`.
#[test]
fn w0_edge_decode_tunnel_header_refuses() {
    for input in INPUTS {
        refuses(
            "decode_tunnel_header",
            fstp_edge::decode_tunnel_header(input),
        );
    }
}

/// Design section 5.1: `fstp_cell_core::replay` over an empty ledger.
#[test]
fn w0_cell_core_replay_refuses() {
    refuses("replay", fstp_cell_core::replay(&[]));
}

/// I-78, design section 5.4 step 3: `HighRiskAction::of` classifies no
/// action until lane W2c fills it from `HIGH_RISK_TABLE`.
#[test]
fn w0_cell_core_high_risk_action_of_refuses() {
    use fstp_cell_core::gate::{Action, HighRiskAction, ReadAction};
    refuses(
        "HighRiskAction::of",
        HighRiskAction::of(&Action::Read(ReadAction::ReadContent)),
    );
}

/// I-82, design sections 4.1 and 9.2: `fstp_control::pg::cell_role_plan`.
#[test]
fn w0_control_cell_role_plan_refuses() {
    refuses(
        "cell_role_plan",
        fstp_control::pg::cell_role_plan(fstp_cp_proto::CellId([0; 16])),
    );
}

/// I-82, design section 9.3:
/// `fstp_control::isolation_audit::privilege_graph`.
#[test]
fn w0_control_privilege_graph_refuses() {
    refuses(
        "privilege_graph",
        fstp_control::isolation_audit::privilege_graph(
            &fstp_control::isolation_audit::CatalogueRows::default(),
        ),
    );
}

/// B4, I-16, ADR-009: the cell connector opens nothing until lane W3a
/// writes it.
#[test]
fn w0_cell_egress_connect_refuses() {
    refuses(
        "fstp_cell::egress::connect",
        fstp_cell::egress::connect(&fstp_cell::Destination::Witness),
    );
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

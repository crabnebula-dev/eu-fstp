//! Tenant command and record codecs (ADR-007, TH-26, H-05; M4 design
//! sections 4.2 and 9, lane W2d).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use fstp_prop::{check, prop_assert_eq};
use fstp_tenant::TenantError;

use common::gens::{self, Focus, test_env};
use common::prod;
use common::reference::Reference;
use common::{drive, vocab::Op};

/// ADR-007: every tenant command has one canonical RFC 8785 text. The
/// production decoder accepts it, and encoding the decoded command again
/// gives the same bytes.
#[test]
fn adr007_tenant_commands_round_trip() {
    check("adr007_tenant_commands_round_trip", |g| {
        let model = Reference::new(&test_env());
        let focus = *g.pick(&[
            Focus::Steps,
            Focus::Admins,
            Focus::Settings,
            Focus::Inference,
        ]);
        let op = gens::op(g, &model, focus);
        g.note("op", &op);
        let text = prod::encode_command(&op).map_err(|e| e.to_string())?;
        let again = prod::command_reencoded(&text).map_err(|e| e.to_string())?;
        prop_assert_eq!(again, Some(text));
        Ok(())
    });
}

/// ADR-007, Q31: every record a run appends has a canonical text that the
/// stored-record decoder accepts and encodes again to the same bytes. A
/// ledger of tenant records therefore replays structurally.
#[test]
fn adr007_tenant_records_round_trip() {
    check("adr007_tenant_records_round_trip", |g| {
        let env = test_env();
        let mut model = Reference::new(&env);
        let ops: Vec<Op> = g.vec(1..=24, |g| {
            let op = gens::op(g, &model, Focus::Steps);
            model.apply(&op);
            op
        });
        let (sut, _) = drive(&env, &ops).map_err(|e| e.to_string())?;
        for text in sut.record_texts().map_err(|e| e.to_string())? {
            let again = prod::record_reencoded(&text).map_err(|e| e.to_string())?;
            prop_assert_eq!(again, Some(text));
        }
        Ok(())
    });
}

/// Inputs no decoder may accept: empty, wrong JSON types, an unknown
/// command kind, non-canonical text, invalid UTF-8, deep nesting, and a
/// JSON number where an id or amount would be (ADR-006, ADR-007).
fn malformed() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = [
        &b""[..],
        b"null",
        b"[]",
        b"{}",
        b"\"SaveStep\"",
        b"{\"kind\":\"Nope\"}",
        b"{ \"kind\" : \"SaveStep\" }",
        b"{\"kind\":\"InviteAdmin\",\"invitation\":1}",
        b"{\"kind\":\"SetSetting\",\"param\":\"P-73\"}",
        b"{\"kind\":\"SetSetting\",\"param\":\"P-78\"}",
        b"\xff\xfe",
    ]
    .iter()
    .map(|b| b.to_vec())
    .collect();
    let mut deep = vec![b'['; 4096];
    deep.extend(vec![b']'; 4096]);
    v.push(deep);
    v
}

/// TH-26, H-05: the command decoder refuses every malformed input with a
/// typed decoding error, never a panic. The W0 refusal does not count.
#[test]
fn th26_decode_command_refuses_malformed_input_with_a_typed_error() {
    for bytes in malformed() {
        let r = fstp_tenant::decode_command(&bytes);
        assert!(
            matches!(r, Err(ref e) if !matches!(e, TenantError::NotImplemented(_))),
            "{:?}: {r:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// TH-26, H-05: the stored-record decoder refuses every malformed input
/// with a typed decoding error, never a panic. The W0 refusal does not
/// count.
#[test]
fn th26_decode_record_refuses_malformed_input_with_a_typed_error() {
    for bytes in malformed() {
        let r = fstp_tenant::decode_record(&bytes);
        assert!(
            matches!(r, Err(ref e) if !matches!(e, TenantError::NotImplemented(_))),
            "{:?}: {r:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

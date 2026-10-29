//! `fstp_vault::decode_origin_write` and `fstp_vault::decode_fact_body`
//! (design sections 4.3, 6.5 and 15, ADR-009 "Vault origin", TH-26,
//! H-05).
//!
//! The encodings are those of `common`: an origin write is
//! `{"body":<object>,"ticket":"<hex>"}`, and a stored fact body is
//! `{"fields":<object>,"kind":<code>}`. Both are canonical JSON with one
//! spelling.
//!
//! `decode_origin_write` only frames the request. It reads no ticket
//! claim and does not interpret the body, since ADR-009 checks the
//! signature before any other field is used, and the write kind is a
//! claim. So the round trip uses arbitrary ticket bytes.
//!
//! Every refusal test first decodes a valid twin, so a decoder that
//! refuses everything (the W0 stub) fails each test.
//!
//! Gap (lane report): `VaultError` has only `NotImplemented`, so these
//! tests can tell a typed refusal from the stub but not one refusal from
//! another.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::vc::{fact, set};
use common::{fact_body, origin_write};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault::{FactBody, OriginWrite, VaultError, decode_fact_body, decode_origin_write};
use fstp_vault_core::FactWrite;

fn is_stub(e: &VaultError) -> bool {
    matches!(e, VaultError::NotImplemented(_))
}

/// One write of every kind W1c gives a body, with small ids.
fn gen_fact(g: &mut Gen) -> FactWrite {
    let a = u128::from(g.u8_in(1..=40));
    let b = u128::from(g.u8_in(1..=40));
    let ids = set([a, b]);
    match g.u8_in(0..=11) {
        0 => fact::country(a, b, g.u16_in(1..=999)),
        1 => fact::affiliation(a, b, None),
        2 => fact::adult(a, g.i64_in(-1_000_000..=9_007_199_254_740_991)),
        3 => fact::consent(a, b),
        4 => fact::verification(a, b),
        5 => fact::proximity_list(a, &ids),
        6 => fact::reviewer(a, g.option(|g| u128::from(g.u8_in(1..=9))), &ids),
        7 => fact::affiliation(a, b, Some(u128::from(g.u8_in(1..=9)))),
        8 => fact::relationship(a, b),
        9 => fact::consent_withdrawn(a),
        10 => fact::attestation_withdrawn(a),
        _ => fact::affiliation_ended(a, b),
    }
}

fn text(w: &FactWrite) -> String {
    String::from_utf8(w.body.clone()).unwrap()
}

/// ADR-009 "Delivery": an origin write decodes to the ticket bytes from
/// the hex and the exact body bytes.
#[test]
fn th_26_origin_write_golden_vector_decodes() {
    let body = "{\"account\":\"501\",\"country\":250,\"programme\":\"1\"}";
    let bytes = format!("{{\"body\":{body},\"ticket\":\"7b7d00ff\"}}");
    assert_eq!(
        decode_origin_write(bytes.as_bytes()),
        Ok(OriginWrite {
            ticket: vec![0x7b, 0x7d, 0x00, 0xff],
            body: body.as_bytes().to_vec(),
        })
    );
}

/// TH-26, ADR-009: every reference origin write decodes to its parts,
/// with arbitrary ticket bytes, since the decoder reads no claim.
#[test]
fn th_26_origin_write_round_trips_without_reading_claims() {
    fstp_prop::check(
        "th_26_origin_write_round_trips_without_reading_claims",
        |g: &mut Gen| {
            let ticket = g.bytes(1..=300);
            let w = gen_fact(g);
            let bytes = origin_write(&ticket, &text(&w));
            prop_assert_eq!(
                decode_origin_write(&bytes),
                Ok(OriginWrite {
                    ticket,
                    body: w.body
                })
            );
            Ok(())
        },
    );
}

/// TH-26: non-canonical and malformed origin writes are refused with a
/// typed error.
#[test]
fn th_26_origin_write_refuses_malformed_input() {
    let body = "{\"account\":\"501\"}";
    let good = format!("{{\"body\":{body},\"ticket\":\"7b7d\"}}");
    assert!(decode_origin_write(good.as_bytes()).is_ok(), "the twin");
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        (
            "upper hex",
            format!("{{\"body\":{body},\"ticket\":\"7B7D\"}}"),
        ),
        ("odd hex", format!("{{\"body\":{body},\"ticket\":\"7b7\"}}")),
        (
            "non-hex",
            format!("{{\"body\":{body},\"ticket\":\"7g7d\"}}"),
        ),
        (
            "empty ticket",
            format!("{{\"body\":{body},\"ticket\":\"\"}}"),
        ),
        ("no ticket", format!("{{\"body\":{body}}}")),
        ("no body", "{\"ticket\":\"7b7d\"}".to_owned()),
        (
            "body not an object",
            "{\"body\":\"x\",\"ticket\":\"7b7d\"}".to_owned(),
        ),
        (
            "unknown member",
            format!("{{\"body\":{body},\"kind\":1,\"ticket\":\"7b7d\"}}"),
        ),
        (
            "members out of order",
            format!("{{\"ticket\":\"7b7d\",\"body\":{body}}}"),
        ),
        ("space", format!("{{\"body\": {body},\"ticket\":\"7b7d\"}}")),
        (
            "non-canonical body",
            "{\"body\":{\"account\": \"501\"},\"ticket\":\"7b7d\"}".to_owned(),
        ),
        ("trailing byte", format!("{good}\n")),
        ("deep nesting", "{\"body\":".repeat(50_000)),
    ];
    for (what, b) in &cases {
        let got = decode_origin_write(b.as_bytes());
        assert!(
            matches!(&got, Err(e) if !is_stub(e)),
            "{what}: {b:?} gave {got:?}"
        );
    }
}

/// Design section 4.3: one golden vector per stored fact kind.
#[test]
fn th_26_fact_body_golden_vectors_decode() {
    let writes = [
        fact::country(501, 1, 250),
        fact::affiliation(501, 31, None),
        fact::adult(501, 0),
        fact::consent(1, 105),
        fact::verification(501, 1_001),
        fact::proximity_list(41, &set([31, 32])),
        fact::reviewer(106, Some(31), &set([1_003])),
        fact::affiliation(501, 31, Some(1)),
        fact::relationship(106, 103),
        fact::consent_withdrawn(1),
        fact::attestation_withdrawn(501),
        fact::affiliation_ended(501, 31),
    ];
    for w in writes {
        let bytes = fact_body(w.kind, &text(&w));
        assert_eq!(
            decode_fact_body(&bytes),
            Ok(FactBody {
                kind: w.kind,
                fields: w.body.clone(),
            }),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// TH-26, H-05: every reference fact body decodes to its kind and exact
/// fields.
#[test]
fn th_26_fact_body_round_trips() {
    fstp_prop::check("th_26_fact_body_round_trips", |g: &mut Gen| {
        let w = gen_fact(g);
        let bytes = fact_body(w.kind, &text(&w));
        prop_assert_eq!(
            decode_fact_body(&bytes),
            Ok(FactBody {
                kind: w.kind,
                fields: w.body
            })
        );
        Ok(())
    });
}

/// NOTE 2, H-05: a stored body of an unknown kind, or with the fields of
/// another kind, is refused. A stored body is decoded after unsealing, so
/// a refusal means a corrupt row and fails closed.
#[test]
fn note2_fact_body_refuses_unknown_kinds_and_foreign_fields() {
    fstp_prop::check(
        "note2_fact_body_refuses_unknown_kinds_and_foreign_fields",
        |g: &mut Gen| {
            let w = gen_fact(g);
            let other = gen_fact(g);
            let good = fact_body(w.kind, &text(&w));
            prop_assert!(decode_fact_body(&good).is_ok(), "the twin {w:?}");
            let mut bad = vec![
                fact_body(0, &text(&w)),
                fact_body(14, &text(&w)),
                fact_body(u16::MAX, &text(&w)),
                [good.as_slice(), b" "].concat(),
                fact_body(w.kind, &text(&w).replacen(':', ": ", 1)),
            ];
            let same_shape = matches!(
                (w.kind, other.kind),
                (fact::AFFILIATION_DECLARED, fact::PARTNER_STAFF_DECLARED)
                    | (fact::PARTNER_STAFF_DECLARED, fact::AFFILIATION_DECLARED)
            );
            if w.kind != other.kind && !same_shape {
                bad.push(fact_body(w.kind, &text(&other)));
            }
            for b in bad {
                let got = decode_fact_body(&b);
                prop_assert!(
                    matches!(&got, Err(e) if !is_stub(e)),
                    "{:?} gave {got:?}",
                    String::from_utf8_lossy(&b)
                );
            }
            Ok(())
        },
    );
}

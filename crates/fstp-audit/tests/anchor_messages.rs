//! R-CR-03: the signed messages of anchors and receipts (ADR-010
//! "Anchors" and "Receipt").
//!
//! The anchor message is the ADR-010 proposal. The receipt message order
//! is the W1e reading, since ADR-010 gives its label and fields only. Both
//! are fixed with Daniel under ADR-010 open point 2.
//!
//! The interim test that wanted anchor signing to refuse is gone: Daniel
//! accepted the composite encoding table on 2026-10-29 (design section
//! 21.0). Anchor signing is tested in `signatures.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::reference::{self as r, CELL, Chain, Hash, ReceiptFields, vectors as v};
use common::{answered, api, hex32};
use fstp_prop::{Gen, check, prop_assert_eq, prop_assert_ne};

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

fn gen_cell(g: &mut Gen) -> [u8; 16] {
    let mut c = [0u8; 16];
    for b in &mut c {
        *b = g.u8();
    }
    c
}

fn gen_fields(g: &mut Gen) -> ReceiptFields {
    ReceiptFields {
        n: g.u64(),
        link: gen_hash(g),
        witness_seq: g.u64(),
        witness_link: gen_hash(g),
        received_at: g.i64(),
    }
}

/// The recorded receipt vector's fields.
fn vector_receipt() -> ReceiptFields {
    ReceiptFields {
        n: 2,
        link: hex32(v::LINK2_APP),
        witness_seq: v::RECEIPT_WITNESS_SEQ,
        witness_link: v::RECEIPT_WITNESS_LINK,
        received_at: v::AT + 5,
    }
}

/// R-CR-03, ADR-010: `"fstp-anchor-v1" || cell || chain || be64(n) ||
/// link || be64(at)` for App row 2, against the recorded length and
/// SHA-256.
#[test]
fn r_cr_03_anchor_message_matches_recorded_vector() {
    let got = api::anchor_message(CELL, Chain::App, 2, &hex32(v::LINK2_APP), v::AT)
        .map(|m| (m.len(), r::sha256(&[&m])));
    assert_eq!(
        got,
        Ok((v::ANCHOR_MESSAGE_LEN, hex32(v::ANCHOR_MESSAGE_SHA)))
    );
}

/// R-CR-03: the production anchor message equals the test reference.
#[test]
fn r_cr_03_anchor_message_matches_test_reference() {
    check("r_cr_03_anchor_message_matches_test_reference", |g| {
        let (cell, chain, n, link, at) = (
            gen_cell(g),
            *g.pick(&Chain::ALL),
            g.u64(),
            gen_hash(g),
            g.i64(),
        );
        let got = answered(
            "anchor message",
            api::anchor_message(cell, chain, n, &link, at),
        )?;
        prop_assert_eq!(got, r::anchor_message(cell, chain, n, &link, at));
        Ok(())
    });
}

/// R-CR-03, I-24: the anchor message binds the cell, the chain, `n`, the
/// link and `at`. Changing any one gives another message.
#[test]
fn r_cr_03_anchor_message_binds_every_field() {
    check("r_cr_03_anchor_message_binds_every_field", |g| {
        let (cell, chain, n, link, at) = (
            gen_cell(g),
            *g.pick(&Chain::ALL),
            g.u64(),
            gen_hash(g),
            g.i64(),
        );
        let base = answered(
            "anchor message",
            api::anchor_message(cell, chain, n, &link, at),
        )?;
        let mut cell2 = cell;
        cell2[15] ^= 1;
        let mut link2 = link;
        link2[31] ^= 1;
        let others = [
            api::anchor_message(cell2, chain, n, &link, at),
            api::anchor_message(cell, chain.other(), n, &link, at),
            api::anchor_message(cell, chain, n.wrapping_add(1), &link, at),
            api::anchor_message(cell, chain, n, &link2, at),
            api::anchor_message(cell, chain, n, &link, at.wrapping_add(1)),
        ];
        for (i, o) in others.into_iter().enumerate() {
            prop_assert_ne!(
                answered("anchor message", o)?,
                base,
                "field {} not bound",
                i
            );
        }
        Ok(())
    });
}

/// R-CR-03, ADR-010: the receipt message of the recorded vector, against
/// its length and SHA-256.
#[test]
fn r_cr_03_receipt_message_matches_recorded_vector() {
    let got = api::receipt_message(CELL, Chain::App, &vector_receipt())
        .map(|m| (m.len(), r::sha256(&[&m])));
    assert_eq!(
        got,
        Ok((v::RECEIPT_MESSAGE_LEN, hex32(v::RECEIPT_MESSAGE_SHA)))
    );
}

/// R-CR-03: the production receipt message equals the test reference.
#[test]
fn r_cr_03_receipt_message_matches_test_reference() {
    check("r_cr_03_receipt_message_matches_test_reference", |g| {
        let (cell, chain, f) = (gen_cell(g), *g.pick(&Chain::ALL), gen_fields(g));
        let got = answered("receipt message", api::receipt_message(cell, chain, &f))?;
        prop_assert_eq!(got, r::receipt_message(cell, chain, &f));
        Ok(())
    });
}

/// R-CR-03, I-24: the receipt message binds the cell, the chain and
/// every receipt field.
#[test]
fn r_cr_03_receipt_message_binds_every_field() {
    check("r_cr_03_receipt_message_binds_every_field", |g| {
        let (cell, chain, f) = (gen_cell(g), *g.pick(&Chain::ALL), gen_fields(g));
        let base = answered("receipt message", api::receipt_message(cell, chain, &f))?;
        let mut cell2 = cell;
        cell2[0] ^= 1;
        let mut changed = Vec::new();
        for i in 0..5 {
            let mut x = f;
            match i {
                0 => x.n = x.n.wrapping_add(1),
                1 => x.link[0] ^= 1,
                2 => x.witness_seq = x.witness_seq.wrapping_add(1),
                3 => x.witness_link[0] ^= 1,
                _ => x.received_at = x.received_at.wrapping_add(1),
            }
            changed.push(api::receipt_message(cell, chain, &x));
        }
        changed.push(api::receipt_message(cell2, chain, &f));
        changed.push(api::receipt_message(cell, chain.other(), &f));
        for (i, o) in changed.into_iter().enumerate() {
            prop_assert_ne!(
                answered("receipt message", o)?,
                base,
                "field {} not bound",
                i
            );
        }
        Ok(())
    });
}

/// R-CR-03: an anchor message is never a receipt message. The labels
/// differ, so no anchor signature can stand for a receipt.
#[test]
fn r_cr_03_anchor_and_receipt_messages_have_distinct_labels() {
    let a = api::anchor_message(CELL, Chain::App, 2, &hex32(v::LINK2_APP), v::AT);
    let rc = api::receipt_message(CELL, Chain::App, &vector_receipt());
    let prefixes = (
        a.map(|m| m.starts_with(r::ANCHOR_LABEL)),
        rc.map(|m| m.starts_with(r::RECEIPT_LABEL)),
    );
    assert_eq!(prefixes, (Ok(true), Ok(true)));
}

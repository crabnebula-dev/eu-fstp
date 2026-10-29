//! TH-26: the `fstp-audit` decoders of design section 15
//! (`chain_row_decode`, `anchor_decode`, `receipt_decode`).
//!
//! The design fixes no wire layout for these values, so the properties
//! hold for any one-spelling layout: round trip, one spelling, every
//! truncation refused, trailing bytes refused, empty input refused. An
//! anchor signature has the composite length of draft 19 (R-CR-03).
//!
//! Lane W2g landed the encoders and the decoders. A stub decoder that
//! refused with `NotImplemented` would fail every test here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::codec::Codec;
use common::reference::{Chain, Hash, Kind, ReceiptFields, RowCols};
use common::view::{AnchorRec, ReceiptRec};
use common::{api, real_refusal};
use fstp_crypto::composite::SIGNATURE_LEN;
use fstp_prop::{Gen, check};

const ROW: Codec<RowCols> = Codec {
    what: "chain row",
    encode: api::encode_chain_row,
    decode: api::decode_chain_row,
};

const ANCHOR: Codec<AnchorRec> = Codec {
    what: "anchor",
    encode: api::encode_anchor,
    decode: api::decode_anchor,
};

const RECEIPT: Codec<ReceiptRec> = Codec {
    what: "receipt",
    encode: api::encode_receipt,
    decode: api::decode_receipt,
};

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

fn gen_row(g: &mut Gen) -> RowCols {
    let kind = if g.bool() {
        Kind::Ledger { seq: g.u64() }
    } else {
        Kind::Event {
            body: g.bytes(0..=64),
        }
    };
    RowCols {
        n: g.u64_in(1..=u64::MAX),
        at: g.i64(),
        kind,
        stored_hash: gen_hash(g),
    }
}

fn gen_signature(g: &mut Gen) -> Vec<u8> {
    let mut s = vec![0u8; SIGNATURE_LEN];
    let i = g.usize_in(0..=SIGNATURE_LEN - 1);
    s[i] = g.u8();
    s[0] = g.u8();
    s
}

fn gen_anchor(g: &mut Gen) -> AnchorRec {
    AnchorRec {
        cell: gen_cell(g),
        chain: *g.pick(&Chain::ALL),
        n: g.u64_in(1..=u64::MAX),
        link: gen_hash(g),
        at: g.i64(),
        signature: gen_signature(g),
    }
}

fn gen_receipt(g: &mut Gen) -> ReceiptRec {
    ReceiptRec {
        cell: gen_cell(g),
        chain: *g.pick(&Chain::ALL),
        fields: ReceiptFields {
            n: g.u64_in(1..=u64::MAX),
            link: gen_hash(g),
            witness_seq: g.u64_in(1..=u64::MAX),
            witness_link: gen_hash(g),
            received_at: g.i64(),
        },
        signature: gen_signature(g),
    }
}

// ---------------------------------------------------------------------------
// Chain rows (`chain_row_decode`).

/// TH-26, I-24: a chain row of either kind round-trips.
#[test]
fn th_26_chain_row_round_trips() {
    check("th_26_chain_row_round_trips", |g| {
        ROW.round_trip(&gen_row(g))
    });
}

/// TH-26, I-24: one spelling per chain row. A changed byte never decodes
/// to the same row.
#[test]
fn th_26_chain_row_has_one_spelling() {
    check("th_26_chain_row_has_one_spelling", |g| {
        let row = gen_row(g);
        ROW.one_spelling_under_change(&row, g)
    });
}

/// TH-26, I-24: arbitrary bytes are refused for real or re-encode byte
/// for byte.
#[test]
fn th_26_chain_row_decode_of_arbitrary_bytes_has_one_spelling() {
    check(
        "th_26_chain_row_decode_of_arbitrary_bytes_has_one_spelling",
        |g| ROW.one_spelling_on(&g.bytes(0..=96)),
    );
}

/// TH-26, I-24: every proper prefix of an encoded row is refused.
#[test]
fn th_26_chain_row_decode_refuses_every_truncation() {
    check("th_26_chain_row_decode_refuses_every_truncation", |g| {
        ROW.refuses_prefixes(&gen_row(g))
    });
}

/// TH-26, I-24: an encoded row with trailing bytes is refused.
#[test]
fn th_26_chain_row_decode_refuses_trailing_bytes() {
    check("th_26_chain_row_decode_refuses_trailing_bytes", |g| {
        let row = gen_row(g);
        let extra = g.bytes(1..=8);
        ROW.refuses_trailing(&row, &extra)
    });
}

/// TH-26, I-24: row number 0 does not exist; rows start at 1 (ADR-010
/// "`n` starts at 1"). Its encoding, if any, is refused on decode.
#[test]
fn th_26_chain_row_number_zero_is_refused() {
    let row = RowCols {
        n: 0,
        at: 1,
        kind: Kind::Event { body: Vec::new() },
        stored_hash: [7; 32],
    };
    let r = match api::encode_chain_row(&row) {
        Ok(bytes) => api::decode_chain_row(&bytes),
        Err(e) => Err(e),
    };
    if let Err(msg) = real_refusal("chain row number 0", &r) {
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// Anchors (`anchor_decode`).

/// TH-26, R-CR-03: an anchor round-trips.
#[test]
fn th_26_anchor_round_trips() {
    check("th_26_anchor_round_trips", |g| {
        ANCHOR.round_trip(&gen_anchor(g))
    });
}

/// TH-26, R-CR-03: one spelling per anchor.
#[test]
fn th_26_anchor_has_one_spelling() {
    check("th_26_anchor_has_one_spelling", |g| {
        let a = gen_anchor(g);
        ANCHOR.one_spelling_under_change(&a, g)
    });
}

/// TH-26: arbitrary bytes are refused for real or re-encode byte for
/// byte.
#[test]
fn th_26_anchor_decode_of_arbitrary_bytes_has_one_spelling() {
    check(
        "th_26_anchor_decode_of_arbitrary_bytes_has_one_spelling",
        |g| ANCHOR.one_spelling_on(&g.bytes(0..=128)),
    );
}

/// TH-26: every proper prefix of an encoded anchor is refused.
#[test]
fn th_26_anchor_decode_refuses_every_truncation() {
    check("th_26_anchor_decode_refuses_every_truncation", |g| {
        ANCHOR.refuses_prefixes(&gen_anchor(g))
    });
}

/// TH-26: an encoded anchor with trailing bytes is refused.
#[test]
fn th_26_anchor_decode_refuses_trailing_bytes() {
    check("th_26_anchor_decode_refuses_trailing_bytes", |g| {
        let a = gen_anchor(g);
        let extra = g.bytes(1..=8);
        ANCHOR.refuses_trailing(&a, &extra)
    });
}

/// R-CR-03, I-90: an anchor signature is a composite signature of
/// exactly the draft 19 length. Any other length is refused, by the
/// encoder or by the decoder.
#[test]
fn r_cr_03_anchor_signature_has_the_composite_length() {
    check("r_cr_03_anchor_signature_has_the_composite_length", |g| {
        let mut a = gen_anchor(g);
        let len = if g.bool() {
            g.usize_in(0..=SIGNATURE_LEN - 1)
        } else {
            g.usize_in(SIGNATURE_LEN + 1..=SIGNATURE_LEN + 64)
        };
        a.signature.resize(len, 0x11);
        let r = api::encode_anchor(&a).and_then(|b| api::decode_anchor(&b));
        real_refusal(&format!("anchor with a {len}-byte signature"), &r)
    });
}

// ---------------------------------------------------------------------------
// Receipts (`receipt_decode`).

/// TH-26, R-CR-03: a receipt with every ADR-010 field round-trips.
#[test]
fn th_26_receipt_round_trips() {
    check("th_26_receipt_round_trips", |g| {
        RECEIPT.round_trip(&gen_receipt(g))
    });
}

/// TH-26, R-CR-03: one spelling per receipt.
#[test]
fn th_26_receipt_has_one_spelling() {
    check("th_26_receipt_has_one_spelling", |g| {
        let r = gen_receipt(g);
        RECEIPT.one_spelling_under_change(&r, g)
    });
}

/// TH-26: arbitrary bytes are refused for real or re-encode byte for
/// byte.
#[test]
fn th_26_receipt_decode_of_arbitrary_bytes_has_one_spelling() {
    check(
        "th_26_receipt_decode_of_arbitrary_bytes_has_one_spelling",
        |g| RECEIPT.one_spelling_on(&g.bytes(0..=128)),
    );
}

/// TH-26: every proper prefix of an encoded receipt is refused.
#[test]
fn th_26_receipt_decode_refuses_every_truncation() {
    check("th_26_receipt_decode_refuses_every_truncation", |g| {
        RECEIPT.refuses_prefixes(&gen_receipt(g))
    });
}

/// TH-26: an encoded receipt with trailing bytes is refused.
#[test]
fn th_26_receipt_decode_refuses_trailing_bytes() {
    check("th_26_receipt_decode_refuses_trailing_bytes", |g| {
        let r = gen_receipt(g);
        let extra = g.bytes(1..=8);
        RECEIPT.refuses_trailing(&r, &extra)
    });
}

/// R-CR-03, I-90: a receipt signature has the composite length too.
#[test]
fn r_cr_03_receipt_signature_has_the_composite_length() {
    check("r_cr_03_receipt_signature_has_the_composite_length", |g| {
        let mut rc = gen_receipt(g);
        let len = g.usize_in(0..=SIGNATURE_LEN - 1);
        rc.signature.truncate(len);
        let r = api::encode_receipt(&rc).and_then(|b| api::decode_receipt(&b));
        real_refusal(&format!("receipt with a {len}-byte signature"), &r)
    });
}

/// TH-26: empty input is refused by each decoder.
#[test]
fn th_26_audit_decoders_refuse_empty_input() {
    let refusals = [
        real_refusal("empty chain row", &api::decode_chain_row(&[])),
        real_refusal("empty anchor", &api::decode_anchor(&[])),
        real_refusal("empty receipt", &api::decode_receipt(&[])),
    ];
    assert_eq!(refusals, [Ok(()), Ok(()), Ok(())]);
}

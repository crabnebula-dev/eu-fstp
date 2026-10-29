//! I-24, I-90: the anchorer core takes a receipt only when a pinned
//! witness key signed it for this cell and chain (ADR-010 "Keys", design
//! section 7.2).
//!
//! `fstp_audit::anchorer::Anchorer::signed_receipt` checks the receipt
//! before the receipt fields reach `Anchorer::receipt`. A receipt that
//! fails the check moves the core to `MustAbort`, so no COMMIT is sent on
//! it and the prepare the witness may hold is withdrawn.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::signing as s;
use common::{ANCHOR_CTX, RECEIPT_CTX};
use fstp_audit::anchor::receipt_message;
use fstp_audit::anchorer::{Anchorer, Next, PhaseName, ReceiptRefused, Step};
use fstp_audit::{CellId, ChainId, Link, Receipt, ReceiptFields};
use fstp_crypto::composite::CompositeSigningKey;

const CELL: CellId = CellId([7u8; 16]);
const OTHER_CELL: CellId = CellId([8u8; 16]);
const HEAD: (u64, Link) = (3, Link([0x33; 32]));

/// An anchorer that sent the prepare of [`HEAD`] and waits for its
/// receipt.
fn prepared() -> Anchorer {
    let mut a = Anchorer::new();
    a.begin(true).unwrap();
    for step in Step::ALL {
        a.step_done(step).unwrap();
    }
    a.prepared(HEAD).unwrap();
    a
}

/// The receipt fields for head `(n, link)`.
fn fields(head: (u64, Link)) -> ReceiptFields {
    ReceiptFields {
        n: head.0,
        link: head.1,
        witness_seq: 5,
        witness_link: Link([0x55; 32]),
        received_at: 1_700_000_000_000_000,
    }
}

/// A receipt for `cell`'s `chain` over `f`, signed by `k` under `ctx`.
fn receipt(
    k: &CompositeSigningKey,
    cell: CellId,
    chain: ChainId,
    f: ReceiptFields,
    ctx: &[u8],
) -> Receipt {
    let msg = receipt_message(cell, chain, &f);
    Receipt {
        cell,
        chain,
        fields: f,
        signature: s::sign(k, &msg, ctx),
    }
}

/// I-24, I-90, ADR-010 "Keys": a receipt that no pinned witness key
/// signed for this cell and chain is refused as `NotSigned`. The core
/// then aborts the prepare and never reaches COMMIT. The cases: an
/// unpinned key, another cell, another chain, a flipped signature byte,
/// the anchor context and an empty pinned key set.
#[test]
fn i24_anchorer_refuses_a_receipt_no_pinned_witness_key_signed() {
    let witness = s::key();
    let stranger = s::key();
    let pinned = vec![s::public(&witness)];
    let good = receipt(&witness, CELL, ChainId::App, fields(HEAD), RECEIPT_CTX);
    let mut flipped = good.clone();
    flipped.signature[17] ^= 1;
    let mut other_cell = good.clone();
    other_cell.cell = OTHER_CELL;
    let cases: [(&str, Receipt, &[Vec<u8>]); 7] = [
        (
            "unpinned key",
            receipt(&stranger, CELL, ChainId::App, fields(HEAD), RECEIPT_CTX),
            &pinned,
        ),
        (
            "signed for another cell",
            receipt(
                &witness,
                OTHER_CELL,
                ChainId::App,
                fields(HEAD),
                RECEIPT_CTX,
            ),
            &pinned,
        ),
        ("relabelled to another cell", other_cell, &pinned),
        (
            "another chain",
            receipt(&witness, CELL, ChainId::Vault, fields(HEAD), RECEIPT_CTX),
            &pinned,
        ),
        ("flipped signature byte", flipped, &pinned),
        (
            "anchor context",
            receipt(&witness, CELL, ChainId::App, fields(HEAD), ANCHOR_CTX),
            &pinned,
        ),
        ("no pinned key", good, &[]),
    ];
    for (what, rc, keys) in cases {
        let mut a = prepared();
        let got = a.signed_receipt(CELL, ChainId::App, &rc, keys);
        assert_eq!(got, Err(ReceiptRefused::NotSigned), "{what}");
        assert_eq!(a.next(), Next::SendAbort { head: HEAD }, "{what}");
        assert!(a.commit_sent().is_err(), "{what}: COMMIT allowed");
    }
}

/// I-24, design section 7.2: a receipt that a pinned witness key signed
/// for this cell, chain and head is taken, and COMMIT follows the
/// inserted anchor row. Any key of the pinned set serves.
#[test]
fn i24_anchorer_takes_a_pinned_witness_signed_receipt() {
    let old = s::key();
    let current = s::key();
    let pinned = vec![s::public(&old), s::public(&current)];
    for k in [&old, &current] {
        let mut a = prepared();
        let rc = receipt(k, CELL, ChainId::App, fields(HEAD), RECEIPT_CTX);
        assert_eq!(a.signed_receipt(CELL, ChainId::App, &rc, &pinned), Ok(()));
        assert_eq!(a.next(), Next::InsertAnchor);
        a.anchor_inserted().unwrap();
        assert_eq!(a.commit_sent(), Ok(()));
    }
}

/// I-24, `no-unwitnessed-commit`: a signed receipt for another head is
/// refused as out of order and leaves the prepare waiting. So is any
/// receipt when no prepare waits.
#[test]
fn i24_anchorer_refuses_a_signed_receipt_for_another_head() {
    let witness = s::key();
    let pinned = vec![s::public(&witness)];
    let other = (HEAD.0 + 1, HEAD.1);
    let rc = receipt(&witness, CELL, ChainId::App, fields(other), RECEIPT_CTX);
    let mut a = prepared();
    let got = a.signed_receipt(CELL, ChainId::App, &rc, &pinned);
    assert!(
        matches!(got, Err(ReceiptRefused::OutOfOrder(o)) if o.phase == PhaseName::Prepared),
        "{got:?}"
    );
    assert_eq!(a.next(), Next::AwaitReceipt);

    let mut idle = Anchorer::new();
    let rc = receipt(&witness, CELL, ChainId::App, fields(HEAD), RECEIPT_CTX);
    let got = idle.signed_receipt(CELL, ChainId::App, &rc, &pinned);
    assert!(
        matches!(got, Err(ReceiptRefused::OutOfOrder(o)) if o.phase == PhaseName::Idle),
        "{got:?}"
    );
    assert_eq!(idle.next(), Next::Nothing);
}

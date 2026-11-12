//! Review reproducer (lane W2g, robustness): the verifier's time grows
//! with the square of the number of anchors.
//!
//! `anchor_rows` scans the whole witness log for each anchor row, and
//! `witness_log` scans every anchor row for each prepare. One append makes
//! one anchor row and one prepare (ADR-010), so a chain of N appends costs
//! about N^2 comparisons. The cell and the vault verify their chains
//! before they serve requests (ADR-010 "Start-up"), so start-up time grows
//! with the square of the chain's age.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::time::{Duration, Instant};

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, ReceiptFields};
use fstp_audit::chain::{ChainWriter, RowKind};
use fstp_audit::verify::{ChainView, verify};
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId, Link, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// An honest chain of `appends` appends, one row and one anchor each, with
/// its witness log. Returns the time `verify` takes over it.
fn time_verify(appends: u64) -> Duration {
    let cell = CellId([7; 16]);
    let chain = ChainId::App;
    let mut w = ChainWriter::genesis(cell, chain);
    let mut rows = Vec::new();
    let mut anchors = Vec::new();
    for at in 0..appends {
        let r = w
            .append(
                cell,
                chain,
                i64::try_from(at).unwrap(),
                RowKind::Event { body: vec![1] },
                None,
            )
            .unwrap();
        let (n, link) = (r.row.n, r.link);
        rows.push(r);
        anchors.push(AnchorRow {
            anchor: Anchor {
                cell,
                chain,
                n,
                link,
                at: 0,
                signature: vec![0; SIGNATURE_LEN],
            },
            receipt: Receipt {
                cell,
                chain,
                fields: ReceiptFields {
                    n,
                    link,
                    witness_seq: n,
                    witness_link: Link([0; 32]),
                    received_at: 0,
                },
                signature: vec![0; SIGNATURE_LEN],
            },
        });
    }
    let witness: Vec<WitnessRecord> = anchors
        .iter()
        .cloned()
        .map(WitnessRecord::Prepare)
        .collect();
    let keys = vec![vec![0u8; PUBLIC_KEY_LEN]];
    let view = ChainView {
        cell,
        chain,
        rows: &rows,
        ledger: &[],
        anchors: &anchors,
        witness: &witness,
        anchor_keys: &keys,
        witness_keys: &keys,
    };
    let start = Instant::now();
    let got = verify(&view);
    let took = start.elapsed();
    assert!(got.is_err(), "fails closed while signatures are unchecked");
    took
}

/// I-24, ADR-010 "Start-up": verify time grows linearly with the chain.
/// Four times the appends may take at most eight times as long, plus
/// 100 ms of slack for noise. With linear lookups the ratio is about
/// four. With the current per-anchor scans it is about sixteen, and a
/// chain of a million appends would take hours to verify.
///
/// Each size is timed three times and the fastest run counts, so a busy
/// CI runner does not fail a linear verifier (CI run 43191138164 timed one
/// slow run of 32,000). The bound is unchanged.
#[test]
fn review_i24_verify_time_is_not_quadratic_in_anchors() {
    let best = |appends: u64| (0..3).map(|_| time_verify(appends)).min().unwrap();
    let small = best(8_000);
    let large = best(32_000);
    assert!(
        large < small * 8 + Duration::from_millis(100),
        "verify of 8,000 appends took {small:?}, of 32,000 took {large:?}"
    );
}

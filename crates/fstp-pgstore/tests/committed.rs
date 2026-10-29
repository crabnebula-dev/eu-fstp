//! What a committed append of `PgRecordStore` reports, and the chain it
//! reads back for the start-up verification (lane int3, M3 design
//! sections 5.3 and 7.2, ADR-010, I-24, I-78).
//!
//! - `append_committed` gives the ledger head, the chain row and link of
//!   its last entry and the witness sequence of its receipt. The engine's
//!   `CellStore` needs the link for the vault acknowledgement (NOTE 4).
//! - `stored_commit` gives the same for any stored entry: its link and
//!   the first receipt at or after its row.
//! - `read_chain_rows` reads every chain row, stored ledger row and
//!   anchor, and `fstp_audit::verify` accepts them against the witness.
//! - The step-up row is keyed by the step-up id, which is the challenge
//!   id end to end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, FakeWitness, Rec, Store, must, uuid_text};
use fstp_audit::chain::{ChainId, Link};
use fstp_audit::verify::{ChainView, verify};
use fstp_ledger::Seq;
use fstp_pgstore::{AppendFault, SessionEnd, SideEffects, StepUpUse, StoredCommit};

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

fn recs(n: usize, text: &str) -> Vec<Rec> {
    (0..n)
        .map(|i| Rec::new(u8::try_from(i % 4).unwrap(), text))
        .collect()
}

fn world() -> (CellDb, FakeWitness, Store) {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let s = must(Store::open(&db, &w));
    (db, w, s)
}

/// I-24, design sections 5.3 and 7.2: a committed append reports its new
/// head, the chain row and link of its last entry, and the witness
/// sequence of the receipt it committed on. `stored_commit` gives the same
/// link and receipt for that entry, the batch's covering receipt for an
/// earlier entry of the batch, and nothing past the head.
#[test]
fn i24_append_reports_the_link_and_receipt_it_committed_on() {
    let (_db, w, mut s) = world();
    let none = SideEffects::default();
    let c1 = s
        .append_committed(Seq::ZERO, AT, [0x11; 16], recs(2, "a"), &none)
        .unwrap();
    assert_eq!(c1.head, Seq::from_raw(2));
    let last = w.receipts().last().cloned().unwrap();
    assert_eq!(
        (last.fields.n, last.fields.link, last.fields.witness_seq),
        (c1.n, c1.link, c1.witness_seq),
        "the reported commit is not the receipted head"
    );
    assert_eq!(
        s.stored_commit(Seq::from_raw(2)),
        Some(StoredCommit {
            n: c1.n,
            link: c1.link,
            witness_seq: Some(c1.witness_seq),
        })
    );
    let first = s.stored_commit(Seq::from_raw(1)).unwrap();
    assert_eq!(first.n + 1, c1.n);
    assert_ne!(first.link, c1.link);
    assert_eq!(first.witness_seq, Some(c1.witness_seq));
    let c2 = s
        .append_committed(Seq::from_raw(2), AT, [0x12; 16], recs(1, "b"), &none)
        .unwrap();
    assert_eq!(c2.head, Seq::from_raw(3));
    assert!(c2.witness_seq > c1.witness_seq);
    assert_eq!(
        s.stored_commit(Seq::from_raw(3))
            .map(|c| (c.link, c.witness_seq)),
        Some((c2.link, Some(c2.witness_seq)))
    );
    assert_eq!(s.stored_commit(Seq::from_raw(4)), None);
}

/// I-24, design section 7.2 "Start-up": the chain the store reads back
/// holds every chain row, stored ledger row and anchor, and it verifies
/// against the witness log under the store's anchor and witness keys. A
/// changed link in the read copy does not verify.
#[test]
fn i24_read_chain_rows_verify_against_the_witness_log() {
    let (db, w, mut s) = world();
    let none = SideEffects::default();
    s.append_committed(Seq::ZERO, AT, [0x21; 16], recs(2, "a"), &none)
        .unwrap();
    s.append_committed(Seq::from_raw(2), AT, [0x22; 16], recs(1, "b"), &none)
        .unwrap();
    let chain = s.read_chain_rows();
    assert_eq!(
        (chain.rows.len(), chain.stored.len(), chain.anchors.len()),
        (3, 3, 2)
    );
    let log = w.witness_log();
    let anchor_keys = vec![s.anchor_key()];
    let witness_keys = s.witness_keys();
    let view = |rows: &[fstp_audit::chain::StoredRow]| {
        verify(&ChainView {
            cell: db.cell_id(),
            chain: ChainId::App,
            rows,
            ledger: &chain.stored,
            anchors: &chain.anchors,
            witness: &log,
            anchor_keys: &anchor_keys,
            witness_keys: &witness_keys,
        })
        .is_ok()
    };
    assert!(view(&chain.rows), "the stored chain did not verify");
    let mut tampered = chain.rows.clone();
    tampered[1].link = Link([0xEE; 32]);
    assert!(!view(&tampered), "a changed link verified");
}

/// I-78, design sections 4.2 and 5.3: the `auth_log.stepup_consumed` row
/// is keyed by the step-up id, the challenge id end to end. A second
/// append that consumes the same id aborts as a replay and commits
/// nothing.
#[test]
fn i78_step_up_row_is_keyed_by_the_step_up_id() {
    let (db, _w, mut s) = world();
    let id = [0xC4; 16];
    let side = SideEffects {
        stepup_consumed: Some(StepUpUse {
            challenge: id,
            record: 0,
        }),
        stepup_fresh_until: Some(i64::MAX),
        ..SideEffects::default()
    };
    s.append_committed(Seq::ZERO, AT, [0x31; 16], recs(1, "a"), &side)
        .unwrap();
    let keyed = db.count(&format!(
        "SELECT count(*) FROM auth_log.stepup_consumed WHERE challenge_id = '{}'",
        uuid_text(&id)
    ));
    assert_eq!(keyed, 1);
    assert_eq!(
        s.append_committed(Seq::from_raw(1), AT, [0x32; 16], recs(1, "b"), &side),
        Err(AppendFault::StepUpReplayed)
    );
    assert_eq!(s.stored_commit(Seq::from_raw(2)), None);
}

/// I-77, I-78, design sections 4.2 and 5.3: in a batch that consumes a
/// fresh step-up and ends a session that an earlier batch ended, the
/// session-end row is the one that conflicts. The refusal names it, not
/// a step-up replay, and nothing commits.
#[test]
fn i77_a_session_end_replay_names_the_session_row() {
    let (db, _w, mut s) = world();
    let session = [0x5E; 16];
    let first = SideEffects {
        sessions_ended: vec![SessionEnd { session, record: 0 }],
        ..SideEffects::default()
    };
    s.append_committed(Seq::ZERO, AT, [0x41; 16], recs(1, "a"), &first)
        .unwrap();
    let again = SideEffects {
        stepup_consumed: Some(StepUpUse {
            challenge: [0xC6; 16],
            record: 0,
        }),
        stepup_fresh_until: Some(i64::MAX),
        sessions_ended: vec![SessionEnd { session, record: 1 }],
        ..SideEffects::default()
    };
    assert_eq!(
        s.append_committed(Seq::from_raw(1), AT, [0x42; 16], recs(2, "b"), &again),
        Err(AppendFault::SessionEndReplayed)
    );
    assert_eq!(s.stored_commit(Seq::from_raw(2)), None);
    assert_eq!(
        db.count("SELECT count(*) FROM auth_log.stepup_consumed"),
        0,
        "the aborted append left its step-up row"
    );
}

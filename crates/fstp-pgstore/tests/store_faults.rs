//! Regression tests of the W2e fix round (M3 design sections 4.1, 4.2,
//! 5.3 and 7.2, ADR-004, ADR-007, ADR-010, I-24, I-77, I-78, I-83,
//! TH-21).
//!
//! - The abort, alert and in-doubt steps hold `pg_advisory_xact_lock(1)`.
//! - Outbox rows, the alerts among them, are sealed under a data key of
//!   their own, never under the ledger key.
//! - The side effects carry outbox rows, and each `auth_log` row names
//!   the entry of its own record.
//! - A failure or a lost connection after any statement of an append
//!   commits all of its rows or none (I-24).
//! - `fstp_audit::verify` over the production rows finds superuser edits.
//! - A receipt no pinned witness key signed is refused and aborted.
//! - A reused ledger key generation is refused before it seals.
//! - A read past the client's result limit pages instead of failing.
//! - The placement table holds one row, naming its own cell.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    CellDb, FAULTS, FRESH, FakeWitness, INJECTED_ROWS, Mode, Rec, Recorded, Store, append_rows,
    arm, canary, fresh16, holds_canary, injected_side, must, outbox_row, recompute_chain,
    verify_production,
};
use fstp_audit::AuditError;
use fstp_audit::anchorer::Resolution;
use fstp_audit::chain::Link;
use fstp_audit::verify::Tamper;
use fstp_ledger::{AppendError, Seq};
use fstp_pgstore::{
    AppendFault, MAX_OUTBOX_BODY, OutboxRow, SessionEnd, SideEffects, StepUpUse, StoreFault,
};

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

/// Superuser SQL that holds `pg_advisory_xact_lock(1)` for four seconds,
/// as an open append or a reader view under the ADR-010 rule does.
const HOLD_LOCK: &str = "BEGIN;\nSELECT pg_advisory_xact_lock(1);\nSELECT pg_sleep(10);\nCOMMIT;";

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

fn appended(r: Result<Result<Seq, AppendError>, common::Gap>) -> Seq {
    match must(r) {
        Ok(h) => h,
        Err(e) => panic!("the append was refused: {e}"),
    }
}

fn prepares(w: &FakeWitness) -> usize {
    w.recorded()
        .iter()
        .filter(|r| matches!(r, Recorded::Prepare { .. }))
        .count()
}

/// Waits until some session holds `pg_advisory_xact_lock(1)`.
fn lock_held(db: &CellDb) -> bool {
    db.count(
        "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND granted \
         AND classid = 0 AND objid = 1 AND objsubid = 1;",
    ) > 0
}

fn wait_for_advisory_lock(db: &CellDb) {
    let start = Instant::now();
    while !lock_held(db) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the lock was never taken"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// The advisory lock (fstp_audit::verify::ChainView, W2e obligation).

/// I-24, ADR-010, `fstp_audit::verify::ChainView` (W2e obligation): an
/// in-doubt record that is still due waits while another session holds
/// `pg_advisory_xact_lock(1)`, and is sent once the lock is free.
#[test]
fn i24_in_doubt_record_waits_for_the_advisory_lock() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    let lx = (2, Link([0x66; 32]));
    w.hold_outstanding(lx);
    w.lose_in_doubt(1);
    let first = must(s.resolve_in_doubt(lx));
    assert!(first.is_err(), "the in-doubt record was lost: {first:?}");
    assert_eq!(must(s.possible_deletions()), vec![lx], "the alert first");
    std::thread::scope(|scope| {
        let holder = scope.spawn(|| db.psql(HOLD_LOCK));
        wait_for_advisory_lock(&db);
        let before = w.received();
        let watch = w.clone();
        let cell_db = &db;
        // The sample counts only if the lock was still held after it was
        // taken: a slow runner must not let the holder end first.
        let watcher = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            let seen = watch.received();
            (seen, lock_held(cell_db))
        });
        let got = must(s.resolve_in_doubt(lx));
        let (during, still_held) = watcher.join().unwrap();
        assert!(
            still_held,
            "the lock holder ended before the watcher sampled, so this run cannot judge I-24"
        );
        holder.join().unwrap().unwrap();
        assert_eq!(
            during, before,
            "I-24: the in-doubt record was sent while another session held the lock"
        );
        assert_eq!(got, Ok(Resolution::AbsentRaisePossibleDeletion));
    });
    assert!(
        w.recorded()
            .contains(&Recorded::InDoubtAbsent { n: 2, link: lx.1 }),
        "ADR-010: the in-doubt record"
    );
    assert!(s.idle(), "the core resolved the prepare");
}

// ---------------------------------------------------------------------------
// Outbox rows (ADR-004, ADR-007, design section 5.3 step 6).

/// ADR-004 "Seal-count limit": every `PossibleDeletion` alert is sealed
/// under a data key of its own, and none names a ledger key generation's
/// data key. Each alert opens under its own key and outbox AAD.
#[test]
fn adr004_possible_deletion_alerts_never_name_a_ledger_data_key() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    for b in [0x41u8, 0x42, 0x43] {
        let head = (2, Link([b; 32]));
        w.hold_outstanding(head);
        assert_eq!(
            must(s.resolve_in_doubt(head)),
            Ok(Resolution::AbsentRaisePossibleDeletion)
        );
    }
    let rows = db.outbox_rows();
    assert_eq!(rows.len(), 3, "three alerts");
    let ledger = common::ledger_deks(db.cell);
    for r in &rows {
        assert!(
            !ledger.contains(&r.dek),
            "ADR-004: an alert names a ledger key generation's data key"
        );
        let plain = common::open_outbox_row(&db.cell, r)
            .unwrap_or_else(|| panic!("ADR-004: an alert does not open under its own key"));
        assert_eq!(plain.len(), 40, "be64(n) || link");
    }
}

/// ADR-007 "Insert-only side effects", design section 5.3 step 6, gap
/// G12: the outbox rows of an append commit with it, each sealed under a
/// fresh data key of its own and opening under its outbox AAD. No body
/// is readable at rest.
#[test]
fn adr007_outbox_rows_commit_sealed_with_their_append() {
    let (db, _w, mut s) = world();
    let text = canary(&db.hex, "outbox");
    let side = SideEffects {
        outbox: vec![
            outbox_row(2, text.as_bytes()),
            outbox_row(3, b"recovery mail"),
        ],
        ..SideEffects::default()
    };
    assert_eq!(
        s.append_effects(Seq::ZERO, AT, fresh16(), recs(1, "mail"), &side),
        Ok(Seq::from_raw(1))
    );
    let rows = db.outbox_rows();
    assert_eq!(rows.len(), 2, "ADR-007: the outbox rows of the append");
    assert_ne!(rows[0].dek, rows[1].dek, "ADR-004: one data key per row");
    let ledger = common::ledger_deks(db.cell);
    for want in &side.outbox {
        let r = rows
            .iter()
            .find(|r| r.id == want.id)
            .unwrap_or_else(|| panic!("no row {:?}", want.id));
        assert_eq!(
            (r.kind, r.idem.as_slice()),
            (want.kind, want.idem.as_slice())
        );
        assert!(!ledger.contains(&r.dek), "ADR-004: a ledger data key");
        assert_eq!(
            common::open_outbox_row(&db.cell, r),
            Some(want.body.clone()),
            "ADR-004: the row opens under its own key and AAD"
        );
    }
    assert!(
        !holds_canary(&db.dump(), &text),
        "R-NF-08: an outbox body in clear"
    );
}

/// TH-21, ADR-007: an outbox row whose idem is already stored aborts the
/// whole append before its prepare. No entry, chain row or side row of
/// it remains.
#[test]
fn th_21_outbox_row_with_a_stored_idem_aborts_the_whole_append() {
    let (db, w, mut s) = world();
    let first = outbox_row(2, b"magic link");
    let side = SideEffects {
        outbox: vec![first.clone()],
        ..SideEffects::default()
    };
    assert_eq!(
        s.append_effects(Seq::ZERO, AT, fresh16(), recs(1, "one"), &side),
        Ok(Seq::from_raw(1))
    );
    let before = append_rows(&db);
    let sent = prepares(&w);
    let again = SideEffects {
        outbox: vec![OutboxRow {
            id: fresh16(),
            ..first
        }],
        ..SideEffects::default()
    };
    assert_eq!(
        s.append_effects(Seq::from_raw(1), AT, fresh16(), recs(2, "two"), &again),
        Err(AppendFault::OutboxDuplicate),
        "TH-21: a second message under one idem"
    );
    assert_eq!(
        append_rows(&db),
        before,
        "TH-21: rows of the aborted append"
    );
    assert_eq!(prepares(&w), sent, "TH-21: the aborted append was prepared");
}

/// ADR-007, design section 7.2: a caller cannot enqueue a row of the
/// alert kind, an unknown kind 0, or a body over its limit. Nothing is
/// written and nothing reaches the witness.
#[test]
fn adr007_outbox_rows_refuse_the_alert_kind_and_oversized_bodies() {
    let (db, w, mut s) = world();
    let before = append_rows(&db);
    for row in [
        outbox_row(1, b"forged alert"),
        outbox_row(0, b"kind zero"),
        outbox_row(2, &vec![0u8; MAX_OUTBOX_BODY + 1]),
    ] {
        let side = SideEffects {
            outbox: vec![row],
            ..SideEffects::default()
        };
        let got = s.append_effects(Seq::ZERO, AT, fresh16(), recs(1, "x"), &side);
        assert!(
            matches!(got, Err(AppendFault::Fault(StoreFault::Refused(_)))),
            "ADR-007: {got:?}"
        );
    }
    assert_eq!(append_rows(&db), before, "rows of refused appends");
    assert_eq!(prepares(&w), 0, "a refused append was prepared");
}

/// I-77, I-78, design section 4.2: each `auth_log` row names the entry of
/// the record it belongs to, not the first entry of its batch. A row that
/// names no record of its batch refuses the whole append.
#[test]
fn i78_side_rows_name_the_entry_of_their_own_record() {
    let (db, w, mut s) = world();
    let (challenge, s0, s1) = (fresh16(), fresh16(), fresh16());
    let side = SideEffects {
        stepup_consumed: Some(StepUpUse {
            challenge,
            record: 2,
        }),
        stepup_fresh_until: Some(FRESH),
        sessions_ended: vec![
            SessionEnd {
                session: s0,
                record: 0,
            },
            SessionEnd {
                session: s1,
                record: 1,
            },
        ],
        outbox: Vec::new(),
    };
    assert_eq!(
        s.append_effects(Seq::ZERO, AT, fresh16(), recs(3, "three"), &side),
        Ok(Seq::from_raw(3))
    );
    let seq_of = |sql: String| db.count(&sql);
    assert_eq!(
        seq_of(format!(
            "SELECT ledger_seq FROM auth_log.stepup_consumed WHERE challenge_id = '{}';",
            common::uuid_text(&challenge)
        )),
        3,
        "I-78: the consumption names its own entry"
    );
    for (session, want) in [(s0, 1), (s1, 2)] {
        assert_eq!(
            seq_of(format!(
                "SELECT ledger_seq FROM auth_log.session_end WHERE session_id = '{}';",
                common::uuid_text(&session)
            )),
            want,
            "I-77: the session end names its own entry"
        );
    }
    let before = append_rows(&db);
    let sent = prepares(&w);
    let outside = SideEffects {
        sessions_ended: vec![SessionEnd {
            session: fresh16(),
            record: 1,
        }],
        ..SideEffects::default()
    };
    let got = s.append_effects(Seq::from_raw(3), AT, fresh16(), recs(1, "one"), &outside);
    assert!(
        matches!(got, Err(AppendFault::Fault(StoreFault::Refused(_)))),
        "I-77: a row outside its batch: {got:?}"
    );
    assert_eq!(append_rows(&db), before, "rows of the refused append");
    assert_eq!(prepares(&w), sent, "the refused append was prepared");
}

// ---------------------------------------------------------------------------
// Crash injection (I-24, design section 14.4).

/// I-24, ADR-007, design sections 5.3 and 14.4
/// (`i24_ledger_and_chain_commit_together`): a failure or a lost
/// connection after each statement of an append, from the command row
/// through the anchor insert, and at COMMIT, leaves no ledger, chain,
/// side or anchor row of it. The store then settles every abort and
/// in-doubt step, and an append without a fault commits every row
/// together. The chain still recomputes, and the verifier finds no
/// change.
#[test]
fn i24_append_rows_commit_together_under_crash_injection() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "base")));
    db.psql(FAULTS).unwrap_or_else(|e| panic!("{e:?}"));
    let mut cases: Vec<(u64, u8, u8)> = Vec::new();
    for target in 1..=INJECTED_ROWS {
        for mode in [1, 2] {
            cases.push((target, mode, 0));
        }
    }
    cases.push((0, 0, 1));
    cases.push((0, 0, 2));
    for (target, mode, at_commit) in cases {
        let before = append_rows(&db);
        arm(&db, target, mode, at_commit);
        let got = s.append_effects(
            Seq::from_raw(1),
            AT,
            fresh16(),
            recs(2, "injected"),
            &injected_side(),
        );
        arm(&db, 0, 0, 0);
        assert!(
            got.is_err(),
            "I-24: an injected fault after row {target} (mode {mode}, commit {at_commit}) committed"
        );
        assert_eq!(
            append_rows(&db),
            before,
            "I-24: rows of an append that failed after row {target} (mode {mode}, commit {at_commit})"
        );
        let settled = s.settle();
        assert!(settled.is_ok(), "the store did not settle: {settled:?}");
        assert!(s.idle(), "an unfinished step after row {target}");
        assert_eq!(append_rows(&db), before, "I-24: rows after the settle");
    }
    let before = append_rows(&db);
    assert_eq!(
        s.append_effects(
            Seq::from_raw(1),
            AT,
            fresh16(),
            recs(2, "whole"),
            &injected_side()
        ),
        Ok(Seq::from_raw(3))
    );
    let after = append_rows(&db);
    let grew: BTreeMap<&str, u64> = after.iter().map(|(t, n)| (*t, n - before[t])).collect();
    let want: BTreeMap<&str, u64> = [
        ("ledger.command", 1),
        ("ledger.entry", 2),
        ("audit.chain", 2),
        ("audit.anchor", 1),
        ("auth_log.stepup_consumed", 1),
        ("auth_log.session_end", 1),
        ("ops.outbox", 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(grew, want, "I-24: the rows of one append, together");
    recompute_chain(db.cell_id(), &db.chain_rows(), &db.ledger_rows())
        .unwrap_or_else(|e| panic!("I-24: {e}"));
    assert_no_tamper(&verify_production(&db, &w, &s), "after the injections");
}

// ---------------------------------------------------------------------------
// The verifier over production rows (I-24, design section 14.4).

/// The verifier found no change, signatures included.
fn assert_no_tamper(got: &Result<fstp_audit::verify::Verified, AuditError>, when: &str) {
    assert!(
        got.is_ok(),
        "I-24: the verifier found a change {when}: {got:?}"
    );
}

/// Three appends of one entry each, so rows 1, 2 and 3 hold entries 1, 2
/// and 3.
fn three_appends() -> (CellDb, FakeWitness, Store) {
    let (db, w, mut s) = world();
    for (i, text) in ["one", "two", "three"].into_iter().enumerate() {
        appended(s.append(
            Seq::from_raw(u64::try_from(i).unwrap()),
            AT,
            fresh16(),
            recs(1, text),
        ));
    }
    (db, w, s)
}

/// I-24, design section 14.4: the verifier finds no change in the rows
/// the production store wrote.
#[test]
fn i24_production_rows_pass_every_verifier_check() {
    let (db, w, s) = three_appends();
    assert_no_tamper(&verify_production(&db, &w, &s), "in untouched rows");
}

/// I-24, design section 14.4 (`i24_database_refuses_bad_link_and_mutation`,
/// "superuser edits then detected by verify"): a superuser who swaps two
/// ledger bodies, triggers bypassed, is found as a stored hash mismatch.
#[test]
fn i24_superuser_body_swap_is_found_by_the_verifier() {
    let (db, w, s) = three_appends();
    db.psql(
        "SET session_replication_role = replica;\nUPDATE ledger.entry e SET body = o.body \
         FROM ledger.entry o WHERE (e.seq = 1 AND o.seq = 2) OR (e.seq = 2 AND o.seq = 1);",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        verify_production(&db, &w, &s),
        Err(AuditError::Tamper(Tamper::StoredHashMismatch { seq: 1 })),
        "I-24: a swapped body"
    );
}

/// I-24, design section 7.2: a superuser who deletes a row inside the
/// chain, with its entry and anchor, is found as a gap.
#[test]
fn i24_superuser_row_deletion_is_found_by_the_verifier() {
    let (db, w, s) = three_appends();
    db.psql(
        "SET session_replication_role = replica;\nDELETE FROM audit.anchor WHERE n = 2;\n\
         DELETE FROM audit.chain WHERE n = 2;\nDELETE FROM ledger.entry WHERE seq = 2;",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        verify_production(&db, &w, &s),
        Err(AuditError::Tamper(Tamper::Gap { n: 2 })),
        "I-24: a deleted row"
    );
}

/// I-24, design section 7.2: a superuser who deletes the head row, with
/// its entry and anchor, is found as a truncation, since the witness
/// receipted that head.
#[test]
fn i24_superuser_head_deletion_is_found_by_the_verifier() {
    let (db, w, s) = three_appends();
    db.psql(
        "SET session_replication_role = replica;\nDELETE FROM audit.anchor WHERE n = 3;\n\
         DELETE FROM audit.chain WHERE n = 3;\nDELETE FROM ledger.entry WHERE seq = 3;",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        verify_production(&db, &w, &s),
        Err(AuditError::Tamper(Tamper::Truncated {
            witnessed: 3,
            have: 2
        })),
        "I-24: a deleted head"
    );
}

// ---------------------------------------------------------------------------
// Receipts (ADR-010 "Keys").

/// ADR-010 "Keys", I-24: a receipt that no pinned witness key signed is
/// refused before COMMIT. The append writes no row, and its prepare is
/// aborted at the witness.
#[test]
fn i24_receipt_signed_by_no_pinned_key_is_refused_and_aborted() {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let other = fstp_crypto::composite::generate()
        .unwrap()
        .public_key()
        .to_bytes()
        .to_vec();
    let mut s = must(Store::open_pinned(&db, &w, vec![other]));
    let before = append_rows(&db);
    let got = s.append_effects(
        Seq::ZERO,
        AT,
        fresh16(),
        recs(1, "unpinned"),
        &SideEffects::default(),
    );
    assert_eq!(
        got,
        Err(AppendFault::Fault(StoreFault::ReceiptUnsigned)),
        "ADR-010: a receipt of an unpinned key"
    );
    assert_eq!(append_rows(&db), before, "I-24: rows of a refused receipt");
    match w.recorded().as_slice() {
        [
            Recorded::Prepare { n: 1, link: p, .. },
            Recorded::Abort { n: 1, link: a },
        ] => assert_eq!(p, a, "ADR-010: the abort names the prepared link"),
        other => panic!("ADR-010: the witness recorded {other:#?}"),
    }
}

// ---------------------------------------------------------------------------
// Ledger key generations (ADR-004 "Seal-count limit").

/// ADR-004 "Seal-count limit": a process start that reuses a ledger key
/// generation whose index names stored rows is refused before it seals,
/// by the store and by the checkpoints. Nothing is written or prepared.
#[test]
fn adr004_reused_ledger_key_generation_is_refused_before_it_seals() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "first")));
    common::stop(s);
    let keys = Arc::new(common::ledger_keys_reusing_last(db.cell));
    let mut again = must(Store::open_with_keys(&db, &w, vec![w.public_key()], keys));
    let before = append_rows(&db);
    let sent = prepares(&w);
    assert_eq!(
        again.append_effects(
            Seq::from_raw(1),
            AT,
            fresh16(),
            recs(1, "reused"),
            &SideEffects::default()
        ),
        Err(AppendFault::Fault(StoreFault::KeyGenerationReused)),
        "ADR-004: a reused generation sealed"
    );
    assert_eq!(
        append_rows(&db),
        before,
        "ADR-004: rows under a reused generation"
    );
    assert_eq!(
        prepares(&w),
        sent,
        "ADR-004: a reused generation was prepared"
    );
    let cp = must(again.put_checkpoint(Seq::from_raw(1), b"state"));
    assert!(
        cp.as_ref().is_err_and(|e| e.contains("already sealed")),
        "ADR-004: a checkpoint under a reused generation: {cp:?}"
    );
    let mut fresh = must(Store::open(&db, &w));
    appended(fresh.append(Seq::from_raw(1), AT, fresh16(), recs(1, "fresh")));
}

// ---------------------------------------------------------------------------
// Reads (ADR-007, design section 5.5).

/// ADR-007, design section 5.5: a read with a limit past one page returns
/// every entry in order, as a replay at start-up asks.
#[test]
fn adr007_reads_page_across_more_than_one_page() {
    let (_db, _w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(2_100, "page")));
    let all = must(s.read(Seq::ZERO, 1_000_000)).unwrap_or_else(|e| panic!("{e}"));
    let seqs: Vec<u64> = all.iter().map(|e| e.seq.raw()).collect();
    assert_eq!(
        seqs,
        (1..=2_100).collect::<Vec<u64>>(),
        "every entry, in order"
    );
    let part = must(s.read(Seq::from_raw(1_500), 700)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        part.first().map(|e| e.seq.raw()),
        Some(1_500),
        "a read from inside the ledger"
    );
    assert_eq!(part.len(), 601, "a read stops at the head");
}

/// ADR-007, design section 5.5: a read whose rows pass the client's
/// result limit reads in smaller pages and returns every entry, where
/// one query fails.
#[test]
fn adr007_reads_past_the_result_limit_halve_the_page() {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let mut s = must(Store::open_limited(&db, &w, 64 << 10));
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1_200, "limit")));
    let all = must(s.read(Seq::ZERO, 10_000)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(all.len(), 1_200, "ADR-007: every entry past the limit");
    assert!(
        all.iter()
            .enumerate()
            .all(|(i, e)| e.seq.raw() == u64::try_from(i).unwrap() + 1 && e.record.text == "limit"),
        "ADR-007: the entries in order"
    );
}

// ---------------------------------------------------------------------------
// Placement (I-83, design section 4.1).

/// I-83, design section 4.1: the placement table holds the one row that
/// provisioning wrote. A second row, even a valid one, is refused, a row
/// naming another cell is refused, and the row cannot change.
#[test]
fn i83_app_placement_is_one_row_of_its_own_cell() {
    let db = must(CellDb::provision());
    let cluster = common::bytea(&fresh16());
    let state = |sql: String| db.psql(&sql).err().and_then(|e| e.state);
    assert_eq!(
        state(format!(
            "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ({}, {cluster}, 1);",
            common::bytea(&db.cell)
        )),
        Some("23505".to_owned()),
        "I-83: a second placement row"
    );
    assert_eq!(
        state(format!(
            "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ({}, {cluster}, 1);",
            common::bytea(&fresh16())
        )),
        Some("23514".to_owned()),
        "I-83: a placement row of another cell"
    );
    for sql in [
        "UPDATE fstp_meta.placement SET kind = 1;",
        "DELETE FROM fstp_meta.placement;",
        "TRUNCATE fstp_meta.placement;",
    ] {
        assert_eq!(
            state(sql.to_owned()),
            Some("42501".to_owned()),
            "I-83: {sql}"
        );
    }
    assert_eq!(db.count("SELECT count(*) FROM fstp_meta.placement;"), 1);
}

/// Harness self-test: the witness of these tests refuses while
/// unreachable, so the lock tests above see no message.
#[test]
fn harness_unreachable_witness_records_nothing() {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let mut s = must(Store::open(&db, &w));
    w.set_mode(Mode::Unreachable);
    let got = must(s.append(Seq::ZERO, AT, fresh16(), recs(1, "lost")));
    assert!(got.is_err(), "committed without a witness: {got:?}");
    assert!(w.recorded().is_empty(), "an unreachable witness recorded");
}

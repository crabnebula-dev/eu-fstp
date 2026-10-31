//! Review reproducers for lane W2e (M3 design sections 5.3 and 7.2,
//! ADR-004, ADR-007, ADR-010, I-24). Each test fails against the code
//! under review and passes once the named defect is fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::time::{Duration, Instant};

use common::{CellDb, FakeWitness, Mode, Rec, Store, fresh16, must};
use fstp_audit::anchorer::Resolution;
use fstp_audit::chain::Link;
use fstp_ledger::{AppendError, Seq};
use fstp_pgstore::SideEffects;

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

/// Superuser SQL that holds `pg_advisory_xact_lock(1)` for four seconds,
/// as an open append or a reader view under the ADR-010 rule does.
const HOLD_LOCK: &str = "BEGIN;\nSELECT pg_advisory_xact_lock(1);\nSELECT pg_sleep(4);\nCOMMIT;";

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

/// Waits until some session holds `pg_advisory_xact_lock(1)`.
fn wait_for_advisory_lock(db: &CellDb) {
    let start = Instant::now();
    while db.count(
        "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND granted \
         AND classid = 0 AND objid = 1 AND objsubid = 1;",
    ) == 0
    {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the lock was never taken"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// I-24, ADR-010, `fstp_audit::verify::ChainView` (W2e obligation): "The
/// anchorer takes the same lock in a new transaction for each abort,
/// alert and in-doubt step". A due abort must therefore wait while
/// another session holds `pg_advisory_xact_lock(1)`. The store sends it
/// at once, so a reader view under the lock can see the witness log
/// change between its reads.
#[test]
fn review_abort_waits_for_the_advisory_lock() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    // The prepare's answer is lost, so the store owes an abort. The
    // abort is lost too, so it stays due.
    w.set_mode(Mode::Unreachable);
    let lost = must(s.append(Seq::from_raw(1), AT, fresh16(), recs(1, "lost")));
    assert!(lost.is_err(), "committed without a witness: {lost:?}");
    w.set_mode(Mode::Accept);
    std::thread::scope(|scope| {
        let holder = scope.spawn(|| db.psql(HOLD_LOCK));
        wait_for_advisory_lock(&db);
        let before = w.received();
        let watch = w.clone();
        let watcher = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            watch.received()
        });
        // The next append first sends the due abort.
        let _ = s.append(Seq::from_raw(1), AT, fresh16(), recs(1, "next"));
        let during = watcher
            .join()
            .unwrap_or_else(|_| panic!("the watcher panicked"));
        holder
            .join()
            .unwrap_or_else(|_| panic!("the lock holder panicked"))
            .unwrap_or_else(|e| panic!("the lock holder: {e:?}"));
        assert_eq!(
            during, before,
            "I-24: a witness message was sent while another session held \
             pg_advisory_xact_lock(1)"
        );
    });
}

/// ADR-004 "Seal-count limit": an outbox row is sealed under its own
/// per-object data key, and the ledger key seals only ledger bodies,
/// chain event bodies and checkpoints. The `PossibleDeletion` alerts in
/// `ops.outbox` are sealed under the ledger key and all name its data
/// key in `ops.outbox.dek`.
#[test]
fn review_possible_deletion_alerts_are_not_sealed_under_the_ledger_key() {
    let (db, w, mut s) = world();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    for b in [0x51u8, 0x52] {
        let head = (2, Link([b; 32]));
        w.hold_outstanding(head);
        assert_eq!(
            must(s.resolve_in_doubt(head)),
            Ok(Resolution::AbsentRaisePossibleDeletion),
            "a missing row"
        );
    }
    assert_eq!(must(s.possible_deletions()).len(), 2, "two alerts");
    let rows = db.count("SELECT count(*) FROM ops.outbox;");
    let deks = db.count("SELECT count(DISTINCT dek) FROM ops.outbox;");
    assert_eq!(
        deks, rows,
        "ADR-004: outbox rows share one data key, the ledger key's"
    );
}

/// ADR-007 "Insert-only side effects" and design section 5.3 step 6: the
/// side effects of an append include sealed `ops.outbox` rows, inserted
/// in the same transaction as the entries (design gap G12: magic links
/// and recovery mails). `SideEffects` carries no outbox rows, so no
/// caller can enqueue one with its append.
#[test]
fn review_side_effects_carry_outbox_rows() {
    let shown = format!("{:?}", SideEffects::default());
    assert!(
        shown.contains("outbox"),
        "ADR-007: SideEffects has no outbox rows: {shown}"
    );
}

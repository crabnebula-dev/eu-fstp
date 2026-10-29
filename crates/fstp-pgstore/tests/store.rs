//! `PgRecordStore` over a real application database (M3 design sections
//! 4.7, 5.3 and 7.2, ADR-007, ADR-010, I-23, I-24, I-77, I-78, I-82,
//! R-NF-08).
//!
//! The in-memory side is `fstp_ledger::MemStore` itself, so the store
//! property compares the two implementations of one contract. The
//! witness is `common::FakeWitness`, which records every prepare, abort
//! and in-doubt record in order and signs real composite receipts.
//!
//! The W2e test author wrote these tests before the production code. They
//! are red until `fstp_pgstore` exports its migrations and `PgRecordStore`
//! appends (`common::MIGRATIONS_SEAM`, `common::STORE_SEAM` and the seams
//! named in each test). The witness self-test is green.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use common::{
    CellDb, FakeWitness, Mode, REFERENCE_APP, Rec, Recorded, Side, Store, block_on, canary,
    fresh16, holds_canary, insert_chain_sql, insert_entries_sql, must, open_pool, rec,
    recompute_chain,
};
use fstp_audit::anchor::{Anchor, decode_receipt};
use fstp_audit::anchorer::{PrepareWitness, Resolution, WitnessFault};
use fstp_audit::chain::{
    ChainId, ChainRow, Link, RowKind, StoredEntry, genesis, link_of, stored_hash,
};
use fstp_audit::witness::Prepare;
use fstp_ledger::{AppendError, MAX_AT, MemStore, RecordStore, Seq};
use fstp_prop::{Config, Gen, prop_assert_eq};

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

fn recs(n: usize, text: &str) -> Vec<Rec> {
    (0..n)
        .map(|i| Rec::new(u8::try_from(i % 4).unwrap(), text))
        .collect()
}

/// A fresh database, its witness and its store, or the gap.
fn world() -> Result<(CellDb, FakeWitness, Store), common::Gap> {
    let db = CellDb::provision()?;
    let w = FakeWitness::new(db.cell_id());
    let s = Store::open(&db, &w)?;
    Ok((db, w, s))
}

/// The value of an append that must succeed.
fn appended(r: Result<Result<Seq, AppendError>, common::Gap>) -> Seq {
    match must(r) {
        Ok(h) => h,
        Err(e) => panic!("the append was refused: {e}"),
    }
}

/// The prepares the witness recorded: `(prev, n, link)`.
fn prepares(w: &FakeWitness) -> Vec<((u64, Link), u64, Link)> {
    w.recorded()
        .into_iter()
        .filter_map(|r| match r {
            Recorded::Prepare { prev, n, link } => Some((prev, n, link)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The store contract (ADR-007, I-23).

/// ADR-007, design section 14.6: for any sequence of appends with stale
/// heads, repeated command ids, empty batches and times at and past the
/// bound, `PgRecordStore` gives the results and the refusal order of
/// `fstp_ledger::MemStore`. Its head and every read, from any position
/// and with any limit, then equal the in-memory store's, records
/// decrypted and decoded.
#[test]
fn adr007_pg_store_matches_fstp_ledger_mem_store() {
    fstp_prop::check_with(
        "adr007_pg_store_matches_fstp_ledger_mem_store",
        Config::default().with_cases(8),
        |g: &mut Gen| {
            let (_db, _w, mut pg) = world()?;
            let mut mem: MemStore<Rec> = MemStore::new();
            for _ in 0..g.usize_in(1..=6) {
                let head = RecordStore::head(&mem);
                let expected = if g.bool() {
                    head
                } else {
                    Seq::from_raw(g.u64_in(0..=head.raw() + 2))
                };
                let at = *g.pick(&[0, AT, MAX_AT, -MAX_AT, MAX_AT + 1, -MAX_AT - 1]);
                let command = [g.u8_in(0..=3); 16];
                let n = g.usize_in(0..=3);
                let batch: Vec<Rec> = (0..n).map(|_| rec(g)).collect();
                let want = RecordStore::append(&mut mem, expected, at, command, batch.clone());
                let got = pg.append(expected, at, command, batch)?;
                prop_assert_eq!(got, want, "ADR-007: append at {at} expecting {expected:?}");
                prop_assert_eq!(pg.head()?, Ok(RecordStore::head(&mem)), "ADR-007: head");
            }
            let head = RecordStore::head(&mem).raw();
            for _ in 0..3 {
                let from = Seq::from_raw(g.u64_in(0..=head + 2));
                let limit = g.usize_in(0..=5);
                let mut want = Vec::new();
                RecordStore::read(&mem, from, limit, &mut want).map_err(|e| e.to_string())?;
                prop_assert_eq!(
                    pg.read(from, limit)?,
                    Ok(want),
                    "ADR-007: read {from:?} {limit}"
                );
            }
            Ok(())
        },
    );
}

/// I-23, ADR-007: a refused append, for a repeated command, a stale head,
/// an empty batch or a time past the bound, writes no row in any table
/// and sends nothing to the witness.
#[test]
fn i23_refused_append_writes_no_row() {
    let (db, w, mut s) = must(world());
    let cmd = fresh16();
    appended(s.append(Seq::ZERO, AT, cmd, recs(2, "first")));
    let before = db.row_counts();
    let sent = w.received();
    let refusals = [
        (Seq::from_raw(2), AT, cmd, recs(1, "dup")),
        (Seq::ZERO, AT, fresh16(), recs(1, "stale")),
        (Seq::from_raw(2), AT, fresh16(), Vec::new()),
        (Seq::from_raw(2), MAX_AT + 1, fresh16(), recs(1, "late")),
    ];
    for (expected, at, command, batch) in refusals {
        let got = must(s.append(expected, at, command, batch));
        assert!(
            got.is_err(),
            "I-23: the append at {at} was accepted: {got:?}"
        );
    }
    assert_eq!(
        db.row_counts(),
        before,
        "I-23: a refused append wrote a row"
    );
    assert_eq!(
        w.received(),
        sent,
        "I-23: a refused append reached the witness"
    );
}

/// ADR-007: a repeated command id is reported with the first entry of
/// its earlier append, whatever head the retry expects.
#[test]
fn adr007_duplicate_command_names_the_first_entry_of_its_append() {
    let (_db, _w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(2, "a")));
    let cmd = fresh16();
    appended(s.append(Seq::from_raw(2), AT, cmd, recs(3, "b")));
    for expected in [0, 2, 5, 9] {
        assert_eq!(
            must(s.append(Seq::from_raw(expected), AT, cmd, recs(1, "c"))),
            Err(AppendError::DuplicateCommand {
                at: Seq::from_raw(3)
            }),
            "ADR-007: retry expecting {expected}"
        );
    }
}

/// ADR-007: a reopened store, as after a restart, has the same head and
/// entries, and its next append continues the same chain.
#[test]
fn adr007_store_reopens_at_its_head_and_continues_the_chain() {
    let (db, w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(2, "before")));
    let read = must(s.read(Seq::ZERO, 10));
    common::stop(s);
    let mut s = must(Store::open(&db, &w));
    assert_eq!(
        must(s.head()),
        Ok(Seq::from_raw(2)),
        "ADR-007: head after reopen"
    );
    assert_eq!(
        must(s.read(Seq::ZERO, 10)),
        read,
        "ADR-007: entries after reopen"
    );
    appended(s.append(Seq::from_raw(2), AT + 1, fresh16(), recs(1, "after")));
    recompute_chain(db.cell_id(), &db.chain_rows(), &db.ledger_rows())
        .unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-23, I-24, ADR-007 "a second process contends through the expected
/// head": two stores over one database append concurrently, retrying on
/// a stale head. Every command lands once, the ledger has no gap, and the
/// chain recomputes with `fstp-audit`.
#[test]
fn adr007_concurrent_stores_never_fork_the_ledger() {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let stores = [must(Store::open(&db, &w)), must(Store::open(&db, &w))];
    let commands: Vec<Vec<[u8; 16]>> = (0..2)
        .map(|_| (0..4).map(|_| fresh16()).collect())
        .collect();
    std::thread::scope(|scope| {
        for (mut s, cmds) in stores.into_iter().zip(commands.iter().cloned()) {
            scope.spawn(move || {
                for cmd in cmds {
                    for _ in 0..100 {
                        let head = match must(s.head()) {
                            Ok(h) => h,
                            Err(e) => panic!("head: {e}"),
                        };
                        match must(s.append(head, AT, cmd, recs(2, "race"))) {
                            Ok(_) => break,
                            Err(AppendError::StaleHead { .. }) => continue,
                            Err(e) => panic!("append: {e}"),
                        }
                    }
                }
            });
        }
    });
    let ledger = db.ledger_rows();
    assert_eq!(ledger.len(), 16, "I-23: entries");
    let landed: BTreeSet<[u8; 16]> = ledger.iter().map(|e| e.command).collect();
    let sent: BTreeSet<[u8; 16]> = commands.iter().flatten().copied().collect();
    assert_eq!(landed, sent, "I-23: every command once");
    recompute_chain(db.cell_id(), &db.chain_rows(), &ledger)
        .unwrap_or_else(|e| panic!("I-24: {e}"));
    let p = prepares(&w);
    for pair in p.windows(2) {
        assert_eq!(
            pair[1].0,
            (pair[0].1, pair[0].2),
            "I-24: a prepare skipped a head"
        );
    }
}

// ---------------------------------------------------------------------------
// Sealing (R-NF-08, ADR-007 amendment).

/// R-NF-08, ADR-007 "Sealed bodies": records that hold canaries are
/// stored sealed. No canary appears in any form in a data dump of the
/// database, and a read returns every record.
#[test]
fn r_nf_08_ledger_bodies_hold_no_canary_at_rest() {
    let (db, _w, mut s) = must(world());
    let canaries: Vec<String> = (0..3)
        .map(|i| canary(&db.hex, &format!("text{i}")))
        .collect();
    let batch: Vec<Rec> = canaries.iter().map(|c| Rec::new(1, c)).collect();
    appended(s.append(Seq::ZERO, AT, fresh16(), batch.clone()));
    let dump = db.dump();
    for c in &canaries {
        assert!(!holds_canary(&dump, c), "R-NF-08: {c} is readable at rest");
    }
    let got: Vec<Rec> = must(s.read(Seq::ZERO, 10))
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .map(|e| e.record)
        .collect();
    assert_eq!(got, batch, "the sealed records read back");
}

/// R-NF-08, ADR-007 "Random nonces": committed bodies of identical
/// records never share their first twelve bytes, which hold the random
/// nonce. A counter or reused nonce would repeat them.
#[test]
fn r_nf_08_committed_bodies_never_share_a_nonce() {
    let (db, _w, mut s) = must(world());
    let mut head = Seq::ZERO;
    for _ in 0..5 {
        head = appended(s.append(head, AT, fresh16(), recs(4, "same")));
    }
    let bodies = db.ledger_rows();
    let prefixes: BTreeSet<Vec<u8>> = bodies.iter().map(|e| e.body[..12].to_vec()).collect();
    assert_eq!(prefixes.len(), bodies.len(), "R-NF-08: a nonce repeated");
}

/// The superuser SQL that swaps the bodies of entries 1 and 2, with the
/// triggers bypassed.
const SWAP_BODIES: &str = "SET session_replication_role = replica;\nUPDATE ledger.entry e SET body = o.body FROM ledger.entry o WHERE (e.seq = 1 AND o.seq = 2) OR (e.seq = 2 AND o.seq = 1);";

/// ADR-007 "The AAD": a body moved to another entry does not open. A
/// superuser who swaps two bodies, triggers bypassed, makes the read
/// fail rather than return the swapped records.
#[test]
fn adr007_body_moved_to_another_entry_does_not_open() {
    let (db, _w, s) = {
        let (db, w, mut s) = must(world());
        appended(s.append(
            Seq::ZERO,
            AT,
            fresh16(),
            vec![Rec::new(1, "one"), Rec::new(2, "two")],
        ));
        (db, w, s)
    };
    db.psql(SWAP_BODIES)
        .unwrap_or_else(|e| panic!("the swap: {e:?}"));
    let got = must(s.read(Seq::ZERO, 10));
    assert!(got.is_err(), "ADR-007: swapped bodies opened: {got:?}");
}

// ---------------------------------------------------------------------------
// The chain and the witness (design sections 5.3 and 7.2, I-24).

/// I-24, design section 5.3 step 5: each appended entry has one kind 1
/// chain row, rows are numbered without a gap, and every stored hash and
/// link is the `fstp-audit` value over the stored ciphertext.
#[test]
fn i24_pg_chain_rows_recompute_with_fstp_audit() {
    let (db, _w, mut s) = must(world());
    let mut head = Seq::ZERO;
    for n in [1u8, 3, 2] {
        head = appended(s.append(
            head,
            AT + i64::from(n),
            fresh16(),
            recs(usize::from(n), "chain"),
        ));
    }
    recompute_chain(db.cell_id(), &db.chain_rows(), &db.ledger_rows())
        .unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24, design section 5.3 step 7 and section 7.2: one prepare per
/// append, for its prospective head, extending the previous head. The
/// committed `audit.anchor` row of each head holds the chain link at that
/// row and the witness's receipt for exactly that `(n, link)`.
#[test]
fn i24_every_append_commits_with_the_receipt_for_its_head() {
    let (db, w, mut s) = must(world());
    let mut head = Seq::ZERO;
    for n in [1usize, 3, 2] {
        head = appended(s.append(head, AT, fresh16(), recs(n, "anchor")));
    }
    let rows = db.chain_rows();
    let link_at = |n: u64| rows.iter().find(|r| r.row.n == n).map(|r| r.link);
    let heads = [1u64, 4, 6];
    let anchors = db.anchor_rows();
    assert_eq!(
        anchors.iter().map(|a| a.0).collect::<Vec<_>>(),
        heads.to_vec(),
        "I-24: anchored rows"
    );
    for (n, link, receipt) in &anchors {
        assert_eq!(Some(*link), link_at(*n), "I-24: anchor link at {n}");
        let r = decode_receipt(receipt).unwrap_or_else(|e| panic!("receipt at {n}: {e}"));
        assert_eq!(
            (r.fields.n, r.fields.link),
            (*n, *link),
            "I-24: receipt at {n}"
        );
        assert!(
            w.receipts().contains(&r),
            "I-24: a receipt the witness never gave"
        );
    }
    let mut prev = (0, genesis(db.cell_id(), ChainId::App));
    let p = prepares(&w);
    assert_eq!(p.len(), heads.len(), "I-24: one prepare per append");
    for (got, n) in p.iter().zip(heads) {
        let want_link = link_at(n).unwrap();
        assert_eq!(*got, (prev, n, want_link), "I-24: the prepare of head {n}");
        prev = (n, want_link);
    }
}

/// I-24, ADR-010: a prepare the witness refuses ends the append with
/// nothing committed and nothing to abort. The next append prepares the
/// same row number and commits.
#[test]
fn i24_refused_prepare_commits_nothing() {
    let (db, w, mut s) = must(world());
    w.set_mode(Mode::Refuse);
    let before = db.row_counts();
    let got = must(s.append(Seq::ZERO, AT, fresh16(), recs(2, "refused")));
    assert!(got.is_err(), "I-24: committed without a receipt: {got:?}");
    assert_eq!(db.row_counts(), before, "I-24: rows of a refused prepare");
    assert_eq!(
        w.recorded(),
        Vec::new(),
        "the witness recorded a refused prepare"
    );
    w.set_mode(Mode::Accept);
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(2, "retry")));
    assert_eq!(
        prepares(&w).first().map(|p| p.1),
        Some(2),
        "the retry's head"
    );
}

/// I-24, design risk R8: without a reachable witness the store refuses
/// writes, commits nothing, and keeps serving reads.
#[test]
fn i24_unreachable_witness_refuses_writes_and_serves_reads() {
    let (db, w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    let entries = must(s.read(Seq::ZERO, 10));
    w.set_mode(Mode::Unreachable);
    let before = db.row_counts();
    let got = must(s.append(Seq::from_raw(1), AT, fresh16(), recs(1, "lost")));
    assert!(got.is_err(), "I-24: committed without a witness: {got:?}");
    assert_eq!(db.row_counts(), before, "I-24: rows without a witness");
    assert_eq!(must(s.read(Seq::ZERO, 10)), entries, "R8: reads are served");
}

/// The superuser SQL that makes every commit of a `ledger.entry` insert
/// fail at COMMIT, through a deferred constraint trigger, while armed.
const FAIL_AT_COMMIT: &str = "CREATE SCHEMA fstp_test;
CREATE TABLE fstp_test.flag (armed boolean NOT NULL);
INSERT INTO fstp_test.flag VALUES (true);
CREATE FUNCTION fstp_test.fail_at_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF (SELECT armed FROM fstp_test.flag) THEN RAISE EXCEPTION 'injected commit failure'; END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER fstp_test_fail AFTER INSERT ON ledger.entry
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fstp_test.fail_at_commit();";

/// I-24, design section 7.2 "Abort": when COMMIT returns an error, the
/// store sends `Abort { n, link }` and the witness records it before row
/// `n` is prepared again with another link. The failed link never
/// appears in the chain.
#[test]
fn i24_failed_commit_is_aborted_before_its_n_is_prepared_again() {
    let (db, w, mut s) = must(world());
    db.psql(FAIL_AT_COMMIT).unwrap_or_else(|e| panic!("{e:?}"));
    let got = must(s.append(Seq::ZERO, AT, fresh16(), recs(1, "fails")));
    assert!(
        got.is_err(),
        "the injected commit failure was not reported: {got:?}"
    );
    db.psql("UPDATE fstp_test.flag SET armed = false;").unwrap();
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "commits")));
    let g = (0, genesis(db.cell_id(), ChainId::App));
    let rec = w.recorded();
    let rows = db.chain_rows();
    assert_eq!(rows.len(), 1, "the committed rows");
    let committed = rows[0].link;
    match rec.as_slice() {
        [
            Recorded::Prepare {
                prev: p1,
                n: 1,
                link: l1,
            },
            Recorded::Abort { n: 1, link: a1 },
            Recorded::Prepare {
                prev: p2,
                n: 1,
                link: l2,
            },
        ] => {
            assert_eq!((*p1, *p2), (g, g), "both prepares extend the genesis");
            assert_eq!(a1, l1, "I-24: the abort names the failed link");
            assert_ne!(l1, l2, "a fresh nonce gives a fresh link");
            assert_eq!(*l2, committed, "I-24: the committed link");
        }
        other => panic!("I-24: the witness recorded {other:#?}"),
    }
}

/// I-24, ADR-010 "In doubt": an in-doubt prepare whose row exists with
/// its link resolves as committed, with no alert and no in-doubt record.
#[test]
fn i24_in_doubt_present_row_resolves_as_committed() {
    let (_db, w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(2, "present")));
    let head = w
        .outstanding()
        .unwrap_or_else(|| panic!("no outstanding prepare"));
    assert_eq!(
        must(s.resolve_in_doubt(head)),
        Ok(Resolution::Committed),
        "ADR-010: a present row"
    );
    assert_eq!(
        must(s.possible_deletions()),
        Vec::new(),
        "I-24: a false alert"
    );
    assert!(
        !w.recorded()
            .iter()
            .any(|r| matches!(r, Recorded::InDoubtAbsent { .. })),
        "I-24: an in-doubt record for a committed row"
    );
}

/// I-24, ADR-010 "In doubt", the store obligations of
/// `fstp_audit::anchorer`: a missing row raises `PossibleDeletion`
/// durably before `InDoubtAbsent` is sent. A crash after the alert and
/// before the record raises it again on restart, and the alert keyed by
/// `(n, link)` stays one alert. Another link at the same `n` is another
/// alert.
#[test]
fn i24_in_doubt_absent_row_raises_one_possible_deletion_per_n_and_link() {
    let (db, w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "kept")));
    let lx = (2, Link([0x77; 32]));
    w.hold_outstanding(lx);
    w.set_mode(Mode::Unreachable);
    let first = must(s.resolve_in_doubt(lx));
    assert!(
        first.is_err(),
        "the in-doubt record cannot reach the witness: {first:?}"
    );
    assert_eq!(
        must(s.possible_deletions()),
        vec![lx],
        "I-24: the alert comes first"
    );
    common::stop(s);
    w.set_mode(Mode::Accept);
    let mut s = must(Store::open(&db, &w));
    assert_eq!(
        must(s.resolve_in_doubt(lx)),
        Ok(Resolution::AbsentRaisePossibleDeletion),
        "ADR-010: a missing row after restart"
    );
    assert_eq!(
        must(s.possible_deletions()),
        vec![lx],
        "I-24: one alert per (n, link)"
    );
    let ly = (2, Link([0x78; 32]));
    w.hold_outstanding(ly);
    assert_eq!(
        must(s.resolve_in_doubt(ly)),
        Ok(Resolution::AbsentRaisePossibleDeletion),
        "ADR-010: another link"
    );
    assert_eq!(
        must(s.possible_deletions()),
        vec![lx, ly],
        "I-24: alerts by (n, link)"
    );
    let in_doubt: Vec<Recorded> = w
        .recorded()
        .into_iter()
        .filter(|r| matches!(r, Recorded::InDoubtAbsent { .. }))
        .collect();
    assert_eq!(
        in_doubt,
        vec![
            Recorded::InDoubtAbsent { n: 2, link: lx.1 },
            Recorded::InDoubtAbsent { n: 2, link: ly.1 },
        ],
        "ADR-010: one in-doubt record per prepare"
    );
}

/// The superuser script that appends row `n` after `prev`, with its
/// ledger entry, as the writer, while it holds `pg_advisory_xact_lock(1)`
/// for three seconds before COMMIT. It gives the script and the row's
/// link.
fn in_flight_row(db: &CellDb, n: u64, prev: Link) -> (String, Link) {
    let command = fresh16();
    let entry = StoredEntry {
        seq: n,
        at: AT,
        command,
        schema: 1,
        key_ix: 0,
        body: vec![0x3C; 44],
    };
    let kind = RowKind::Ledger { seq: n };
    let sh = stored_hash(AT, &kind, Some(&entry)).unwrap();
    let link = link_of(&prev, db.cell_id(), ChainId::App, n, &sh);
    let script = format!(
        "BEGIN;\nSELECT pg_advisory_xact_lock(1);\nSET LOCAL ROLE {};\n{}{}SELECT pg_sleep(3);\nCOMMIT;",
        db.role("writer"),
        insert_entries_sql(&command, AT, std::slice::from_ref(&entry)),
        insert_chain_sql(
            &ChainRow {
                n,
                at: AT,
                kind,
                stored_hash: sh,
            },
            &link
        ),
    );
    (script, link)
}

/// Waits until some session of the server holds `pg_advisory_xact_lock(1)`.
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

/// I-24, `fstp_audit::anchorer::Next::ReadChain` (W2e obligation): the
/// in-doubt read takes `pg_advisory_xact_lock(1)`, so it waits for an
/// open append. A row whose COMMIT is still in flight resolves as
/// committed, never as a deletion.
#[test]
fn i24_in_doubt_read_waits_for_the_advisory_lock() {
    let (db, w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "first")));
    let prev = db.chain_rows()[0].link;
    let (script, link) = in_flight_row(&db, 2, prev);
    std::thread::scope(|scope| {
        let holder = scope.spawn(|| db.psql(&script));
        wait_for_advisory_lock(&db);
        w.hold_outstanding((2, link));
        assert_eq!(
            must(s.resolve_in_doubt((2, link))),
            Ok(Resolution::Committed),
            "I-24: the in-doubt read did not wait for the open append"
        );
        holder
            .join()
            .unwrap_or_else(|_| panic!("the lock holder panicked"))
            .unwrap_or_else(|e| panic!("the lock holder: {e:?}"));
    });
    assert_eq!(
        must(s.possible_deletions()),
        Vec::new(),
        "I-24: a false alert"
    );
}

// ---------------------------------------------------------------------------
// Side effects (design section 5.3 step 6, I-77, I-78).

/// The last microsecond a fresh step-up may commit in these tests.
const FRESH: i64 = MAX_AT;

/// I-78, design section 5.3 step 6: a step-up consumed twice violates the
/// primary key of `auth_log.stepup_consumed`, and the whole second append
/// aborts before its prepare. Its entries, chain rows and side rows are
/// absent, and the head is unchanged.
#[test]
fn i78_replayed_step_up_aborts_the_whole_append() {
    let (db, w, mut s) = must(world());
    let side = Side {
        stepup_consumed: Some(fresh16()),
        stepup_fresh_until: Some(FRESH),
        sessions_ended: Vec::new(),
    };
    appended(s.append_with(Seq::ZERO, AT, fresh16(), recs(1, "grant"), &side));
    let before = db.row_counts();
    let sent = prepares(&w).len();
    let got = must(s.append_with(Seq::from_raw(1), AT, fresh16(), recs(2, "replay"), &side));
    assert!(got.is_err(), "I-78: a replayed step-up committed: {got:?}");
    assert_eq!(db.row_counts(), before, "I-78: rows of the aborted append");
    assert_eq!(must(s.head()), Ok(Seq::from_raw(1)), "I-78: the head moved");
    assert_eq!(
        prepares(&w).len(),
        sent,
        "I-78: the aborted append was prepared"
    );
}

/// I-78, `SideEffects::stepup_fresh_until`: a batch whose step-up is past
/// its freshness bound at commit is not committed. A fresh one is.
#[test]
fn i78_step_up_past_its_freshness_is_not_committed() {
    let (db, _w, mut s) = must(world());
    let stale = Side {
        stepup_consumed: Some(fresh16()),
        stepup_fresh_until: Some(0),
        sessions_ended: Vec::new(),
    };
    let before = db.row_counts();
    let got = must(s.append_with(Seq::ZERO, AT, fresh16(), recs(1, "stale"), &stale));
    assert!(got.is_err(), "I-78: a stale step-up committed: {got:?}");
    assert_eq!(db.row_counts(), before, "I-78: rows of a stale step-up");
    let fresh = Side {
        stepup_fresh_until: Some(FRESH),
        ..stale
    };
    appended(s.append_with(Seq::ZERO, AT, fresh16(), recs(1, "fresh"), &fresh));
    assert_eq!(
        db.count("SELECT count(*) FROM auth_log.stepup_consumed;"),
        1,
        "the fresh consumption"
    );
}

/// I-77, design section 4.2: the sessions a batch ends get one
/// `auth_log.session_end` row each, at the batch time and naming an entry
/// of the batch, in the same transaction. Ending one of them again aborts
/// the whole later append.
#[test]
fn i77_ended_sessions_commit_with_their_batch() {
    let (db, _w, mut s) = must(world());
    appended(s.append(Seq::ZERO, AT, fresh16(), recs(1, "before")));
    let (s1, s2) = (fresh16(), fresh16());
    let side = Side {
        sessions_ended: vec![s1, s2],
        ..Side::default()
    };
    appended(s.append_with(Seq::from_raw(1), AT + 7, fresh16(), recs(2, "ends"), &side));
    let rows = db
        .psql(
            "SELECT encode(uuid_send(session_id), 'hex') || '|' || at || '|' || ledger_seq \
             FROM auth_log.session_end ORDER BY 1;",
        )
        .unwrap();
    let mut want: Vec<String> = [s1, s2].iter().map(|s| common::hex(s)).collect();
    want.sort();
    let got: Vec<(String, i64, u64)> = rows
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            (
                f[0].to_owned(),
                f[1].parse().unwrap(),
                f[2].parse().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got.iter().map(|g| g.0.clone()).collect::<Vec<_>>(),
        want,
        "I-77: the ended sessions"
    );
    for (id, at, seq) in &got {
        assert_eq!(*at, AT + 7, "I-77: the end time of {id}");
        assert!(
            (2..=3).contains(seq),
            "I-77: {id} names entry {seq}, outside its batch"
        );
    }
    let before = db.row_counts();
    let again = Side {
        sessions_ended: vec![s1],
        ..Side::default()
    };
    let got = must(s.append_with(
        Seq::from_raw(3),
        AT + 8,
        fresh16(),
        recs(1, "again"),
        &again,
    ));
    assert!(got.is_err(), "I-77: a session ended twice: {got:?}");
    assert_eq!(db.row_counts(), before, "I-77: rows of the aborted append");
}

// ---------------------------------------------------------------------------
// Pools (design section 4.7, ADR-005, I-82).

/// I-82, ADR-005, design section 4.7: a pool belongs to one cell. A pool
/// for cell A refuses a role login of cell B, and accepts its own.
#[test]
fn i82_pool_refuses_a_role_of_another_cell() {
    let a = must(CellDb::provision());
    let b = must(CellDb::provision());
    for suffix in ["writer", "app", "keys", "auditor"] {
        let foreign = must(open_pool(a.cell, &b.logins[suffix], &b));
        assert!(
            foreign.is_err(),
            "I-82: a pool of cell A took {suffix} of cell B"
        );
        let own = must(open_pool(a.cell, &a.logins[suffix], &a));
        assert_eq!(own, Ok(()), "the pool of cell A for its own {suffix}");
    }
}

// ---------------------------------------------------------------------------
// Harness self-test.

fn prepare_of(cell: fstp_audit::CellId, prev: (u64, Link), sh: [u8; 32]) -> Prepare {
    let n = prev.0 + 1;
    let link = link_of(&prev.1, cell, ChainId::App, n, &sh);
    Prepare {
        prev,
        stored_hashes: vec![sh],
        anchor: Anchor {
            cell,
            chain: ChainId::App,
            n,
            link,
            at: AT,
            signature: vec![0; fstp_audit::SIGNATURE_LEN],
        },
    }
}

/// Harness self-test: the fake witness keeps one outstanding prepare,
/// answers a retransmit with its first receipt, refuses a prepare that
/// neither extends nor repeats it, and withdraws only the outstanding
/// head. Each receipt carries a composite signature that verifies.
#[test]
fn harness_fake_witness_keeps_one_outstanding_prepare() {
    let cell = fstp_audit::CellId(fresh16());
    let w = FakeWitness::new(cell);
    let g = (0, genesis(cell, ChainId::App));
    let p1 = prepare_of(cell, g, [1; 32]);
    let r1 = block_on(w.prepare(&p1)).unwrap();
    assert!(fstp_audit::anchor::receipt_signature_verifies(
        &r1,
        &[w.public_key()]
    ));
    assert_eq!(block_on(w.prepare(&p1)), Ok(r1.clone()), "a retransmit");
    let rival = prepare_of(cell, g, [2; 32]);
    assert_eq!(
        block_on(w.prepare(&rival)),
        Err(WitnessFault::Refused),
        "a rival prepare"
    );
    let h1 = (p1.anchor.n, p1.anchor.link);
    let p2 = prepare_of(cell, h1, [3; 32]);
    let r2 = block_on(w.prepare(&p2)).unwrap();
    assert_eq!(r2.fields.witness_seq, 2, "the second record");
    assert_eq!(
        block_on(w.abort(h1)),
        Err(WitnessFault::UnknownPrepare),
        "a stale abort"
    );
    let h2 = (p2.anchor.n, p2.anchor.link);
    assert_eq!(
        block_on(w.abort(h2)),
        Ok(()),
        "the abort of the open prepare"
    );
    assert_eq!(w.outstanding(), None);
    let bad = Prepare {
        stored_hashes: vec![[9; 32]],
        ..prepare_of(cell, h1, [4; 32])
    };
    assert_eq!(
        block_on(w.prepare(&bad)),
        Err(WitnessFault::Refused),
        "a prepare whose hashes do not recompute"
    );
    assert_eq!(
        w.recorded(),
        vec![
            Recorded::Prepare {
                prev: g,
                n: 1,
                link: h1.1
            },
            Recorded::Prepare {
                prev: h1,
                n: 2,
                link: h2.1
            },
            Recorded::Abort { n: 2, link: h2.1 },
        ]
    );
}

/// Harness self-test: `recompute_chain` accepts a chain built with
/// `fstp-audit` and refuses one with a changed body.
#[test]
fn harness_recompute_chain_has_teeth() {
    let cell = fstp_audit::CellId(fresh16());
    let mut prev = genesis(cell, ChainId::App);
    let mut rows = Vec::new();
    let mut ledger = Vec::new();
    for seq in 1..=3u64 {
        let e = StoredEntry {
            seq,
            at: AT,
            command: [u8::try_from(seq).unwrap(); 16],
            schema: 1,
            key_ix: 0,
            body: vec![u8::try_from(seq).unwrap(); 30],
        };
        let kind = RowKind::Ledger { seq };
        let sh = stored_hash(AT, &kind, Some(&e)).unwrap();
        let link = link_of(&prev, cell, ChainId::App, seq, &sh);
        rows.push(fstp_audit::chain::StoredRow {
            row: ChainRow {
                n: seq,
                at: AT,
                kind,
                stored_hash: sh,
            },
            link,
        });
        ledger.push(e);
        prev = link;
    }
    assert_eq!(recompute_chain(cell, &rows, &ledger), Ok(()));
    ledger[1].body[0] ^= 1;
    assert!(
        recompute_chain(cell, &rows, &ledger).is_err(),
        "I-24: a changed body passed"
    );
}

/// Harness self-test over the reference schema: the in-flight row script
/// holds the advisory lock for its three seconds, so another session
/// waits for it, and then commits a row that the link trigger accepts.
#[test]
fn harness_in_flight_row_holds_the_lock_then_commits() {
    let db = CellDb::provision_with(REFERENCE_APP);
    let (script, link) = in_flight_row(&db, 1, genesis(db.cell_id(), ChainId::App));
    std::thread::scope(|scope| {
        let holder = scope.spawn(|| db.psql(&script));
        wait_for_advisory_lock(&db);
        let start = Instant::now();
        db.psql("BEGIN;\nSELECT pg_advisory_xact_lock(1);\nCOMMIT;")
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the second session did not wait for the lock"
        );
        holder
            .join()
            .unwrap_or_else(|_| panic!("the lock holder panicked"))
            .unwrap_or_else(|e| panic!("the lock holder: {e:?}"));
    });
    let rows = db.chain_rows();
    assert_eq!(rows.len(), 1, "the in-flight row committed");
    assert_eq!(rows[0].link, link, "the in-flight row's link");
}

/// Harness self-test over the reference schema: the injected failure
/// passes every insert and fails the COMMIT while armed, and no row
/// commits. Disarmed, the same inserts commit.
#[test]
fn harness_commit_failure_injection_fails_only_at_commit() {
    let db = CellDb::provision_with(REFERENCE_APP);
    db.psql(FAIL_AT_COMMIT).unwrap_or_else(|e| panic!("{e:?}"));
    let command = fresh16();
    let entry = StoredEntry {
        seq: 1,
        at: AT,
        command,
        schema: 1,
        key_ix: 0,
        body: vec![1; 30],
    };
    let tx = format!(
        "BEGIN;\n{}SELECT 'inserted';\nCOMMIT;",
        insert_entries_sql(&command, AT, std::slice::from_ref(&entry))
    );
    let armed = db.psql_as("writer", &tx);
    let err = armed.expect_err("an armed commit succeeded");
    // psql numbers the lines of `\set VERBOSITY` and `SET ROLE` first.
    let commit_line = 2 + tx.lines().position(|l| l == "COMMIT;").unwrap() + 1;
    assert!(
        err.text.contains("injected commit failure")
            && err.text.contains(&format!("psql:<stdin>:{commit_line}:")),
        "the failure did not come at COMMIT: {err:?}"
    );
    assert_eq!(db.count("SELECT count(*) FROM ledger.entry;"), 0);
    db.psql("UPDATE fstp_test.flag SET armed = false;").unwrap();
    db.psql_as("writer", &tx)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(db.count("SELECT count(*) FROM ledger.entry;"), 1);
}

/// Harness self-test over the reference schema: the superuser swap
/// bypasses the mutation trigger and exchanges the two bodies.
#[test]
fn harness_superuser_swap_exchanges_two_bodies() {
    let db = CellDb::provision_with(REFERENCE_APP);
    let command = fresh16();
    let entries: Vec<StoredEntry> = [1u64, 2]
        .into_iter()
        .map(|seq| StoredEntry {
            seq,
            at: AT,
            command,
            schema: 1,
            key_ix: 0,
            body: vec![u8::try_from(seq).unwrap(); 30],
        })
        .collect();
    db.psql_as("writer", &insert_entries_sql(&command, AT, &entries))
        .unwrap_or_else(|e| panic!("{e:?}"));
    db.psql(SWAP_BODIES).unwrap_or_else(|e| panic!("{e:?}"));
    let bodies: Vec<Vec<u8>> = db.ledger_rows().into_iter().map(|e| e.body).collect();
    assert_eq!(bodies, vec![vec![2; 30], vec![1; 30]], "the swap");
}

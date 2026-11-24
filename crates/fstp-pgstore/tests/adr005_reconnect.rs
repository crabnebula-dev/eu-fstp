//! ADR-005 record of lane m10/store-reconnect (interim, pending Daniel):
//! the pools of a cell reconnect after their PostgreSQL cluster restarts.
//!
//! Each test restarts or stops the cluster of this test binary, so the
//! tests take one lock and run one at a time. No other test binary
//! shares the cluster.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::{CellDb, FakeWitness, Rec, Store, block_on, fresh16, must, rt};
use fstp_ledger::Seq;
use fstp_pgstore::{
    ChainRow, KeystoreChanges, KeystoreRows, KeystoreTables, Pool, PoolError, RECONNECT_MAX, Role,
};
use fstp_rt::tokio::TokioRuntime;

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn pool(db: &CellDb, suffix: &str, role: Role, size: usize) -> Pool<TokioRuntime> {
    block_on(Pool::open(
        rt().clone(),
        db.cell,
        role,
        db.config(suffix),
        size,
    ))
    .unwrap_or_else(|e| panic!("the {suffix} pool: {e}"))
}

/// One statement over a client of `pool`, released when it worked. It
/// also returns the backend's process id.
async fn one(pool: &Pool<TokioRuntime>) -> Result<i32, String> {
    let mut c = pool.get().await.map_err(|e| format!("get: {e}"))?;
    let row = c
        .query_one("SELECT pg_catalog.pg_backend_pid()", &[])
        .await
        .map_err(|e| format!("query: {e}"))?;
    let pid: i32 = row.get(0).map_err(|e| format!("get: {e}"))?;
    c.release();
    Ok(pid)
}

/// Fills `pool` with `n` idle clients, each used once.
async fn fill(pool: &Pool<TokioRuntime>, n: usize) {
    let mut held = Vec::new();
    for _ in 0..n {
        let mut c = pool.get().await.unwrap();
        c.query_one("SELECT 1::pg_catalog.int4", &[]).await.unwrap();
        held.push(c);
    }
    for c in held {
        c.release();
    }
}

/// ADR-005 (record of lane m10/store-reconnect, row "Pool"), I-82: after
/// a restart of the cluster, every call through a pool whose clients all
/// went idle before the restart succeeds, the first one included. Each
/// runs on a new session, which passed the I-82 identity check of a
/// first connect again.
#[test]
fn adr005_reconnect_pool_serves_the_first_call_after_a_restart() {
    let _g = serial();
    let db = must(CellDb::provision());
    let p = pool(&db, "app", Role::App, 4);
    block_on(fill(&p, 4));
    let before = block_on(one(&p)).unwrap();
    db.server.restart().unwrap();
    for i in 0..6 {
        let pid = block_on(one(&p)).unwrap_or_else(|e| panic!("call {i} after the restart: {e}"));
        assert_ne!(pid, before, "call {i} ran on a session of the old server");
    }
}

/// ADR-005 (record of lane m10/store-reconnect, rows "Pool" and
/// "Backoff"): while the cluster is down a call fails cleanly with
/// [`PoolError::Connect`], at once and without waiting for a connect
/// timeout, and once the cluster is back and the bounded backoff ended,
/// the next call succeeds.
#[test]
fn adr005_reconnect_pool_fails_cleanly_while_down_and_recovers() {
    let _g = serial();
    let db = must(CellDb::provision());
    let p = pool(&db, "app", Role::App, 2);
    block_on(fill(&p, 2));
    db.server
        .while_down(|| {
            for i in 0..5 {
                let start = Instant::now();
                let got = block_on(p.get());
                assert!(
                    matches!(got, Err(PoolError::Connect(_))),
                    "call {i} while down: {got:?}"
                );
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "call {i} waited {:?}",
                    start.elapsed()
                );
            }
        })
        .unwrap();
    std::thread::sleep(RECONNECT_MAX);
    block_on(one(&p)).unwrap();
    block_on(one(&p)).unwrap();
}

/// ADR-005 (record of lane m10/store-reconnect, row "Pool"), ADR-010,
/// I-24: after a restart of the cluster the append protocol of the
/// cell's store works on the first append, every append is anchored at
/// the witness, and the head reads on.
#[test]
fn adr005_reconnect_store_appends_after_a_restart() {
    let _g = serial();
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let mut s = must(Store::open(&db, &w));
    let mut head = Seq::ZERO;
    for i in 0..4u8 {
        head = must(s.append(head, AT, [i; 16], vec![Rec::new(1, "before")]))
            .unwrap_or_else(|e| panic!("append {i} before the restart: {e}"));
    }
    db.server.restart().unwrap();
    for i in 0..4u8 {
        let next = must(s.append(head, AT, [i + 10; 16], vec![Rec::new(1, "after")]))
            .unwrap_or_else(|e| panic!("append {i} after the restart: {e}"));
        assert_eq!(next.raw(), head.raw() + 1);
        head = next;
    }
    assert_eq!(must(s.head()), Ok(head));
    assert_eq!(db.ledger_rows().len(), 8);
}

/// ADR-005 (record of lane m10/store-reconnect, row "Pool"), ADR-004,
/// I-81: the keystore tables of the keys role read and write on the
/// first call after a restart, which erasure step 5 and the daily
/// keystore snapshot need.
#[test]
fn adr005_reconnect_keystore_tables_after_a_restart() {
    let _g = serial();
    let db = must(CellDb::provision());
    let keys = db.role("keys");
    // The keystore tables of migrations 0011 and 0012, granted as the
    // production plan grants them (`keystore_tables.rs`).
    for t in [
        "keystore.chain",
        "keystore.text",
        "keystore.signer",
        "keystore.login_digest",
        "keystore.login_text",
        "keystore.erasure_request",
        "keystore.display_name",
    ] {
        db.psql(&format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {keys};"
        ))
        .unwrap();
    }
    let t = KeystoreTables::new(pool(&db, "keys", Role::Keys, 2)).unwrap();
    assert_eq!(block_on(t.load()).unwrap(), KeystoreRows::default());
    db.server.restart().unwrap();
    let chain = ChainRow {
        epoch: 1,
        state: vec![7; 80],
        lookup_group: Some(fresh16()),
        login_group: None,
        startup_unwrap: Some(fresh16()),
    };
    let changes = KeystoreChanges {
        chain: Some(chain.clone()),
        ..KeystoreChanges::default()
    };
    block_on(t.apply(&changes)).unwrap();
    db.server.restart().unwrap();
    assert_eq!(block_on(t.load()).unwrap().chain, Some(chain));
}

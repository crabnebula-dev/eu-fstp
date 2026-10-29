//! `AsyncRecordStore`: the same contract and refusal order as
//! `RecordStore`, using only `core::future` (ADR-007, I-23, M3 design
//! sections 0.5, 2.2 and 5.3).
//!
//! The trait is additive. `PgRecordStore` implements it in lane W2e, and
//! `fstp-cell` drives it from its engine task. These tests hold its
//! contract:
//!
//! - every append, refusal and read equals what `MemStore` gives for the
//!   same operations, in the refusal order of `RecordStore::append`
//!   (duplicate command first, then stale head, then the store errors);
//! - every future completes when polled with a no-op waker, so the trait
//!   needs no runtime;
//! - the crate exports the trait from `src/async_store.rs` and gains no
//!   dependency (design section 0.5: additive, runtime-free).
//!
//! The harness is checked against a reference adapter over the sync
//! store, and against a mutant that checks the head before the command
//! id, which it must catch. Lane W2c's test author wrote these before the
//! trait. The production check is red on [`ASYNC_STORE_SEAM`] and the
//! source scan is red until `src/async_store.rs` exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::{Future, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use fstp_ledger::{AppendError, Entry, MAX_AT, MemStore, RecordStore, Seq, StoreError};
use fstp_prop::{Config, Gen, Outcome, check, prop_assert_eq, run};

// ---------------------------------------------------------------------------
// A runtime-free executor.

/// The most polls a future gets. A store future that needs a runtime
/// never becomes ready under a no-op waker.
const POLLS: usize = 1024;

/// Polls `f` to completion with a no-op waker, or reports that it stayed
/// pending.
fn block_on<F: Future>(f: F) -> Result<F::Output, String> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..POLLS {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Ok(v);
        }
    }
    Err(format!("still pending after {POLLS} polls with no runtime"))
}

// ---------------------------------------------------------------------------
// The contract under test.

/// The designed shape of `AsyncRecordStore<R>` (design section 2.2): the
/// three operations of `RecordStore`, each returning a future. `head` may
/// fail, since a database store reads it over a connection.
trait AsyncContract<R> {
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>>;
    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> impl Future<Output = Result<Seq, AppendError>>;
    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<R>>,
    ) -> impl Future<Output = Result<(), StoreError>>;
}

/// The reference: a sync store whose operations return ready futures.
struct SyncAsAsync<S>(S);

impl<R, S: RecordStore<R>> AsyncContract<R> for SyncAsAsync<S> {
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> {
        ready(Ok(self.0.head()))
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> impl Future<Output = Result<Seq, AppendError>> {
        ready(self.0.append(expected, at, command, batch))
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<R>>,
    ) -> impl Future<Output = Result<(), StoreError>> {
        ready(self.0.read(from, limit, out))
    }
}

/// The teeth mutant: it checks the head before the command id, so a
/// lost-acknowledgement retry is told `StaleHead` instead of
/// `DuplicateCommand` (ADR-007).
struct HeadFirst<S>(S);

impl<R, S: RecordStore<R>> AsyncContract<R> for HeadFirst<S> {
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> {
        ready(Ok(self.0.head()))
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> impl Future<Output = Result<Seq, AppendError>> {
        let head = self.0.head();
        if expected != head {
            return ready(Err(AppendError::StaleHead { head }));
        }
        ready(self.0.append(expected, at, command, batch))
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<R>>,
    ) -> impl Future<Output = Result<(), StoreError>> {
        ready(self.0.read(from, limit, out))
    }
}

/// The seam: `fstp_ledger::AsyncRecordStore` does not exist yet (design
/// section 0.5, `docs/handoff/m3-base.md`, lane W2c).
///
/// API request to lane W2c. Once the trait lands with an implementation
/// over `MemStore` (ready futures), replace [`production_store`] with:
///
/// ```text
/// struct Prod<S>(S);
/// impl<S: fstp_ledger::AsyncRecordStore<u32>> AsyncContract<u32> for Prod<S> {
///     // each method forwards to the trait method of the same name
/// }
/// fn production_store() -> Result<Prod<MemStore<u32>>, &'static str> {
///     Ok(Prod(MemStore::new()))
/// }
/// ```
///
/// Lane W2e then runs the same contract over `PgRecordStore`.
const ASYNC_STORE_SEAM: &str =
    "fstp_ledger::AsyncRecordStore does not exist (design sections 0.5 and 2.2, lane W2c)";

/// The production trait under the contract: each method forwards to the
/// `fstp_ledger::AsyncRecordStore` method of the same name. Lane W2c
/// closed [`ASYNC_STORE_SEAM`] with the trait and its `MemStore` impl.
struct Prod<S>(S);

impl<S: fstp_ledger::AsyncRecordStore<u32>> AsyncContract<u32> for Prod<S> {
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> {
        fstp_ledger::AsyncRecordStore::head(&self.0)
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<u32>,
    ) -> impl Future<Output = Result<Seq, AppendError>> {
        fstp_ledger::AsyncRecordStore::append(&mut self.0, expected, at, command, batch)
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<u32>>,
    ) -> impl Future<Output = Result<(), StoreError>> {
        fstp_ledger::AsyncRecordStore::read(&self.0, from, limit, out)
    }
}

/// The production store under the contract: `MemStore` through
/// `fstp_ledger::AsyncRecordStore`. Lane W2e runs the same contract over
/// `PgRecordStore`.
fn production_store() -> Result<Prod<MemStore<u32>>, &'static str> {
    Ok(Prod(MemStore::new()))
}

// ---------------------------------------------------------------------------
// The conformance property.

/// The command ids the property draws from. A small pool makes repeats,
/// so duplicates are common.
const COMMANDS: [[u8; 16]; 4] = [[1; 16], [2; 16], [3; 16], [4; 16]];

/// Runs a random sequence of appends and reads against `store` and a
/// fresh `MemStore`, and compares every result and every read.
fn conformance<S: AsyncContract<u32>>(g: &mut Gen, store: &mut S) -> Result<(), String> {
    let mut oracle: MemStore<u32> = MemStore::new();
    let steps = g.usize_in(1..=24);
    for step in 0..steps {
        if g.weighted(&[3, 1]) == 0 {
            let head = oracle.head();
            let expected = match g.u8_in(0..=3) {
                0 => Seq::from_raw(head.raw().saturating_add(1)),
                1 => Seq::from_raw(head.raw().saturating_sub(1)),
                _ => head,
            };
            let at = match g.u8_in(0..=5) {
                0 => MAX_AT + 1,
                1 => -MAX_AT - 1,
                2 => MAX_AT,
                _ => g.i64_in(0..=1_000_000),
            };
            let command = *g.pick(&COMMANDS);
            let batch = g.vec(0..=3, |g| g.u32());
            let want = oracle.append(expected, at, command, batch.clone());
            let got = block_on(store.append(expected, at, command, batch))?;
            prop_assert_eq!(got, want, "append at step {step}");
        } else {
            let from = Seq::from_raw(g.u64_in(0..=6));
            let limit = g.usize_in(0..=4);
            let mut want = Vec::new();
            let w = oracle.read(from, limit, &mut want);
            let mut got = Vec::new();
            let r = block_on(store.read(from, limit, &mut got))?;
            prop_assert_eq!(r, w, "read at step {step}");
            prop_assert_eq!(got, want, "read at step {step}");
        }
        let head = block_on(store.head())?;
        prop_assert_eq!(head, Ok(oracle.head()), "head after step {step}");
    }
    Ok(())
}

/// The property configuration of the teeth run.
fn teeth_config() -> Config {
    Config::default().with_cases(512)
}

/// ADR-007: the harness accepts the reference, a sync `MemStore` behind
/// ready futures. This keeps the harness itself honest.
#[test]
fn adr007_async_contract_harness_accepts_the_sync_reference() {
    check(
        "adr007_async_contract_harness_accepts_the_sync_reference",
        |g: &mut Gen| conformance(g, &mut SyncAsAsync(MemStore::new())),
    );
}

/// ADR-007, teeth: a store that checks the head before the command id is
/// caught by the harness.
#[test]
fn adr007_async_contract_harness_catches_head_before_command() {
    let outcome = run(
        "adr007_async_contract_harness_catches_head_before_command",
        teeth_config(),
        |g: &mut Gen| conformance(g, &mut HeadFirst(MemStore::new())),
    );
    assert!(
        matches!(outcome, Outcome::Failed(_)),
        "the harness missed a head-first refusal order"
    );
}

/// ADR-007, I-23, design section 2.2: the production `AsyncRecordStore`
/// gives the results of `RecordStore` for the same operations, in the same
/// refusal order, with every future ready without a runtime.
#[test]
fn adr007_async_record_store_matches_the_record_store_contract() {
    check(
        "adr007_async_record_store_matches_the_record_store_contract",
        |g: &mut Gen| {
            let mut store = production_store().map_err(|s| format!("{s} (NotImplemented)"))?;
            conformance(g, &mut store)
        },
    );
}

/// The source of `relative` inside this crate, or why it is missing.
fn source(relative: &str) -> Result<String, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Names whose presence would tie the trait to a runtime or to threads.
const RUNTIME_NAMES: [&str; 6] = [
    "tokio",
    "smol",
    "fstp_rt",
    "async_std",
    "std::thread",
    "block_on",
];

/// ADR-007, design sections 0.5 and 2.2: `AsyncRecordStore` lives in
/// `src/async_store.rs`, the crate root exports it, the module names no
/// runtime, and the crate's dependencies stay `fstp-json` alone, so the
/// change is additive and runtime-free.
#[test]
fn adr007_async_record_store_is_exported_and_runtime_free() {
    let module = source("src/async_store.rs")
        .unwrap_or_else(|e| panic!("{e}: {ASYNC_STORE_SEAM} (NotImplemented)"));
    assert!(
        module.contains("pub trait AsyncRecordStore"),
        "src/async_store.rs declares no AsyncRecordStore trait"
    );
    for name in RUNTIME_NAMES {
        assert!(!module.contains(name), "src/async_store.rs names {name}");
    }
    let lib = source("src/lib.rs").unwrap();
    assert!(
        lib.contains("mod async_store;"),
        "src/lib.rs declares no async_store module"
    );
    assert!(
        lib.lines()
            .any(|l| l.starts_with("pub use async_store::") && l.contains("AsyncRecordStore")),
        "src/lib.rs does not export AsyncRecordStore"
    );
    let manifest = source("Cargo.toml").unwrap();
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(
        deps,
        vec!["fstp-json.workspace = true"],
        "fstp-ledger gained a dependency"
    );
}

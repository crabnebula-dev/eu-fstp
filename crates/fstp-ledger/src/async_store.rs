//! The asynchronous record store (ADR-007, I-23, M3 design sections 0.5,
//! 2.2 and 5.3).
//!
//! [`AsyncRecordStore`] has the contract of [`RecordStore`] with each
//! operation returning a future. The refusal order of an append is the
//! one `RecordStore::append` states: a duplicate command first, then a
//! stale head, then the store errors. A database store such as
//! `fstp_pgstore::PgRecordStore` implements it over a connection pool.
//!
//! The trait names only `core::future`. It ties no implementation to a
//! runtime, so the cell engine task drives it under whichever runtime its
//! binary uses (ADR-002). Every future is `Send`, as the runtime trait of
//! `fstp-rt` requires of a spawned task.
//!
//! [`MemStore`] implements it with futures that are ready at once, so a
//! test or model can drive the asynchronous contract without a runtime.

use core::future::{Future, ready};

use crate::entry::{Entry, Seq};
use crate::store::{AppendError, MemStore, RecordStore, StoreError};

/// An append-only record store whose operations complete as futures.
///
/// The contract is the one of [`RecordStore`], operation for operation:
///
/// - [`AsyncRecordStore::head`] gives the sequence number of the last
///   entry, or [`Seq::ZERO`] when empty. It may fail, since a database
///   store reads it over a connection.
/// - [`AsyncRecordStore::append`] appends atomically if the head is still
///   `expected`, and refuses in the order of `RecordStore::append`. A
///   refused append changes nothing and does not use up its command id.
/// - [`AsyncRecordStore::read`] pushes at most `limit` entries starting at
///   `from` onto `out`.
///
/// There is no update or delete.
pub trait AsyncRecordStore<R> {
    /// The sequence number of the last entry, or [`Seq::ZERO`] when empty.
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> + Send;

    /// Appends `batch` atomically if the head is still `expected`, and
    /// gives the new head. The refusal order is the one of
    /// `RecordStore::append`.
    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> impl Future<Output = Result<Seq, AppendError>> + Send;

    /// Reads at most `limit` entries starting at `from` and pushes them
    /// onto `out`. A read from past the head pushes nothing.
    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<R>>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The in-memory store, whose futures are ready at once. Each operation
/// runs the [`RecordStore`] operation of the same name before it returns,
/// so the result never depends on when the future is polled.
impl<R: Clone> AsyncRecordStore<R> for MemStore<R> {
    fn head(&self) -> impl Future<Output = Result<Seq, StoreError>> + Send {
        ready(Ok(RecordStore::head(self)))
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> impl Future<Output = Result<Seq, AppendError>> + Send {
        ready(RecordStore::append(self, expected, at, command, batch))
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<R>>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        ready(RecordStore::read(self, from, limit, out))
    }
}

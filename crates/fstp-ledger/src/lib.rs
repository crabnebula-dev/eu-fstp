//! Generic append-only record ledger (I-23).
//!
//! - [`Seq`] numbers entries from 1. A head of 0 means an empty ledger.
//! - [`Entry`] wraps one record with its sequence number, time, command id
//!   and schema version.
//! - [`RecordStore`] appends atomically against an expected head and has no
//!   update or delete. [`MemStore`] is the in-memory store for tests and
//!   models.
//! - [`verify_append_only`] checks that a later read of a ledger extends an
//!   earlier one without changing, dropping or reordering entries.
//! - [`Canonical`] gives the RFC 8785 bytes of a record.
//!
//! Status: public API stub from milestone M2 step W0. Appends, reads, the
//! verifier and the entry codec return a `NotImplemented` error until lane
//! W1b replaces them. No body panics.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt;

use fstp_json::{FromJson, FromJsonError, ToJson, Value};

/// Position of an entry in a ledger, from 1. The head of an empty ledger is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(u64);

impl Seq {
    /// The head of an empty ledger.
    pub const ZERO: Seq = Seq(0);

    /// The sequence number `r`.
    pub const fn from_raw(r: u64) -> Seq {
        Seq(r)
    }

    /// The raw number.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// One ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entry<R> {
    /// Position in the ledger.
    pub seq: Seq,
    /// UTC microseconds since the Unix epoch, from the command context.
    pub at: i64,
    /// Idempotency key of the command that produced the entry.
    pub command: [u8; 16],
    /// Schema version of the record encoding.
    pub schema: u16,
    /// The record.
    pub record: R,
}

impl<R: ToJson> ToJson for Entry<R> {
    /// The JSON form of the entry. `seq` is a decimal string.
    ///
    /// Stub: returns `null` until lane W1b.
    fn to_json(&self) -> Value {
        Value::Null
    }
}

impl<R: FromJson> FromJson for Entry<R> {
    /// Decodes an entry, rejecting unknown members.
    ///
    /// Stub: rejects every value until lane W1b.
    fn from_json(value: &Value) -> Result<Entry<R>, FromJsonError> {
        let _ = value;
        Err(FromJsonError::invalid("entry decoding is not implemented"))
    }
}

/// An append-only record store.
pub trait RecordStore<R> {
    /// The sequence number of the last entry, or [`Seq::ZERO`] when empty.
    fn head(&self) -> Seq;

    /// Appends atomically if the head is still `expected`. There is no update or delete.
    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> Result<Seq, AppendError>;

    /// Reads at most `limit` entries starting at `from` into `out`.
    fn read(&self, from: Seq, limit: usize, out: &mut Vec<Entry<R>>) -> Result<(), StoreError>;
}

/// Why an append was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppendError {
    /// The head moved since the caller read it.
    StaleHead {
        /// The current head.
        head: Seq,
    },
    /// The command id was already appended.
    DuplicateCommand {
        /// The entry that holds the earlier append.
        at: Seq,
    },
    /// The store failed.
    Store(StoreError),
}

/// A store failure.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreError {
    /// The store cannot be reached.
    Unavailable,
    /// Temporary: the operation is still a W0 stub. Lane W1b removes this
    /// variant when it replaces the stub bodies.
    NotImplemented,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable => f.write_str("store unavailable"),
            StoreError::NotImplemented => f.write_str("not implemented"),
        }
    }
}

impl std::error::Error for StoreError {}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppendError::StaleHead { head } => write!(f, "stale head, current head {}", head.0),
            AppendError::DuplicateCommand { at } => {
                write!(f, "duplicate command, appended at {}", at.0)
            }
            AppendError::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl std::error::Error for AppendError {}

/// In-memory append-only store. Its fields are private, so no caller can
/// change a past entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemStore<R> {
    entries: Vec<Entry<R>>,
    commands: BTreeMap<[u8; 16], Seq>,
}

impl<R> MemStore<R> {
    /// An empty store.
    pub fn new() -> MemStore<R> {
        MemStore {
            entries: Vec::new(),
            commands: BTreeMap::new(),
        }
    }
}

impl<R> Default for MemStore<R> {
    fn default() -> MemStore<R> {
        MemStore::new()
    }
}

impl<R> RecordStore<R> for MemStore<R> {
    /// Stub: always [`Seq::ZERO`] until lane W1b.
    fn head(&self) -> Seq {
        let _ = (&self.entries, &self.commands);
        Seq::ZERO
    }

    /// Stub: returns `NotImplemented` until lane W1b.
    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> Result<Seq, AppendError> {
        let _ = (expected, at, command, batch);
        Err(AppendError::Store(StoreError::NotImplemented))
    }

    /// Stub: returns `NotImplemented` until lane W1b.
    fn read(&self, from: Seq, limit: usize, out: &mut Vec<Entry<R>>) -> Result<(), StoreError> {
        let _ = (from, limit, out);
        Err(StoreError::NotImplemented)
    }
}

/// The RFC 8785 canonical bytes of a record.
pub trait Canonical {
    /// The canonical bytes.
    fn canonical(&self) -> Vec<u8>;
}

/// How a later read of a ledger differs from an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Divergence {
    /// The later read is shorter.
    Truncated {
        /// Entries in the earlier read.
        old_len: u64,
        /// Entries in the later read.
        new_len: u64,
    },
    /// An entry present in both reads changed.
    Changed {
        /// The changed entry.
        seq: Seq,
    },
    /// A sequence number is missing.
    Gap {
        /// The first missing number.
        seq: Seq,
    },
    /// Entries are out of order.
    Reordered {
        /// The first entry out of order.
        seq: Seq,
    },
    /// Temporary: the verifier is still a W0 stub. Lane W1b removes this
    /// variant when it replaces the stub body.
    NotImplemented,
}

/// Checks that `new` extends `old` without changing, dropping or reordering
/// any entry, comparing records by their canonical bytes.
///
/// Stub: reports `NotImplemented` for every input until lane W1b, so no
/// ledger passes unchecked.
pub fn verify_append_only<R: Canonical>(
    old: &[Entry<R>],
    new: &[Entry<R>],
) -> Result<(), Divergence> {
    let _ = (old, new);
    Err(Divergence::NotImplemented)
}

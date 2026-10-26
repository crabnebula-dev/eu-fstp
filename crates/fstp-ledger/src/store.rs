//! The insert-only record store (I-23, ADR-007).

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;

use crate::entry::{Entry, SCHEMA_V1, Seq, time_in_range};

/// An append-only record store.
pub trait RecordStore<R> {
    /// The sequence number of the last entry, or [`Seq::ZERO`] when empty.
    fn head(&self) -> Seq;

    /// Appends atomically if the head is still `expected`. There is no update or delete.
    ///
    /// On success it returns the new head. A refused append changes nothing
    /// and does not use up its command id.
    ///
    /// An empty batch is refused with [`StoreError::EmptyBatch`]. A command
    /// id is used up only by the entries it appends. So an acknowledged
    /// command always names a stored entry, and a store over database rows
    /// can key idempotency on those rows alone (ADR-007).
    ///
    /// When several refusals apply, the store reports the first of these:
    ///
    /// 1. [`AppendError::DuplicateCommand`] when the command id was already
    ///    appended, whatever `expected` is. A caller that lost the
    ///    acknowledgement of an append learns on its first retry that the
    ///    command was applied.
    /// 2. [`AppendError::StaleHead`] when the head is not `expected`.
    /// 3. [`AppendError::Store`] for a time out of range, an empty batch or
    ///    a full ledger.
    ///
    /// Every store follows this order, so two stores give the same answer
    /// to the same input.
    ///
    /// The store does not check that `at` is non-decreasing. `decide`
    /// refuses a time earlier than the latest recorded time (design 2.2).
    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> Result<Seq, AppendError>;

    /// Reads at most `limit` entries starting at `from` and pushes them onto
    /// `out`. A read from past the head pushes nothing. [`Seq::ZERO`] reads
    /// from the first entry.
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
        /// The first entry of the earlier append.
        at: Seq,
    },
    /// The store failed or refused the entry.
    Store(StoreError),
}

/// A store failure.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreError {
    /// The store cannot be reached.
    Unavailable,
    /// The time is beyond [`MAX_AT`](crate::MAX_AT) in magnitude, so the entry has no
    /// exact RFC 8785 form.
    TimeOutOfRange,
    /// The batch would take the head past `u64::MAX`.
    Full,
    /// The batch holds no record. Refusing it keeps its command id unused.
    EmptyBatch,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable => f.write_str("store unavailable"),
            StoreError::TimeOutOfRange => f.write_str("time out of range"),
            StoreError::Full => f.write_str("sequence numbers exhausted"),
            StoreError::EmptyBatch => f.write_str("empty batch"),
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

/// [`SCHEMA_V1`] as a non-zero value.
const V1: NonZeroU16 = match NonZeroU16::new(SCHEMA_V1) {
    Some(v) => v,
    None => NonZeroU16::MIN,
};

/// In-memory append-only store. Its fields are private, so no caller can
/// change a past entry or forget a command id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemStore<R> {
    entries: Vec<Entry<R>>,
    /// First entry of each appended command.
    commands: BTreeMap<[u8; 16], Seq>,
    /// Schema version given to every appended entry.
    schema: NonZeroU16,
}

impl<R> MemStore<R> {
    /// An empty store that writes [`SCHEMA_V1`] entries.
    pub fn new() -> MemStore<R> {
        MemStore::with_schema(V1)
    }

    /// An empty store that writes entries of schema version `schema`.
    pub fn with_schema(schema: NonZeroU16) -> MemStore<R> {
        MemStore {
            entries: Vec::new(),
            commands: BTreeMap::new(),
            schema,
        }
    }

    /// The schema version this store gives to appended entries.
    pub fn schema(&self) -> u16 {
        self.schema.get()
    }

    /// Sets the schema version of later appends. Entries already stored
    /// keep their version, so a test or model can build a ledger that mixes
    /// versions, as ADR-007 allows.
    pub fn set_schema(&mut self, schema: NonZeroU16) {
        self.schema = schema;
    }
}

impl<R> Default for MemStore<R> {
    fn default() -> MemStore<R> {
        MemStore::new()
    }
}

impl<R: Clone> RecordStore<R> for MemStore<R> {
    fn head(&self) -> Seq {
        self.entries.last().map_or(Seq::ZERO, |e| e.seq)
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<R>,
    ) -> Result<Seq, AppendError> {
        // The order of these checks is the one `RecordStore::append` states.
        if let Some(&first) = self.commands.get(&command) {
            return Err(AppendError::DuplicateCommand { at: first });
        }
        let head = self.head();
        if expected != head {
            return Err(AppendError::StaleHead { head });
        }
        if !time_in_range(at) {
            return Err(AppendError::Store(StoreError::TimeOutOfRange));
        }
        if batch.is_empty() {
            return Err(AppendError::Store(StoreError::EmptyBatch));
        }
        let new_head = u64::try_from(batch.len())
            .ok()
            .and_then(|len| head.0.checked_add(len))
            .ok_or(AppendError::Store(StoreError::Full))?;
        // Every check has passed, so nothing below can fail part way.
        let schema = self.schema.get();
        let mut seq = head.0;
        self.entries.reserve(batch.len());
        for record in batch {
            seq = seq.saturating_add(1);
            self.entries
                .push(Entry::new(Seq(seq), at, command, schema, record));
        }
        self.commands.insert(command, Seq(head.0.saturating_add(1)));
        Ok(Seq(new_head))
    }

    fn read(&self, from: Seq, limit: usize, out: &mut Vec<Entry<R>>) -> Result<(), StoreError> {
        let start = usize::try_from(from.0.saturating_sub(1)).unwrap_or(usize::MAX);
        let tail = self.entries.get(start..).unwrap_or(&[]);
        out.extend(tail.iter().take(limit).cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-007: an empty batch is refused and changes nothing, so its
    /// command id stays unused and a later non-empty append under it
    /// succeeds once. A repeat after that is refused.
    #[test]
    fn adr007_empty_batch_is_refused_and_keeps_the_command_id_unused() {
        let mut store: MemStore<u8> = MemStore::new();
        let command = [7u8; 16];
        assert_eq!(
            store.append(Seq::ZERO, 0, command, Vec::new()),
            Err(AppendError::Store(StoreError::EmptyBatch))
        );
        assert_eq!(store.head(), Seq::ZERO);
        assert_eq!(store.append(Seq::ZERO, 0, command, vec![1, 2]), Ok(Seq(2)));
        assert_eq!(
            store.append(Seq(2), 0, command, Vec::new()),
            Err(AppendError::DuplicateCommand { at: Seq(1) })
        );
        assert_eq!(
            store.append(Seq(2), 0, [8u8; 16], Vec::new()),
            Err(AppendError::Store(StoreError::EmptyBatch))
        );
        assert_eq!(store.head(), Seq(2));
    }

    /// ADR-007: a retry of an applied command is refused as a duplicate
    /// even when it still carries the old head. A caller that lost the
    /// acknowledgement learns at once that the command was applied.
    #[test]
    fn adr007_lost_ack_retry_is_reported_as_duplicate() {
        let mut store: MemStore<u8> = MemStore::new();
        let command = [3u8; 16];
        assert_eq!(store.append(Seq::ZERO, 0, command, vec![1]), Ok(Seq(1)));
        assert_eq!(
            store.append(Seq::ZERO, 0, command, vec![1]),
            Err(AppendError::DuplicateCommand { at: Seq(1) })
        );
        assert_eq!(
            store.append(Seq(9), 0, [4u8; 16], vec![1]),
            Err(AppendError::StaleHead { head: Seq(1) })
        );
        assert_eq!(store.head(), Seq(1));
    }

    /// ADR-007: every entry carries its own schema version. `set_schema`
    /// changes only later appends, so one store holds a ledger that mixes
    /// versions and the earlier entries keep theirs.
    #[test]
    fn adr007_set_schema_changes_only_later_appends() {
        let mut store: MemStore<u8> = MemStore::new();
        assert_eq!(
            store.append(Seq::ZERO, 0, [1u8; 16], vec![1, 2]),
            Ok(Seq(2))
        );
        let v2 = NonZeroU16::new(2).unwrap_or(NonZeroU16::MAX);
        store.set_schema(v2);
        assert_eq!(store.schema(), 2);
        assert_eq!(store.append(Seq(2), 0, [2u8; 16], vec![3]), Ok(Seq(3)));
        let mut out = Vec::new();
        assert_eq!(store.read(Seq::ZERO, usize::MAX, &mut out), Ok(()));
        let versions: Vec<(u64, u16)> = out.iter().map(|e| (e.seq.0, e.schema)).collect();
        assert_eq!(versions, vec![(1, 1), (2, 1), (3, 2)]);
    }
}

//! The append-only verifier (I-23).

use crate::entry::{Entry, Seq};

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
    /// An entry of the earlier read differs at its position in the later
    /// read. This covers byte changes, deletions, swaps and insertions
    /// inside the earlier read.
    Changed {
        /// The position of the changed entry.
        seq: Seq,
    },
    /// A sequence number is missing.
    Gap {
        /// The first missing number.
        seq: Seq,
    },
    /// Entries are out of order: a number repeats or goes back.
    Reordered {
        /// The number found out of order.
        seq: Seq,
    },
}

/// Checks that `new` extends `old` without changing, dropping, inserting or
/// reordering any entry.
///
/// The checks run in this order, and the first failure is reported:
///
/// 1. `new` is at least as long as `old`, or [`Divergence::Truncated`].
/// 2. Position by position from the start: each entry of `old` equals the
///    entry at the same position of `new`, or [`Divergence::Changed`].
///    Records are compared by their canonical bytes, and the sequence
///    number, time, command id and schema version exactly.
/// 3. In the same pass, the entry at position `i` of `new` has sequence
///    number `i`, counting from 1. A higher number is a
///    [`Divergence::Gap`] and a lower one is [`Divergence::Reordered`].
pub fn verify_append_only<R: Canonical>(
    old: &[Entry<R>],
    new: &[Entry<R>],
) -> Result<(), Divergence> {
    if new.len() < old.len() {
        return Err(Divergence::Truncated {
            old_len: len_u64(old.len()),
            new_len: len_u64(new.len()),
        });
    }
    let mut expected: u64 = 0;
    let mut earlier = old.iter();
    for e in new {
        expected = expected.saturating_add(1);
        if let Some(o) = earlier.next()
            && !same_stored(o, e)
        {
            return Err(Divergence::Changed { seq: Seq(expected) });
        }
        if e.seq.0 > expected {
            return Err(Divergence::Gap { seq: Seq(expected) });
        }
        if e.seq.0 < expected {
            return Err(Divergence::Reordered { seq: e.seq });
        }
    }
    Ok(())
}

/// True when both entries have the same stored form.
fn same_stored<R: Canonical>(a: &Entry<R>, b: &Entry<R>) -> bool {
    a.seq == b.seq
        && a.at == b.at
        && a.command == b.command
        && a.schema == b.schema
        && a.record.canonical() == b.record.canonical()
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

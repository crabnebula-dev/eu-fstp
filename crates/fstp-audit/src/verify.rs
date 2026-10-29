//! The chain verifier (I-24, design section 7.1, ADR-010 "Verifier").
//!
//! It needs no content key. It checks, in this order, and reports the
//! first change it finds:
//!
//! 1. Row order: rows are numbered 1, 2, 3 in stored order.
//! 2. Ledger coverage: each kind 1 row names one stored entry, and each
//!    entry has exactly one row.
//! 3. Stored hashes and links, from genesis.
//! 4. The anchor rows of `audit.anchor`: each matches its receipt and the
//!    chain at its row, and the witness holds its prepare.
//! 5. The witness log: every prepared link is a present row, or carries
//!    an `Abort` or an `InDoubtAbsent`, never both. Every row is covered
//!    by a receipted prepare.
//! 6. The anchor and receipt signatures.
//!
//! Steps 1 to 5 read no key. Step 6 refuses with
//! [`AuditError::AwaitsAcceptance`] until Daniel accepts the composite
//! encoding table (ADR-010, lane W2g hard limit). The verifier therefore
//! never answers `Ok` while any signature is unchecked. Only a view with
//! no row, no anchor row and no witness record verifies today.
//!
//! An `Ok` lists every `InDoubtAbsent` record as a possible deletion
//! ([`Verified::possible_deletions`]). ADR-010 "In doubt" makes that alert
//! the detection, so an auditor run shows it without a second pass.
//!
//! A receipted prepare beyond the last row with no withdrawal is
//! `Truncated`. A view taken while an append is in flight has one, for
//! an honest chain: the witness log and the chain sit in separate
//! databases. So a live view must be quiescent, and the reader takes it
//! as [`ChainView`] states. A view of a restored or offline copy is read
//! as it is. A receipted head beyond it is then `Truncated` by design
//! (ADR-010 open point 8).
//!
//! Steps 4 and 5 index the witness log and the anchor rows once each, so
//! the whole check costs O(N log N) in the number of appends. The view
//! still holds every row at once. A streaming entry point for long
//! chains is open for W2e.

use std::collections::{BTreeMap, BTreeSet};

use crate::anchor::AnchorRow;
use crate::chain::{ChainId, Link, RowKind, StoredEntry, StoredRow, genesis, link, stored_hash};
use crate::witness::WitnessRecord;
use crate::{AuditError, COMPOSITE_ENCODING_ACCEPTANCE, CellId, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// A change the verifier found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tamper {
    /// A row's stored hash or link does not match its bytes.
    Changed {
        /// The row number.
        n: u64,
    },
    /// A row number is missing inside the chain.
    Gap {
        /// The row number.
        n: u64,
    },
    /// Rows are out of order.
    Reordered {
        /// The row number.
        n: u64,
    },
    /// The witness receipted a head beyond the chain's last row.
    Truncated {
        /// The witnessed head.
        witnessed: u64,
        /// The stored length.
        have: u64,
    },
    /// An anchor does not match the chain or its receipt at its row.
    AnchorMismatch {
        /// The row number.
        n: u64,
    },
    /// An anchor or receipt signature fails, including when only one half
    /// verifies.
    BadSignature {
        /// The row number.
        n: u64,
    },
    /// A ledger entry has no chain row.
    LedgerWithoutRow {
        /// The ledger sequence.
        seq: u64,
    },
    /// A kind 1 row names a missing ledger entry.
    RowWithoutLedger {
        /// The row number.
        n: u64,
    },
    /// A ledger entry's bytes differ from the hash its row holds.
    StoredHashMismatch {
        /// The ledger sequence.
        seq: u64,
    },
    /// A prepared link at the witness has no row, no `Abort` and no
    /// `InDoubtAbsent`.
    Deleted {
        /// The row number.
        n: u64,
    },
    /// An `Abort` or `InDoubtAbsent` exists for a link that is present.
    AbortedButPresent {
        /// The row number.
        n: u64,
    },
    /// Reading (W1e): a committed row that no receipted prepare covers.
    /// ADR-010 lists no variant for it.
    Unwitnessed {
        /// The first uncovered row number.
        n: u64,
    },
}

/// A verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The number of verified rows.
    pub rows: u64,
    /// The `(n, link)` of every `InDoubtAbsent` record in the witness
    /// log, in witness order. Each is a `PossibleDeletion` (ADR-010 "In
    /// doubt"): the cell could not tell an abort from a deletion. A chain
    /// verifies with them, so callers and the auditor view must show
    /// them. Reading of lane W2g, for ADR-010.
    pub possible_deletions: Vec<(u64, Link)>,
}

/// Everything the verifier reads for one cell and chain.
///
/// A view of a live chain is taken at a quiescent point. Otherwise the
/// prepare of an append in flight reads as `Truncated`. The reader, the
/// start-up verify (W3a), the restore drill and an auditor run follow
/// this rule (W2e obligation):
///
/// 1. In the cell database, open a transaction and take
///    `pg_advisory_xact_lock(1)`. This waits for any open append, which
///    holds that lock until its COMMIT or rollback ends.
/// 2. Check that the chain's anchorer core is idle
///    ([`crate::anchorer::Phase::Idle`]). A core that still owes an
///    abort, a chain read, an alert or an in-doubt record holds an
///    unresolved prepare. Release the lock and retry later.
/// 3. Read the witness log, then the chain, before the lock is released.
///
/// The anchorer takes the same lock in a new transaction for each abort,
/// alert and in-doubt step, so no step resolves a prepare between the
/// check and the reads. A cell that crashed with a prepare open serves
/// no view until its start-up resolution has run (ADR-010 "Start-up").
#[derive(Clone, Copy, Debug)]
pub struct ChainView<'a> {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The stored rows with their link column, in stored order.
    pub rows: &'a [StoredRow],
    /// The stored ledger entries. Kind 1 rows name them.
    pub ledger: &'a [StoredEntry],
    /// The rows of `audit.anchor`.
    pub anchors: &'a [AnchorRow],
    /// The witness log for this cell and chain, in witness order.
    pub witness: &'a [WitnessRecord],
    /// The chain's anchor public key history, encoded.
    pub anchor_keys: &'a [Vec<u8>],
    /// The pinned witness public keys, encoded.
    pub witness_keys: &'a [Vec<u8>],
}

fn tamper<T>(t: Tamper) -> Result<T, AuditError> {
    Err(AuditError::Tamper(t))
}

fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Steps 1 and 2: row order and ledger coverage. Returns the entries by
/// `seq`.
fn order_and_coverage<'a>(
    view: &ChainView<'a>,
) -> Result<BTreeMap<u64, &'a StoredEntry>, AuditError> {
    let numbers: BTreeSet<u64> = view.rows.iter().map(|r| r.row.n).collect();
    let mut expected: u64 = 0;
    for r in view.rows {
        expected = expected.saturating_add(1);
        if r.row.n != expected {
            return tamper(if numbers.contains(&expected) {
                Tamper::Reordered { n: expected }
            } else {
                Tamper::Gap { n: expected }
            });
        }
    }
    let mut entries: BTreeMap<u64, &StoredEntry> = BTreeMap::new();
    let mut duplicate: Option<u64> = None;
    for e in view.ledger {
        if entries.insert(e.seq, e).is_some() && duplicate.is_none() {
            duplicate = Some(e.seq);
        }
    }
    let mut named: BTreeSet<u64> = BTreeSet::new();
    for r in view.rows {
        if let RowKind::Ledger { seq } = r.row.kind {
            if !entries.contains_key(&seq) {
                return tamper(Tamper::RowWithoutLedger { n: r.row.n });
            }
            if !named.insert(seq) {
                return tamper(Tamper::Changed { n: r.row.n });
            }
        }
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for e in view.ledger {
        if !seen.insert(e.seq) || !named.contains(&e.seq) {
            return tamper(Tamper::LedgerWithoutRow { seq: e.seq });
        }
    }
    if let Some(seq) = duplicate {
        return tamper(Tamper::LedgerWithoutRow { seq });
    }
    Ok(entries)
}

/// Step 3: stored hashes and links from genesis.
fn hashes_and_links(
    view: &ChainView<'_>,
    entries: &BTreeMap<u64, &StoredEntry>,
) -> Result<(), AuditError> {
    let mut prev = genesis(view.cell, view.chain);
    for r in view.rows {
        let row = &r.row;
        let entry = match row.kind {
            RowKind::Ledger { seq } => entries.get(&seq).copied(),
            RowKind::Event { .. } => None,
        };
        let sh = stored_hash(row.at, &row.kind, entry);
        if sh.as_ref().ok() != Some(&row.stored_hash) {
            return tamper(match row.kind {
                RowKind::Ledger { seq } => Tamper::StoredHashMismatch { seq },
                RowKind::Event { .. } => Tamper::Changed { n: row.n },
            });
        }
        let l = link(&prev, view.cell, view.chain, row);
        if l != r.link {
            return tamper(Tamper::Changed { n: row.n });
        }
        prev = l;
    }
    Ok(())
}

/// Whether the fields of an anchor row agree with each other and with
/// this cell and chain. Signatures are not read.
fn row_consistent(view: &ChainView<'_>, row: &AnchorRow) -> bool {
    let a = &row.anchor;
    let rc = &row.receipt;
    a.cell == view.cell
        && a.chain == view.chain
        && rc.cell == view.cell
        && rc.chain == view.chain
        && rc.fields.n == a.n
        && rc.fields.link == a.link
}

/// Whether a signature could verify at all: its length is the composite
/// length and some key of the history has the composite key length.
fn signature_shape(sig: &[u8], keys: &[Vec<u8>]) -> bool {
    sig.len() == SIGNATURE_LEN && keys.iter().any(|k| k.len() == PUBLIC_KEY_LEN)
}

fn signatures_shaped(view: &ChainView<'_>, row: &AnchorRow) -> bool {
    signature_shape(&row.anchor.signature, view.anchor_keys)
        && signature_shape(&row.receipt.signature, view.witness_keys)
}

/// The `(n, link)` of every receipted prepare in the witness log.
fn prepared_heads(view: &ChainView<'_>) -> BTreeSet<(u64, Link)> {
    view.witness
        .iter()
        .filter_map(|w| match w {
            WitnessRecord::Prepare(p) => Some((p.anchor.n, p.anchor.link)),
            WitnessRecord::Abort { .. } | WitnessRecord::InDoubtAbsent { .. } => None,
        })
        .collect()
}

/// The `(n, link)` of every row of `audit.anchor`.
fn anchored_heads(view: &ChainView<'_>) -> BTreeSet<(u64, Link)> {
    view.anchors
        .iter()
        .map(|a| (a.anchor.n, a.anchor.link))
        .collect()
}

/// Step 4: the anchor rows. Each lookup in the witness log is a set
/// lookup, so the step costs O(N log N) for N anchor rows.
fn anchor_rows(
    view: &ChainView<'_>,
    link_at: &dyn Fn(u64) -> Option<Link>,
) -> Result<(), AuditError> {
    let have = count(view.rows.len());
    let prepared = prepared_heads(view);
    for row in view.anchors {
        let n = row.anchor.n;
        if !signatures_shaped(view, row) {
            return tamper(Tamper::BadSignature { n });
        }
        if !row_consistent(view, row) {
            return tamper(Tamper::AnchorMismatch { n });
        }
        if n > have {
            return tamper(Tamper::Truncated { witnessed: n, have });
        }
        if link_at(n) != Some(row.anchor.link) {
            return tamper(Tamper::AnchorMismatch { n });
        }
        if !prepared.contains(&(n, row.anchor.link)) {
            return tamper(Tamper::AnchorMismatch { n });
        }
    }
    Ok(())
}

/// Step 5: the witness log. Each lookup in the anchor rows is a set
/// lookup, so the step costs O(N log N) for N witness records.
fn witness_log(
    view: &ChainView<'_>,
    link_at: &dyn Fn(u64) -> Option<Link>,
) -> Result<(), AuditError> {
    let have = count(view.rows.len());
    let anchored = anchored_heads(view);
    let withdrawn: BTreeSet<(u64, Link)> = view
        .witness
        .iter()
        .filter_map(|w| match w {
            WitnessRecord::Abort { n, link } | WitnessRecord::InDoubtAbsent { n, link } => {
                Some((*n, *link))
            }
            WitnessRecord::Prepare(_) => None,
        })
        .collect();
    let mut covered: u64 = 0;
    let mut beyond: Option<u64> = None;
    for w in view.witness {
        let WitnessRecord::Prepare(p) = w else {
            continue;
        };
        let (n, l) = (p.anchor.n, p.anchor.link);
        if !signatures_shaped(view, p) {
            return tamper(Tamper::BadSignature { n });
        }
        if !row_consistent(view, p) {
            return tamper(Tamper::AnchorMismatch { n });
        }
        let present = link_at(n) == Some(l);
        let out = withdrawn.contains(&(n, l));
        if present && out {
            return tamper(Tamper::AbortedButPresent { n });
        }
        if present {
            if !anchored.contains(&(n, l)) {
                return tamper(Tamper::AnchorMismatch { n });
            }
            covered = covered.max(n);
        } else if !out {
            if n > have {
                beyond = Some(beyond.map_or(n, |b| b.max(n)));
            } else {
                return tamper(Tamper::Deleted { n });
            }
        }
    }
    if let Some(witnessed) = beyond {
        return tamper(Tamper::Truncated { witnessed, have });
    }
    if have > covered {
        return tamper(Tamper::Unwitnessed {
            n: covered.saturating_add(1),
        });
    }
    Ok(())
}

/// The `InDoubtAbsent` records of the witness log, in witness order.
fn possible_deletions(view: &ChainView<'_>) -> Vec<(u64, Link)> {
    view.witness
        .iter()
        .filter_map(|w| match w {
            WitnessRecord::InDoubtAbsent { n, link } => Some((*n, *link)),
            WitnessRecord::Prepare(_) | WitnessRecord::Abort { .. } => None,
        })
        .collect()
}

/// Step 6: the signatures. Refuses while any signature would need a
/// check (lane W2g hard limit).
fn signatures(view: &ChainView<'_>) -> Result<(), AuditError> {
    if view.rows.is_empty() && view.anchors.is_empty() && view.witness.is_empty() {
        return Ok(());
    }
    Err(AuditError::AwaitsAcceptance(COMPOSITE_ENCODING_ACCEPTANCE))
}

/// Verifies one chain of one cell against its ledger entries, its anchor
/// rows, the witness log and the key histories (I-24). A live `view` is
/// taken under the read rule of [`ChainView`].
///
/// # Errors
///
/// [`AuditError::Tamper`] with the first change found, or
/// [`AuditError::AwaitsAcceptance`] when the structure holds but its
/// signatures cannot be checked yet. Never `Ok` while a signature is
/// unchecked.
pub fn verify(view: &ChainView<'_>) -> Result<Verified, AuditError> {
    let entries = order_and_coverage(view)?;
    hashes_and_links(view, &entries)?;
    let link_at = |n: u64| -> Option<Link> {
        let i = usize::try_from(n.checked_sub(1)?).ok()?;
        view.rows.get(i).map(|r| r.link)
    };
    anchor_rows(view, &link_at)?;
    witness_log(view, &link_at)?;
    signatures(view)?;
    Ok(Verified {
        rows: count(view.rows.len()),
        possible_deletions: possible_deletions(view),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// I-24, ADR-010 "In doubt": the verifier result carries every
    /// `InDoubtAbsent` record as a possible deletion, in witness order,
    /// and no `Abort` or prepare.
    #[test]
    fn i24_verifier_lists_in_doubt_records_as_possible_deletions() {
        let cell = CellId([3; 16]);
        let witness = [
            WitnessRecord::InDoubtAbsent {
                n: 2,
                link: Link([2; 32]),
            },
            WitnessRecord::Abort {
                n: 1,
                link: Link([1; 32]),
            },
            WitnessRecord::InDoubtAbsent {
                n: 1,
                link: Link([4; 32]),
            },
        ];
        let view = ChainView {
            cell,
            chain: ChainId::App,
            rows: &[],
            ledger: &[],
            anchors: &[],
            witness: &witness,
            anchor_keys: &[],
            witness_keys: &[],
        };
        assert_eq!(
            possible_deletions(&view),
            vec![(2, Link([2; 32])), (1, Link([4; 32]))]
        );
    }
}

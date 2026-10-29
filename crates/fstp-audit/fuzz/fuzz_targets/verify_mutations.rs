//! Fuzz target `verify_mutations` of `fstp-audit` (TH-26, H-05, I-24, M3
//! design section 15).
//!
//! Design checks: the verifier never accepts a mutated chain.
//!
//! The input becomes a list of rows. The target checks four chains:
//!
//! - the rows with arbitrary stored hashes and link columns: never `Ok`.
//! - the same rows written by `ChainWriter`, with their ledger entries
//!   and no witness record: every structural check passes, and the
//!   verifier reports the first row as unwitnessed.
//! - those rows with an anchor row and its prepare at the witness: never
//!   `Ok`, since no signature can be checked before Daniel accepts the
//!   composite encoding (lane W2g hard limit, ADR-010).
//! - the honest anchored chain with one keyless change the input
//!   chooses: always the tamper that change makes, never `Ok` and never
//!   the acceptance refusal. The changes: a changed `at` or stored hash,
//!   a removed, swapped or inserted row, a consistent recomputation, a
//!   deleted or changed anchor row, a deleted prepare, an abort for the
//!   present head, and a changed ledger entry.
//!
//! The first input byte picks the cell, the chain and the row. The second
//! picks the change.

#![no_main]

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, ReceiptFields};
use fstp_audit::chain::{ChainWriter, RowKind, StoredEntry, StoredRow};
use fstp_audit::verify::{ChainView, Tamper, verify};
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{AuditError, CellId, ChainId, ChainRow, Link, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use libfuzzer_sys::fuzz_target;

const CHUNK: usize = 1 + 8 + 8 + 32;

/// One row of the input: a kind, `at`, a value and a 32-byte hash.
struct Spec {
    ledger: bool,
    at: i64,
    x: u64,
    hash: [u8; 32],
}

fn spec_of(c: &[u8]) -> Option<Spec> {
    let (&tag, rest) = c.split_first()?;
    Some(Spec {
        ledger: tag & 1 == 0,
        at: i64::from_be_bytes(rest.get(..8)?.try_into().ok()?),
        x: u64::from_be_bytes(rest.get(8..16)?.try_into().ok()?),
        hash: rest.get(16..48)?.try_into().ok()?,
    })
}

fn view<'a>(
    cell: CellId,
    chain: ChainId,
    rows: &'a [StoredRow],
    ledger: &'a [StoredEntry],
    anchors: &'a [AnchorRow],
    witness: &'a [WitnessRecord],
    keys: &'a [Vec<u8>],
) -> ChainView<'a> {
    ChainView {
        cell,
        chain,
        rows,
        ledger,
        anchors,
        witness,
        anchor_keys: keys,
        witness_keys: keys,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let Some((&pick, rest)) = rest.split_first() else {
        return;
    };
    let specs: Vec<Spec> = rest.chunks(CHUNK).filter_map(spec_of).collect();
    if specs.is_empty() {
        return;
    }
    let chain = if choice & 0x80 == 0 {
        ChainId::App
    } else {
        ChainId::Vault
    };
    let cell = CellId([choice; 16]);
    let keys = vec![vec![0u8; PUBLIC_KEY_LEN]];

    // Arbitrary rows: never Ok.
    let arbitrary: Vec<StoredRow> = specs
        .iter()
        .zip(1u64..)
        .map(|(s, n)| StoredRow {
            row: ChainRow {
                n,
                at: s.at,
                kind: if s.ledger {
                    RowKind::Ledger { seq: s.x }
                } else {
                    RowKind::Event {
                        body: s.x.to_be_bytes().to_vec(),
                    }
                },
                stored_hash: s.hash,
            },
            link: Link(s.hash),
        })
        .collect();
    let r = verify(&view(cell, chain, &arbitrary, &[], &[], &[], &keys));
    assert!(r.is_err(), "arbitrary rows verified: {r:?}");

    // Honest rows through ChainWriter, ledger rows numbered from seq 1.
    let mut w = ChainWriter::genesis(cell, chain);
    let mut rows = Vec::new();
    let mut ledger = Vec::new();
    for (s, seq) in specs.iter().zip(1u64..) {
        let (kind, entry) = if s.ledger {
            let e = StoredEntry {
                seq,
                at: s.at,
                command: [choice; 16],
                schema: 1,
                key_ix: 0,
                body: s.x.to_be_bytes().to_vec(),
            };
            (RowKind::Ledger { seq }, Some(e))
        } else {
            (
                RowKind::Event {
                    body: s.hash.to_vec(),
                },
                None,
            )
        };
        let Ok(row) = w.append(cell, chain, s.at, kind, entry.as_ref()) else {
            return;
        };
        rows.push(row);
        ledger.extend(entry);
    }
    let r = verify(&view(cell, chain, &rows, &ledger, &[], &[], &keys));
    assert_eq!(
        r,
        Err(AuditError::Tamper(Tamper::Unwitnessed { n: 1 })),
        "honest rows without receipts"
    );

    // With an anchor row and its prepare: never Ok while signatures are
    // unchecked.
    let (n, link) = w.head();
    let anchor_row = AnchorRow {
        anchor: Anchor {
            cell,
            chain,
            n,
            link,
            at: 0,
            signature: vec![0; SIGNATURE_LEN],
        },
        receipt: Receipt {
            cell,
            chain,
            fields: ReceiptFields {
                n,
                link,
                witness_seq: 1,
                witness_link: Link([0; 32]),
                received_at: 0,
            },
            signature: vec![0; SIGNATURE_LEN],
        },
    };
    let mut anchors = vec![anchor_row.clone()];
    let mut witness = vec![WitnessRecord::Prepare(anchor_row)];
    let r = verify(&view(
        cell, chain, &rows, &ledger, &anchors, &witness, &keys,
    ));
    assert!(
        matches!(r, Err(AuditError::AwaitsAcceptance(_))),
        "an anchored honest chain must wait on the acceptance: {r:?}"
    );

    // One keyless change, as the input chooses. Each is found by the
    // structural checks as its own tamper, never left to the acceptance
    // refusal.
    let i = usize::from(choice & 0x7F) % rows.len();
    let last = rows.len() - 1;
    let n_of = |k: usize| u64::try_from(k).unwrap_or(u64::MAX) + 1;
    let expected: fn(&Tamper, &Ctx) -> bool = match pick % 11 {
        // A changed `at` or stored hash.
        0 | 1 => {
            if pick % 11 == 0 {
                rows[i].row.at = rows[i].row.at.wrapping_add(1);
            } else {
                rows[i].row.stored_hash[0] ^= 1;
            }
            |t, _| {
                matches!(
                    t,
                    Tamper::Changed { .. } | Tamper::StoredHashMismatch { .. }
                )
            }
        }
        // A removed row: a gap inside the chain, or a lost tail.
        2 => {
            let removed = rows.remove(i);
            match removed.row.kind {
                _ if i < last => |t, c| *t == Tamper::Gap { n: c.n_i },
                RowKind::Ledger { .. } => |t, c| *t == Tamper::LedgerWithoutRow { seq: c.seq_i },
                RowKind::Event { .. } => |t, c| {
                    *t == Tamper::Truncated {
                        witnessed: c.head,
                        have: c.head - 1,
                    }
                },
            }
        }
        // Two rows swapped.
        3 => {
            if rows.len() < 2 {
                return;
            }
            let j = (i + 1) % rows.len();
            rows.swap(i, j);
            |t, c| *t == Tamper::Reordered { n: c.n_min }
        }
        // A row inserted: a copy of row i after it.
        4 => {
            let copy = rows[i].clone();
            rows.insert(i + 1, copy);
            if i < last {
                |t, c| *t == Tamper::Reordered { n: c.n_i + 1 }
            } else {
                |t, c| *t == Tamper::Gap { n: c.head + 1 }
            }
        }
        // A consistent recomputation after a change: every stored hash and
        // link is recomputed, so only the anchor no longer matches.
        5 => {
            let mut w = ChainWriter::genesis(cell, chain);
            let mut again = Vec::new();
            for (k, r) in rows.iter().enumerate() {
                let at = if k == i {
                    r.row.at.wrapping_add(1)
                } else {
                    r.row.at
                };
                let entry = match r.row.kind {
                    RowKind::Ledger { seq } => ledger.iter().find(|e| e.seq == seq),
                    RowKind::Event { .. } => None,
                };
                let Ok(row) = w.append(cell, chain, at, r.row.kind.clone(), entry) else {
                    return;
                };
                again.push(row);
            }
            rows = again;
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The anchor row deleted.
        6 => {
            anchors.clear();
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The anchor row's link changed, with its receipt.
        7 => {
            anchors[0].anchor.link.0[0] ^= 1;
            anchors[0].receipt.fields.link.0[0] ^= 1;
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The prepare deleted from the witness log.
        8 => {
            witness.clear();
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // An abort added for the present head.
        9 => {
            witness.push(WitnessRecord::Abort { n, link });
            |t, c| *t == Tamper::AbortedButPresent { n: c.head }
        }
        // A ledger entry's body changed.
        _ => {
            let k = i % ledger.len().max(1);
            let Some(e) = ledger.get_mut(k) else {
                return;
            };
            let Some(b) = e.body.first_mut() else {
                return;
            };
            *b ^= 1;
            |t, c| matches!(t, Tamper::StoredHashMismatch { seq } if c.ledger_seqs.contains(seq))
        }
    };
    let ctx = Ctx {
        n_i: n_of(i),
        n_min: n_of(i.min((i + 1) % (last + 1))),
        head: n,
        seq_i: spec_seq(&specs, i).unwrap_or(0),
        ledger_seqs: ledger.iter().map(|e| e.seq).collect(),
    };
    let r = verify(&view(
        cell, chain, &rows, &ledger, &anchors, &witness, &keys,
    ));
    match &r {
        Err(AuditError::Tamper(t)) => {
            assert!(expected(t, &ctx), "change {} found as {t:?}", pick % 11);
        }
        other => panic!("change {} not found as a tamper: {other:?}", pick % 11),
    }
});

/// What the expected tamper of a change refers to.
struct Ctx {
    /// The row number of row `i`.
    n_i: u64,
    /// The lower row number of a swapped pair.
    n_min: u64,
    /// The head the anchor names.
    head: u64,
    /// The ledger sequence of row `i`, if it is a ledger row.
    seq_i: u64,
    /// The ledger sequences after the change.
    ledger_seqs: Vec<u64>,
}

/// The ledger sequence that row `i` names: rows take seq `i + 1`.
fn spec_seq(specs: &[Spec], i: usize) -> Option<u64> {
    let s = specs.get(i)?;
    if s.ledger {
        u64::try_from(i).ok().map(|k| k + 1)
    } else {
        None
    }
}

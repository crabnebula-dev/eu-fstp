//! Fuzz target `verify_mutations` of `fstp-audit` (TH-26, H-05, I-24,
//! I-90, R-CR-03, M3 design section 15).
//!
//! Design checks: the verifier never accepts a mutated chain.
//!
//! The input becomes a list of rows. The target checks four chains:
//!
//! - the rows with arbitrary stored hashes and link columns: never `Ok`.
//! - the same rows written by `ChainWriter`, with their ledger entries
//!   and no witness record: every structural check passes, and the
//!   verifier reports the first row as unwitnessed.
//! - those rows with an anchor row and its prepare at the witness, signed
//!   for real: the anchor by `fstp_audit::anchor::sign_anchor` under a
//!   fixed composite `Anchor` key, the receipt under a fixed witness key
//!   with the pinned context `fstp-receipt-v1` (ADR-010 open point 2,
//!   interim reading of lane W2g). That honest chain verifies.
//! - the honest anchored chain with one change the input chooses: always
//!   the tamper that change makes, never `Ok` and never a stub refusal.
//!   The keyless changes: a changed `at` or stored hash, a removed,
//!   swapped or inserted row, a consistent recomputation, a deleted or
//!   changed anchor row, a deleted prepare, an abort for the present
//!   head, and a changed ledger entry. The signature changes, each
//!   `BadSignature` of the head: a flipped bit of the anchor or receipt
//!   signature in either stored copy, a changed anchor `at`, a changed
//!   witness sequence, either signature half from another message, and
//!   an anchor key history without the key.
//!
//! The first input byte picks the cell, the chain and the row. The second
//! picks the change. The first row's hash picks the signature byte.
//!
//! Lane W2g landed anchor signing. A signer that refused would stop the
//! target on its first input.

#![no_main]

use std::sync::OnceLock;

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, ReceiptFields, receipt_message, sign_anchor};
use fstp_audit::chain::{ChainWriter, RowKind, StoredEntry, StoredRow};
use fstp_audit::verify::{ChainView, Tamper, verify};
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{AuditError, CellId, ChainId, ChainRow, CompositeSigningKey, Link, SIGNATURE_LEN};
use libfuzzer_sys::fuzz_target;

const CHUNK: usize = 1 + 8 + 8 + 32;

/// The receipt context (ADR-010 open point 2, interim reading of lane
/// W2g).
const RECEIPT_CTX: &[u8] = b"fstp-receipt-v1";

/// The length of the ML-DSA-65 half, first in the signature (ADR-010
/// "Composite encoding", row "Signature").
const MLDSA_SIG_LEN: usize = 3309;

/// The fixed test keys and their encoded public keys.
struct Keys {
    anchor: CompositeSigningKey,
    witness: CompositeSigningKey,
    anchor_pk: Vec<Vec<u8>>,
    witness_pk: Vec<Vec<u8>>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let key = |b: u8| match CompositeSigningKey::from_bytes(&[b; 64]) {
            Ok(k) => k,
            Err(e) => panic!("fixed composite key: {e:?}"),
        };
        let (anchor, witness) = (key(0xA1), key(0x3E));
        let anchor_pk = vec![anchor.public_key().to_bytes().to_vec()];
        let witness_pk = vec![witness.public_key().to_bytes().to_vec()];
        Keys {
            anchor,
            witness,
            anchor_pk,
            witness_pk,
        }
    })
}

/// The witness key's signature over `fields` of `cell`'s `chain`.
fn receipt_sig(cell: CellId, chain: ChainId, fields: &ReceiptFields) -> Vec<u8> {
    let msg = receipt_message(cell, chain, fields);
    match keys().witness.sign_with_context(&msg, RECEIPT_CTX) {
        Ok(s) => s.to_bytes().to_vec(),
        Err(e) => panic!("receipt signing: {e:?}"),
    }
}

/// The anchor key's signature over the anchor of `(n, link)` at `at`.
fn anchor_sig(cell: CellId, chain: ChainId, n: u64, link: &Link, at: i64) -> Vec<u8> {
    match sign_anchor(&keys().anchor, cell, chain, n, link, at) {
        Ok(a) => a.signature,
        Err(e) => panic!("sign_anchor refused an honest head: {e:?}"),
    }
}

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

/// What the verifier reads. The witness log and the anchor rows hold one
/// copy each of the signed head.
struct Parts {
    rows: Vec<StoredRow>,
    ledger: Vec<StoredEntry>,
    anchors: Vec<AnchorRow>,
    witness: Vec<WitnessRecord>,
    anchor_keys: Vec<Vec<u8>>,
    witness_keys: Vec<Vec<u8>>,
}

impl Parts {
    fn verify(&self, cell: CellId, chain: ChainId) -> Result<u64, AuditError> {
        verify(&ChainView {
            cell,
            chain,
            rows: &self.rows,
            ledger: &self.ledger,
            anchors: &self.anchors,
            witness: &self.witness,
            anchor_keys: &self.anchor_keys,
            witness_keys: &self.witness_keys,
        })
        .map(|ok| ok.rows)
    }

    /// The anchor row of `audit.anchor`, or the witness copy.
    fn copy_mut(&mut self, witness: bool) -> Option<&mut AnchorRow> {
        if witness {
            match self.witness.first_mut()? {
                WitnessRecord::Prepare(p) => Some(p),
                WitnessRecord::Abort { .. } | WitnessRecord::InDoubtAbsent { .. } => None,
            }
        } else {
            self.anchors.first_mut()
        }
    }
}

/// The number of changes the second input byte picks from.
const CHANGES: u8 = 18;

fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let Some((&pick, rest)) = rest.split_first() else {
        return;
    };
    let specs: Vec<Spec> = rest.chunks(CHUNK).filter_map(spec_of).collect();
    let Some(first) = specs.first() else {
        return;
    };
    let chain = if choice & 0x80 == 0 {
        ChainId::App
    } else {
        ChainId::Vault
    };
    let cell = CellId([choice; 16]);
    let k = keys();
    let byte_at = usize::from(u16::from_be_bytes([first.hash[0], first.hash[1]])) % SIGNATURE_LEN;
    let bit = 1u8 << (first.hash[2] & 7);

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
    let mut p = Parts {
        rows: arbitrary,
        ledger: Vec::new(),
        anchors: Vec::new(),
        witness: Vec::new(),
        anchor_keys: k.anchor_pk.clone(),
        witness_keys: k.witness_pk.clone(),
    };
    let r = p.verify(cell, chain);
    assert!(r.is_err(), "arbitrary rows verified: {r:?}");

    // Honest rows through ChainWriter, ledger rows numbered from seq 1.
    let mut w = ChainWriter::genesis(cell, chain);
    p.rows = Vec::new();
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
        p.rows.push(row);
        p.ledger.extend(entry);
    }
    let r = p.verify(cell, chain);
    assert_eq!(
        r,
        Err(AuditError::Tamper(Tamper::Unwitnessed { n: 1 })),
        "honest rows without receipts"
    );

    // With a signed anchor row and its prepare: the honest chain verifies.
    let (n, link) = w.head();
    let at = first.at;
    let fields = ReceiptFields {
        n,
        link,
        witness_seq: 1,
        witness_link: Link(first.hash),
        received_at: at.wrapping_add(1),
    };
    let anchor_row = AnchorRow {
        anchor: Anchor {
            cell,
            chain,
            n,
            link,
            at,
            signature: anchor_sig(cell, chain, n, &link, at),
        },
        receipt: Receipt {
            cell,
            chain,
            fields,
            signature: receipt_sig(cell, chain, &fields),
        },
    };
    p.anchors = vec![anchor_row.clone()];
    p.witness = vec![WitnessRecord::Prepare(anchor_row)];
    let have = u64::try_from(p.rows.len()).unwrap_or(u64::MAX);
    let r = p.verify(cell, chain);
    assert_eq!(r, Ok(have), "an honest signed chain must verify");

    // One change, as the input chooses. Each is found as its own tamper,
    // never left to a stub refusal.
    let i = usize::from(choice & 0x7F) % p.rows.len();
    let last = p.rows.len() - 1;
    let n_of = |k: usize| u64::try_from(k).unwrap_or(u64::MAX) + 1;
    let bad = |t: &Tamper, c: &Ctx| *t == Tamper::BadSignature { n: c.head };
    let change = pick % CHANGES;
    let expected: fn(&Tamper, &Ctx) -> bool = match change {
        // A changed `at` or stored hash.
        0 | 1 => {
            if change == 0 {
                p.rows[i].row.at = p.rows[i].row.at.wrapping_add(1);
            } else {
                p.rows[i].row.stored_hash[0] ^= 1;
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
            let removed = p.rows.remove(i);
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
            if p.rows.len() < 2 {
                return;
            }
            let j = (i + 1) % p.rows.len();
            p.rows.swap(i, j);
            |t, c| *t == Tamper::Reordered { n: c.n_min }
        }
        // A row inserted: a copy of row i after it.
        4 => {
            let copy = p.rows[i].clone();
            p.rows.insert(i + 1, copy);
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
            for (k, r) in p.rows.iter().enumerate() {
                let at = if k == i {
                    r.row.at.wrapping_add(1)
                } else {
                    r.row.at
                };
                let entry = match r.row.kind {
                    RowKind::Ledger { seq } => p.ledger.iter().find(|e| e.seq == seq),
                    RowKind::Event { .. } => None,
                };
                let Ok(row) = w.append(cell, chain, at, r.row.kind.clone(), entry) else {
                    return;
                };
                again.push(row);
            }
            p.rows = again;
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The anchor row deleted.
        6 => {
            p.anchors.clear();
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The anchor row's link changed, with its receipt.
        7 => {
            p.anchors[0].anchor.link.0[0] ^= 1;
            p.anchors[0].receipt.fields.link.0[0] ^= 1;
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // The prepare deleted from the witness log.
        8 => {
            p.witness.clear();
            |t, c| *t == Tamper::AnchorMismatch { n: c.head }
        }
        // An abort added for the present head.
        9 => {
            p.witness.push(WitnessRecord::Abort { n, link });
            |t, c| *t == Tamper::AbortedButPresent { n: c.head }
        }
        // A ledger entry's body changed.
        10 => {
            let k = i % p.ledger.len().max(1);
            let Some(e) = p.ledger.get_mut(k) else {
                return;
            };
            let Some(b) = e.body.first_mut() else {
                return;
            };
            *b ^= 1;
            |t, c| matches!(t, Tamper::StoredHashMismatch { seq } if c.ledger_seqs.contains(seq))
        }
        // A flipped bit of the anchor or receipt signature, in either
        // stored copy (I-90, R-CR-03).
        11..=14 => {
            let Some(row) = p.copy_mut(change >= 13) else {
                return;
            };
            let sig = if change % 2 == 1 {
                &mut row.anchor.signature
            } else {
                &mut row.receipt.signature
            };
            let Some(b) = sig.get_mut(byte_at) else {
                return;
            };
            *b ^= bit;
            bad
        }
        // A changed anchor `at` in the anchor row, or a changed witness
        // sequence in the witness copy: only the signature binds them.
        15 => {
            let Some(row) = p.copy_mut(choice & 1 == 1) else {
                return;
            };
            if choice & 2 == 0 {
                row.anchor.at = row.anchor.at.wrapping_add(1);
            } else {
                row.receipt.fields.witness_seq = 2;
            }
            bad
        }
        // One half of the anchor signature taken from the same key's
        // signature over another head (I-90).
        16 => {
            let Some(row) = p.copy_mut(choice & 1 == 1) else {
                return;
            };
            let other = anchor_sig(cell, chain, n, &link, at.wrapping_add(1));
            let range = if choice & 2 == 0 {
                0..MLDSA_SIG_LEN
            } else {
                MLDSA_SIG_LEN..SIGNATURE_LEN
            };
            let (Some(dst), Some(src)) = (
                row.anchor.signature.get_mut(range.clone()),
                other.get(range),
            ) else {
                return;
            };
            dst.copy_from_slice(src);
            bad
        }
        // An anchor key history without the chain's key, or witness keys
        // without the witness key.
        _ => {
            if choice & 1 == 0 {
                p.anchor_keys = k.witness_pk.clone();
            } else {
                p.witness_keys = k.anchor_pk.clone();
            }
            bad
        }
    };
    let ctx = Ctx {
        n_i: n_of(i),
        n_min: n_of(i.min((i + 1) % (last + 1))),
        head: n,
        seq_i: spec_seq(&specs, i).unwrap_or(0),
        ledger_seqs: p.ledger.iter().map(|e| e.seq).collect(),
    };
    let r = p.verify(cell, chain);
    match &r {
        Err(AuditError::Tamper(t)) => {
            assert!(expected(t, &ctx), "change {change} found as {t:?}");
        }
        other => panic!("change {change} not found as a tamper: {other:?}"),
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

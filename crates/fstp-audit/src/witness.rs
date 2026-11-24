//! What the anchorer sends the witness and what the witness logs
//! (ADR-010 "Prepare, receipt, commit").
//!
//! The witness keeps its own chain per cell and chain. Each prepare, abort
//! and in-doubt record advances it:
//!
//! ```text
//! witness genesis = SHA-256("fstp-witness-v1" || cell || chain)
//! witness link    = SHA-256("fstp-witness-v1" || cell || chain || kind
//!                           || be64(witness_seq) || previous witness link
//!                           || be64(n) || link)
//! ```
//!
//! ADR-010 fixes no layout for it. This is the W1e reading, so the
//! witness core and the reference witness agree state for state. It lives
//! here, beside the other audit hashes, so that the verifier can
//! recompute it once the witness log carries its own links.

use std::collections::BTreeSet;

use crate::anchor::{Anchor, AnchorRow, signed_by_any};
use crate::chain::{ChainId, Link, genesis, link_of};
use crate::codec::{Reader, sha256};
use crate::{AuditError, CellId, CompositeSigningKey, DecodeError, Invalid, SIGNATURE_LEN};

/// The witness chain label (W1e reading).
pub const WITNESS_LABEL: &[u8] = b"fstp-witness-v1";
/// The most rows one prepare covers. A batch of entries shares one
/// prepare (design section 7.2).
pub const MAX_PREPARE_ROWS: usize = 65_536;

/// A prepare: the head it extends, the stored hashes of its rows, and the
/// anchor of the prospective head (ADR-010 "Prepare", reading of open
/// point 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepare {
    /// The head this prepare extends: its row number and link.
    pub prev: (u64, Link),
    /// The stored hashes of the rows after `prev`, in order.
    pub stored_hashes: Vec<[u8; 32]>,
    /// The anchor of the prospective head.
    pub anchor: Anchor,
}

impl Prepare {
    /// Whether the prepare has a shape a witness can check: one to
    /// [`MAX_PREPARE_ROWS`] rows, and an anchor `n` that is `prev` plus
    /// the row count.
    ///
    /// # Errors
    ///
    /// [`Invalid::PrepareShape`] otherwise.
    pub fn check_shape(&self) -> Result<(), Invalid> {
        let count = self.stored_hashes.len();
        if count == 0 || count > MAX_PREPARE_ROWS {
            return Err(Invalid::PrepareShape);
        }
        let count = u64::try_from(count).map_err(|_| Invalid::PrepareShape)?;
        match self.prev.0.checked_add(count) {
            Some(n) if n == self.anchor.n => Ok(()),
            _ => Err(Invalid::PrepareShape),
        }
    }

    /// The head the stored hashes recompute to after `prev`, for the
    /// anchor's cell and chain. `None` when the row number overflows.
    pub fn recomputed_head(&self) -> Option<(u64, Link)> {
        let (mut n, mut l) = self.prev;
        for sh in &self.stored_hashes {
            n = n.checked_add(1)?;
            l = link_of(&l, self.anchor.cell, self.anchor.chain, n, sh);
        }
        Some((n, l))
    }
}

/// The kind of a witness log record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// A receipted prepare. Code 1.
    Prepare,
    /// An abort of the outstanding prepare. Code 2.
    Abort,
    /// An in-doubt prepare whose row was missing. Code 3.
    InDoubtAbsent,
    /// A declared restore (ADR-012 record of lane m10/declared-restore).
    /// Code 4.
    RestoreDeclared,
}

impl RecordKind {
    /// The record code in the witness link.
    pub const fn code(self) -> u8 {
        match self {
            RecordKind::Prepare => 1,
            RecordKind::Abort => 2,
            RecordKind::InDoubtAbsent => 3,
            RecordKind::RestoreDeclared => 4,
        }
    }
}

/// One record of the witness log for one cell and chain, as the verifier
/// reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessRecord {
    /// A receipted prepare: the anchor and the receipt the witness gave.
    Prepare(AnchorRow),
    /// An abort of a prepare.
    Abort {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
    /// A prepare whose commit outcome was unknown and whose row was
    /// missing at reconnect.
    InDoubtAbsent {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
    /// A declared restore: the head the restored chain resumes from, and
    /// the window it lost (ADR-012 record of lane m10/declared-restore).
    RestoreDeclared(Declaration),
}

/// The witness chain head before any record of `cell`'s `chain`.
pub fn witness_genesis(cell: CellId, chain: ChainId) -> Link {
    Link(sha256(&[WITNESS_LABEL, &cell.0, &[chain.byte()]]))
}

/// The witness chain link after a record of `kind` for `(n, link)` at
/// witness sequence `seq`, after `prev`.
pub fn witness_link(
    prev: &Link,
    cell: CellId,
    chain: ChainId,
    kind: RecordKind,
    seq: u64,
    n: u64,
    link: &Link,
) -> Link {
    Link(sha256(&[
        WITNESS_LABEL,
        &cell.0,
        &[chain.byte(), kind.code()],
        &seq.to_be_bytes(),
        &prev.0,
        &n.to_be_bytes(),
        &link.0,
    ]))
}

// ---------------------------------------------------------------------------
// Declared restores (ADR-012 record of lane m10/declared-restore). Every
// layout below is interim, pending Daniel.
//
// ```text
// declaration link = SHA-256("fstp-witness-v1" || cell || chain || 4
//                            || be64(witness_seq) || previous witness link
//                            || be64(head n) || head link || be64(lost to)
//                            || job)
// signed message   = "fstp-restore-v1" || cell || chain || be64(head n)
//                    || head link || be64(lost to) || job
//                    || be64(witness_seq) || witness link || be64(received_at)
// body             = be64(head n) || head link (32) || be64(lost to)
//                    || job (16) || be64(witness_seq) || witness link (32)
//                    || be64(received_at) || signature (SIGNATURE_LEN)
// ```

/// The label of a signed restore declaration.
pub const RESTORE_LABEL: &[u8] = b"fstp-restore-v1";
/// The draft 19 application context of a restore declaration signature.
/// Interim reading of lane m10/declared-restore: the label, as for
/// anchors and receipts.
pub const RESTORE_CONTEXT: &[u8] = b"fstp-restore-v1";
/// The length of a signed declaration message: 15 + 16 + 1 + 8 + 32 + 8 +
/// 16 + 8 + 32 + 8.
pub const RESTORE_MESSAGE_LEN: usize = 144;
/// The most declarations one chain holds. The next one is refused, so a
/// reply that lists them stays bounded.
pub const MAX_DECLARATIONS: usize = 1024;
/// The length that [`put_declaration`] writes.
pub const DECLARATION_BODY_LEN: usize = 8 + 32 + 8 + 16 + 8 + 32 + 8 + SIGNATURE_LEN;

/// What a declared restore states, and the witness fields it was
/// recorded under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeclarationFields {
    /// The head the restored chain resumes from: genesis or a receipted
    /// prepare that was live at the declaration.
    pub head: (u64, Link),
    /// The highest row of a live prepare beyond the head, or the head's
    /// row when none was.
    pub lost_to: u64,
    /// The restore job that declared it.
    pub job: [u8; 16],
    /// The witness sequence of the record.
    pub witness_seq: u64,
    /// The witness chain link after the record.
    pub witness_link: Link,
    /// When the witness recorded it, UTC microseconds.
    pub received_at: i64,
}

impl DeclarationFields {
    /// The rows the restore lost, `head n + 1` to `lost to`, if any.
    #[must_use]
    pub fn lost(&self) -> Option<(u64, u64)> {
        (self.lost_to > self.head.0).then(|| (self.head.0.saturating_add(1), self.lost_to))
    }

    fn check(&self) -> Result<(), Invalid> {
        if self.lost_to < self.head.0 || self.witness_seq == 0 {
            Err(Invalid::DeclarationShape)
        } else {
            Ok(())
        }
    }
}

/// A recorded restore declaration and the witness signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The signed fields.
    pub fields: DeclarationFields,
    /// The composite signature of the witness receipt key.
    pub signature: Vec<u8>,
}

/// The witness chain link after a declaration of `head`, losing up to
/// `lost_to`, by `job`, at witness sequence `seq` after `prev`.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one field the link binds"
)]
pub fn declaration_link(
    prev: &Link,
    cell: CellId,
    chain: ChainId,
    seq: u64,
    head: &(u64, Link),
    lost_to: u64,
    job: &[u8; 16],
) -> Link {
    Link(sha256(&[
        WITNESS_LABEL,
        &cell.0,
        &[chain.byte(), RecordKind::RestoreDeclared.code()],
        &seq.to_be_bytes(),
        &prev.0,
        &head.0.to_be_bytes(),
        &head.1.0,
        &lost_to.to_be_bytes(),
        job,
    ]))
}

/// The message a declaration signature covers.
#[must_use]
pub fn declaration_message(cell: CellId, chain: ChainId, f: &DeclarationFields) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESTORE_MESSAGE_LEN);
    out.extend_from_slice(RESTORE_LABEL);
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
    out.extend_from_slice(&f.head.0.to_be_bytes());
    out.extend_from_slice(&f.head.1.0);
    out.extend_from_slice(&f.lost_to.to_be_bytes());
    out.extend_from_slice(&f.job);
    out.extend_from_slice(&f.witness_seq.to_be_bytes());
    out.extend_from_slice(&f.witness_link.0);
    out.extend_from_slice(&f.received_at.to_be_bytes());
    out
}

/// Signs `fields` for `cell`'s `chain` with the witness receipt key, over
/// [`declaration_message`] under [`RESTORE_CONTEXT`]. Interim reading of
/// lane m10/declared-restore: a self-hosted host has no restore
/// declaration key, so the witness's own key signs.
///
/// # Errors
///
/// [`Invalid::DeclarationShape`] for a window that ends before the head
/// or a witness sequence of 0, and [`AuditError::Signing`] when the
/// composite signer gives no signature.
pub fn sign_declaration(
    key: &CompositeSigningKey,
    cell: CellId,
    chain: ChainId,
    fields: &DeclarationFields,
) -> Result<Declaration, AuditError> {
    fields.check()?;
    let signature = key
        .sign_with_context(&declaration_message(cell, chain, fields), RESTORE_CONTEXT)
        .map_err(AuditError::Signing)?;
    Ok(Declaration {
        fields: *fields,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Whether the declaration's signature verifies under one key of
/// `witness_keys`, both halves (I-90).
#[must_use]
pub fn declaration_signature_verifies(
    cell: CellId,
    chain: ChainId,
    d: &Declaration,
    witness_keys: &[Vec<u8>],
) -> bool {
    signed_by_any(
        witness_keys,
        &declaration_message(cell, chain, &d.fields),
        RESTORE_CONTEXT,
        &d.signature,
    )
}

/// Writes the declaration body of the module layout.
///
/// # Errors
///
/// [`Invalid::DeclarationShape`] or [`Invalid::SignatureLength`].
pub fn put_declaration(out: &mut Vec<u8>, d: &Declaration) -> Result<(), Invalid> {
    let f = &d.fields;
    f.check()?;
    if d.signature.len() != SIGNATURE_LEN {
        return Err(Invalid::SignatureLength);
    }
    out.extend_from_slice(&f.head.0.to_be_bytes());
    out.extend_from_slice(&f.head.1.0);
    out.extend_from_slice(&f.lost_to.to_be_bytes());
    out.extend_from_slice(&f.job);
    out.extend_from_slice(&f.witness_seq.to_be_bytes());
    out.extend_from_slice(&f.witness_link.0);
    out.extend_from_slice(&f.received_at.to_be_bytes());
    out.extend_from_slice(&d.signature);
    Ok(())
}

/// Reads a declaration body written by [`put_declaration`].
///
/// # Errors
///
/// [`DecodeError::Truncated`] for a short input, and
/// [`Invalid::DeclarationShape`] for fields [`put_declaration`] refuses.
pub fn read_declaration(r: &mut Reader<'_>) -> Result<Declaration, DecodeError> {
    let head = (r.be64()?, Link(r.array()?));
    let lost_to = r.be64()?;
    let job = r.array()?;
    let witness_seq = r.be64()?;
    let witness_link = Link(r.array()?);
    let received_at = r.bei64()?;
    let signature = r.take(SIGNATURE_LEN)?.to_vec();
    let fields = DeclarationFields {
        head,
        lost_to,
        job,
        witness_seq,
        witness_link,
        received_at,
    };
    fields.check()?;
    Ok(Declaration { fields, signature })
}

/// The live prepares of a witness log: receipted, not aborted, not in
/// doubt, and not cut off by an earlier declaration. The witness accepts a
/// declaration only of a live head or of genesis, and the verifier reads
/// the log with the same rule (ADR-012 record of lane
/// m10/declared-restore).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live {
    genesis: (u64, Link),
    heads: BTreeSet<(u64, Link)>,
}

impl Live {
    /// No record yet, for `cell`'s `chain`.
    #[must_use]
    pub fn new(cell: CellId, chain: ChainId) -> Live {
        Live {
            genesis: (0, genesis(cell, chain)),
            heads: BTreeSet::new(),
        }
    }

    /// The live set after every record of `log`.
    #[must_use]
    pub fn of(cell: CellId, chain: ChainId, log: &[WitnessRecord]) -> Live {
        let mut live = Live::new(cell, chain);
        for r in log {
            live.step(r);
        }
        live
    }

    /// Whether a restore may resume from `head`: genesis or a live head.
    #[must_use]
    pub fn accepts(&self, head: &(u64, Link)) -> bool {
        *head == self.genesis || self.heads.contains(head)
    }

    /// The live heads beyond row `n`, in row order.
    pub fn beyond(&self, n: u64) -> impl Iterator<Item = &(u64, Link)> {
        self.heads.iter().filter(move |(m, _)| *m > n)
    }

    /// The `lost to` of a declaration of `head` now: the highest live row
    /// beyond it, or its own row.
    #[must_use]
    pub fn lost_to(&self, head: &(u64, Link)) -> u64 {
        self.beyond(head.0).map(|(n, _)| *n).max().unwrap_or(head.0)
    }

    /// Applies one record. A declaration of a head [`Live::accepts`]
    /// cuts every live head beyond it; any other declaration changes
    /// nothing.
    pub fn step(&mut self, r: &WitnessRecord) {
        match r {
            WitnessRecord::Prepare(p) => {
                self.heads.insert((p.anchor.n, p.anchor.link));
            }
            WitnessRecord::Abort { n, link } | WitnessRecord::InDoubtAbsent { n, link } => {
                self.heads.remove(&(*n, *link));
            }
            WitnessRecord::RestoreDeclared(d) => {
                let head = d.fields.head;
                if self.accepts(&head) {
                    self.heads.retain(|(n, _)| *n <= head.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code asserts on known-good values"
    )]

    use super::*;
    use crate::anchor::{Receipt, ReceiptFields};

    const CELL: CellId = CellId([7; 16]);

    fn prepare(n: u64, l: u8) -> WitnessRecord {
        WitnessRecord::Prepare(AnchorRow {
            anchor: Anchor {
                cell: CELL,
                chain: ChainId::App,
                n,
                link: Link([l; 32]),
                at: 0,
                signature: Vec::new(),
            },
            receipt: Receipt {
                cell: CELL,
                chain: ChainId::App,
                fields: ReceiptFields {
                    n,
                    link: Link([l; 32]),
                    witness_seq: 1,
                    witness_link: Link([0; 32]),
                    received_at: 0,
                },
                signature: Vec::new(),
            },
        })
    }

    fn declared(n: u64, l: u8) -> WitnessRecord {
        WitnessRecord::RestoreDeclared(Declaration {
            fields: DeclarationFields {
                head: (n, Link([l; 32])),
                lost_to: n,
                job: [1; 16],
                witness_seq: 1,
                witness_link: Link([0; 32]),
                received_at: 0,
            },
            signature: Vec::new(),
        })
    }

    /// I-24, ADR-012 record of lane m10/declared-restore: only genesis or
    /// a live head may be declared, and the lost window is the highest
    /// live row beyond it. An aborted head is not live, and a declaration
    /// cuts the heads beyond it.
    #[test]
    fn i24_declaration_heads_are_live_and_cut_what_lies_beyond() {
        let g = (0, genesis(CELL, ChainId::App));
        let mut live = Live::of(CELL, ChainId::App, &[prepare(2, 2), prepare(5, 5)]);
        assert!(live.accepts(&g));
        assert!(live.accepts(&(2, Link([2; 32]))));
        assert!(!live.accepts(&(3, Link([2; 32]))), "never receipted");
        assert!(!live.accepts(&(2, Link([9; 32]))), "another link");
        assert_eq!(live.lost_to(&(2, Link([2; 32]))), 5);
        assert_eq!(live.lost_to(&(5, Link([5; 32]))), 5, "nothing lost");
        live.step(&WitnessRecord::Abort {
            n: 5,
            link: Link([5; 32]),
        });
        assert!(!live.accepts(&(5, Link([5; 32]))), "aborted");
        live.step(&prepare(7, 7));
        live.step(&declared(2, 2));
        assert!(!live.accepts(&(7, Link([7; 32]))), "cut by the declaration");
        assert_eq!(live.lost_to(&g), 2);
        // A declaration of a head that is not live cuts nothing.
        live.step(&prepare(4, 4));
        live.step(&declared(3, 3));
        assert!(live.accepts(&(4, Link([4; 32]))));
    }

    /// I-24, I-90, ADR-012: a declaration signature verifies under the
    /// witness key, binds every field, and never verifies as a receipt.
    #[test]
    fn i24_declaration_signature_binds_every_field() {
        let key = fstp_crypto::composite::generate().unwrap();
        let keys = vec![key.public_key().to_bytes().to_vec()];
        let fields = DeclarationFields {
            head: (4, Link([4; 32])),
            lost_to: 9,
            job: [3; 16],
            witness_seq: 12,
            witness_link: Link([5; 32]),
            received_at: 77,
        };
        let d = sign_declaration(&key, CELL, ChainId::Vault, &fields).unwrap();
        assert!(declaration_signature_verifies(
            CELL,
            ChainId::Vault,
            &d,
            &keys
        ));
        assert!(!declaration_signature_verifies(
            CELL,
            ChainId::App,
            &d,
            &keys
        ));
        let mut other = d.clone();
        other.fields.lost_to = 8;
        assert!(!declaration_signature_verifies(
            CELL,
            ChainId::Vault,
            &other,
            &keys
        ));
        let mut other = d.clone();
        other.fields.job[0] ^= 1;
        assert!(!declaration_signature_verifies(
            CELL,
            ChainId::Vault,
            &other,
            &keys
        ));
        assert_eq!(fields.lost(), Some((5, 9)));
        let none = DeclarationFields {
            lost_to: 4,
            ..fields
        };
        assert_eq!(none.lost(), None);
        let bad = DeclarationFields {
            lost_to: 3,
            ..fields
        };
        assert!(sign_declaration(&key, CELL, ChainId::Vault, &bad).is_err());
        let mut body = Vec::new();
        put_declaration(&mut body, &d).unwrap();
        assert_eq!(body.len(), DECLARATION_BODY_LEN);
        let mut r = Reader::new(&body);
        assert_eq!(read_declaration(&mut r).unwrap(), d);
        r.finish().unwrap();
    }
}

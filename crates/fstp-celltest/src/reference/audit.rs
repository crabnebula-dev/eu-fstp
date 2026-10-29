//! The reference audit chain: rows, links, anchors, the strict tail D of
//! prepare, witness receipt and commit, the witness core, the anchorer
//! decisions, the verifier, attacker mutations and custody reconciliation
//! (I-24, I-90, R-CR-03). Lane W1e owns this file.
//!
//! The reference is written from ADR-010, ADR-004 "Reconciliation" and
//! design section 7 alone, not from `fstp-audit` or `fstp-witness`. It
//! names no production item. SHA-256, Ed25519 and ML-DSA-65 come from
//! aws-lc-rs, as test oracles only (ADR-001 A6).
//!
//! # Signatures
//!
//! [`RefSig`] holds the two halves of a composite signature side by side,
//! as two byte strings. It is a structural stand-in for verifying both
//! halves (I-90). It is not the draft-ietf-lamps-pq-composite-sigs-19
//! encoding, which ADR-010 has not transcribed yet (open point 1). Each
//! half signs the message bytes as they are. No reference signature ever
//! reaches production code. [`test_encoding`] is a byte layout of the
//! reference's own, for the I-90 teeth only, and is not draft 19 either.
//!
//! # Symbolic and concrete forms
//!
//! A [`SymChain`] holds rows and ledger entries in full, but anchors,
//! receipts and witness records without signature bytes. That keeps model
//! states small. [`Keys::materialize`] signs them into a [`RefChainView`],
//! which [`verify`] reads. An attacker in the model or a property test
//! holds no signing key, so it changes a signed field only after signing,
//! through [`Forgery`].
//!
//! # Readings
//!
//! The ADR leaves these open. Each is reported by lane W1e.
//!
//! - Byte layouts are the ADR-010 proposals: genesis, row bytes and the
//!   anchor message. The receipt message is this reference's proposal,
//!   [`receipt_message`], since the ADR gives its label only.
//! - The kind 1 payload carries the row's `seq`. The entry is the ledger
//!   entry with that `seq`.
//! - The verifier reads the witness log for this cell and chain. It
//!   reports a committed row that no non-aborted receipted prepare covers
//!   as [`RefTamper::Unwitnessed`]. ADR-010 lists no variant for it.
//! - An `InDoubtAbsent` for a link that is present counts like an `Abort`
//!   for one: [`RefTamper::AbortedButPresent`].
//! - A receipted head that is present must also hold its anchor row in
//!   `audit.anchor`, since both commit in one transaction. A missing one
//!   is [`RefTamper::AnchorMismatch`].
//! - A prepare names the head it extends and the stored hashes of its
//!   rows, so the witness can recompute the link (ADR-010 open point 3).
//! - The witness checks the sender of every message, not only of a
//!   prepare. An `Abort` or an `InDoubtAbsent` from a certificate that
//!   may not write the chain is refused, as a prepare is.
//! - A cell certificate binds its cell. The witness takes a message for
//!   cell A's chain only from cell A's own certificate of the matching
//!   role (ADR-009 "Cell CA", ADR-010 "Witnesses").
//! - The witness refuses a prepare whose `(n, link)` already carries an
//!   `Abort` or an `InDoubtAbsent` record. ADR-010 allows the same `n`
//!   again only "with another link".
//! - A kind 1 row's stored hash binds the row's own columns and its
//!   entry's columns together. The verifier cannot tell which side
//!   changed, so any stored-hash mismatch on a kind 1 row is reported as
//!   [`RefTamper::StoredHashMismatch`]. That includes a changed `at` or
//!   kind column of the row itself. A kind 2 row reports
//!   [`RefTamper::Changed`]. Detection does not depend on the variant.
//! - Reconciliation counts: each `KeyOp` event covers one backend usage
//!   entry with the same request id and operation. A replayed call with a
//!   reused request id therefore raises `CustodyAnomaly`.
//! - A `KeyOp` event body is `"fstp-celltest-keyop-v1" || request_id ||
//!   op` in this reference only. Production seals its event bodies.
//! - A `KeyOp` is a kind 2 event here. ADR-004 and design section 3.3
//!   call it an event, but design section 5.1 also defines a
//!   `RecordKeyOp` ledger record. The lead settles which with Daniel.
//! - While the witness is unreachable the cell admits reads and refuses
//!   writes with [`AdmitRefusal::WitnessUnavailable`], which names the
//!   witness (ADR-010 "Witness unavailable").
//! - Restore declarations are not modelled. ADR-012 "Declared restores at
//!   the witness" and the `LostInRestore` verdict of ADR-010 are interim,
//!   pending Daniel. The witness core therefore refuses the control plane
//!   for every message it models. Once ADR-012 is confirmed, the
//!   reference gains a `RestoreDeclared` record that only the control
//!   plane may send, the `LostInRestore` verdict, and a mutation that
//!   tries to hide a deletion behind a declaration.
//!
//! Every function is total. None panics, and arithmetic is checked.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};

use crate::reference::hybrid::{OracleError, OracleMlDsa65, oracle_mldsa65_verify};

// ---------------------------------------------------------------------------
// Labels and primitives.

/// The link label (design section 7.1).
pub const LINK_LABEL: &[u8] = b"fstp-audit-v1";
/// The genesis label (ADR-010 proposal).
pub const GENESIS_LABEL: &[u8] = b"fstp-audit-genesis-v1";
/// The row bytes label (ADR-010 proposal).
pub const ROW_LABEL: &[u8] = b"fstp-audit-row-v1";
/// The anchor message label (ADR-010 proposal).
pub const ANCHOR_LABEL: &[u8] = b"fstp-anchor-v1";
/// The receipt message label (ADR-010).
pub const RECEIPT_LABEL: &[u8] = b"fstp-receipt-v1";
/// The witness chain label. Reading: ADR-010 gives the witness chain no
/// layout; this one is the reference's own.
pub const WITNESS_LABEL: &[u8] = b"fstp-witness-v1";

/// The row kind code of a ledger entry row.
pub const KIND_LEDGER: u16 = 1;
/// The row kind code of an event row.
pub const KIND_EVENT: u16 = 2;

/// A SHA-256 value.
pub type Hash = [u8; 32];

/// The 16 bytes of a cell id.
pub type CellBytes = [u8; 16];

/// SHA-256 over the concatenation of `parts`, from aws-lc-rs.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut c = Context::new(&SHA256);
    for p in parts {
        c.update(p);
    }
    let d = c.finish();
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(d.as_ref()) {
        *o = *b;
    }
    out
}

/// The two chains of a cell (ADR-010 "Chains").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefChain {
    /// The application chain, byte value 1.
    App,
    /// The vault chain, byte value 2.
    Vault,
}

impl RefChain {
    /// Both chains.
    pub const ALL: [RefChain; 2] = [RefChain::App, RefChain::Vault];

    /// The byte value of ADR-010.
    pub const fn byte(self) -> u8 {
        match self {
            RefChain::App => 1,
            RefChain::Vault => 2,
        }
    }

    /// The other chain.
    pub const fn other(self) -> RefChain {
        match self {
            RefChain::App => RefChain::Vault,
            RefChain::Vault => RefChain::App,
        }
    }
}

// ---------------------------------------------------------------------------
// Rows and links.

/// A stored ledger entry, before decryption. `body` is the sealed text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefLedgerEntry {
    /// The ledger sequence.
    pub seq: u64,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The schema version.
    pub schema: u16,
    /// The ledger key index.
    pub key_ix: u32,
    /// The sealed canonical text.
    pub body: Vec<u8>,
}

/// What a chain row records.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RefRowKind {
    /// Kind 1: a ledger entry, by sequence.
    Ledger {
        /// The ledger sequence.
        seq: u64,
    },
    /// Kind 2: an event with a sealed body.
    Event {
        /// The sealed body.
        body: Vec<u8>,
    },
}

impl RefRowKind {
    /// The kind code.
    pub const fn code(&self) -> u16 {
        match self {
            RefRowKind::Ledger { .. } => KIND_LEDGER,
            RefRowKind::Event { .. } => KIND_EVENT,
        }
    }
}

/// One stored chain row, with its stored hash and link columns.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefRow {
    /// The row number, from 1.
    pub n: u64,
    /// UTC microseconds.
    pub at: i64,
    /// What the row records.
    pub kind: RefRowKind,
    /// SHA-256 of the row bytes.
    pub stored_hash: Hash,
    /// The link.
    pub link: Hash,
}

/// `genesis = SHA-256("fstp-audit-genesis-v1" || cell || chain)`.
pub fn genesis(cell: CellBytes, chain: RefChain) -> Hash {
    sha256(&[GENESIS_LABEL, &cell, &[chain.byte()]])
}

/// `link_n = SHA-256("fstp-audit-v1" || cell || chain || be64(n) ||
/// link_{n-1} || stored_hash_n)`.
pub fn link(prev: &Hash, cell: CellBytes, chain: RefChain, n: u64, stored_hash: &Hash) -> Hash {
    sha256(&[
        LINK_LABEL,
        &cell,
        &[chain.byte()],
        &n.to_be_bytes(),
        prev,
        stored_hash,
    ])
}

/// A field the link must bind (ADR-010 "Link function"): the link
/// inputs, every column of the chain row apart from `stored_hash` and
/// `link`, and every column of the referenced ledger entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkField {
    /// The cell id.
    Cell,
    /// The chain.
    Chain,
    /// The row number.
    N,
    /// The previous link.
    Prev,
    /// The row's `at`.
    RowAt,
    /// The row kind.
    Kind,
    /// The row's ledger sequence (kind 1).
    Seq,
    /// The event body (kind 2).
    EventBody,
    /// The entry's `at` (kind 1).
    EntryAt,
    /// The entry's command id (kind 1).
    Command,
    /// The entry's schema version (kind 1).
    Schema,
    /// The entry's key index (kind 1).
    KeyIx,
    /// The entry's sealed body (kind 1).
    EntryBody,
}

impl LinkField {
    /// Every field.
    pub const ALL: [LinkField; 13] = [
        LinkField::Cell,
        LinkField::Chain,
        LinkField::N,
        LinkField::Prev,
        LinkField::RowAt,
        LinkField::Kind,
        LinkField::Seq,
        LinkField::EventBody,
        LinkField::EntryAt,
        LinkField::Command,
        LinkField::Schema,
        LinkField::KeyIx,
        LinkField::EntryBody,
    ];
}

/// Everything one link depends on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinkInput {
    /// The cell id.
    pub cell: CellBytes,
    /// The chain.
    pub chain: RefChain,
    /// The previous link.
    pub prev: Hash,
    /// The row number.
    pub n: u64,
    /// The row's `at`.
    pub at: i64,
    /// The row kind.
    pub kind: RefRowKind,
    /// The ledger entry a kind 1 row names.
    pub entry: Option<RefLedgerEntry>,
}

fn len32(bytes: &[u8]) -> Option<[u8; 4]> {
    u32::try_from(bytes.len()).ok().map(u32::to_be_bytes)
}

/// The row bytes, with `omit` replaced by a constant. `omit` is `None`
/// for the reference itself; `Some` is a teeth twin.
fn row_bytes_omitting(
    at: i64,
    kind: &RefRowKind,
    entry: Option<&RefLedgerEntry>,
    omit: Option<LinkField>,
) -> Option<Vec<u8>> {
    let keep = |f: LinkField| omit != Some(f);
    let mut out = ROW_LABEL.to_vec();
    if keep(LinkField::Kind) {
        out.extend_from_slice(&kind.code().to_be_bytes());
    }
    out.extend_from_slice(&(if keep(LinkField::RowAt) { at } else { 0 }).to_be_bytes());
    match kind {
        RefRowKind::Ledger { seq } => {
            let e = entry?;
            let seq = if keep(LinkField::Seq) { *seq } else { 0 };
            out.extend_from_slice(&seq.to_be_bytes());
            let eat = if keep(LinkField::EntryAt) { e.at } else { 0 };
            out.extend_from_slice(&eat.to_be_bytes());
            let cmd = if keep(LinkField::Command) {
                e.command
            } else {
                [0; 16]
            };
            out.extend_from_slice(&cmd);
            let schema = if keep(LinkField::Schema) { e.schema } else { 0 };
            out.extend_from_slice(&schema.to_be_bytes());
            let key_ix = if keep(LinkField::KeyIx) { e.key_ix } else { 0 };
            out.extend_from_slice(&key_ix.to_be_bytes());
            let body: &[u8] = if keep(LinkField::EntryBody) {
                &e.body
            } else {
                &[]
            };
            out.extend_from_slice(&len32(body)?);
            out.extend_from_slice(body);
        }
        RefRowKind::Event { body } => {
            let body: &[u8] = if keep(LinkField::EventBody) {
                body
            } else {
                &[]
            };
            out.extend_from_slice(&len32(body)?);
            out.extend_from_slice(body);
        }
    }
    Some(out)
}

/// The fixed row bytes of ADR-010. `None` for a kind 1 row without its
/// entry, or a body longer than `u32::MAX`.
pub fn row_bytes(at: i64, kind: &RefRowKind, entry: Option<&RefLedgerEntry>) -> Option<Vec<u8>> {
    row_bytes_omitting(at, kind, entry, None)
}

/// `stored_hash = SHA-256(row bytes)`.
pub fn stored_hash(at: i64, kind: &RefRowKind, entry: Option<&RefLedgerEntry>) -> Option<Hash> {
    row_bytes(at, kind, entry).map(|b| sha256(&[&b]))
}

impl LinkInput {
    /// The stored hash of the row.
    pub fn stored_hash(&self) -> Option<Hash> {
        stored_hash(self.at, &self.kind, self.entry.as_ref())
    }

    /// The link of the row.
    pub fn link(&self) -> Option<Hash> {
        self.link_omitting(None)
    }

    /// The link of a teeth twin that leaves `omit` out, or the reference
    /// link for `None`.
    pub fn link_omitting(&self, omit: Option<LinkField>) -> Option<Hash> {
        let keep = |f: LinkField| omit != Some(f);
        let row = row_bytes_omitting(self.at, &self.kind, self.entry.as_ref(), omit)?;
        let sh = sha256(&[&row]);
        let cell = if keep(LinkField::Cell) {
            self.cell
        } else {
            [0; 16]
        };
        let chain: &[u8] = if keep(LinkField::Chain) {
            &[self.chain.byte()][..]
        } else {
            &[]
        };
        let n = if keep(LinkField::N) { self.n } else { 0 };
        let prev = if keep(LinkField::Prev) {
            self.prev
        } else {
            [0; 32]
        };
        Some(sha256(&[
            LINK_LABEL,
            &cell,
            chain,
            &n.to_be_bytes(),
            &prev,
            &sh,
        ]))
    }

    /// Two inputs that differ only in `field`, so a link that binds the
    /// field gives them different links. `None` when the field does not
    /// apply to this row's kind.
    ///
    /// For [`LinkField::Kind`] the pair is a kind 1 row and a kind 2 row
    /// whose payload bytes are equal. Only the kind code then tells them
    /// apart, so a link that omits it collides.
    pub fn pair(&self, field: LinkField) -> Option<(LinkInput, LinkInput)> {
        let mut b = self.clone();
        match field {
            LinkField::Cell => b.cell = flip16(b.cell),
            LinkField::Chain => b.chain = b.chain.other(),
            LinkField::N => b.n = b.n.checked_add(1).unwrap_or(1),
            LinkField::Prev => b.prev = flip32(b.prev),
            LinkField::RowAt => b.at = b.at.checked_add(1).unwrap_or(0),
            LinkField::Kind => return self.kind_pair(),
            LinkField::Seq => match (&mut b.kind, b.entry.as_mut()) {
                (RefRowKind::Ledger { seq }, Some(e)) => {
                    *seq = seq.checked_add(1).unwrap_or(0);
                    e.seq = *seq;
                }
                _ => return None,
            },
            LinkField::EventBody => match &mut b.kind {
                RefRowKind::Event { body } => change_body(body),
                RefRowKind::Ledger { .. } => return None,
            },
            LinkField::EntryAt
            | LinkField::Command
            | LinkField::Schema
            | LinkField::KeyIx
            | LinkField::EntryBody => {
                let RefRowKind::Ledger { .. } = b.kind else {
                    return None;
                };
                let e = b.entry.as_mut()?;
                change_entry(e, field);
            }
        }
        Some((self.clone(), b))
    }

    /// A kind 1 row and a kind 2 row with equal payload bytes.
    fn kind_pair(&self) -> Option<(LinkInput, LinkInput)> {
        let body = match (&self.kind, self.entry.as_ref()) {
            (RefRowKind::Ledger { .. }, Some(e)) => e.body.clone(),
            (RefRowKind::Event { body }, _) => body.clone(),
            (RefRowKind::Ledger { .. }, None) => return None,
        };
        let payload_len = u64::try_from(body.len()).ok()?.checked_add(42)?;
        let top = payload_len.checked_sub(4)?;
        let seq = top.checked_shl(32)?;
        let entry = RefLedgerEntry {
            seq,
            at: self.at,
            command: [0x4B; 16],
            schema: 1,
            key_ix: 0,
            body,
        };
        let ledger = LinkInput {
            kind: RefRowKind::Ledger { seq },
            entry: Some(entry),
            ..self.clone()
        };
        let row = row_bytes(ledger.at, &ledger.kind, ledger.entry.as_ref())?;
        // The ledger payload starts after the label, the kind code and `at`.
        let payload = row.get(ROW_LABEL.len().checked_add(10)?..)?;
        let event = LinkInput {
            kind: RefRowKind::Event {
                body: payload.get(4..)?.to_vec(),
            },
            entry: None,
            ..self.clone()
        };
        Some((ledger, event))
    }
}

fn flip16(mut a: [u8; 16]) -> [u8; 16] {
    if let Some(b) = a.first_mut() {
        *b ^= 0x01;
    }
    a
}

fn flip32(mut a: [u8; 32]) -> [u8; 32] {
    if let Some(b) = a.first_mut() {
        *b ^= 0x01;
    }
    a
}

fn change_body(body: &mut Vec<u8>) {
    match body.first_mut() {
        Some(b) => *b ^= 0x01,
        None => body.push(0),
    }
}

fn change_entry(e: &mut RefLedgerEntry, field: LinkField) {
    match field {
        LinkField::EntryAt => e.at = e.at.checked_add(1).unwrap_or(0),
        LinkField::Command => e.command = flip16(e.command),
        LinkField::Schema => e.schema = e.schema.checked_add(1).unwrap_or(0),
        LinkField::KeyIx => e.key_ix = e.key_ix.checked_add(1).unwrap_or(0),
        _ => change_body(&mut e.body),
    }
}

/// The predicate of ADR-010 "The link binds every column": for every
/// field that applies to `input`, the two inputs of
/// [`LinkInput::pair`] get different links under `link_of`.
///
/// # Errors
///
/// The first field the link does not bind, as an `I-24:` message, or the
/// error `link_of` returned.
pub fn binds_every_field(
    input: &LinkInput,
    link_of: &dyn Fn(&LinkInput) -> Result<Hash, String>,
) -> Result<(), String> {
    for field in LinkField::ALL {
        let Some((a, b)) = input.pair(field) else {
            continue;
        };
        if link_of(&a)? == link_of(&b)? {
            return Err(format!(
                "I-24: the link does not bind {field:?}: {a:?} and {b:?} share a link"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signatures.

/// A reference composite public key: both halves, side by side.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RefPublicKey {
    /// The Ed25519 public key.
    pub ed25519: Vec<u8>,
    /// The ML-DSA-65 public key.
    pub mldsa: Vec<u8>,
}

impl std::fmt::Debug for RefPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefPublicKey")
            .field("ed25519", &hex8(&self.ed25519))
            .finish_non_exhaustive()
    }
}

/// A reference composite signature: both halves, side by side.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RefSig {
    /// The Ed25519 half.
    pub ed25519: Vec<u8>,
    /// The ML-DSA-65 half.
    pub mldsa: Vec<u8>,
}

impl std::fmt::Debug for RefSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefSig")
            .field("ed25519", &hex8(&self.ed25519))
            .finish_non_exhaustive()
    }
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

/// A reference composite signing key from a fixed seed.
pub struct RefSigner {
    ed: Ed25519KeyPair,
    ml: OracleMlDsa65,
    public: RefPublicKey,
}

impl std::fmt::Debug for RefSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefSigner")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl RefSigner {
    /// The signer whose two seeds are 32 copies of `seed` and of
    /// `!seed`. Test keys only.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs rejects a seed.
    pub fn from_seed(seed: u8) -> Result<RefSigner, OracleError> {
        let ed = Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .map_err(|_| OracleError("Ed25519 keygen from seed"))?;
        let ml = OracleMlDsa65::from_seed(&[!seed; 32])?;
        let public = RefPublicKey {
            ed25519: ed.public_key().as_ref().to_vec(),
            mldsa: ml.public_key(),
        };
        Ok(RefSigner { ed, ml, public })
    }

    /// The public key.
    pub fn public(&self) -> &RefPublicKey {
        &self.public
    }

    /// Both halves over `message`.
    ///
    /// # Errors
    ///
    /// Refuses when the ML-DSA-65 oracle fails.
    pub fn sign(&self, message: &[u8]) -> Result<RefSig, OracleError> {
        Ok(RefSig {
            ed25519: self.ed.sign(message).as_ref().to_vec(),
            mldsa: self.ml.sign(message)?,
        })
    }
}

/// Whether the Ed25519 half verifies.
pub fn ed25519_half_verifies(pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
    UnparsedPublicKey::new(&ED25519, &pk.ed25519)
        .verify(message, &sig.ed25519)
        .is_ok()
}

/// Whether the ML-DSA-65 half verifies.
pub fn mldsa_half_verifies(pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
    oracle_mldsa65_verify(&pk.mldsa, message, &sig.mldsa)
}

/// I-90: a composite signature verifies only when both halves verify.
pub fn composite_verifies(pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
    ed25519_half_verifies(pk, message, sig) && mldsa_half_verifies(pk, message, sig)
}

/// The I-90 teeth twin: accepts when either half verifies.
pub fn either_half_verifies(pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
    ed25519_half_verifies(pk, message, sig) || mldsa_half_verifies(pk, message, sig)
}

/// How [`verify`] checks a signature.
pub trait SigCheck {
    /// Whether `sig` over `message` verifies under `pk`.
    fn verifies(&self, pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool;
}

/// The I-90 check, uncached: both halves.
#[derive(Clone, Copy, Debug, Default)]
pub struct BothHalves;

impl SigCheck for BothHalves {
    fn verifies(&self, pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
        composite_verifies(pk, message, sig)
    }
}

/// A byte layout of the reference's own for the I-90 teeth: the ML-DSA-65
/// half, then the Ed25519 half. It is not draft 19, and production never
/// reads it.
pub mod test_encoding {
    use super::{RefPublicKey, RefSig};
    use crate::reference::hybrid::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN};

    /// The encoded signature length.
    pub const SIG_LEN: usize = MLDSA65_SIG_LEN + 64;
    /// The encoded public key length.
    pub const PK_LEN: usize = MLDSA65_PK_LEN + 32;

    /// `mldsa || ed25519`.
    pub fn encode_sig(sig: &RefSig) -> Vec<u8> {
        let mut out = sig.mldsa.clone();
        out.extend_from_slice(&sig.ed25519);
        out
    }

    /// The inverse of [`encode_sig`]. `None` on a wrong length.
    pub fn decode_sig(bytes: &[u8]) -> Option<RefSig> {
        if bytes.len() != SIG_LEN {
            return None;
        }
        let (ml, ed) = bytes.split_at(MLDSA65_SIG_LEN);
        Some(RefSig {
            ed25519: ed.to_vec(),
            mldsa: ml.to_vec(),
        })
    }

    /// `mldsa || ed25519`.
    pub fn encode_pk(pk: &RefPublicKey) -> Vec<u8> {
        let mut out = pk.mldsa.clone();
        out.extend_from_slice(&pk.ed25519);
        out
    }

    /// The inverse of [`encode_pk`]. `None` on a wrong length.
    pub fn decode_pk(bytes: &[u8]) -> Option<RefPublicKey> {
        if bytes.len() != PK_LEN {
            return None;
        }
        let (ml, ed) = bytes.split_at(MLDSA65_PK_LEN);
        Some(RefPublicKey {
            ed25519: ed.to_vec(),
            mldsa: ml.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Anchors, receipts and the witness log.

/// The signed message of an anchor (ADR-010 proposal):
/// `"fstp-anchor-v1" || cell || chain || be64(n) || link || be64(at)`.
pub fn anchor_message(cell: CellBytes, chain: RefChain, n: u64, link: &Hash, at: i64) -> Vec<u8> {
    let mut out = ANCHOR_LABEL.to_vec();
    out.extend_from_slice(&cell);
    out.push(chain.byte());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(link);
    out.extend_from_slice(&at.to_be_bytes());
    out
}

/// The signed message of a receipt. Reading: ADR-010 gives only the
/// label and the fields, so the order is this reference's proposal:
/// `"fstp-receipt-v1" || cell || chain || be64(n) || link ||
/// be64(witness_seq) || witness_link || be64(received_at)`.
pub fn receipt_message(cell: CellBytes, chain: RefChain, r: &ReceiptFields) -> Vec<u8> {
    let mut out = RECEIPT_LABEL.to_vec();
    out.extend_from_slice(&cell);
    out.push(chain.byte());
    out.extend_from_slice(&r.n.to_be_bytes());
    out.extend_from_slice(&r.link);
    out.extend_from_slice(&r.witness_seq.to_be_bytes());
    out.extend_from_slice(&r.witness_link);
    out.extend_from_slice(&r.received_at.to_be_bytes());
    out
}

/// The signed fields of an anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AnchorFields {
    /// The head row number.
    pub n: u64,
    /// The head link.
    pub link: Hash,
    /// UTC microseconds.
    pub at: i64,
}

/// The signed fields of a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptFields {
    /// The head row number.
    pub n: u64,
    /// The head link.
    pub link: Hash,
    /// The witness sequence.
    pub witness_seq: u64,
    /// The witness chain link.
    pub witness_link: Hash,
    /// UTC microseconds.
    pub received_at: i64,
}

/// A signed anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefAnchor {
    /// The cell.
    pub cell: CellBytes,
    /// The chain.
    pub chain: RefChain,
    /// The signed fields.
    pub fields: AnchorFields,
    /// The composite signature.
    pub sig: RefSig,
}

/// A signed receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefReceipt {
    /// The cell.
    pub cell: CellBytes,
    /// The chain.
    pub chain: RefChain,
    /// The signed fields.
    pub fields: ReceiptFields,
    /// The composite signature.
    pub sig: RefSig,
}

/// One row of `audit.anchor`: an anchor and its receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefAnchorRow {
    /// The anchor.
    pub anchor: RefAnchor,
    /// The receipt.
    pub receipt: RefReceipt,
}

/// One record of the witness log for one cell and chain.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "test-only views, built a few at a time"
)]
pub enum RefWitnessRecord {
    /// A receipted prepare.
    Prepare(RefAnchorRow),
    /// An abort of a prepare.
    Abort {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
    /// A prepare whose commit outcome was unknown and whose row was
    /// missing at reconnect.
    InDoubtAbsent {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
}

/// The input of [`verify`]: what the cell stores, what the witness holds
/// for this cell and chain, and the key histories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefChainView {
    /// The cell.
    pub cell: CellBytes,
    /// The chain.
    pub chain: RefChain,
    /// The stored chain rows, in stored order.
    pub rows: Vec<RefRow>,
    /// The stored ledger entries (kind 1 rows name them).
    pub ledger: Vec<RefLedgerEntry>,
    /// The rows of `audit.anchor`.
    pub anchors: Vec<RefAnchorRow>,
    /// The witness log, in witness order.
    pub witness: Vec<RefWitnessRecord>,
    /// The chain's anchor key history.
    pub anchor_keys: Vec<RefPublicKey>,
    /// The pinned witness keys.
    pub witness_keys: Vec<RefPublicKey>,
}

// ---------------------------------------------------------------------------
// The verifier.

/// A change the reference verifier found (ADR-010 "Verifier", plus
/// [`RefTamper::Unwitnessed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefTamper {
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
    /// An anchor does not match the chain at its row.
    AnchorMismatch {
        /// The row number.
        n: u64,
    },
    /// An anchor or receipt signature fails, including one half alone.
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
    /// A prepared link has no row, no abort and no in-doubt record.
    Deleted {
        /// The row number.
        n: u64,
    },
    /// An abort or in-doubt record exists for a link that is present.
    AbortedButPresent {
        /// The row number.
        n: u64,
    },
    /// Reading: a committed row that no receipted prepare covers.
    Unwitnessed {
        /// The first uncovered row number.
        n: u64,
    },
}

/// A verified chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefVerified {
    /// The number of verified rows.
    pub rows: u64,
}

fn idx(n: u64) -> Option<usize> {
    usize::try_from(n.checked_sub(1)?).ok()
}

fn key_verifies(keys: &[RefPublicKey], msg: &[u8], sig: &RefSig, check: &dyn SigCheck) -> bool {
    keys.iter().any(|k| check.verifies(k, msg, sig))
}

/// Whether an anchor row is signed and consistent for this cell and chain.
fn anchor_row_ok(view: &RefChainView, row: &RefAnchorRow, check: &dyn SigCheck) -> bool {
    let a = &row.anchor;
    let r = &row.receipt;
    let msg = anchor_message(a.cell, a.chain, a.fields.n, &a.fields.link, a.fields.at);
    let rmsg = receipt_message(r.cell, r.chain, &r.fields);
    a.cell == view.cell
        && a.chain == view.chain
        && r.cell == view.cell
        && r.chain == view.chain
        && r.fields.n == a.fields.n
        && r.fields.link == a.fields.link
        && key_verifies(&view.anchor_keys, &msg, &a.sig, check)
        && key_verifies(&view.witness_keys, &rmsg, &r.sig, check)
}

/// The reference verifier. It needs no content key. It reports the first
/// change it finds, in this order: row order, ledger coverage, stored
/// hashes and links, the anchor rows, then the witness log.
///
/// # Errors
///
/// The change found.
pub fn verify(view: &RefChainView, check: &dyn SigCheck) -> Result<RefVerified, RefTamper> {
    let have = u64::try_from(view.rows.len()).unwrap_or(u64::MAX);
    // Row order.
    for (i, row) in view.rows.iter().enumerate() {
        let expected = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        if row.n != expected {
            return Err(if view.rows.iter().any(|r| r.n == expected) {
                RefTamper::Reordered { n: expected }
            } else {
                RefTamper::Gap { n: expected }
            });
        }
    }
    // Ledger coverage: one entry per seq, one kind 1 row per entry.
    let mut named: BTreeMap<u64, u64> = BTreeMap::new();
    for row in &view.rows {
        if let RefRowKind::Ledger { seq } = row.kind {
            if !view.ledger.iter().any(|e| e.seq == seq) {
                return Err(RefTamper::RowWithoutLedger { n: row.n });
            }
            if named.insert(seq, row.n).is_some() {
                return Err(RefTamper::Changed { n: row.n });
            }
        }
    }
    for (j, e) in view.ledger.iter().enumerate() {
        let dup = view.ledger.iter().take(j).any(|x| x.seq == e.seq);
        if dup || !named.contains_key(&e.seq) {
            return Err(RefTamper::LedgerWithoutRow { seq: e.seq });
        }
    }
    // Stored hashes and links.
    let mut prev = genesis(view.cell, view.chain);
    for row in &view.rows {
        let entry = match row.kind {
            RefRowKind::Ledger { seq } => view.ledger.iter().find(|e| e.seq == seq),
            RefRowKind::Event { .. } => None,
        };
        let sh = stored_hash(row.at, &row.kind, entry);
        if sh != Some(row.stored_hash) {
            return Err(match row.kind {
                RefRowKind::Ledger { seq } => RefTamper::StoredHashMismatch { seq },
                RefRowKind::Event { .. } => RefTamper::Changed { n: row.n },
            });
        }
        let l = link(&prev, view.cell, view.chain, row.n, &row.stored_hash);
        if l != row.link {
            return Err(RefTamper::Changed { n: row.n });
        }
        prev = l;
    }
    let link_at = |n: u64| idx(n).and_then(|i| view.rows.get(i)).map(|r| r.link);
    // The anchor rows of `audit.anchor`.
    for row in &view.anchors {
        let n = row.anchor.fields.n;
        if !anchor_row_ok(view, row, check) {
            return Err(RefTamper::BadSignature { n });
        }
        if n > have {
            return Err(RefTamper::Truncated { witnessed: n, have });
        }
        if link_at(n) != Some(row.anchor.fields.link) {
            return Err(RefTamper::AnchorMismatch { n });
        }
        let receipted = view.witness.iter().any(|w| match w {
            RefWitnessRecord::Prepare(p) => {
                p.anchor.fields.n == n && p.anchor.fields.link == row.anchor.fields.link
            }
            _ => false,
        });
        if !receipted {
            return Err(RefTamper::AnchorMismatch { n });
        }
    }
    // The witness log.
    let withdrawn = |n: u64, l: &Hash| {
        view.witness.iter().any(|w| match w {
            RefWitnessRecord::Abort { n: an, link }
            | RefWitnessRecord::InDoubtAbsent { n: an, link } => *an == n && link == l,
            RefWitnessRecord::Prepare(_) => false,
        })
    };
    let mut covered: u64 = 0;
    let mut beyond: Option<u64> = None;
    for w in &view.witness {
        let RefWitnessRecord::Prepare(p) = w else {
            continue;
        };
        let n = p.anchor.fields.n;
        let l = p.anchor.fields.link;
        if !anchor_row_ok(view, p, check) {
            return Err(RefTamper::BadSignature { n });
        }
        let present = link_at(n) == Some(l);
        let out = withdrawn(n, &l);
        if present && out {
            return Err(RefTamper::AbortedButPresent { n });
        }
        if present {
            let in_store = view
                .anchors
                .iter()
                .any(|a| a.anchor.fields.n == n && a.anchor.fields.link == l);
            if !in_store {
                return Err(RefTamper::AnchorMismatch { n });
            }
            covered = covered.max(n);
        } else if !out {
            if n > have {
                beyond = Some(beyond.map_or(n, |b| b.max(n)));
            } else {
                return Err(RefTamper::Deleted { n });
            }
        }
    }
    if let Some(witnessed) = beyond {
        return Err(RefTamper::Truncated { witnessed, have });
    }
    if have > covered {
        return Err(RefTamper::Unwitnessed {
            n: covered.saturating_add(1),
        });
    }
    Ok(RefVerified { rows: have })
}

/// The view a verifier without the witness comparison sees: the witness
/// log rebuilt from the stored anchor rows alone (teeth twin of
/// "verifier skips the receipt comparison").
pub fn without_witness_comparison(view: &RefChainView) -> RefChainView {
    RefChainView {
        witness: view
            .anchors
            .iter()
            .cloned()
            .map(RefWitnessRecord::Prepare)
            .collect(),
        ..view.clone()
    }
}

/// The view a verifier that accepts an abort for a present row sees:
/// abort and in-doubt records of present links dropped (teeth twin).
pub fn without_aborts_for_present_rows(view: &RefChainView) -> RefChainView {
    let present = |n: u64, l: &Hash| {
        idx(n)
            .and_then(|i| view.rows.get(i))
            .is_some_and(|r| r.link == *l)
    };
    RefChainView {
        witness: view
            .witness
            .iter()
            .filter(|w| match w {
                RefWitnessRecord::Abort { n, link }
                | RefWitnessRecord::InDoubtAbsent { n, link } => !present(*n, link),
                RefWitnessRecord::Prepare(_) => true,
            })
            .cloned()
            .collect(),
        ..view.clone()
    }
}

// ---------------------------------------------------------------------------
// The witness core (ADR-010 "Prepare, receipt, commit").

/// Who sends a message to the witness, by client certificate. A cell
/// certificate names the cell whose CA issued it (ADR-009 "Cell CA").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefSender {
    /// A `cell-witness` certificate of `cell`.
    CellWitness {
        /// The cell whose CA issued the certificate.
        cell: CellBytes,
    },
    /// A `vault-witness` certificate of `cell`'s vault.
    VaultWitness {
        /// The cell whose CA issued the certificate.
        cell: CellBytes,
    },
    /// A control-plane CA certificate. It only sends restore declarations.
    ControlPlane,
}

impl RefSender {
    /// Every sender over the cells `own` and `other`: both cell
    /// certificates of each, and the control plane.
    pub fn all(own: CellBytes, other: CellBytes) -> [RefSender; 5] {
        [
            RefSender::CellWitness { cell: own },
            RefSender::VaultWitness { cell: own },
            RefSender::CellWitness { cell: other },
            RefSender::VaultWitness { cell: other },
            RefSender::ControlPlane,
        ]
    }

    /// The writer's certificate for `cell`'s `chain`.
    pub fn writer(cell: CellBytes, chain: RefChain) -> RefSender {
        match chain {
            RefChain::App => RefSender::CellWitness { cell },
            RefChain::Vault => RefSender::VaultWitness { cell },
        }
    }
}

/// ADR-009 and ADR-010 "Witnesses": the witness pins each cell CA. It
/// takes a `cell-witness` certificate only for the App chain of that
/// cell, and a `vault-witness` certificate only for that cell's Vault
/// chain. The control plane never sends a prepare, an abort or an
/// in-doubt record.
pub fn witness_accepts_sender(sender: RefSender, cell: CellBytes, chain: RefChain) -> bool {
    match (sender, chain) {
        (RefSender::CellWitness { cell: from }, RefChain::App)
        | (RefSender::VaultWitness { cell: from }, RefChain::Vault) => from == cell,
        _ => false,
    }
}

/// The witness's state for one cell and chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefWitnessState {
    /// The last head known committed: extended by a later prepare, or
    /// genesis.
    pub confirmed: (u64, Hash),
    /// The outstanding prepare, if any.
    pub outstanding: Option<(u64, Hash)>,
    /// The prepares withdrawn by an `Abort` or an `InDoubtAbsent`. None
    /// of them may be prepared again.
    pub withdrawn: BTreeSet<(u64, Hash)>,
    /// The witness sequence of the last record.
    pub seq: u64,
    /// The witness chain head.
    pub head: Hash,
}

impl RefWitnessState {
    /// The empty witness for `cell` and `chain`.
    pub fn genesis(cell: CellBytes, chain: RefChain) -> RefWitnessState {
        RefWitnessState {
            confirmed: (0, genesis(cell, chain)),
            outstanding: None,
            withdrawn: BTreeSet::new(),
            seq: 0,
            head: sha256(&[WITNESS_LABEL, &cell, &[chain.byte()]]),
        }
    }

    fn append(&mut self, cell: CellBytes, chain: RefChain, kind: u8, n: u64, link: &Hash) {
        self.seq = self.seq.saturating_add(1);
        self.head = sha256(&[
            WITNESS_LABEL,
            &cell,
            &[chain.byte(), kind],
            &self.seq.to_be_bytes(),
            &self.head,
            &n.to_be_bytes(),
            link,
        ]);
    }
}

/// A prepare: the head it extends, the stored hashes of its rows, and the
/// anchor (reading of ADR-010 open point 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefPrepare {
    /// The head this prepare extends.
    pub prev: (u64, Hash),
    /// The stored hashes of the rows after `prev`, in order.
    pub stored_hashes: Vec<Hash>,
    /// The anchor's signed fields.
    pub anchor: AnchorFields,
}

/// Why the witness refused a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WitnessRefusal {
    /// The sender may not write this cell's chain.
    WrongSender,
    /// Another prepare is outstanding and this one does not extend it.
    Outstanding,
    /// The prepare does not extend the last confirmed head.
    NotExtending,
    /// The rows do not recompute to the anchor's link.
    LinkMismatch,
    /// An abort or in-doubt record names no outstanding prepare.
    UnknownPrepare,
    /// The prepare's `(n, link)` was already aborted or recorded in
    /// doubt. The same `n` may come again only with another link.
    Withdrawn,
}

/// The witness core's answer to a prepare: its next state and the
/// receipt's fields.
///
/// # Errors
///
/// The refusal.
pub fn witness_prepare(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
    sender: RefSender,
    p: &RefPrepare,
    received_at: i64,
) -> Result<(RefWitnessState, ReceiptFields), WitnessRefusal> {
    if !witness_accepts_sender(sender, cell, chain) {
        return Err(WitnessRefusal::WrongSender);
    }
    let expected = st.outstanding.unwrap_or(st.confirmed);
    if p.prev != expected {
        return Err(if st.outstanding.is_some() {
            WitnessRefusal::Outstanding
        } else {
            WitnessRefusal::NotExtending
        });
    }
    let (mut n, mut l) = p.prev;
    for sh in &p.stored_hashes {
        n = n.checked_add(1).ok_or(WitnessRefusal::LinkMismatch)?;
        l = link(&l, cell, chain, n, sh);
    }
    if p.stored_hashes.is_empty() || n != p.anchor.n || l != p.anchor.link {
        return Err(WitnessRefusal::LinkMismatch);
    }
    if st.withdrawn.contains(&(n, l)) {
        return Err(WitnessRefusal::Withdrawn);
    }
    Ok(witness_record_prepare(st, cell, chain, n, &l, received_at))
}

/// The witness's record step for a prepare of `(n, link)` that passed
/// every check of [`witness_prepare`]. The outstanding prepare, if any,
/// becomes the confirmed head. Teeth mutants call it to skip a check.
pub fn witness_record_prepare(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
    n: u64,
    link: &Hash,
    received_at: i64,
) -> (RefWitnessState, ReceiptFields) {
    let mut next = st.clone();
    if let Some(o) = st.outstanding {
        next.confirmed = o;
    }
    next.outstanding = Some((n, *link));
    next.append(cell, chain, 1, n, link);
    let receipt = ReceiptFields {
        n,
        link: *link,
        witness_seq: next.seq,
        witness_link: next.head,
        received_at,
    };
    (next, receipt)
}

/// The witness core's answer to `Abort { n, link }` from `sender`.
///
/// # Errors
///
/// [`WitnessRefusal::WrongSender`] unless `sender` may write `cell`'s `chain`
/// (ADR-010 "Witnesses"), then [`WitnessRefusal::UnknownPrepare`] unless
/// `(n, link)` is outstanding.
pub fn witness_abort(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
    sender: RefSender,
    n: u64,
    link: &Hash,
) -> Result<RefWitnessState, WitnessRefusal> {
    withdraw(st, cell, chain, sender, 2, n, link)
}

/// The witness core's answer to `InDoubtAbsent { n, link }` from
/// `sender`.
///
/// # Errors
///
/// [`WitnessRefusal::WrongSender`] unless `sender` may write `cell`'s `chain`
/// (ADR-010 "Witnesses"), then [`WitnessRefusal::UnknownPrepare`] unless
/// `(n, link)` is outstanding.
pub fn witness_in_doubt_absent(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
    sender: RefSender,
    n: u64,
    link: &Hash,
) -> Result<RefWitnessState, WitnessRefusal> {
    withdraw(st, cell, chain, sender, 3, n, link)
}

fn withdraw(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
    sender: RefSender,
    kind: u8,
    n: u64,
    link: &Hash,
) -> Result<RefWitnessState, WitnessRefusal> {
    if !witness_accepts_sender(sender, cell, chain) {
        return Err(WitnessRefusal::WrongSender);
    }
    if st.outstanding != Some((n, *link)) {
        return Err(WitnessRefusal::UnknownPrepare);
    }
    let mut next = st.clone();
    next.outstanding = None;
    next.withdrawn.insert((n, *link));
    next.append(cell, chain, kind, n, link);
    Ok(next)
}

// ---------------------------------------------------------------------------
// The anchorer decisions (design section 7.2).

/// The outcome of COMMIT, as the cell sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitOutcome {
    /// COMMIT succeeded.
    Committed,
    /// The transaction failed before COMMIT was sent, or COMMIT returned
    /// an error. Nothing was committed.
    Failed,
    /// The outcome is unknown: a lost connection or a crash.
    Unknown,
}

/// What the anchorer does after a commit outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AfterCommit {
    /// Nothing more: the entry holds its receipt.
    Done,
    /// Send `Abort { n, link }` before the same `n` is prepared again.
    SendAbort,
    /// Read the chain at reconnect or restart, then resolve.
    InDoubt,
}

/// The anchorer's step after `outcome`.
pub fn after_commit(outcome: CommitOutcome) -> AfterCommit {
    match outcome {
        CommitOutcome::Committed => AfterCommit::Done,
        CommitOutcome::Failed => AfterCommit::SendAbort,
        CommitOutcome::Unknown => AfterCommit::InDoubt,
    }
}

/// How the anchorer resolves an in-doubt prepare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Row `n` holds the prepared link: it committed, and the next
    /// prepare extends it.
    Committed,
    /// The row is missing: send `InDoubtAbsent { n, link }` and raise
    /// `PossibleDeletion` to tenant admins and the auditor view.
    AbsentRaisePossibleDeletion,
}

/// The resolution of an in-doubt prepare of `prepared`, given the link
/// the chain holds at its row, if any.
pub fn resolve_in_doubt(link_at_n: Option<Hash>, prepared: &Hash) -> Resolution {
    if link_at_n == Some(*prepared) {
        Resolution::Committed
    } else {
        Resolution::AbsentRaisePossibleDeletion
    }
}

/// The anchorer commits only once it holds the receipt for its link.
pub fn may_commit(receipted: bool) -> bool {
    receipted
}

/// What a request asks of the cell, for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefOp {
    /// A request that reads only.
    Read,
    /// A request that appends to the chain.
    Write,
}

impl RefOp {
    /// Both kinds.
    pub const ALL: [RefOp; 2] = [RefOp::Read, RefOp::Write];
}

/// Why the cell refused a request at admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmitRefusal {
    /// The witness is unreachable. The refusal names it (design risk R8).
    WitnessUnavailable,
}

/// ADR-010 "Witness unavailable": without a reachable witness the cell
/// refuses writes, naming the witness, and keeps serving reads.
///
/// # Errors
///
/// [`AdmitRefusal::WitnessUnavailable`] for a write while the witness is
/// down.
pub fn admit(op: RefOp, witness_up: bool) -> Result<(), AdmitRefusal> {
    match op {
        RefOp::Read => Ok(()),
        RefOp::Write if witness_up => Ok(()),
        RefOp::Write => Err(AdmitRefusal::WitnessUnavailable),
    }
}

// ---------------------------------------------------------------------------
// Symbolic chains.

/// An anchor row without signature bytes, and the forgery an attacker
/// applied to it after signing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SymAnchorRow {
    /// The anchor's fields.
    pub anchor: AnchorFields,
    /// The receipt's fields.
    pub receipt: ReceiptFields,
    /// The attacker's change, applied after signing.
    pub forgery: Option<Forgery>,
}

/// A change to a signed anchor row. The attacker holds no key, so the
/// signature stays the genuine one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Forgery {
    /// The anchor's cell.
    AnchorCell,
    /// The anchor's chain.
    AnchorChain,
    /// The anchor's row number.
    AnchorN,
    /// The anchor's link.
    AnchorLink,
    /// The anchor's `at`.
    AnchorAt,
    /// One byte of the anchor's Ed25519 half.
    AnchorSigEd25519,
    /// One byte of the anchor's ML-DSA-65 half.
    AnchorSigMlDsa,
    /// The anchor's Ed25519 half replaced by one over another message.
    AnchorEd25519FromAnotherMessage,
    /// The anchor's ML-DSA-65 half replaced by one over another message.
    AnchorMlDsaFromAnotherMessage,
    /// The receipt's row number.
    ReceiptN,
    /// The receipt's link.
    ReceiptLink,
    /// The receipt's witness sequence.
    ReceiptSeq,
    /// The receipt's witness link.
    ReceiptWitnessLink,
    /// The receipt's `received_at`.
    ReceiptAt,
    /// One byte of the receipt's Ed25519 half.
    ReceiptSigEd25519,
    /// One byte of the receipt's ML-DSA-65 half.
    ReceiptSigMlDsa,
}

impl Forgery {
    /// Every forgery.
    pub const ALL: [Forgery; 16] = [
        Forgery::AnchorCell,
        Forgery::AnchorChain,
        Forgery::AnchorN,
        Forgery::AnchorLink,
        Forgery::AnchorAt,
        Forgery::AnchorSigEd25519,
        Forgery::AnchorSigMlDsa,
        Forgery::AnchorEd25519FromAnotherMessage,
        Forgery::AnchorMlDsaFromAnotherMessage,
        Forgery::ReceiptN,
        Forgery::ReceiptLink,
        Forgery::ReceiptSeq,
        Forgery::ReceiptWitnessLink,
        Forgery::ReceiptAt,
        Forgery::ReceiptSigEd25519,
        Forgery::ReceiptSigMlDsa,
    ];
}

/// A witness record without signature bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymWitnessRecord {
    /// A receipted prepare.
    Prepare {
        /// The anchor's fields.
        anchor: AnchorFields,
        /// The receipt's fields.
        receipt: ReceiptFields,
    },
    /// An abort.
    Abort {
        /// The row number.
        n: u64,
        /// The link.
        link: Hash,
    },
    /// An in-doubt prepare with a missing row.
    InDoubtAbsent {
        /// The row number.
        n: u64,
        /// The link.
        link: Hash,
    },
}

/// What the cell's databases hold for one chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SymStore {
    /// The chain rows.
    pub rows: Vec<RefRow>,
    /// The ledger entries.
    pub ledger: Vec<RefLedgerEntry>,
    /// The rows of `audit.anchor`.
    pub anchors: Vec<SymAnchorRow>,
}

impl SymStore {
    /// The head row number and link, or genesis.
    pub fn head(&self, cell: CellBytes, chain: RefChain) -> (u64, Hash) {
        self.rows
            .last()
            .map_or((0, genesis(cell, chain)), |r| (r.n, r.link))
    }

    /// The next ledger sequence.
    pub fn next_seq(&self) -> u64 {
        self.ledger
            .iter()
            .map(|e| e.seq)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// The link stored at row `n`.
    pub fn link_at(&self, n: u64) -> Option<Hash> {
        idx(n).and_then(|i| self.rows.get(i)).map(|r| r.link)
    }

    /// The store with every row from `first_n` on removed, with the
    /// ledger entries those rows name and the anchor rows beyond.
    pub fn truncated_from(&self, first_n: u64) -> SymStore {
        let keep = usize::try_from(first_n.saturating_sub(1)).unwrap_or(usize::MAX);
        let rows: Vec<RefRow> = self.rows.iter().take(keep).cloned().collect();
        let gone: Vec<u64> = self
            .rows
            .iter()
            .skip(keep)
            .filter_map(|r| match r.kind {
                RefRowKind::Ledger { seq } => Some(seq),
                RefRowKind::Event { .. } => None,
            })
            .collect();
        SymStore {
            rows,
            ledger: self
                .ledger
                .iter()
                .filter(|e| !gone.contains(&e.seq))
                .cloned()
                .collect(),
            anchors: self
                .anchors
                .iter()
                .filter(|a| a.anchor.n < first_n)
                .cloned()
                .collect(),
        }
    }
}

/// One append attempt: its rows, ledger entries and head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attempt {
    /// The rows.
    pub rows: Vec<RefRow>,
    /// The ledger entries.
    pub ledger: Vec<RefLedgerEntry>,
    /// The head this attempt extends.
    pub prev: (u64, Hash),
    /// The anchor's fields.
    pub anchor: AnchorFields,
}

impl Attempt {
    /// The prepare of this attempt.
    pub fn prepare(&self) -> RefPrepare {
        RefPrepare {
            prev: self.prev,
            stored_hashes: self.rows.iter().map(|r| r.stored_hash).collect(),
            anchor: self.anchor,
        }
    }

    /// The first row number.
    pub fn first_n(&self) -> u64 {
        self.prev.0.saturating_add(1)
    }
}

/// What a new row records, before it is numbered and linked.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RowSpec {
    /// A ledger entry and its kind 1 row.
    Ledger {
        /// UTC microseconds, of the entry and its row.
        at: i64,
        /// The command id.
        command: [u8; 16],
        /// The schema version.
        schema: u16,
        /// The ledger key index.
        key_ix: u32,
        /// The sealed body.
        body: Vec<u8>,
    },
    /// A kind 2 event row.
    Event {
        /// UTC microseconds.
        at: i64,
        /// The sealed body.
        body: Vec<u8>,
    },
}

/// Numbers and links `specs` after `prev`, with ledger sequences from
/// `seq`, under the reference link. `None` when the chain would overflow.
pub fn build_attempt(
    cell: CellBytes,
    chain: RefChain,
    prev: (u64, Hash),
    seq: u64,
    specs: &[RowSpec],
    at: i64,
) -> Option<Attempt> {
    let (mut n, mut l) = prev;
    let mut seq = seq;
    let mut rows = Vec::new();
    let mut ledger = Vec::new();
    for spec in specs {
        n = n.checked_add(1)?;
        let (row_at, kind, entry) = match spec {
            RowSpec::Ledger {
                at,
                command,
                schema,
                key_ix,
                body,
            } => {
                let e = RefLedgerEntry {
                    seq,
                    at: *at,
                    command: *command,
                    schema: *schema,
                    key_ix: *key_ix,
                    body: body.clone(),
                };
                let kind = RefRowKind::Ledger { seq };
                seq = seq.checked_add(1)?;
                (*at, kind, Some(e))
            }
            RowSpec::Event { at, body } => (*at, RefRowKind::Event { body: body.clone() }, None),
        };
        let sh = stored_hash(row_at, &kind, entry.as_ref())?;
        l = link(&l, cell, chain, n, &sh);
        rows.push(RefRow {
            n,
            at: row_at,
            kind,
            stored_hash: sh,
            link: l,
        });
        if let Some(e) = entry {
            ledger.push(e);
        }
    }
    if rows.is_empty() {
        return None;
    }
    Some(Attempt {
        rows,
        ledger,
        prev,
        anchor: AnchorFields { n, link: l, at },
    })
}

/// One chain of one cell, as the cell's databases, the witness and the
/// write-ahead log hold it, without signature bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SymChain {
    /// The cell.
    pub cell: CellBytes,
    /// The chain.
    pub chain: RefChain,
    /// The cell's stored rows, entries and anchor rows.
    pub store: SymStore,
    /// The witness's state for this chain.
    pub witness_state: RefWitnessState,
    /// The witness log.
    pub witness: Vec<SymWitnessRecord>,
    /// Attempts that never committed, whose rows remain in the WAL.
    pub wal: Vec<Attempt>,
}

/// Why an honest step of the reference protocol did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    /// The witness refused.
    Witness(WitnessRefusal),
    /// The chain would overflow, or an attempt had no rows.
    Build,
}

impl SymChain {
    /// The empty chain.
    pub fn genesis(cell: CellBytes, chain: RefChain) -> SymChain {
        SymChain {
            cell,
            chain,
            store: SymStore::default(),
            witness_state: RefWitnessState::genesis(cell, chain),
            witness: Vec::new(),
            wal: Vec::new(),
        }
    }

    /// The sender this chain's writer uses: its own cell's certificate.
    pub fn sender(&self) -> RefSender {
        RefSender::writer(self.cell, self.chain)
    }

    /// The next attempt over the stored head.
    pub fn attempt(&self, specs: &[RowSpec], at: i64) -> Option<Attempt> {
        build_attempt(
            self.cell,
            self.chain,
            self.store.head(self.cell, self.chain),
            self.store.next_seq(),
            specs,
            at,
        )
    }

    /// The witness records `a`'s prepare and returns its receipt.
    ///
    /// # Errors
    ///
    /// The witness's refusal.
    pub fn prepare(&mut self, a: &Attempt, at: i64) -> Result<ReceiptFields, StepError> {
        let (next, receipt) = witness_prepare(
            &self.witness_state,
            self.cell,
            self.chain,
            self.sender(),
            &a.prepare(),
            at,
        )
        .map_err(StepError::Witness)?;
        self.witness_state = next;
        self.witness.push(SymWitnessRecord::Prepare {
            anchor: a.anchor,
            receipt,
        });
        Ok(receipt)
    }

    /// Commits `a` with its receipt: rows, entries and the anchor row.
    pub fn commit(&mut self, a: &Attempt, receipt: ReceiptFields) {
        self.store.rows.extend(a.rows.iter().cloned());
        self.store.ledger.extend(a.ledger.iter().cloned());
        self.store.anchors.push(SymAnchorRow {
            anchor: a.anchor,
            receipt,
            forgery: None,
        });
    }

    /// The witness records an abort of `a`, which stays in the WAL.
    ///
    /// # Errors
    ///
    /// The witness's refusal.
    pub fn abort(&mut self, a: &Attempt) -> Result<(), StepError> {
        self.witness_state = witness_abort(
            &self.witness_state,
            self.cell,
            self.chain,
            self.sender(),
            a.anchor.n,
            &a.anchor.link,
        )
        .map_err(StepError::Witness)?;
        self.witness.push(SymWitnessRecord::Abort {
            n: a.anchor.n,
            link: a.anchor.link,
        });
        self.wal.push(a.clone());
        Ok(())
    }

    /// The witness records an in-doubt prepare of `a` with a missing row.
    ///
    /// # Errors
    ///
    /// The witness's refusal.
    pub fn in_doubt_absent(&mut self, a: &Attempt) -> Result<(), StepError> {
        self.witness_state = witness_in_doubt_absent(
            &self.witness_state,
            self.cell,
            self.chain,
            self.sender(),
            a.anchor.n,
            &a.anchor.link,
        )
        .map_err(StepError::Witness)?;
        self.witness.push(SymWitnessRecord::InDoubtAbsent {
            n: a.anchor.n,
            link: a.anchor.link,
        });
        Ok(())
    }

    /// Prepare, receipt and commit of `specs`, the honest path.
    ///
    /// # Errors
    ///
    /// A build failure or the witness's refusal.
    pub fn append(&mut self, specs: &[RowSpec], at: i64) -> Result<Attempt, StepError> {
        let a = self.attempt(specs, at).ok_or(StepError::Build)?;
        let r = self.prepare(&a, at)?;
        self.commit(&a, r);
        Ok(a)
    }

    /// A prepare of `specs` that the cell then aborts.
    ///
    /// # Errors
    ///
    /// A build failure or the witness's refusal.
    pub fn aborted(&mut self, specs: &[RowSpec], at: i64) -> Result<Attempt, StepError> {
        let a = self.attempt(specs, at).ok_or(StepError::Build)?;
        self.prepare(&a, at)?;
        self.abort(&a)?;
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Keys and materialization.

/// The signing keys of a test world, with signature caches. The caches
/// keep model states free of signature bytes and make repeated checks
/// cheap. A cached answer is the answer of [`composite_verifies`].
pub struct Keys {
    app_anchor: RefSigner,
    vault_anchor: RefSigner,
    witness: RefSigner,
    signed: RefCell<BTreeMap<(u8, Vec<u8>), RefSig>>,
    checked: RefCell<BTreeMap<Hash, bool>>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}

/// Which key signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyRole {
    /// The anchor key of a chain.
    Anchor(RefChain),
    /// The witness receipt key.
    Witness,
}

impl Keys {
    /// The fixed test keys.
    ///
    /// # Errors
    ///
    /// Refuses when an oracle rejects a seed.
    pub fn new() -> Result<Keys, OracleError> {
        Ok(Keys {
            app_anchor: RefSigner::from_seed(0xA1)?,
            vault_anchor: RefSigner::from_seed(0xB2)?,
            witness: RefSigner::from_seed(0xC3)?,
            signed: RefCell::new(BTreeMap::new()),
            checked: RefCell::new(BTreeMap::new()),
        })
    }

    /// The signer of `role`.
    pub fn signer(&self, role: KeyRole) -> &RefSigner {
        match role {
            KeyRole::Anchor(RefChain::App) => &self.app_anchor,
            KeyRole::Anchor(RefChain::Vault) => &self.vault_anchor,
            KeyRole::Witness => &self.witness,
        }
    }

    fn role_byte(role: KeyRole) -> u8 {
        match role {
            KeyRole::Anchor(c) => c.byte(),
            KeyRole::Witness => 0xFF,
        }
    }

    /// `role`'s signature over `message`, signed once and cached.
    ///
    /// # Errors
    ///
    /// Refuses when the ML-DSA-65 oracle fails.
    pub fn sign(&self, role: KeyRole, message: &[u8]) -> Result<RefSig, OracleError> {
        let key = (Keys::role_byte(role), message.to_vec());
        if let Some(s) = self.signed.borrow().get(&key) {
            return Ok(s.clone());
        }
        let s = self.signer(role).sign(message)?;
        self.signed.borrow_mut().insert(key, s.clone());
        Ok(s)
    }

    /// The signed anchor row of `row` for `cell` and `chain`, its anchor
    /// signed by `signer`'s anchor key, then forged as `row` says.
    ///
    /// # Errors
    ///
    /// Refuses when the ML-DSA-65 oracle fails.
    pub fn anchor_row(
        &self,
        cell: CellBytes,
        chain: RefChain,
        signer: RefChain,
        anchor: &AnchorFields,
        receipt: &ReceiptFields,
        forgery: Option<Forgery>,
    ) -> Result<RefAnchorRow, OracleError> {
        let amsg = anchor_message(cell, chain, anchor.n, &anchor.link, anchor.at);
        let rmsg = receipt_message(cell, chain, receipt);
        let mut row = RefAnchorRow {
            anchor: RefAnchor {
                cell,
                chain,
                fields: *anchor,
                sig: self.sign(KeyRole::Anchor(signer), &amsg)?,
            },
            receipt: RefReceipt {
                cell,
                chain,
                fields: *receipt,
                sig: self.sign(KeyRole::Witness, &rmsg)?,
            },
        };
        if let Some(f) = forgery {
            self.forge(&mut row, f, signer)?;
        }
        Ok(row)
    }

    fn forge(
        &self,
        row: &mut RefAnchorRow,
        f: Forgery,
        signer: RefChain,
    ) -> Result<(), OracleError> {
        let a = &mut row.anchor;
        let r = &mut row.receipt;
        let other = b"fstp-celltest another message";
        match f {
            Forgery::AnchorCell => a.cell = flip16(a.cell),
            Forgery::AnchorChain => a.chain = a.chain.other(),
            Forgery::AnchorN => a.fields.n = a.fields.n.saturating_add(1),
            Forgery::AnchorLink => a.fields.link = flip32(a.fields.link),
            Forgery::AnchorAt => a.fields.at = a.fields.at.wrapping_add(1),
            Forgery::AnchorSigEd25519 => change_body(&mut a.sig.ed25519),
            Forgery::AnchorSigMlDsa => change_body(&mut a.sig.mldsa),
            Forgery::AnchorEd25519FromAnotherMessage => {
                a.sig.ed25519 = self.sign(KeyRole::Anchor(signer), other)?.ed25519;
            }
            Forgery::AnchorMlDsaFromAnotherMessage => {
                a.sig.mldsa = self.sign(KeyRole::Anchor(signer), other)?.mldsa;
            }
            Forgery::ReceiptN => r.fields.n = r.fields.n.saturating_add(1),
            Forgery::ReceiptLink => r.fields.link = flip32(r.fields.link),
            Forgery::ReceiptSeq => r.fields.witness_seq = r.fields.witness_seq.wrapping_add(1),
            Forgery::ReceiptWitnessLink => r.fields.witness_link = flip32(r.fields.witness_link),
            Forgery::ReceiptAt => r.fields.received_at = r.fields.received_at.wrapping_add(1),
            Forgery::ReceiptSigEd25519 => change_body(&mut r.sig.ed25519),
            Forgery::ReceiptSigMlDsa => change_body(&mut r.sig.mldsa),
        }
        Ok(())
    }

    /// The concrete view of `sym`, every anchor signed by `chain`'s own
    /// anchor key.
    ///
    /// # Errors
    ///
    /// Refuses when the ML-DSA-65 oracle fails.
    pub fn materialize(&self, sym: &SymChain) -> Result<RefChainView, OracleError> {
        self.materialize_signed_by(sym, sym.chain)
    }

    /// The concrete view of `sym`, every anchor signed by `signer`'s
    /// anchor key. The view's key history is `sym.chain`'s own key.
    ///
    /// # Errors
    ///
    /// Refuses when the ML-DSA-65 oracle fails.
    pub fn materialize_signed_by(
        &self,
        sym: &SymChain,
        signer: RefChain,
    ) -> Result<RefChainView, OracleError> {
        let mut anchors = Vec::new();
        for a in &sym.store.anchors {
            anchors.push(self.anchor_row(
                sym.cell, sym.chain, signer, &a.anchor, &a.receipt, a.forgery,
            )?);
        }
        let mut witness = Vec::new();
        for w in &sym.witness {
            witness.push(match w {
                SymWitnessRecord::Prepare { anchor, receipt } => RefWitnessRecord::Prepare(
                    self.anchor_row(sym.cell, sym.chain, signer, anchor, receipt, None)?,
                ),
                SymWitnessRecord::Abort { n, link } => {
                    RefWitnessRecord::Abort { n: *n, link: *link }
                }
                SymWitnessRecord::InDoubtAbsent { n, link } => {
                    RefWitnessRecord::InDoubtAbsent { n: *n, link: *link }
                }
            });
        }
        Ok(RefChainView {
            cell: sym.cell,
            chain: sym.chain,
            rows: sym.store.rows.clone(),
            ledger: sym.store.ledger.clone(),
            anchors,
            witness,
            anchor_keys: vec![self.signer(KeyRole::Anchor(sym.chain)).public().clone()],
            witness_keys: vec![self.witness.public().clone()],
        })
    }
}

/// The cache key of one signature check. Every part carries its length,
/// so no byte can move between two parts, such as the two halves of a
/// signature, without changing the key (I-90).
fn check_key(pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> Hash {
    let parts: [&[u8]; 5] = [&pk.ed25519, &pk.mldsa, message, &sig.ed25519, &sig.mldsa];
    let mut c = Context::new(&SHA256);
    for p in parts {
        c.update(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        c.update(p);
    }
    let d = c.finish();
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(d.as_ref()) {
        *o = *b;
    }
    out
}

impl SigCheck for Keys {
    fn verifies(&self, pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
        let key = check_key(pk, message, sig);
        if let Some(v) = self.checked.borrow().get(&key) {
            return *v;
        }
        let v = composite_verifies(pk, message, sig);
        self.checked.borrow_mut().insert(key, v);
        v
    }
}

// ---------------------------------------------------------------------------
// Attacker mutations (design sections 14.2 and 14.4).

/// One change by an attacker who holds the cell's database owner or
/// superuser role but no key. It never touches the witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mutation {
    /// A row's `n`.
    RowN(usize),
    /// A row's `at`.
    RowAt(usize),
    /// A row's kind: an event row becomes a kind 1 row and back.
    RowKind(usize),
    /// A kind 1 row's `seq`.
    RowSeq(usize),
    /// A kind 2 row's body.
    RowBody(usize),
    /// A row's stored hash column.
    RowStoredHash(usize),
    /// A row's link column.
    RowLink(usize),
    /// A ledger entry's `seq`.
    EntrySeq(usize),
    /// A ledger entry's `at`.
    EntryAt(usize),
    /// A ledger entry's command id.
    EntryCommand(usize),
    /// A ledger entry's schema version.
    EntrySchema(usize),
    /// A ledger entry's key index.
    EntryKeyIx(usize),
    /// A ledger entry's sealed body.
    EntryBody(usize),
    /// One row deleted, nothing recomputed.
    DeleteRow(usize),
    /// One row deleted, later rows renumbered, hashes and links recomputed.
    DeleteRowRecomputed(usize),
    /// One ledger entry deleted.
    DeleteEntry(usize),
    /// A forged ledger entry with an unused `seq` inserted at position
    /// `j`, with no chain row (an injected decision record).
    InsertEntry(usize),
    /// Ledger entry `j` stored a second time, right after itself.
    DuplicateEntry(usize),
    /// A forged event row inserted, nothing recomputed.
    InsertRow(usize),
    /// A forged event row inserted, later rows renumbered and recomputed.
    InsertRowRecomputed(usize),
    /// Two neighbouring rows swapped.
    SwapRows(usize),
    /// The last `k` rows deleted with their entries, anchor rows kept.
    Truncate(usize),
    /// The last `k` rows deleted with their entries and anchor rows.
    TruncateWithAnchors(usize),
    /// A row's content changed, then every stored hash and link from it
    /// recomputed (a consistent recomputation).
    ChangeRecomputed(usize),
    /// An anchor row forged.
    Anchor(usize, Forgery),
    /// An anchor row deleted.
    DeleteAnchor(usize),
    /// An aborted attempt's rows and anchor row put back from the WAL, in
    /// place of whatever followed its head.
    ResurrectAborted(usize),
}

fn recompute_from(sym: &mut SymChain, from: usize) -> Option<()> {
    let mut prev = match from.checked_sub(1) {
        None => genesis(sym.cell, sym.chain),
        Some(p) => sym.store.rows.get(p)?.link,
    };
    let ledger = sym.store.ledger.clone();
    for (i, row) in sym.store.rows.iter_mut().enumerate().skip(from) {
        row.n = u64::try_from(i).ok()?.checked_add(1)?;
        let entry = match row.kind {
            RefRowKind::Ledger { seq } => ledger.iter().find(|e| e.seq == seq),
            RefRowKind::Event { .. } => None,
        };
        row.stored_hash = stored_hash(row.at, &row.kind, entry)?;
        row.link = link(&prev, sym.cell, sym.chain, row.n, &row.stored_hash);
        prev = row.link;
    }
    Some(())
}

fn forged_row(at: i64) -> RefRow {
    RefRow {
        n: 0,
        at,
        kind: RefRowKind::Event {
            body: b"forged".to_vec(),
        },
        stored_hash: [0x5A; 32],
        link: [0xA5; 32],
    }
}

fn change_content(sym: &mut SymChain, i: usize) -> Option<()> {
    let row = sym.store.rows.get_mut(i)?;
    match &mut row.kind {
        RefRowKind::Event { body } => change_body(body),
        RefRowKind::Ledger { seq } => {
            let seq = *seq;
            let e = sym.store.ledger.iter_mut().find(|e| e.seq == seq)?;
            change_body(&mut e.body);
        }
    }
    Some(())
}

fn truncate(sym: &mut SymChain, k: usize, anchors: bool) -> Option<()> {
    let len = sym.store.rows.len();
    let keep = len.checked_sub(k)?;
    if k == 0 {
        return None;
    }
    let first_n = u64::try_from(keep).ok()?.checked_add(1)?;
    let t = sym.store.truncated_from(first_n);
    sym.store.rows = t.rows;
    sym.store.ledger = t.ledger;
    if anchors {
        sym.store.anchors = t.anchors;
    }
    Some(())
}

/// `sym` after `m`. `None` when `m` does not apply or changes nothing.
pub fn apply(sym: &SymChain, m: Mutation) -> Option<SymChain> {
    let mut s = sym.clone();
    match m {
        Mutation::RowN(i) => {
            let r = s.store.rows.get_mut(i)?;
            r.n = r.n.wrapping_add(7);
        }
        Mutation::RowAt(i) => {
            let r = s.store.rows.get_mut(i)?;
            r.at = r.at.wrapping_add(1);
        }
        Mutation::RowKind(i) => {
            let r = s.store.rows.get_mut(i)?;
            r.kind = match &r.kind {
                RefRowKind::Event { body } => RefRowKind::Ledger {
                    seq: u64::try_from(body.len()).ok()?.wrapping_add(1_000),
                },
                RefRowKind::Ledger { seq } => RefRowKind::Event {
                    body: seq.to_be_bytes().to_vec(),
                },
            };
        }
        Mutation::RowSeq(i) => match &mut s.store.rows.get_mut(i)?.kind {
            RefRowKind::Ledger { seq } => *seq = seq.wrapping_add(1),
            RefRowKind::Event { .. } => return None,
        },
        Mutation::RowBody(i) => match &mut s.store.rows.get_mut(i)?.kind {
            RefRowKind::Event { body } => change_body(body),
            RefRowKind::Ledger { .. } => return None,
        },
        Mutation::RowStoredHash(i) => {
            let r = s.store.rows.get_mut(i)?;
            r.stored_hash = flip32(r.stored_hash);
        }
        Mutation::RowLink(i) => {
            let r = s.store.rows.get_mut(i)?;
            r.link = flip32(r.link);
        }
        Mutation::EntrySeq(j) => {
            let e = s.store.ledger.get_mut(j)?;
            e.seq = e.seq.wrapping_add(1);
        }
        Mutation::EntryAt(j) => change_entry(s.store.ledger.get_mut(j)?, LinkField::EntryAt),
        Mutation::EntryCommand(j) => change_entry(s.store.ledger.get_mut(j)?, LinkField::Command),
        Mutation::EntrySchema(j) => change_entry(s.store.ledger.get_mut(j)?, LinkField::Schema),
        Mutation::EntryKeyIx(j) => change_entry(s.store.ledger.get_mut(j)?, LinkField::KeyIx),
        Mutation::EntryBody(j) => change_entry(s.store.ledger.get_mut(j)?, LinkField::EntryBody),
        Mutation::DeleteRow(i) => {
            s.store.rows.get(i)?;
            s.store.rows.remove(i);
        }
        Mutation::DeleteRowRecomputed(i) => {
            s.store.rows.get(i)?;
            s.store.rows.remove(i);
            recompute_from(&mut s, i)?;
        }
        Mutation::DeleteEntry(j) => {
            s.store.ledger.get(j)?;
            s.store.ledger.remove(j);
        }
        Mutation::InsertEntry(j) => {
            if j > s.store.ledger.len() {
                return None;
            }
            let at = s.store.ledger.get(j).map_or(0, |e| e.at);
            let entry = RefLedgerEntry {
                seq: s.store.next_seq(),
                at,
                command: [0x66; 16],
                schema: 1,
                key_ix: 0,
                body: b"forged decision".to_vec(),
            };
            s.store.ledger.insert(j, entry);
        }
        Mutation::DuplicateEntry(j) => {
            let e = s.store.ledger.get(j)?.clone();
            s.store.ledger.insert(j.checked_add(1)?, e);
        }
        Mutation::InsertRow(i) | Mutation::InsertRowRecomputed(i) => {
            if i > s.store.rows.len() {
                return None;
            }
            let at = s.store.rows.get(i).map_or(0, |r| r.at);
            let mut row = forged_row(at);
            row.n = u64::try_from(i).ok()?.checked_add(1)?;
            s.store.rows.insert(i, row);
            if matches!(m, Mutation::InsertRowRecomputed(_)) {
                recompute_from(&mut s, i)?;
            }
        }
        Mutation::SwapRows(i) => {
            let j = i.checked_add(1)?;
            s.store.rows.get(j)?;
            s.store.rows.swap(i, j);
        }
        Mutation::Truncate(k) => truncate(&mut s, k, false)?,
        Mutation::TruncateWithAnchors(k) => truncate(&mut s, k, true)?,
        Mutation::ChangeRecomputed(i) => {
            change_content(&mut s, i)?;
            recompute_from(&mut s, i)?;
        }
        Mutation::Anchor(a, f) => {
            let row = s.store.anchors.get_mut(a)?;
            if row.forgery.is_some() {
                return None;
            }
            row.forgery = Some(f);
        }
        Mutation::DeleteAnchor(a) => {
            s.store.anchors.get(a)?;
            s.store.anchors.remove(a);
        }
        Mutation::ResurrectAborted(x) => {
            let at = s.wal.get(x)?.clone();
            let t = s.store.truncated_from(at.first_n());
            s.store = t;
            if s.store.head(s.cell, s.chain) != at.prev {
                return None;
            }
            s.store.rows.extend(at.rows.iter().cloned());
            s.store.ledger.extend(at.ledger.iter().cloned());
            let receipt = s.witness.iter().find_map(|w| match w {
                SymWitnessRecord::Prepare { anchor, receipt } if *anchor == at.anchor => {
                    Some(*receipt)
                }
                _ => None,
            })?;
            s.store.anchors.push(SymAnchorRow {
                anchor: at.anchor,
                receipt,
                forgery: None,
            });
        }
    }
    (s.store != sym.store).then_some(s)
}

/// Every mutation that could apply to a chain of `rows` rows, `entries`
/// ledger entries, `anchors` anchor rows and `wal` aborted attempts.
pub fn mutations(rows: usize, entries: usize, anchors: usize, wal: usize) -> Vec<Mutation> {
    let mut out = Vec::new();
    for i in 0..rows {
        out.extend([
            Mutation::RowN(i),
            Mutation::RowAt(i),
            Mutation::RowKind(i),
            Mutation::RowSeq(i),
            Mutation::RowBody(i),
            Mutation::RowStoredHash(i),
            Mutation::RowLink(i),
            Mutation::DeleteRow(i),
            Mutation::DeleteRowRecomputed(i),
            Mutation::SwapRows(i),
            Mutation::ChangeRecomputed(i),
        ]);
    }
    for i in 0..=rows {
        out.extend([Mutation::InsertRow(i), Mutation::InsertRowRecomputed(i)]);
    }
    for k in 1..=rows {
        out.extend([Mutation::Truncate(k), Mutation::TruncateWithAnchors(k)]);
    }
    for j in 0..entries {
        out.extend([
            Mutation::EntrySeq(j),
            Mutation::EntryAt(j),
            Mutation::EntryCommand(j),
            Mutation::EntrySchema(j),
            Mutation::EntryKeyIx(j),
            Mutation::EntryBody(j),
            Mutation::DeleteEntry(j),
            Mutation::DuplicateEntry(j),
        ]);
    }
    for j in 0..=entries {
        out.push(Mutation::InsertEntry(j));
    }
    for a in 0..anchors {
        out.push(Mutation::DeleteAnchor(a));
        for f in Forgery::ALL {
            out.push(Mutation::Anchor(a, f));
        }
    }
    for x in 0..wal {
        out.push(Mutation::ResurrectAborted(x));
    }
    out
}

// ---------------------------------------------------------------------------
// Custody reconciliation (ADR-004 "Reconciliation").

/// One custody operation with its request id: a backend usage entry, or
/// a `KeyOp` event of the chain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefKeyOp {
    /// The request id.
    pub request_id: [u8; 16],
    /// The operation name, such as `create`, `wrap`, `unwrap` or `destroy`.
    pub op: Vec<u8>,
}

/// The backend usage entries without a matching `KeyOp` event, by
/// request id and operation. Each one raises `CustodyAnomaly`.
///
/// Matching counts: each event covers one usage entry, in usage order.
/// A call replayed under a request id that already has its event is
/// therefore reported.
pub fn reconcile(usage: &[RefKeyOp], key_ops: &[RefKeyOp]) -> Vec<RefKeyOp> {
    let mut unused: BTreeMap<&RefKeyOp, usize> = BTreeMap::new();
    for k in key_ops {
        let c = unused.entry(k).or_insert(0);
        *c = c.saturating_add(1);
    }
    let mut out = Vec::new();
    for u in usage {
        match unused.get_mut(u) {
            Some(c) if *c > 0 => *c = c.saturating_sub(1),
            _ => out.push(u.clone()),
        }
    }
    out
}

/// The `KeyOp` event label of this reference.
pub const KEY_OP_LABEL: &[u8] = b"fstp-celltest-keyop-v1";

/// The body of the `KeyOp` event for `op`, in this reference's layout:
/// `"fstp-celltest-keyop-v1" || request_id || op`.
pub fn key_op_event(op: &RefKeyOp) -> Vec<u8> {
    let mut out = KEY_OP_LABEL.to_vec();
    out.extend_from_slice(&op.request_id);
    out.extend_from_slice(&op.op);
    out
}

/// The `KeyOp` event an event body holds, if it is one.
pub fn key_op_of_event(body: &[u8]) -> Option<RefKeyOp> {
    let rest = body.strip_prefix(KEY_OP_LABEL)?;
    let request_id = <[u8; 16]>::try_from(rest.get(..16)?).ok()?;
    Some(RefKeyOp {
        request_id,
        op: rest.get(16..)?.to_vec(),
    })
}

/// The `KeyOp` events of a chain's rows, in row order.
pub fn key_ops_of_rows(rows: &[RefRow]) -> Vec<RefKeyOp> {
    rows.iter()
        .filter_map(|r| match &r.kind {
            RefRowKind::Event { body } => key_op_of_event(body),
            RefRowKind::Ledger { .. } => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell() -> CellBytes {
        [0x11; 16]
    }

    /// I-24: an honest chain of both kinds verifies, and the witness
    /// recomputes every prepared link.
    #[test]
    fn i24_reference_honest_chain_verifies() {
        let keys = Keys::new().unwrap_or_else(|e| panic!("{e}"));
        for chain in RefChain::ALL {
            let mut s = SymChain::genesis(cell(), chain);
            let specs = [
                RowSpec::Ledger {
                    at: 10,
                    command: [1; 16],
                    schema: 1,
                    key_ix: 0,
                    body: vec![1, 2, 3],
                },
                RowSpec::Event {
                    at: 11,
                    body: vec![4],
                },
            ];
            s.append(&specs, 12).unwrap_or_else(|e| panic!("{e:?}"));
            s.aborted(&specs, 13).unwrap_or_else(|e| panic!("{e:?}"));
            s.append(&specs[1..], 14)
                .unwrap_or_else(|e| panic!("{e:?}"));
            let view = keys.materialize(&s).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(verify(&view, &keys), Ok(RefVerified { rows: 3 }));
            assert_eq!(verify(&view, &BothHalves), Ok(RefVerified { rows: 3 }));
        }
    }

    /// I-90: the cached check of [`Keys`] keeps the two halves apart. A
    /// signature whose boundary moved by one byte after the genuine one
    /// was cached is checked afresh and refused.
    #[test]
    fn i90_reference_signature_cache_keeps_the_halves_apart() {
        let keys = Keys::new().unwrap_or_else(|e| panic!("{e}"));
        let msg = b"fstp-celltest cache boundary";
        let genuine = keys
            .sign(KeyRole::Witness, msg)
            .unwrap_or_else(|e| panic!("{e}"));
        let pk = keys.signer(KeyRole::Witness).public().clone();
        assert!(keys.verifies(&pk, msg, &genuine));
        let mut ed25519 = genuine.ed25519.clone();
        ed25519.extend(genuine.mldsa.first().copied());
        let shifted = RefSig {
            ed25519,
            mldsa: genuine
                .mldsa
                .get(1..)
                .map(<[u8]>::to_vec)
                .unwrap_or_default(),
        };
        assert!(!composite_verifies(&pk, msg, &shifted));
        assert!(
            !keys.verifies(&pk, msg, &shifted),
            "I-90: the cache answered a shifted signature with the genuine one's verdict"
        );
    }

    /// I-24, ADR-004: each `KeyOp` event covers one usage entry, so a
    /// replayed call under a reused request id is reported.
    #[test]
    fn i24_reference_reconcile_counts_each_event_once() {
        let op = RefKeyOp {
            request_id: [7; 16],
            op: b"unwrap".to_vec(),
        };
        let usage = vec![op.clone(), op.clone()];
        assert_eq!(
            reconcile(&usage, std::slice::from_ref(&op)),
            vec![op.clone()]
        );
        assert!(reconcile(&usage, &usage).is_empty());
        assert_eq!(key_op_of_event(&key_op_event(&op)), Some(op));
    }
}

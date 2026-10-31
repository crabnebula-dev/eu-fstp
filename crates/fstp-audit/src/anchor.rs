//! Anchors and witness receipts (design section 7.2, ADR-010 "Anchors"
//! and "Receipt", R-CR-03).
//!
//! ```text
//! anchor message  = "fstp-anchor-v1" || cell || chain || be64(n) || link || be64(at)
//! receipt message = "fstp-receipt-v1" || cell || chain || be64(n) || link
//!                   || be64(witness_seq) || witness_link || be64(received_at)
//! ```
//!
//! The anchor message is the ADR-010 proposal. The receipt message order
//! is the W1e reading, since ADR-010 gives only its label and fields. Both
//! are open under ADR-010 open point 2.
//!
//! Signatures follow the ADR-010 "Composite encoding" table, which Daniel
//! accepted on 2026-10-29. Each message is signed with
//! `Composite-ML-DSA.Sign` of draft 19 under its own application context:
//! [`ANCHOR_CONTEXT`] for anchors and [`RECEIPT_CONTEXT`] for receipts.
//! Both are interim readings of lane W2g under ADR-010 open point 2. The
//! label inside the message and the context both separate the two kinds,
//! so an anchor signature never verifies as a receipt signature, and the
//! reverse. A signature checks out only when both halves verify (I-90).

use fstp_crypto::composite;

use crate::chain::{ChainId, Link};
use crate::codec::Reader;
use crate::{
    AuditError, CellId, CompositeSigningKey, DecodeError, Invalid, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

/// The anchor message label (ADR-010 proposal).
pub const ANCHOR_LABEL: &[u8] = b"fstp-anchor-v1";
/// The receipt message label (ADR-010).
pub const RECEIPT_LABEL: &[u8] = b"fstp-receipt-v1";
/// The draft 19 application context `ctx` of every anchor signature.
/// Interim reading of lane W2g, recorded in ADR-010 (row "Application
/// context of platform messages", open point 2): the anchor label.
pub const ANCHOR_CONTEXT: &[u8] = b"fstp-anchor-v1";
/// The draft 19 application context `ctx` of every receipt signature.
/// Interim reading of lane W2g, as [`ANCHOR_CONTEXT`]: the receipt label.
pub const RECEIPT_CONTEXT: &[u8] = b"fstp-receipt-v1";
/// The anchor message length: 14 + 16 + 1 + 8 + 32 + 8.
pub const ANCHOR_MESSAGE_LEN: usize = 79;
/// The receipt message length: 15 + 16 + 1 + 8 + 32 + 8 + 32 + 8.
pub const RECEIPT_MESSAGE_LEN: usize = 120;
/// The format version of an encoded anchor.
pub const ANCHOR_FORMAT: u8 = 1;
/// The format version of an encoded receipt.
pub const RECEIPT_FORMAT: u8 = 1;
/// The length that [`put_anchor`] writes: cell (16), chain (1), n (8),
/// link (32), at (8) and the signature.
pub const ANCHOR_BODY_LEN: usize = 16 + 1 + 8 + 32 + 8 + SIGNATURE_LEN;
/// The length of an encoded anchor: the version byte, then
/// [`ANCHOR_BODY_LEN`].
pub const ANCHOR_ENCODED_LEN: usize = 1 + ANCHOR_BODY_LEN;
/// The length of an encoded receipt: version (1), cell (16), chain (1),
/// n (8), link (32), witness_seq (8), witness_link (32), received_at (8)
/// and the signature.
pub const RECEIPT_ENCODED_LEN: usize = 1 + 16 + 1 + 8 + 32 + 8 + 32 + 8 + SIGNATURE_LEN;

/// A signed statement of a chain head, sent to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The row number of the head, from 1.
    pub n: u64,
    /// The head link.
    pub link: Link,
    /// UTC microseconds.
    pub at: i64,
    /// The composite signature bytes, [`SIGNATURE_LEN`] long.
    pub signature: Vec<u8>,
}

impl Anchor {
    /// The signed message of this anchor.
    pub fn message(&self) -> Vec<u8> {
        anchor_message(self.cell, self.chain, self.n, &self.link, self.at)
    }
}

/// The signed fields of a receipt, other than its cell and chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptFields {
    /// The head row number.
    pub n: u64,
    /// The head link.
    pub link: Link,
    /// The witness sequence, from 1.
    pub witness_seq: u64,
    /// The witness chain link after this prepare.
    pub witness_link: Link,
    /// UTC microseconds at the witness.
    pub received_at: i64,
}

/// The witness's receipt for an anchor (ADR-010 "Receipt").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The signed fields.
    pub fields: ReceiptFields,
    /// The witness's composite signature bytes, [`SIGNATURE_LEN`] long.
    pub signature: Vec<u8>,
}

impl Receipt {
    /// The signed message of this receipt.
    pub fn message(&self) -> Vec<u8> {
        receipt_message(self.cell, self.chain, &self.fields)
    }
}

/// One row of `audit.anchor`: an anchor and its receipt, committed in the
/// append transaction (design section 5.3 step 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRow {
    /// The anchor.
    pub anchor: Anchor,
    /// Its receipt.
    pub receipt: Receipt,
}

/// `"fstp-anchor-v1" || cell || chain || be64(n) || link || be64(at)`.
pub fn anchor_message(cell: CellId, chain: ChainId, n: u64, link: &Link, at: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANCHOR_MESSAGE_LEN);
    out.extend_from_slice(ANCHOR_LABEL);
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&link.0);
    out.extend_from_slice(&at.to_be_bytes());
    out
}

/// `"fstp-receipt-v1" || cell || chain || be64(n) || link ||
/// be64(witness_seq) || witness_link || be64(received_at)`.
pub fn receipt_message(cell: CellId, chain: ChainId, r: &ReceiptFields) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIPT_MESSAGE_LEN);
    out.extend_from_slice(RECEIPT_LABEL);
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
    out.extend_from_slice(&r.n.to_be_bytes());
    out.extend_from_slice(&r.link.0);
    out.extend_from_slice(&r.witness_seq.to_be_bytes());
    out.extend_from_slice(&r.witness_link.0);
    out.extend_from_slice(&r.received_at.to_be_bytes());
    out
}

/// Signs the anchor of `cell`'s `chain` at head `(n, link)` at `at` with
/// the chain's composite `Anchor` key (R-CR-03, ADR-010 "Anchors").
///
/// The signature is `Composite-ML-DSA.Sign` of draft 19 over
/// [`anchor_message`] under [`ANCHOR_CONTEXT`], through
/// `fstp_crypto::composite`. Both halves sign. Custody of `key` stays with
/// the caller (lanes W2f and W3a).
///
/// # Errors
///
/// [`Invalid::RowNumberZero`] when `n` is 0, since rows start at 1. Then
/// [`AuditError::Signing`] when the composite signer gives no signature.
pub fn sign_anchor(
    key: &CompositeSigningKey,
    cell: CellId,
    chain: ChainId,
    n: u64,
    link: &Link,
    at: i64,
) -> Result<Anchor, AuditError> {
    if n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    let message = anchor_message(cell, chain, n, link, at);
    let signature = key
        .sign_with_context(&message, ANCHOR_CONTEXT)
        .map_err(AuditError::Signing)?;
    Ok(Anchor {
        cell,
        chain,
        n,
        link: *link,
        at,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Whether `sig` is a composite signature over `message` under the
/// context `ctx` by one key of `keys` (I-90: both halves verify). A
/// signature or key of another length never verifies, and nothing
/// panics on one.
fn signed_by_any(keys: &[Vec<u8>], message: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    sig.len() == SIGNATURE_LEN
        && keys
            .iter()
            .filter(|k| k.len() == PUBLIC_KEY_LEN)
            .any(|k| composite::verify_with_context(k, message, ctx, sig).is_ok())
}

/// Whether the anchor's signature verifies over its [`anchor_message`]
/// under [`ANCHOR_CONTEXT`] and one key of `anchor_keys`, the chain's
/// anchor key history (ADR-010 "Keys"). Old keys stay in the history, so
/// any of them may have signed. Both halves must verify (I-90).
pub fn anchor_signature_verifies(a: &Anchor, anchor_keys: &[Vec<u8>]) -> bool {
    signed_by_any(anchor_keys, &a.message(), ANCHOR_CONTEXT, &a.signature)
}

/// Whether the receipt's signature verifies over its [`receipt_message`]
/// under [`RECEIPT_CONTEXT`] and one key of `witness_keys`, the witness
/// keys the cell pins (ADR-010 "Keys"). Both halves must verify (I-90).
pub fn receipt_signature_verifies(rc: &Receipt, witness_keys: &[Vec<u8>]) -> bool {
    signed_by_any(witness_keys, &rc.message(), RECEIPT_CONTEXT, &rc.signature)
}

fn chain_of(b: u8) -> Result<ChainId, DecodeError> {
    ChainId::from_byte(b).ok_or(DecodeError::UnknownTag(u16::from(b)))
}

fn check_signature(sig: &[u8]) -> Result<(), Invalid> {
    if sig.len() == SIGNATURE_LEN {
        Ok(())
    } else {
        Err(Invalid::SignatureLength)
    }
}

/// Writes the anchor fields and signature without the version byte, for
/// layouts that embed an anchor, such as the witness prepare.
///
/// # Errors
///
/// [`Invalid::RowNumberZero`] or [`Invalid::SignatureLength`].
pub fn put_anchor(out: &mut Vec<u8>, a: &Anchor) -> Result<(), Invalid> {
    if a.n == 0 {
        return Err(Invalid::RowNumberZero);
    }
    check_signature(&a.signature)?;
    out.extend_from_slice(&a.cell.0);
    out.push(a.chain.byte());
    out.extend_from_slice(&a.n.to_be_bytes());
    out.extend_from_slice(&a.link.0);
    out.extend_from_slice(&a.at.to_be_bytes());
    out.extend_from_slice(&a.signature);
    Ok(())
}

/// Reads what [`put_anchor`] wrote.
///
/// # Errors
///
/// [`DecodeError`] when the bytes are not an anchor.
pub fn read_anchor(r: &mut Reader<'_>) -> Result<Anchor, DecodeError> {
    let cell = CellId(r.array()?);
    let chain = chain_of(r.u8()?)?;
    let n = r.be64()?;
    if n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    let link = Link(r.array()?);
    let at = r.bei64()?;
    let signature = r.take(SIGNATURE_LEN)?.to_vec();
    Ok(Anchor {
        cell,
        chain,
        n,
        link,
        at,
        signature,
    })
}

/// Encodes an anchor:
///
/// ```text
/// version (1) || cell (16) || chain (1) || be64(n) || link (32) || be64(at)
///   || signature (SIGNATURE_LEN)
/// ```
///
/// # Errors
///
/// [`Invalid::RowNumberZero`] or [`Invalid::SignatureLength`].
pub fn encode_anchor(a: &Anchor) -> Result<Vec<u8>, AuditError> {
    let mut out = vec![ANCHOR_FORMAT];
    put_anchor(&mut out, a)?;
    Ok(out)
}

/// Decodes an anchor. One spelling: the input is exactly
/// [`encode_anchor`] of the result. Fuzzed (`anchor_decode`).
///
/// # Errors
///
/// [`AuditError::Decode`] for any other input.
pub fn decode_anchor(bytes: &[u8]) -> Result<Anchor, AuditError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != ANCHOR_FORMAT {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let a = read_anchor(&mut r)?;
    r.finish()?;
    Ok(a)
}

/// Encodes a receipt:
///
/// ```text
/// version (1) || cell (16) || chain (1) || be64(n) || link (32)
///   || be64(witness_seq) || witness_link (32) || be64(received_at)
///   || signature (SIGNATURE_LEN)
/// ```
///
/// # Errors
///
/// [`Invalid::RowNumberZero`], [`Invalid::WitnessSeqZero`] or
/// [`Invalid::SignatureLength`].
pub fn encode_receipt(rc: &Receipt) -> Result<Vec<u8>, AuditError> {
    let f = &rc.fields;
    if f.n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    if f.witness_seq == 0 {
        return Err(Invalid::WitnessSeqZero.into());
    }
    check_signature(&rc.signature)?;
    let mut out = vec![RECEIPT_FORMAT];
    out.extend_from_slice(&rc.cell.0);
    out.push(rc.chain.byte());
    out.extend_from_slice(&f.n.to_be_bytes());
    out.extend_from_slice(&f.link.0);
    out.extend_from_slice(&f.witness_seq.to_be_bytes());
    out.extend_from_slice(&f.witness_link.0);
    out.extend_from_slice(&f.received_at.to_be_bytes());
    out.extend_from_slice(&rc.signature);
    Ok(out)
}

/// Decodes a receipt. One spelling: the input is exactly
/// [`encode_receipt`] of the result. Fuzzed (`receipt_decode`).
///
/// # Errors
///
/// [`AuditError::Decode`] for any other input.
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, AuditError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != RECEIPT_FORMAT {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let cell = CellId(r.array()?);
    let chain = chain_of(r.u8()?)?;
    let n = r.be64()?;
    if n == 0 {
        return Err(DecodeError::Invalid(Invalid::RowNumberZero).into());
    }
    let link = Link(r.array()?);
    let witness_seq = r.be64()?;
    if witness_seq == 0 {
        return Err(DecodeError::Invalid(Invalid::WitnessSeqZero).into());
    }
    let witness_link = Link(r.array()?);
    let received_at = r.bei64()?;
    let signature = r.take(SIGNATURE_LEN)?.to_vec();
    r.finish()?;
    Ok(Receipt {
        cell,
        chain,
        fields: ReceiptFields {
            n,
            link,
            witness_seq,
            witness_link,
            received_at,
        },
        signature,
    })
}

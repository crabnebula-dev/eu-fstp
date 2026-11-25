//! Messages to the witness: prepare, abort and in-doubt (design section
//! 15, `witness_message_decode`).
//!
//! ```text
//! message  = version (1) || tag (1) || body
//! prepare  : tag 1 || be64(prev_n) || prev_link (32) || be32(count)
//!            || count stored hashes (32 each) || anchor
//! abort    : tag 2 || cell (16) || chain (1) || be64(n) || link (32)
//! in doubt : tag 3 || cell (16) || chain (1) || be64(n) || link (32)
//! anchor   = cell (16) || chain (1) || be64(n) || link (32) || be64(at)
//!            || signature (SIGNATURE_LEN)
//! ```
//!
//! A prepare has one to `MAX_PREPARE_ROWS` rows, and its anchor `n` is
//! `prev_n` plus the row count. A withdrawal names a row from 1. Each
//! value has one spelling. The design fixes no layout, so this one is
//! W2g's, open with ADR-010 open point 2.

use fstp_audit::anchor::{ANCHOR_BODY_LEN, put_anchor, read_anchor};
use fstp_audit::codec::Reader;
use fstp_audit::witness::{MAX_PREPARE_ROWS, Prepare};
use fstp_audit::{CellId, ChainId, DecodeError, Invalid, Link};

use crate::WitnessError;

/// The format version of a witness message.
pub const MESSAGE_FORMAT: u8 = 1;
/// The tag of a prepare.
pub const TAG_PREPARE: u8 = 1;
/// The tag of an abort.
pub const TAG_ABORT: u8 = 2;
/// The tag of an in-doubt record.
pub const TAG_IN_DOUBT: u8 = 3;
/// The longest encoded witness message: a prepare of
/// [`MAX_PREPARE_ROWS`] rows. Version and tag (2), the previous head
/// (8 + 32), the row count (4), the stored hashes (32 each) and the
/// anchor. A withdrawal is shorter.
pub const MAX_MESSAGE_LEN: usize = 2 + 8 + 32 + 4 + MAX_PREPARE_ROWS * 32 + ANCHOR_BODY_LEN;

/// A message to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessMessage {
    /// Prepare an anchor and ask for its receipt.
    Prepare(Prepare),
    /// Abort the outstanding prepare, whose commit failed.
    Abort {
        /// The cell.
        cell: CellId,
        /// The chain.
        chain: ChainId,
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
    /// The outstanding prepare's commit outcome was unknown, and its row
    /// was missing at reconnect.
    InDoubtAbsent {
        /// The cell.
        cell: CellId,
        /// The chain.
        chain: ChainId,
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Link,
    },
}

fn put_withdrawal(out: &mut Vec<u8>, tag: u8, cell: CellId, chain: ChainId, n: u64, link: &Link) {
    out.push(tag);
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&link.0);
}

/// Encodes a message.
///
/// # Errors
///
/// [`WitnessError::Invalid`] for a prepare of the wrong shape, a
/// withdrawal of row 0, or an anchor the `fstp-audit` encoder refuses.
pub fn encode_witness_message(m: &WitnessMessage) -> Result<Vec<u8>, WitnessError> {
    let mut out = vec![MESSAGE_FORMAT];
    match m {
        WitnessMessage::Prepare(p) => {
            p.check_shape()?;
            let count = u32::try_from(p.stored_hashes.len()).map_err(|_| Invalid::PrepareShape)?;
            out.push(TAG_PREPARE);
            out.extend_from_slice(&p.prev.0.to_be_bytes());
            out.extend_from_slice(&p.prev.1.0);
            out.extend_from_slice(&count.to_be_bytes());
            for sh in &p.stored_hashes {
                out.extend_from_slice(sh);
            }
            put_anchor(&mut out, &p.anchor)?;
        }
        WitnessMessage::Abort {
            cell,
            chain,
            n,
            link,
        } => {
            if *n == 0 {
                return Err(Invalid::RowNumberZero.into());
            }
            put_withdrawal(&mut out, TAG_ABORT, *cell, *chain, *n, link);
        }
        WitnessMessage::InDoubtAbsent {
            cell,
            chain,
            n,
            link,
        } => {
            if *n == 0 {
                return Err(Invalid::RowNumberZero.into());
            }
            put_withdrawal(&mut out, TAG_IN_DOUBT, *cell, *chain, *n, link);
        }
    }
    Ok(out)
}

fn read_withdrawal(r: &mut Reader<'_>) -> Result<(CellId, ChainId, u64, Link), DecodeError> {
    let cell = CellId(r.array()?);
    let b = r.u8()?;
    let chain = ChainId::from_byte(b).ok_or(DecodeError::UnknownTag(u16::from(b)))?;
    let n = r.be64()?;
    if n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    let link = Link(r.array()?);
    Ok((cell, chain, n, link))
}

/// Decodes a message. One spelling: the input is exactly
/// [`encode_witness_message`] of the result. Fuzzed
/// (`witness_message_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] or [`WitnessError::Invalid`] for any other
/// input.
pub fn decode_witness_message(bytes: &[u8]) -> Result<WitnessMessage, WitnessError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != MESSAGE_FORMAT {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let m = match r.u8()? {
        TAG_PREPARE => {
            let prev = (r.be64()?, Link(r.array()?));
            let count = usize::try_from(r.be32()?).map_err(|_| DecodeError::TooLong)?;
            if count == 0 || count > MAX_PREPARE_ROWS {
                return Err(Invalid::PrepareShape.into());
            }
            // Bounded allocation: the hashes must fit in what is left.
            if count
                .checked_mul(32)
                .is_none_or(|need| need > r.remaining())
            {
                return Err(DecodeError::Truncated.into());
            }
            let mut stored_hashes = Vec::with_capacity(count);
            for _ in 0..count {
                stored_hashes.push(r.array::<32>()?);
            }
            let anchor = read_anchor(&mut r)?;
            let p = Prepare {
                prev,
                stored_hashes,
                anchor,
            };
            p.check_shape()?;
            WitnessMessage::Prepare(p)
        }
        TAG_ABORT => {
            let (cell, chain, n, link) = read_withdrawal(&mut r)?;
            WitnessMessage::Abort {
                cell,
                chain,
                n,
                link,
            }
        }
        TAG_IN_DOUBT => {
            let (cell, chain, n, link) = read_withdrawal(&mut r)?;
            WitnessMessage::InDoubtAbsent {
                cell,
                chain,
                n,
                link,
            }
        }
        other => return Err(DecodeError::UnknownTag(u16::from(other)).into()),
    };
    r.finish()?;
    Ok(m)
}

// ---------------------------------------------------------------------------
// Restore declarations (ADR-012 record of lane m10/declared-restore).

/// The tag of a restore declaration record. It is not a [`WitnessMessage`]:
/// no connection carries one, so [`decode_witness_message`] refuses it.
/// Only the root-only console command writes one (`crate::declare`).
pub const TAG_RESTORE_DECLARED: u8 = 4;

/// The length of a declaration record: version and tag (2), the cell and
/// chain (17) and the declaration body.
pub const DECLARATION_RECORD_LEN: usize = 2 + 16 + 1 + fstp_audit::witness::DECLARATION_BODY_LEN;

/// The record of a declared restore of `cell`'s `chain`, as a chain file
/// holds it: `1 || 4 || cell || chain || declaration body`.
///
/// # Errors
///
/// [`WitnessError::Invalid`] for a declaration that `fstp-audit` refuses
/// to encode.
pub fn encode_declaration_record(
    cell: CellId,
    chain: ChainId,
    d: &fstp_audit::witness::Declaration,
) -> Result<Vec<u8>, WitnessError> {
    let mut out = Vec::with_capacity(DECLARATION_RECORD_LEN);
    out.push(MESSAGE_FORMAT);
    out.push(TAG_RESTORE_DECLARED);
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
    fstp_audit::witness::put_declaration(&mut out, d)?;
    Ok(out)
}

/// Decodes a declaration record. One spelling: the input is exactly
/// [`encode_declaration_record`] of the result. Fuzzed
/// (`declaration_record_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] or [`WitnessError::Invalid`] for any other
/// input.
pub fn decode_declaration_record(
    bytes: &[u8],
) -> Result<(CellId, ChainId, fstp_audit::witness::Declaration), WitnessError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != MESSAGE_FORMAT {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let tag = r.u8()?;
    if tag != TAG_RESTORE_DECLARED {
        return Err(DecodeError::UnknownTag(u16::from(tag)).into());
    }
    let cell = CellId(r.array()?);
    let b = r.u8()?;
    let chain = ChainId::from_byte(b).ok_or(DecodeError::UnknownTag(u16::from(b)))?;
    let d = fstp_audit::witness::read_declaration(&mut r)?;
    r.finish()?;
    Ok((cell, chain, d))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code asserts on known-good values"
    )]

    use fstp_audit::witness::{Declaration, DeclarationFields};

    use super::*;
    use crate::wire::{WireReply, WireRequest, decode_reply, decode_request, encode_reply};

    fn declaration() -> Declaration {
        Declaration {
            fields: DeclarationFields {
                head: (3, Link([3; 32])),
                lost_to: 7,
                job: [9; 16],
                witness_seq: 11,
                witness_link: Link([5; 32]),
                received_at: -4,
            },
            signature: vec![0xA5; fstp_audit::SIGNATURE_LEN],
            statement: None,
        }
    }

    /// TH-26, I-24, ADR-012 record of lane m10/declared-restore: the
    /// declaration record round trips with one spelling, refuses every
    /// cut and trailing bytes, and is never a witness message, so no
    /// connection can carry one.
    #[test]
    fn i24_declaration_record_has_one_spelling_and_never_travels() {
        let cell = CellId([2; 16]);
        let d = declaration();
        let bytes = encode_declaration_record(cell, ChainId::Vault, &d).unwrap();
        assert_eq!(bytes.len(), DECLARATION_RECORD_LEN);
        assert_eq!(
            decode_declaration_record(&bytes).unwrap(),
            (cell, ChainId::Vault, d.clone())
        );
        for cut in 0..bytes.len() {
            assert!(
                decode_declaration_record(&bytes[..cut]).is_err(),
                "cut {cut}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_declaration_record(&longer).is_err());
        assert!(decode_witness_message(&bytes).is_err());
        let mut short = d.clone();
        short.fields.lost_to = 2;
        assert!(encode_declaration_record(cell, ChainId::App, &short).is_err());
        let mut raw = bytes;
        raw[19..27].copy_from_slice(&9u64.to_be_bytes());
        assert!(decode_declaration_record(&raw).is_err(), "lost before head");
    }

    /// TH-26, ADR-012: the `Declarations` request and reply, and a log
    /// page that holds a declaration, round trip.
    #[test]
    fn i24_declaration_wire_forms_round_trip() {
        let cell = CellId([6; 16]);
        let req = WireRequest::Declarations { cell };
        assert_eq!(
            decode_request(&crate::wire::encode_request(&req).unwrap()).unwrap(),
            req
        );
        let rep = WireReply::Declarations(vec![
            (ChainId::App, declaration()),
            (ChainId::Vault, declaration()),
        ]);
        assert_eq!(decode_reply(&encode_reply(&rep).unwrap()).unwrap(), rep);
        let page = WireReply::Log(crate::wire::LogPage {
            records: vec![fstp_audit::WitnessRecord::RestoreDeclared(declaration())],
            more: false,
        });
        assert_eq!(decode_reply(&encode_reply(&page).unwrap()).unwrap(), page);
        let empty = WireReply::Declarations(Vec::new());
        assert_eq!(decode_reply(&encode_reply(&empty).unwrap()).unwrap(), empty);
    }
}

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

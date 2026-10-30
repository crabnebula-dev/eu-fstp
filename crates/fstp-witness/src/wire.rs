//! The witness connection protocol: framed requests and replies over the
//! mutual TLS connection of a cell or a vault (ADR-010 "Prepare, receipt,
//! commit", "Start-up", design section 7.2). Lane int5.
//!
//! ADR-010 fixes the messages but no transport framing. This layout is
//! this lane's reading, reported to Daniel and the lead:
//!
//! ```text
//! frame    = be32(len) || payload               len <= MAX_FRAME
//! request  = version (1) || tag (1) || body
//!   tag 1  : a witness message (crate::message)
//!   tag 2  : outstanding  cell (16) || chain (1)
//!   tag 3  : log          cell (16) || chain (1)          the first page
//!   tag 4  : log after    cell (16) || chain (1) || be64(after)
//!                         the page after record `after`, after >= 1
//! reply    = version (1) || tag (1) || body
//!   tag 1  : receipt      fstp_audit::anchor::encode_receipt
//!   tag 2  : recorded
//!   tag 3  : refused
//!   tag 4  : unknown prepare
//!   tag 5  : no outstanding prepare
//!   tag 6  : outstanding  be64(n) || link (32)
//!   tag 7  : log page     be32(count) || more (1) || record*
//!                         more is 0 or 1; a page with more is not empty
//! record   = 1 || encode_anchor || encode_receipt
//!          | 2 || be64(n) || link (32)              an abort
//!          | 3 || be64(n) || link (32)              an in-doubt record
//! ```
//!
//! Each value has one spelling. A log page holds at most
//! [`MAX_LOG_RECORDS`] records, so every frame stays under [`MAX_FRAME`].
//! A longer log takes several pages. The client asks for the page after
//! the records it holds until a page says no more follow. The log only
//! grows at its end, so the pages join into the log as it stood at the
//! last one. The decoders are
//! fuzzed (`witness_wire_decode`).

use fstp_audit::anchor::{
    ANCHOR_ENCODED_LEN, AnchorRow, RECEIPT_ENCODED_LEN, Receipt, decode_anchor, decode_receipt,
    encode_anchor, encode_receipt,
};
use fstp_audit::codec::Reader;
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{AuditError, CellId, ChainId, DecodeError, Invalid, Link};
use fstp_rt::{AsyncRead, AsyncWrite, IoExt};

use crate::WitnessError;
use crate::message::{
    MAX_MESSAGE_LEN, WitnessMessage, decode_witness_message, encode_witness_message,
};

/// The format version of a request or a reply.
pub const WIRE_VERSION: u8 = 1;

/// The most records one log page holds. A longer witness log takes
/// several pages ([`WireRequest::LogAfter`]).
pub const MAX_LOG_RECORDS: usize = 4096;

/// The longest record of a log reply.
const MAX_LOG_RECORD: usize = 1 + ANCHOR_ENCODED_LEN + RECEIPT_ENCODED_LEN;

/// The longest payload of a frame: a log page of [`MAX_LOG_RECORDS`]
/// records, or a request with the longest witness message.
pub const MAX_FRAME: usize = {
    let log = 2 + 4 + 1 + MAX_LOG_RECORDS * MAX_LOG_RECORD;
    let request = 2 + MAX_MESSAGE_LEN;
    if log > request { log } else { request }
};

/// A request to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireRequest {
    /// A prepare, an abort or an in-doubt record.
    Message(WitnessMessage),
    /// The outstanding prepare of a chain.
    Outstanding {
        /// The cell.
        cell: CellId,
        /// The chain.
        chain: ChainId,
    },
    /// The first page of the witness log of a chain.
    Log {
        /// The cell.
        cell: CellId,
        /// The chain.
        chain: ChainId,
    },
    /// The page of the witness log of a chain that follows its first
    /// `after` records. `after` is at least 1: the first page is
    /// [`WireRequest::Log`], so each request has one spelling.
    LogAfter {
        /// The cell.
        cell: CellId,
        /// The chain.
        chain: ChainId,
        /// How many records the client holds.
        after: u64,
    },
}

/// One page of a witness log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogPage {
    /// At most [`MAX_LOG_RECORDS`] records, in witness order.
    pub records: Vec<WitnessRecord>,
    /// Whether more records follow this page. A page with more is never
    /// empty, so a client that pages always advances.
    pub more: bool,
}

/// The witness's reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireReply {
    /// The receipt of a prepare.
    Receipt(Receipt),
    /// An abort or an in-doubt record was recorded.
    Recorded,
    /// The witness refused the message, which changed nothing.
    Refused,
    /// No outstanding prepare of that head.
    UnknownPrepare,
    /// The outstanding prepare, if any.
    Outstanding(Option<(u64, Link)>),
    /// A page of the witness log, in witness order.
    Log(LogPage),
}

const REQ_MESSAGE: u8 = 1;
const REQ_OUTSTANDING: u8 = 2;
const REQ_LOG: u8 = 3;
const REQ_LOG_AFTER: u8 = 4;

const REP_RECEIPT: u8 = 1;
const REP_RECORDED: u8 = 2;
const REP_REFUSED: u8 = 3;
const REP_UNKNOWN: u8 = 4;
const REP_NONE: u8 = 5;
const REP_OUTSTANDING: u8 = 6;
const REP_LOG: u8 = 7;

const REC_PREPARE: u8 = 1;
const REC_ABORT: u8 = 2;
const REC_IN_DOUBT: u8 = 3;

fn audit(e: AuditError) -> WitnessError {
    match e {
        AuditError::Decode(d) => WitnessError::from(d),
        AuditError::Invalid(i) => WitnessError::Invalid(i),
        AuditError::Signing(c) => WitnessError::Signing(c),
        AuditError::Tamper(_) | AuditError::NotImplemented(_) => {
            WitnessError::Decode(DecodeError::Invalid(Invalid::BodyTooLong))
        }
    }
}

fn put_chain(out: &mut Vec<u8>, cell: CellId, chain: ChainId) {
    out.extend_from_slice(&cell.0);
    out.push(chain.byte());
}

fn read_chain(r: &mut Reader<'_>) -> Result<(CellId, ChainId), DecodeError> {
    let cell = CellId(r.array()?);
    let b = r.u8()?;
    let chain = ChainId::from_byte(b).ok_or(DecodeError::UnknownTag(u16::from(b)))?;
    Ok((cell, chain))
}

/// Encodes a request.
///
/// # Errors
///
/// The message encoder's refusal.
pub fn encode_request(req: &WireRequest) -> Result<Vec<u8>, WitnessError> {
    let mut out = vec![WIRE_VERSION];
    match req {
        WireRequest::Message(m) => {
            out.push(REQ_MESSAGE);
            out.extend_from_slice(&encode_witness_message(m)?);
        }
        WireRequest::Outstanding { cell, chain } => {
            out.push(REQ_OUTSTANDING);
            put_chain(&mut out, *cell, *chain);
        }
        WireRequest::Log { cell, chain } => {
            out.push(REQ_LOG);
            put_chain(&mut out, *cell, *chain);
        }
        WireRequest::LogAfter { cell, chain, after } => {
            if *after == 0 {
                return Err(Invalid::RowNumberZero.into());
            }
            out.push(REQ_LOG_AFTER);
            put_chain(&mut out, *cell, *chain);
            out.extend_from_slice(&after.to_be_bytes());
        }
    }
    Ok(out)
}

/// Decodes a request. One spelling. Fuzzed (`witness_wire_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] or [`WitnessError::Invalid`] for any other
/// input.
pub fn decode_request(bytes: &[u8]) -> Result<WireRequest, WitnessError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != WIRE_VERSION {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let req = match r.u8()? {
        REQ_MESSAGE => {
            let rest = r.take(r.remaining())?;
            WireRequest::Message(decode_witness_message(rest)?)
        }
        REQ_OUTSTANDING => {
            let (cell, chain) = read_chain(&mut r)?;
            WireRequest::Outstanding { cell, chain }
        }
        REQ_LOG => {
            let (cell, chain) = read_chain(&mut r)?;
            WireRequest::Log { cell, chain }
        }
        REQ_LOG_AFTER => {
            let (cell, chain) = read_chain(&mut r)?;
            let after = r.be64()?;
            if after == 0 {
                return Err(DecodeError::from(Invalid::RowNumberZero).into());
            }
            WireRequest::LogAfter { cell, chain, after }
        }
        other => return Err(DecodeError::UnknownTag(u16::from(other)).into()),
    };
    r.finish()?;
    Ok(req)
}

fn put_withdrawn(out: &mut Vec<u8>, tag: u8, n: u64, link: &Link) -> Result<(), WitnessError> {
    if n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    out.push(tag);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&link.0);
    Ok(())
}

fn read_withdrawn(r: &mut Reader<'_>) -> Result<(u64, Link), DecodeError> {
    let n = r.be64()?;
    if n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    Ok((n, Link(r.array()?)))
}

/// Encodes a reply.
///
/// # Errors
///
/// [`WitnessError::Invalid`] for a receipt or an anchor the `fstp-audit`
/// encoders refuse, a row 0, a log page longer than [`MAX_LOG_RECORDS`],
/// or an empty page that says more follow.
pub fn encode_reply(rep: &WireReply) -> Result<Vec<u8>, WitnessError> {
    let mut out = vec![WIRE_VERSION];
    match rep {
        WireReply::Receipt(rc) => {
            out.push(REP_RECEIPT);
            out.extend_from_slice(&encode_receipt(rc).map_err(audit)?);
        }
        WireReply::Recorded => out.push(REP_RECORDED),
        WireReply::Refused => out.push(REP_REFUSED),
        WireReply::UnknownPrepare => out.push(REP_UNKNOWN),
        WireReply::Outstanding(None) => out.push(REP_NONE),
        WireReply::Outstanding(Some((n, link))) => {
            put_withdrawn(&mut out, REP_OUTSTANDING, *n, link)?
        }
        WireReply::Log(LogPage { records, more }) => {
            if records.len() > MAX_LOG_RECORDS || (*more && records.is_empty()) {
                return Err(Invalid::BodyTooLong.into());
            }
            let count = u32::try_from(records.len()).map_err(|_| Invalid::BodyTooLong)?;
            out.push(REP_LOG);
            out.extend_from_slice(&count.to_be_bytes());
            out.push(u8::from(*more));
            for rec in records {
                match rec {
                    WitnessRecord::Prepare(row) => {
                        out.push(REC_PREPARE);
                        out.extend_from_slice(&encode_anchor(&row.anchor).map_err(audit)?);
                        out.extend_from_slice(&encode_receipt(&row.receipt).map_err(audit)?);
                    }
                    WitnessRecord::Abort { n, link } => {
                        put_withdrawn(&mut out, REC_ABORT, *n, link)?;
                    }
                    WitnessRecord::InDoubtAbsent { n, link } => {
                        put_withdrawn(&mut out, REC_IN_DOUBT, *n, link)?;
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Decodes a reply. One spelling. Fuzzed (`witness_wire_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] or [`WitnessError::Invalid`] for any other
/// input.
pub fn decode_reply(bytes: &[u8]) -> Result<WireReply, WitnessError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != WIRE_VERSION {
        return Err(DecodeError::UnknownVersion(version).into());
    }
    let rep = match r.u8()? {
        REP_RECEIPT => {
            WireReply::Receipt(decode_receipt(r.take(RECEIPT_ENCODED_LEN)?).map_err(audit)?)
        }
        REP_RECORDED => WireReply::Recorded,
        REP_REFUSED => WireReply::Refused,
        REP_UNKNOWN => WireReply::UnknownPrepare,
        REP_NONE => WireReply::Outstanding(None),
        REP_OUTSTANDING => WireReply::Outstanding(Some(read_withdrawn(&mut r)?)),
        REP_LOG => {
            let count = usize::try_from(r.be32()?).map_err(|_| DecodeError::TooLong)?;
            if count > MAX_LOG_RECORDS {
                return Err(DecodeError::TooLong.into());
            }
            let more = match r.u8()? {
                0 => false,
                1 if count > 0 => true,
                other => return Err(DecodeError::UnknownTag(u16::from(other)).into()),
            };
            // Bounded allocation: each record takes at least 41 bytes.
            if count
                .checked_mul(41)
                .is_none_or(|need| need > r.remaining())
            {
                return Err(DecodeError::Truncated.into());
            }
            let mut records = Vec::with_capacity(count);
            for _ in 0..count {
                let rec = match r.u8()? {
                    REC_PREPARE => {
                        let anchor = decode_anchor(r.take(ANCHOR_ENCODED_LEN)?).map_err(audit)?;
                        let receipt =
                            decode_receipt(r.take(RECEIPT_ENCODED_LEN)?).map_err(audit)?;
                        WitnessRecord::Prepare(AnchorRow { anchor, receipt })
                    }
                    REC_ABORT => {
                        let (n, link) = read_withdrawn(&mut r)?;
                        WitnessRecord::Abort { n, link }
                    }
                    REC_IN_DOUBT => {
                        let (n, link) = read_withdrawn(&mut r)?;
                        WitnessRecord::InDoubtAbsent { n, link }
                    }
                    other => return Err(DecodeError::UnknownTag(u16::from(other)).into()),
                };
                records.push(rec);
            }
            WireReply::Log(LogPage { records, more })
        }
        other => return Err(DecodeError::UnknownTag(u16::from(other)).into()),
    };
    r.finish()?;
    Ok(rep)
}

/// Writes one frame.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] for a payload above
/// [`MAX_FRAME`], or the transport's error.
pub async fn write_frame<C: AsyncRead + AsyncWrite + Unpin>(
    c: &mut C,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(4));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    c.write_all(&frame).await?;
    c.flush().await
}

/// Reads one frame. `Ok(None)` when the peer closed before its first byte.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidData`] for a length above [`MAX_FRAME`],
/// [`std::io::ErrorKind::UnexpectedEof`] inside a frame, or the
/// transport's error.
pub async fn read_frame<C: AsyncRead + AsyncWrite + Unpin>(
    c: &mut C,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    while got < len.len() {
        let Some(slot) = len.get_mut(got..) else {
            break;
        };
        let n = c.read(slot).await?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            };
        }
        got = got.saturating_add(n);
    }
    let len = usize::try_from(u32::from_be_bytes(len))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    if len > MAX_FRAME {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let mut payload = vec![0u8; len];
    c.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const CELL: CellId = CellId([0x51; 16]);

    /// TH-26, ADR-010: each request and reply form round-trips, a cut
    /// value does not decode, and a row 0 is refused.
    #[test]
    fn adr010_wire_forms_round_trip_with_one_spelling() {
        let link = Link([0x0a; 32]);
        let requests = [
            WireRequest::Message(WitnessMessage::Abort {
                cell: CELL,
                chain: ChainId::App,
                n: 3,
                link,
            }),
            WireRequest::Outstanding {
                cell: CELL,
                chain: ChainId::Vault,
            },
            WireRequest::Log {
                cell: CELL,
                chain: ChainId::App,
            },
            WireRequest::LogAfter {
                cell: CELL,
                chain: ChainId::App,
                after: 4096,
            },
        ];
        for r in &requests {
            let bytes = encode_request(r).unwrap();
            assert_eq!(&decode_request(&bytes).unwrap(), r);
            assert!(decode_request(&bytes[..bytes.len() - 1]).is_err());
        }
        let replies = [
            WireReply::Recorded,
            WireReply::Refused,
            WireReply::UnknownPrepare,
            WireReply::Outstanding(None),
            WireReply::Outstanding(Some((7, link))),
            WireReply::Log(LogPage {
                records: vec![
                    WitnessRecord::Abort { n: 1, link },
                    WitnessRecord::InDoubtAbsent { n: 2, link },
                ],
                more: true,
            }),
            WireReply::Log(LogPage {
                records: Vec::new(),
                more: false,
            }),
        ];
        for r in &replies {
            let bytes = encode_reply(r).unwrap();
            assert_eq!(&decode_reply(&bytes).unwrap(), r);
            assert!(decode_reply(&bytes[..bytes.len() - 1]).is_err());
        }
        assert!(encode_reply(&WireReply::Outstanding(Some((0, link)))).is_err());
        let mut bad = encode_reply(&WireReply::Recorded).unwrap();
        bad[0] = 2;
        assert!(decode_reply(&bad).is_err());
    }

    /// I-24, ADR-010 "Start-up": a log page never says more follow without
    /// a record, so a client that pages always advances. The first page
    /// has one spelling: `after` 0 does not encode or decode.
    #[test]
    fn i24_log_pages_always_advance() {
        let empty_more = WireReply::Log(LogPage {
            records: Vec::new(),
            more: true,
        });
        assert!(encode_reply(&empty_more).is_err());
        let mut bytes = encode_reply(&WireReply::Log(LogPage {
            records: Vec::new(),
            more: false,
        }))
        .unwrap();
        let flag = bytes.len() - 1;
        bytes[flag] = 1;
        assert!(decode_reply(&bytes).is_err());
        let first = WireRequest::LogAfter {
            cell: CELL,
            chain: ChainId::App,
            after: 0,
        };
        assert!(encode_request(&first).is_err());
        let mut bytes = encode_request(&WireRequest::LogAfter {
            cell: CELL,
            chain: ChainId::App,
            after: 1,
        })
        .unwrap();
        let last = bytes.len() - 1;
        bytes[last] = 0;
        assert!(decode_request(&bytes).is_err());
    }
}

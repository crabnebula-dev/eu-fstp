//! The append-only file store of a self-hosted witness (ADR-010 "Self-
//! hosted witness", design section 15 `file_store_decode`).
//!
//! ```text
//! file   = record*
//! record = be64(witness_seq) || be32(len) || bytes
//! ```
//!
//! Records are appended and never rewritten, so the encoding of a prefix
//! of the records is a prefix of the file. A file cut inside a record is
//! refused. A file cut at a record boundary, as after a crash between two
//! appends, holds exactly the records before the cut.
//!
//! Two layers read the file:
//!
//! - [`decode_file_store`] reads the framing. It needs only strictly
//!   rising sequences, so it also reads a segment of a longer store.
//! - [`load_file_store`] reads a whole store. One file holds the witness
//!   chain of exactly one cell and chain, because witness sequences
//!   count per cell and chain (reading of lane W2g). Its sequences are
//!   therefore 1, 2, 3 with no gap, and a deleted middle record is
//!   refused.
//!
//! The record content is not fixed yet (ADR-010 open point 4). Once it
//! is, the loader also recomputes the witness links from
//! [`fstp_audit::witness::witness_genesis`] and refuses any break.

use fstp_audit::anchor::RECEIPT_ENCODED_LEN;
use fstp_audit::codec::Reader;
use fstp_audit::{DecodeError, Invalid};

use crate::WitnessError;
use crate::message::MAX_MESSAGE_LEN;

/// The longest record the store holds: the longest witness message and
/// the receipt the witness gave for it. Derived, so that every message
/// the core accepts fits in one record.
pub const MAX_FILE_RECORD_LEN: usize = MAX_MESSAGE_LEN + RECEIPT_ENCODED_LEN;

/// One record of the append-only file store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    /// The witness sequence, from 1.
    pub witness_seq: u64,
    /// The record bytes.
    pub bytes: Vec<u8>,
}

/// The bytes that append `record` after a last record of sequence
/// `last_seq` (0 for an empty store).
///
/// # Errors
///
/// [`Invalid::SequenceNotRising`] unless the sequence rises, and
/// [`Invalid::BodyTooLong`] above [`MAX_FILE_RECORD_LEN`].
pub fn encode_file_record(last_seq: u64, record: &FileRecord) -> Result<Vec<u8>, WitnessError> {
    if record.witness_seq <= last_seq {
        return Err(Invalid::SequenceNotRising.into());
    }
    if record.bytes.len() > MAX_FILE_RECORD_LEN {
        return Err(Invalid::BodyTooLong.into());
    }
    let len = u32::try_from(record.bytes.len()).map_err(|_| Invalid::BodyTooLong)?;
    let mut out = Vec::with_capacity(record.bytes.len().saturating_add(12));
    out.extend_from_slice(&record.witness_seq.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&record.bytes);
    Ok(out)
}

/// Encodes a whole store.
///
/// # Errors
///
/// As [`encode_file_record`], for the first record that fails.
pub fn encode_file_store(records: &[FileRecord]) -> Result<Vec<u8>, WitnessError> {
    let mut out = Vec::new();
    let mut last = 0;
    for r in records {
        out.extend_from_slice(&encode_file_record(last, r)?);
        last = r.witness_seq;
    }
    Ok(out)
}

/// Decodes the framing of the file store. An empty file holds no record.
/// A truncated record is detected. Fuzzed (`file_store_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] for a cut inside a record or a record over
/// its limit, and [`WitnessError::Invalid`] for a sequence that does not
/// rise.
pub fn decode_file_store(bytes: &[u8]) -> Result<Vec<FileRecord>, WitnessError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    let mut last = 0u64;
    while !r.is_empty() {
        let witness_seq = r.be64()?;
        if witness_seq <= last {
            return Err(DecodeError::Invalid(Invalid::SequenceNotRising).into());
        }
        let bytes = r.bytes32(MAX_FILE_RECORD_LEN)?;
        last = witness_seq;
        out.push(FileRecord { witness_seq, bytes });
    }
    Ok(out)
}

/// Loads the whole store of one cell and chain: [`decode_file_store`],
/// then sequences 1, 2, 3 with no gap. Fuzzed (`file_store_decode`).
///
/// # Errors
///
/// As [`decode_file_store`], and [`Invalid::SequenceGap`] for a store that
/// does not start at 1 or misses a record inside it.
pub fn load_file_store(bytes: &[u8]) -> Result<Vec<FileRecord>, WitnessError> {
    let records = decode_file_store(bytes)?;
    let mut expected = 0u64;
    for r in &records {
        expected = expected.checked_add(1).ok_or(Invalid::SequenceGap)?;
        if r.witness_seq != expected {
            return Err(Invalid::SequenceGap.into());
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use fstp_audit::anchor::{Anchor, Receipt, ReceiptFields, encode_receipt};
    use fstp_audit::chain::{genesis, link_of};
    use fstp_audit::witness::{MAX_PREPARE_ROWS, Prepare};
    use fstp_audit::{CellId, ChainId, Link, SIGNATURE_LEN};

    use super::*;
    use crate::message::{WitnessMessage, decode_witness_message, encode_witness_message};

    fn rec(witness_seq: u64) -> FileRecord {
        FileRecord {
            witness_seq,
            bytes: vec![u8::try_from(witness_seq % 256).unwrap()],
        }
    }

    /// I-24, ADR-010 "Self-hosted witness": the loader of a whole store
    /// takes sequences 1, 2, 3 and refuses a deleted middle record, a
    /// deleted first record and a store that starts above 1.
    #[test]
    fn i24_file_store_loader_refuses_a_missing_record() {
        let whole = encode_file_store(&[rec(1), rec(2), rec(3)]).unwrap();
        assert_eq!(load_file_store(&whole).unwrap().len(), 3);
        assert_eq!(load_file_store(&[]).unwrap(), Vec::new());
        for gap in [vec![rec(1), rec(3)], vec![rec(2), rec(3)], vec![rec(5)]] {
            let bytes = encode_file_store(&gap).unwrap();
            assert!(decode_file_store(&bytes).is_ok(), "framing is sound");
            assert_eq!(
                load_file_store(&bytes),
                Err(WitnessError::Invalid(Invalid::SequenceGap)),
                "{gap:?}"
            );
        }
    }

    /// I-24, design section 15: the largest prepare the witness accepts,
    /// with its receipt, fits in one file record and decodes back.
    #[test]
    fn i24_file_store_holds_the_largest_prepare_and_its_receipt() {
        let cell = CellId([9; 16]);
        let chain = ChainId::App;
        let prev = (0, genesis(cell, chain));
        let stored_hashes = vec![[0x5A; 32]; MAX_PREPARE_ROWS];
        let mut head = prev;
        for sh in &stored_hashes {
            head = (head.0 + 1, link_of(&head.1, cell, chain, head.0 + 1, sh));
        }
        let p = Prepare {
            prev,
            stored_hashes,
            anchor: Anchor {
                cell,
                chain,
                n: head.0,
                link: head.1,
                at: 0,
                signature: vec![0; SIGNATURE_LEN],
            },
        };
        let message = encode_witness_message(&WitnessMessage::Prepare(p.clone())).unwrap();
        assert_eq!(message.len(), MAX_MESSAGE_LEN);
        let receipt = encode_receipt(&Receipt {
            cell,
            chain,
            fields: ReceiptFields {
                n: head.0,
                link: head.1,
                witness_seq: 1,
                witness_link: Link([1; 32]),
                received_at: 0,
            },
            signature: vec![0; SIGNATURE_LEN],
        })
        .unwrap();
        assert_eq!(receipt.len(), RECEIPT_ENCODED_LEN);
        let mut bytes = message;
        bytes.extend_from_slice(&receipt);
        assert_eq!(bytes.len(), MAX_FILE_RECORD_LEN);
        let file = encode_file_store(&[FileRecord {
            witness_seq: 1,
            bytes,
        }])
        .unwrap();
        let back = load_file_store(&file).unwrap();
        assert_eq!(back.len(), 1);
        let (m, _) = back[0].bytes.split_at(MAX_MESSAGE_LEN);
        assert_eq!(decode_witness_message(m), Ok(WitnessMessage::Prepare(p)));
        let over = FileRecord {
            witness_seq: 1,
            bytes: vec![0; MAX_FILE_RECORD_LEN + 1],
        };
        assert!(encode_file_store(&[over]).is_err(), "over the limit");
    }
}

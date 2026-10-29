//! The byte layout of one stored ledger row (design sections 4.2 and 15).
//!
//! ```text
//! format (1) || be64(seq) || be64(at) || command (16) || be16(schema)
//!   || be32(key_ix) || be32(len) || sealed (len)
//! ```
//!
//! `sealed` is the `body` column: a 12-byte random nonce, then the
//! AES-256-GCM ciphertext and its 16-byte tag. The read path asks the
//! database for exactly this layout and decodes every row with
//! [`decode_stored_entry`], so the fuzzed decoder is the one that reads
//! production rows. The layout has one spelling: [`encode_stored_entry`]
//! of the result gives the input back.

use fstp_ledger::MAX_AT;

use crate::error::DecodeError;

/// The format byte of the layout.
pub const STORED_ENTRY_FORMAT: u8 = 1;

/// The shortest sealed body: a 12-byte nonce and a 16-byte tag.
pub const MIN_SEALED_LEN: usize = fstp_crypto::aead::NONCE_LEN + fstp_crypto::aead::TAG_LEN;

/// The longest sealed body the store writes or decodes: 16 MiB.
pub const MAX_SEALED_LEN: usize = 1 << 24;

/// The bytes before the sealed body.
const HEADER_LEN: usize = 1 + 8 + 8 + 16 + 2 + 4 + 4;

/// A stored ledger row, before decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The ledger sequence, from 1.
    pub seq: u64,
    /// UTC microseconds, at most `fstp_ledger::MAX_AT` in magnitude.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The schema version, from 1.
    pub schema: u16,
    /// The ledger key generation that sealed the body.
    pub key_ix: u32,
    /// The sealed canonical text: nonce, ciphertext and tag.
    pub sealed: Vec<u8>,
}

impl StoredEntry {
    /// The row as `fstp-audit` hashes it into the chain.
    pub fn to_audit(&self) -> fstp_audit::StoredEntry {
        fstp_audit::StoredEntry {
            seq: self.seq,
            at: self.at,
            command: self.command,
            schema: self.schema,
            key_ix: self.key_ix,
            body: self.sealed.clone(),
        }
    }
}

/// The row checks of `ledger.entry` that both directions apply.
fn check(seq: u64, at: i64, schema: u16, sealed_len: usize) -> Result<(), DecodeError> {
    if seq == 0 {
        return Err(DecodeError::SeqZero);
    }
    if !(-MAX_AT..=MAX_AT).contains(&at) {
        return Err(DecodeError::TimeOutOfRange);
    }
    if schema == 0 {
        return Err(DecodeError::SchemaZero);
    }
    if sealed_len < MIN_SEALED_LEN {
        return Err(DecodeError::SealedTooShort);
    }
    if sealed_len > MAX_SEALED_LEN {
        return Err(DecodeError::SealedTooLong);
    }
    Ok(())
}

/// Encodes a stored row in its one layout.
///
/// # Errors
///
/// The first row check the entry breaks: a sequence or schema version of
/// 0, a time out of range, or a sealed body outside
/// [`MIN_SEALED_LEN`]..=[`MAX_SEALED_LEN`].
pub fn encode_stored_entry(e: &StoredEntry) -> Result<Vec<u8>, DecodeError> {
    check(e.seq, e.at, e.schema, e.sealed.len())?;
    let len = u32::try_from(e.sealed.len()).map_err(|_| DecodeError::SealedTooLong)?;
    let capacity = HEADER_LEN
        .checked_add(e.sealed.len())
        .ok_or(DecodeError::SealedTooLong)?;
    let mut out = Vec::with_capacity(capacity);
    out.push(STORED_ENTRY_FORMAT);
    out.extend_from_slice(&e.seq.to_be_bytes());
    out.extend_from_slice(&e.at.to_be_bytes());
    out.extend_from_slice(&e.command);
    out.extend_from_slice(&e.schema.to_be_bytes());
    out.extend_from_slice(&e.key_ix.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&e.sealed);
    Ok(out)
}

/// Reads fixed-size fields from the front of a slice.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// Decodes a stored row. Only the layout [`encode_stored_entry`] writes
/// decodes, and only for a row that meets the checks of `ledger.entry`.
/// It never panics and allocates at most the input length. Fuzzed
/// (`stored_entry_decode`).
///
/// # Errors
///
/// [`DecodeError`] for any other input.
pub fn decode_stored_entry(bytes: &[u8]) -> Result<StoredEntry, DecodeError> {
    let mut r = Reader { rest: bytes };
    let [format] = r.array::<1>()?;
    if format != STORED_ENTRY_FORMAT {
        return Err(DecodeError::UnknownFormat(format));
    }
    let seq = u64::from_be_bytes(r.array()?);
    let at = i64::from_be_bytes(r.array()?);
    let command = r.array::<16>()?;
    let schema = u16::from_be_bytes(r.array()?);
    let key_ix = u32::from_be_bytes(r.array()?);
    let len =
        usize::try_from(u32::from_be_bytes(r.array()?)).map_err(|_| DecodeError::SealedTooLong)?;
    check(seq, at, schema, len)?;
    let sealed = r.take(len)?.to_vec();
    if !r.rest.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(StoredEntry {
        seq,
        at,
        command,
        schema,
        key_ix,
        sealed,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use super::*;

    fn row() -> StoredEntry {
        StoredEntry {
            seq: 7,
            at: -3,
            command: [9; 16],
            schema: 2,
            key_ix: u32::MAX,
            sealed: vec![0x5A; MIN_SEALED_LEN],
        }
    }

    /// TH-26: the layout is the documented one, field by field.
    #[test]
    fn th_26_stored_entry_layout_is_the_documented_one() {
        let bytes = encode_stored_entry(&row()).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + MIN_SEALED_LEN);
        assert_eq!(bytes[0], STORED_ENTRY_FORMAT);
        assert_eq!(&bytes[1..9], &7u64.to_be_bytes());
        assert_eq!(&bytes[9..17], &(-3i64).to_be_bytes());
        assert_eq!(&bytes[17..33], &[9; 16]);
        assert_eq!(&bytes[33..35], &2u16.to_be_bytes());
        assert_eq!(&bytes[35..39], &u32::MAX.to_be_bytes());
        assert_eq!(&bytes[39..43], &28u32.to_be_bytes());
        assert_eq!(decode_stored_entry(&bytes), Ok(row()));
    }

    /// TH-26: a declared length past the limit is refused before any
    /// allocation, whatever follows.
    #[test]
    fn th_26_stored_entry_refuses_a_length_past_the_limit() {
        let mut bytes = encode_stored_entry(&row()).unwrap();
        bytes[39..43].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_stored_entry(&bytes), Err(DecodeError::SealedTooLong));
    }

    /// TH-26: times past the ledger bound neither encode nor decode.
    #[test]
    fn th_26_stored_entry_refuses_a_time_past_the_bound() {
        let mut e = row();
        e.at = MAX_AT + 1;
        assert_eq!(encode_stored_entry(&e), Err(DecodeError::TimeOutOfRange));
        let mut bytes = encode_stored_entry(&row()).unwrap();
        bytes[9..17].copy_from_slice(&(-MAX_AT - 1).to_be_bytes());
        assert_eq!(
            decode_stored_entry(&bytes),
            Err(DecodeError::TimeOutOfRange)
        );
    }
}

//! Byte readers and writers for the audit layouts (TH-26).
//!
//! Every read is bounds-checked and every length is checked against the
//! bytes that remain before anything is allocated. `fstp-witness` uses the
//! same reader for its message and file store layouts, so both crates
//! share one parser core, fuzzed from both sides.

use crate::DecodeError;

/// A cursor over input bytes. It never panics.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    /// The number of bytes not read yet.
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Whether every byte was read.
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next `len` bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer remain.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(DecodeError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer remain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// One byte.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] at the end of input.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    /// A big-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer than 2 bytes remain.
    pub fn be16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// A big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer than 4 bytes remain.
    pub fn be32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// A big-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer than 8 bytes remain.
    pub fn be64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A big-endian `i64`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] when fewer than 8 bytes remain.
    pub fn bei64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    /// A `be32` length followed by that many bytes, at most `max`. The
    /// length is checked against `max` and the remaining input before any
    /// allocation.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TooLong`] above `max`, [`DecodeError::Truncated`]
    /// when the input ends first.
    pub fn bytes32(&mut self, max: usize) -> Result<Vec<u8>, DecodeError> {
        let len = usize::try_from(self.be32()?).map_err(|_| DecodeError::TooLong)?;
        if len > max {
            return Err(DecodeError::TooLong);
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Refuses unread bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TrailingBytes`] when any byte is left.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Where layout bytes go: a buffer or a running hash.
pub trait Sink {
    /// Appends `bytes`.
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl Sink for fstp_crypto::Sha256 {
    fn put(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

/// The `be32` length of `len`, if it fits and stays within `max`.
pub(crate) fn len32(len: usize, max: usize) -> Option<[u8; 4]> {
    if len > max {
        return None;
    }
    u32::try_from(len).ok().map(u32::to_be_bytes)
}

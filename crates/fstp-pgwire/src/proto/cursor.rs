//! A bounds-checked reader over a message body.

use crate::error::Error;

/// Reads big-endian integers, byte strings and C strings from a message
/// body. Every read checks the remaining length.
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    fn short(&self) -> Error {
        Error::protocol(format!("{} message is truncated", self.what))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.short())?;
        let out = self.buf.get(self.pos..end).ok_or_else(|| self.short())?;
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn i16(&mut self) -> Result<i16, Error> {
        Ok(i16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    /// A NUL-terminated string, without the terminator.
    pub(crate) fn cstr(&mut self) -> Result<&'a [u8], Error> {
        let rest = self.buf.get(self.pos..).ok_or_else(|| self.short())?;
        let Some(nul) = rest.iter().position(|b| *b == 0) else {
            return Err(Error::protocol(format!(
                "{} message has an unterminated string",
                self.what
            )));
        };
        let s = rest.get(..nul).ok_or_else(|| self.short())?;
        self.pos = self.pos.saturating_add(nul).saturating_add(1);
        Ok(s)
    }

    /// A NUL-terminated string that must be valid UTF-8.
    pub(crate) fn cstr_utf8(&mut self) -> Result<&'a str, Error> {
        let what = self.what;
        let raw = self.cstr()?;
        std::str::from_utf8(raw)
            .map_err(|_| Error::protocol(format!("{what} message has a string that is not UTF-8")))
    }

    /// All bytes that are left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let out = self.buf.get(self.pos..).unwrap_or_default();
        self.pos = self.buf.len();
        out
    }

    /// Fails unless every byte was consumed.
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::protocol(format!(
                "{} message has {} trailing bytes",
                self.what,
                self.remaining()
            )))
        }
    }
}

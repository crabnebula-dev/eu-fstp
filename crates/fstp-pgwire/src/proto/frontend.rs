//! Frontend (client to server) messages.
//!
//! Each function appends one complete message to `out`. Strings must not
//! contain NUL, and every count and length must fit its field; violations
//! are errors, never truncation. There is no encoder for the simple Query
//! message: this client uses the extended query protocol only.

use crate::error::Error;
use crate::proto::backend::backpatch_len;
use crate::proto::{CANCEL_REQUEST_CODE, PROTOCOL_VERSION, SSL_REQUEST_CODE};

fn put_cstr(out: &mut Vec<u8>, s: &[u8], what: &str) -> Result<(), Error> {
    if s.contains(&0) {
        return Err(Error::config(format!("{what} contains a NUL byte")));
    }
    out.extend_from_slice(s);
    out.push(0);
    Ok(())
}

fn begin(out: &mut Vec<u8>, tag: u8) -> usize {
    let start = out.len();
    out.push(tag);
    out.extend_from_slice(&[0, 0, 0, 0]);
    start
}

/// Writes a length-prefixed message without a type byte (startup packets).
fn finish_untagged(out: &mut [u8], start: usize) -> Result<(), Error> {
    let len = out.len().saturating_sub(start);
    let len = i32::try_from(len).map_err(|_| Error::config("startup packet too long"))?;
    let end = start.saturating_add(4);
    let slot = out
        .get_mut(start..end)
        .ok_or_else(|| Error::protocol("startup packet header missing"))?;
    slot.copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// The 8-byte SSLRequest.
#[must_use]
pub fn ssl_request() -> [u8; 8] {
    let mut out = [0u8; 8];
    let (len, code) = out.split_at_mut(4);
    len.copy_from_slice(&8i32.to_be_bytes());
    code.copy_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    out
}

/// The 16-byte CancelRequest for a backend's process id and secret key.
#[must_use]
pub fn cancel_request(process_id: i32, secret_key: i32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut parts = [
        16i32.to_be_bytes(),
        CANCEL_REQUEST_CODE.to_be_bytes(),
        process_id.to_be_bytes(),
        secret_key.to_be_bytes(),
    ]
    .into_iter();
    for chunk in out.chunks_exact_mut(4) {
        if let Some(part) = parts.next() {
            chunk.copy_from_slice(&part);
        }
    }
    out
}

/// A StartupMessage for protocol 3.0 with the given parameters.
///
/// # Errors
///
/// Returns an error when a name or value contains NUL or a name is empty.
pub fn startup(params: &[(&str, &str)], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    for (name, value) in params {
        if name.is_empty() {
            return Err(Error::config("empty startup parameter name"));
        }
        put_cstr(out, name.as_bytes(), "startup parameter name")?;
        put_cstr(out, value.as_bytes(), "startup parameter value")?;
    }
    out.push(0);
    finish_untagged(out, start)
}

/// A SASLInitialResponse naming `mechanism`, with `data` as the initial
/// client response.
///
/// # Errors
///
/// Returns an error when `mechanism` contains NUL or `data` is too long.
pub fn sasl_initial_response(mechanism: &str, data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'p');
    put_cstr(out, mechanism.as_bytes(), "SASL mechanism")?;
    let len = i32::try_from(data.len()).map_err(|_| Error::config("SASL data too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    backpatch_len(out, start)
}

/// A SASLResponse carrying `data`.
///
/// # Errors
///
/// Returns an error when the message would be too long.
pub fn sasl_response(data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'p');
    out.extend_from_slice(data);
    backpatch_len(out, start)
}

/// A PasswordMessage carrying a cleartext password. Sent only when
/// `require_auth` explicitly allows cleartext passwords.
///
/// # Errors
///
/// Returns an error when the password contains NUL.
pub fn password(password: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'p');
    put_cstr(out, password, "password")?;
    backpatch_len(out, start)
}

/// A Parse message. Empty `param_types` lets the server infer every
/// parameter type, which this client then checks.
///
/// # Errors
///
/// Returns an error when a string contains NUL or there are more than
/// 65535 parameter types.
pub fn parse(name: &str, query: &str, param_types: &[u32], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'P');
    put_cstr(out, name.as_bytes(), "statement name")?;
    put_cstr(out, query.as_bytes(), "SQL text")?;
    let n = u16::try_from(param_types.len())
        .map_err(|_| Error::config("more than 65535 parameter types"))?;
    out.extend_from_slice(&n.to_be_bytes());
    for t in param_types {
        out.extend_from_slice(&t.to_be_bytes());
    }
    backpatch_len(out, start)
}

/// Whether a Describe or Close names a statement or a portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A prepared statement (`S`).
    Statement,
    /// A portal (`P`).
    Portal,
}

impl Target {
    fn byte(self) -> u8 {
        match self {
            Target::Statement => b'S',
            Target::Portal => b'P',
        }
    }
}

/// A Describe message.
///
/// # Errors
///
/// Returns an error when `name` contains NUL.
pub fn describe(target: Target, name: &str, out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'D');
    out.push(target.byte());
    put_cstr(out, name.as_bytes(), "statement or portal name")?;
    backpatch_len(out, start)
}

/// A Close message.
///
/// # Errors
///
/// Returns an error when `name` contains NUL.
pub fn close(target: Target, name: &str, out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'C');
    out.push(target.byte());
    put_cstr(out, name.as_bytes(), "statement or portal name")?;
    backpatch_len(out, start)
}

/// The start of a Bind message. Parameter values follow through
/// [`BindWriter`].
///
/// Every parameter and every result column uses the binary format.
pub struct BindWriter<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
    remaining: u16,
}

impl<'a> BindWriter<'a> {
    /// Starts a Bind of statement `statement` to portal `portal` with
    /// `param_count` parameters.
    ///
    /// # Errors
    ///
    /// Returns an error when a name contains NUL or there are more than
    /// 65535 parameters.
    pub fn begin(
        portal: &str,
        statement: &str,
        param_count: usize,
        out: &'a mut Vec<u8>,
    ) -> Result<Self, Error> {
        let n =
            u16::try_from(param_count).map_err(|_| Error::config("more than 65535 parameters"))?;
        let start = begin(out, b'B');
        put_cstr(out, portal.as_bytes(), "portal name")?;
        put_cstr(out, statement.as_bytes(), "statement name")?;
        if n == 0 {
            out.extend_from_slice(&0u16.to_be_bytes());
        } else {
            // One format code applies to every parameter: binary.
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
        }
        out.extend_from_slice(&n.to_be_bytes());
        Ok(Self {
            out,
            start,
            remaining: n,
        })
    }

    /// Appends one parameter. `encode` writes the binary value into the
    /// buffer and returns `false` for SQL NULL, in which case anything it
    /// wrote is discarded.
    ///
    /// # Errors
    ///
    /// Returns the error from `encode`, or an error when the value is longer
    /// than `i32::MAX` bytes or more parameters are written than announced.
    pub fn param(
        &mut self,
        encode: impl FnOnce(&mut Vec<u8>) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| Error::config("more parameters than announced"))?;
        let len_at = self.out.len();
        self.out.extend_from_slice(&[0, 0, 0, 0]);
        let value_at = self.out.len();
        let not_null = encode(self.out)?;
        let len: i32 = if not_null {
            i32::try_from(self.out.len().saturating_sub(value_at))
                .map_err(|_| Error::new(crate::ErrorKind::Encode, "value exceeds i32::MAX bytes"))?
        } else {
            self.out.truncate(value_at);
            -1
        };
        let end = len_at.saturating_add(4);
        if let Some(slot) = self.out.get_mut(len_at..end) {
            slot.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    /// Finishes the message: every result column in binary format.
    ///
    /// # Errors
    ///
    /// Returns an error when fewer parameters were written than announced
    /// or the message is too long.
    pub fn finish(self) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::config("fewer parameters than announced"));
        }
        self.out.extend_from_slice(&1u16.to_be_bytes());
        self.out.extend_from_slice(&1u16.to_be_bytes());
        backpatch_len(self.out, self.start)
    }
}

/// An Execute message for `portal`. `max_rows` 0 means no limit.
///
/// # Errors
///
/// Returns an error when `portal` contains NUL.
pub fn execute(portal: &str, max_rows: u32, out: &mut Vec<u8>) -> Result<(), Error> {
    let start = begin(out, b'E');
    put_cstr(out, portal.as_bytes(), "portal name")?;
    let max = i32::try_from(max_rows).map_err(|_| Error::config("row limit too large"))?;
    out.extend_from_slice(&max.to_be_bytes());
    backpatch_len(out, start)
}

/// A Sync message.
pub fn sync(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'S', 0, 0, 0, 4]);
}

/// A Flush message.
pub fn flush(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'H', 0, 0, 0, 4]);
}

/// A Terminate message.
pub fn terminate(out: &mut Vec<u8>) {
    out.extend_from_slice(&[b'X', 0, 0, 0, 4]);
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn fixed_packets() {
        assert_eq!(ssl_request(), [0, 0, 0, 8, 4, 210, 22, 47]);
        let c = cancel_request(1, 2);
        assert_eq!(&c[..8], &[0, 0, 0, 16, 4, 210, 22, 46]);
        assert_eq!(&c[8..], &[0, 0, 0, 1, 0, 0, 0, 2]);
    }

    #[test]
    fn startup_layout() {
        let mut out = Vec::new();
        startup(&[("user", "u")], &mut out).unwrap();
        assert_eq!(out, b"\x00\x00\x00\x10\x00\x03\x00\x00user\0u\0\0");
        assert!(startup(&[("user", "a\0b")], &mut Vec::new()).is_err());
        assert!(startup(&[("", "x")], &mut Vec::new()).is_err());
    }

    #[test]
    fn bind_layout() {
        let mut out = Vec::new();
        let mut b = BindWriter::begin("", "s1", 2, &mut out).unwrap();
        b.param(|o| {
            o.extend_from_slice(&7i32.to_be_bytes());
            Ok(true)
        })
        .unwrap();
        b.param(|o| {
            o.push(9);
            Ok(false)
        })
        .unwrap();
        b.finish().unwrap();
        let expected: &[u8] = b"B\x00\x00\x00\x1e\0s1\0\x00\x01\x00\x01\x00\x02\
            \x00\x00\x00\x04\x00\x00\x00\x07\xff\xff\xff\xff\x00\x01\x00\x01";
        assert_eq!(out, expected);
    }

    #[test]
    fn bind_counts_are_enforced() {
        let mut out = Vec::new();
        let b = BindWriter::begin("", "", 1, &mut out).unwrap();
        assert!(b.finish().is_err());
        let mut out = Vec::new();
        let mut b = BindWriter::begin("", "", 0, &mut out).unwrap();
        assert!(b.param(|_| Ok(true)).is_err());
    }

    #[test]
    fn parse_rejects_nul_in_sql() {
        assert!(parse("", "SELECT 1\0; DROP", &[], &mut Vec::new()).is_err());
        let mut out = Vec::new();
        parse("s", "SELECT 1", &[], &mut out).unwrap();
        assert_eq!(out, b"P\x00\x00\x00\x11s\0SELECT 1\0\x00\x00");
    }
}

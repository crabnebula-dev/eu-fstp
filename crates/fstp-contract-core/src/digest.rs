//! A SHA-256 digest with its stored spelling: 64 lowercase hex digits.
//!
//! The crate never computes a digest. The shell side (`fstp-contract`)
//! hashes bytes through `fstp-crypto` and hands the value in.

use fstp_json::{FromJson, FromJsonError, ToJson, Value};

/// A SHA-256 digest of a PDF revision, a text or a report.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest with these bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 32]) -> Digest {
        Digest(b)
    }

    /// The bytes.
    #[must_use]
    pub const fn bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The lowercase hex spelling.
    #[must_use]
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            for n in [b >> 4, b & 0x0f] {
                s.push(char::from_digit(u32::from(n), 16).unwrap_or('0'));
            }
        }
        s
    }

    /// Parses exactly 64 lowercase hex digits.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Digest> {
        fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => c.checked_sub(b'0'),
                b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
                _ => None,
            }
        }
        let raw = s.as_bytes();
        if raw.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (o, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
            let hi = nibble(*pair.first()?)?;
            let lo = nibble(*pair.get(1)?)?;
            *o = (hi << 4) | lo;
        }
        Some(Digest(out))
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl ToJson for Digest {
    fn to_json(&self) -> Value {
        Value::String(self.hex())
    }
}

impl FromJson for Digest {
    fn from_json(value: &Value) -> Result<Digest, FromJsonError> {
        match value {
            Value::String(s) => {
                Digest::from_hex(s).ok_or_else(|| FromJsonError::invalid("not a SHA-256 digest"))
            }
            other => Err(FromJsonError::wrong_type("string", other)),
        }
    }
}

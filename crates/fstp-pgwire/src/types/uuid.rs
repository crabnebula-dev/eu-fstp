//! `uuid`.

use std::fmt;

use crate::types::{DecodeError, EncodeError, FromSql, IsNull, ToSql, Type, accepts};

/// A UUID: 16 bytes, written in the usual lowercase hyphenated form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// The UUID with these bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Uuid {
        Uuid(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A random version 4 UUID from the system generator (fstp-crypto).
    ///
    /// # Errors
    ///
    /// Returns the error when the system generator fails.
    pub fn new_v4() -> Result<Uuid, fstp_crypto::CryptoError> {
        let mut b: [u8; 16] = fstp_crypto::random_array()?;
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        Ok(Uuid(b))
    }

    /// Parses the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
    /// in either case.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for any other input.
    pub fn parse(s: &str) -> Result<Uuid, DecodeError> {
        let bad = DecodeError("UUID must be 32 hex digits in 8-4-4-4-12 groups");
        let bytes = s.as_bytes();
        if bytes.len() != 36 {
            return Err(bad);
        }
        let mut out = [0u8; 16];
        let mut nibbles = 0usize;
        for (i, b) in bytes.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if *b != b'-' {
                    return Err(bad);
                }
                continue;
            }
            let v = match b {
                b'0'..=b'9' => b.wrapping_sub(b'0'),
                b'a'..=b'f' => b.wrapping_sub(b'a').wrapping_add(10),
                b'A'..=b'F' => b.wrapping_sub(b'A').wrapping_add(10),
                _ => return Err(bad),
            };
            let slot = out.get_mut(nibbles / 2).ok_or(bad.clone())?;
            if nibbles.is_multiple_of(2) {
                *slot = v << 4;
            } else {
                *slot |= v;
            }
            nibbles = nibbles.saturating_add(1);
        }
        Ok(Uuid(out))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({self})")
    }
}

accepts!(Uuid, Type::UUID);

impl ToSql for Uuid {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::UUID
    }

    fn rust_type(&self) -> &'static str {
        "Uuid"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        out.extend_from_slice(&self.0);
        Ok(IsNull::No)
    }
}

impl FromSql for Uuid {
    fn accepts(ty: Type) -> bool {
        ty == Type::UUID
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        let bytes: [u8; 16] = raw
            .try_into()
            .map_err(|_| DecodeError("uuid must be 16 bytes"))?;
        Ok(Uuid(bytes))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        let s = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11";
        let u = Uuid::parse(s).unwrap();
        assert_eq!(u.to_string(), s);
        assert_eq!(Uuid::parse(&s.to_uppercase()).unwrap(), u);
        assert!(Uuid::parse("a0eebc999c0b4ef8bb6d6bb9bd380a11").is_err());
        assert!(Uuid::parse("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1g").is_err());
        assert!(Uuid::parse("a0eebc99+9c0b-4ef8-bb6d-6bb9bd380a11").is_err());
    }

    #[test]
    fn v4_has_version_and_variant_bits() {
        let u = Uuid::new_v4().unwrap();
        assert_eq!(u.as_bytes()[6] >> 4, 4);
        assert_eq!(u.as_bytes()[8] >> 6, 2);
    }

    #[test]
    fn decode_requires_16_bytes() {
        assert!(Uuid::from_sql(Type::UUID, &[0; 15]).is_err());
        assert!(Uuid::from_sql(Type::UUID, &[0; 17]).is_err());
        assert_eq!(Uuid::from_sql(Type::UUID, &[7; 16]).unwrap(), Uuid([7; 16]));
    }
}

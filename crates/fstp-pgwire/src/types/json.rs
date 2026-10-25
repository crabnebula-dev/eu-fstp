//! `jsonb` and `json` through [`fstp_json::Value`].
//!
//! The binary `jsonb` format is a version byte (1) followed by JSON text.
//! The binary `json` format is the JSON text alone. Values are written as
//! compact JSON and read with the strict fstp-json parser under
//! [`json_limits`].
//!
//! # Duplicate keys
//!
//! PostgreSQL `json` stores the input text as given, so an object can hold
//! the same key twice, as in `{"a":1,"a":2}`. fstp-json rejects duplicate
//! keys, so reading such a value fails with a [`DecodeError`]. `jsonb`
//! keeps only the last value of a duplicated key, so its values always
//! decode. Cast in SQL, as in `SELECT body::jsonb`, to read a `json`
//! column that may hold duplicates. A cast to `text` keeps the exact text
//! instead.

use fstp_json::{ParseLimits, Value};

use crate::types::{DecodeError, EncodeError, FromSql, IsNull, ToSql, Type, accepts};

/// The `jsonb` binary format version this client reads and writes.
pub const JSONB_VERSION: u8 = 1;

/// The parse limits used when reading `json` and `jsonb` columns through
/// [`FromSql`]: the fstp-json defaults, except that the input may be as
/// large as one protocol message (1 GiB). Use
/// [`decode_json_with`] for other limits.
#[must_use]
pub fn json_limits() -> ParseLimits {
    ParseLimits::default().with_max_input_bytes(1 << 30)
}

/// Decodes a `json` or `jsonb` value under explicit limits.
///
/// # Errors
///
/// Returns a [`DecodeError`] for a wrong `jsonb` version byte or JSON text
/// that does not parse within `limits`.
pub fn decode_json_with(ty: Type, raw: &[u8], limits: &ParseLimits) -> Result<Value, DecodeError> {
    let text = if ty == Type::JSONB {
        match raw.split_first() {
            Some((&JSONB_VERSION, rest)) => rest,
            Some(_) => return Err(DecodeError("unsupported jsonb format version")),
            None => return Err(DecodeError("jsonb value is empty")),
        }
    } else {
        raw
    };
    fstp_json::parse_with(text, limits).map_err(|_| DecodeError("json value does not parse"))
}

accepts!(Value, Type::JSONB, Type::JSON);

impl ToSql for Value {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::JSONB || ty == Type::JSON
    }

    fn rust_type(&self) -> &'static str {
        "fstp_json::Value"
    }

    fn to_sql(&self, ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        if ty == Type::JSONB {
            out.push(JSONB_VERSION);
        }
        out.extend_from_slice(fstp_json::to_compact(self).as_bytes());
        Ok(IsNull::No)
    }
}

/// Reads `jsonb` and `json` values with the strict fstp-json parser.
///
/// A `json` value whose object repeats a key is a [`DecodeError`], since
/// fstp-json rejects duplicate keys. PostgreSQL accepts such `json` text
/// as given. Cast the column to `jsonb` in SQL to keep the last value of
/// each key instead.
impl FromSql for Value {
    fn accepts(ty: Type) -> bool {
        ty == Type::JSONB || ty == Type::JSON
    }

    fn from_sql(ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        decode_json_with(ty, raw, &json_limits())
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn jsonb_has_a_version_byte() {
        let v = fstp_json::json!({"a": [1, "x", null]});
        let mut out = Vec::new();
        v.to_sql(Type::JSONB, &mut out).unwrap();
        assert_eq!(out[0], 1);
        assert_eq!(Value::from_sql(Type::JSONB, &out).unwrap(), v);
        let mut plain = Vec::new();
        v.to_sql(Type::JSON, &mut plain).unwrap();
        assert_eq!(plain, &out[1..]);
        assert_eq!(Value::from_sql(Type::JSON, &plain).unwrap(), v);
    }

    /// PostgreSQL `json` may repeat a key, which fstp-json rejects. The
    /// decode error names no value (R-NF-02).
    #[test]
    fn json_with_duplicate_keys_is_a_decode_error() {
        let err = Value::from_sql(Type::JSON, br#"{"a":"canary","a":2}"#).unwrap_err();
        assert_eq!(err, DecodeError("json value does not parse"));
        assert!(!format!("{err} {err:?}").contains("canary"));
        assert!(Value::from_sql(Type::JSON, br#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn th26_bad_jsonb_is_rejected() {
        assert!(Value::from_sql(Type::JSONB, b"").is_err());
        assert!(Value::from_sql(Type::JSONB, b"\x02{}").is_err());
        assert!(Value::from_sql(Type::JSONB, b"\x01{").is_err());
        assert!(Value::from_sql(Type::JSONB, b"\x01{\"a\":1,\"a\":2}").is_err());
        let deep = format!("\x01{}{}", "[".repeat(200), "]".repeat(200));
        assert!(Value::from_sql(Type::JSONB, deep.as_bytes()).is_err());
        let limits = ParseLimits::default().with_max_depth(300);
        assert!(decode_json_with(Type::JSONB, deep.as_bytes(), &limits).is_ok());
    }
}

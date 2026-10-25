//! `bool`, integers, `float8`, text and `bytea`.

use crate::types::{DecodeError, EncodeError, FromSql, IsNull, ToSql, ToSqlType, Type, accepts};

/// Copies exactly `N` bytes or fails.
fn fixed<const N: usize>(raw: &[u8], what: &'static str) -> Result<[u8; N], DecodeError> {
    let bytes: [u8; N] = raw.try_into().map_err(|_| DecodeError(what))?;
    Ok(bytes)
}

/// Implements `ToSql` for a sized type through its `ToSqlType` set.
macro_rules! to_sql_via {
    ($t:ty, $name:literal, |$v:ident, $out:ident| $body:expr) => {
        impl ToSql for $t {
            fn accepts(&self, ty: Type) -> bool {
                <$t as ToSqlType>::accepts_null(ty)
            }

            fn rust_type(&self) -> &'static str {
                $name
            }

            fn to_sql(&self, _ty: Type, $out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
                let $v = self;
                $body
            }
        }
    };
}

accepts!(bool, Type::BOOL);
to_sql_via!(bool, "bool", |v, out| {
    out.push(u8::from(*v));
    Ok(IsNull::No)
});

impl FromSql for bool {
    fn accepts(ty: Type) -> bool {
        ty == Type::BOOL
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        match raw {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(DecodeError("bool must be one byte, 0 or 1")),
        }
    }
}

macro_rules! int_type {
    ($t:ty, $pg:path, $name:literal, $len:literal, $err:literal) => {
        accepts!($t, $pg);
        to_sql_via!($t, $name, |v, out| {
            out.extend_from_slice(&v.to_be_bytes());
            Ok(IsNull::No)
        });

        impl FromSql for $t {
            fn accepts(ty: Type) -> bool {
                ty == $pg
            }

            fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
                Ok(<$t>::from_be_bytes(fixed::<$len>(raw, $err)?))
            }
        }
    };
}

int_type!(i16, Type::INT2, "i16", 2, "int2 must be 2 bytes");
int_type!(i32, Type::INT4, "i32", 4, "int4 must be 4 bytes");
int_type!(i64, Type::INT8, "i64", 8, "int8 must be 8 bytes");

accepts!(f64, Type::FLOAT8);
to_sql_via!(f64, "f64", |v, out| {
    out.extend_from_slice(&v.to_bits().to_be_bytes());
    Ok(IsNull::No)
});

impl FromSql for f64 {
    fn accepts(ty: Type) -> bool {
        ty == Type::FLOAT8
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        Ok(f64::from_bits(u64::from_be_bytes(fixed::<8>(
            raw,
            "float8 must be 8 bytes",
        )?)))
    }
}

fn text_types(ty: Type) -> bool {
    matches!(ty, Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME)
}

fn encode_text(s: &str, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
    if s.contains('\0') {
        return Err(EncodeError(
            "text contains a NUL character, which PostgreSQL text cannot store",
        ));
    }
    out.extend_from_slice(s.as_bytes());
    Ok(IsNull::No)
}

impl ToSqlType for str {
    fn accepts_null(ty: Type) -> bool {
        text_types(ty)
    }
}

impl ToSql for str {
    fn accepts(&self, ty: Type) -> bool {
        text_types(ty)
    }

    fn rust_type(&self) -> &'static str {
        "str"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        encode_text(self, out)
    }
}

impl ToSqlType for String {
    fn accepts_null(ty: Type) -> bool {
        text_types(ty)
    }
}

impl ToSql for String {
    fn accepts(&self, ty: Type) -> bool {
        text_types(ty)
    }

    fn rust_type(&self) -> &'static str {
        "String"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        encode_text(self, out)
    }
}

impl FromSql for String {
    fn accepts(ty: Type) -> bool {
        text_types(ty)
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| DecodeError("text is not valid UTF-8"))
    }
}

impl ToSqlType for [u8] {
    fn accepts_null(ty: Type) -> bool {
        ty == Type::BYTEA
    }
}

impl ToSql for [u8] {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::BYTEA
    }

    fn rust_type(&self) -> &'static str {
        "[u8]"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        out.extend_from_slice(self);
        Ok(IsNull::No)
    }
}

impl ToSqlType for Vec<u8> {
    fn accepts_null(ty: Type) -> bool {
        ty == Type::BYTEA
    }
}

impl ToSql for Vec<u8> {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::BYTEA
    }

    fn rust_type(&self) -> &'static str {
        "Vec<u8>"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        out.extend_from_slice(self);
        Ok(IsNull::No)
    }
}

impl FromSql for Vec<u8> {
    fn accepts(ty: Type) -> bool {
        ty == Type::BYTEA
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        Ok(raw.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn enc<T: ToSql + ?Sized>(v: &T, ty: Type) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(v.to_sql(ty, &mut out).unwrap(), IsNull::No);
        out
    }

    #[test]
    fn integers_are_big_endian_and_strict() {
        assert_eq!(enc(&-2i16, Type::INT2), [0xff, 0xfe]);
        assert_eq!(enc(&1i32, Type::INT4), [0, 0, 0, 1]);
        assert_eq!(
            i64::from_sql(Type::INT8, &[0, 0, 0, 0, 0, 0, 1, 0]),
            Ok(256)
        );
        assert!(i32::from_sql(Type::INT4, &[0, 0, 1]).is_err());
        assert!(i16::from_sql(Type::INT2, &[0, 0, 1]).is_err());
        assert!(<i64 as FromSql>::accepts(Type::INT8));
        assert!(!<i64 as FromSql>::accepts(Type::INT4));
        assert!(!1i64.accepts(Type::INT4));
    }

    #[test]
    fn bool_accepts_only_zero_and_one() {
        assert_eq!(bool::from_sql(Type::BOOL, &[1]), Ok(true));
        assert_eq!(bool::from_sql(Type::BOOL, &[0]), Ok(false));
        assert!(bool::from_sql(Type::BOOL, &[2]).is_err());
        assert!(bool::from_sql(Type::BOOL, &[]).is_err());
    }

    #[test]
    fn text_rejects_nul_and_invalid_utf8() {
        let mut out = Vec::new();
        assert!("a\0b".to_sql(Type::TEXT, &mut out).is_err());
        assert!(String::from_sql(Type::TEXT, &[0xff]).is_err());
        assert_eq!(
            String::from_sql(Type::VARCHAR, "é".as_bytes()).unwrap(),
            "é"
        );
        assert!("x".accepts(Type::NAME));
        assert!(!"x".accepts(Type::BYTEA));
    }

    #[test]
    fn floats_keep_their_bits() {
        for v in [
            0.0,
            -0.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN_POSITIVE,
            1.5,
        ] {
            let back = f64::from_sql(Type::FLOAT8, &enc(&v, Type::FLOAT8)).unwrap();
            assert_eq!(back.to_bits(), v.to_bits());
        }
        let nan = f64::from_sql(Type::FLOAT8, &enc(&f64::NAN, Type::FLOAT8)).unwrap();
        assert!(nan.is_nan());
    }

    #[test]
    fn option_none_is_type_checked() {
        let none: Option<i64> = None;
        assert!(none.accepts(Type::INT8));
        assert!(!none.accepts(Type::INT4));
        let none_str: Option<&str> = None;
        assert!(none_str.accepts(Type::TEXT));
        let mut out = Vec::new();
        assert_eq!(none.to_sql(Type::INT8, &mut out).unwrap(), IsNull::Yes);
        assert!(out.is_empty());
        assert_eq!(Option::<i32>::from_sql_nullable(Type::INT4, None), Ok(None));
        assert_eq!(
            i32::from_sql_nullable(Type::INT4, None),
            Err(DecodeError::UNEXPECTED_NULL)
        );
    }
}

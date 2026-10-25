//! Typed parameters and results in the binary format.
//!
//! Each Rust type accepts a fixed set of PostgreSQL types:
//!
//! | Rust | PostgreSQL |
//! | --- | --- |
//! | `bool` | `bool` |
//! | `i16` | `int2` |
//! | `i32` | `int4` |
//! | `i64` | `int8` |
//! | `f64` | `float8` |
//! | `String`, `&str` | `text`, `varchar`, `bpchar`, `name` |
//! | `Vec<u8>`, `&[u8]` | `bytea` |
//! | [`Uuid`] | `uuid` |
//! | [`Timestamptz`] | `timestamptz` |
//! | [`Date`] | `date` |
//! | [`Numeric`] | `numeric`, as an exact decimal string |
//! | [`fstp_json::Value`] | `jsonb`, `json` (no duplicate keys, see below) |
//! | `Option<T>` | as `T`, with `None` for NULL |
//!
//! The client checks every parameter type that the server reports in
//! ParameterDescription, and every column type in RowDescription, against
//! this table. A mismatch is an error. Nothing is converted or
//! reinterpreted: an `int8` parameter needs an `i64`, and an `int4` column
//! cannot be read as `i64`. Cast in SQL when another type is wanted, for
//! example `$1::int8`.
//!
//! Decoding is strict too. A value with the wrong length, a `bool` byte
//! other than 0 or 1, text that is not UTF-8, or a date outside the server's
//! range is a [`DecodeError`]. Error messages never contain the value
//! (R-NF-02).
//!
//! PostgreSQL `json` keeps its input text, so an object may repeat a key.
//! fstp-json rejects duplicate keys, so such a value is a `DecodeError`.
//! Cast to `jsonb` in SQL, which keeps the last value of each key.

use std::fmt;

mod datetime;
mod json;
mod numeric;
mod primitive;
mod uuid;

pub use datetime::{Date, Timestamptz};
pub use json::{JSONB_VERSION, decode_json_with, json_limits};
pub use numeric::{NUMERIC_MAX_INTEGER_DIGITS, NUMERIC_MAX_SCALE, Numeric};
pub use uuid::Uuid;

/// A PostgreSQL type, identified by its OID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Type(u32);

impl Type {
    /// `bool`.
    pub const BOOL: Type = Type(16);
    /// `bytea`.
    pub const BYTEA: Type = Type(17);
    /// `"char"`, the single-byte internal type.
    pub const CHAR: Type = Type(18);
    /// `name`.
    pub const NAME: Type = Type(19);
    /// `int8`.
    pub const INT8: Type = Type(20);
    /// `int2`.
    pub const INT2: Type = Type(21);
    /// `int4`.
    pub const INT4: Type = Type(23);
    /// `text`.
    pub const TEXT: Type = Type(25);
    /// `oid`.
    pub const OID: Type = Type(26);
    /// `json`.
    pub const JSON: Type = Type(114);
    /// `float4`.
    pub const FLOAT4: Type = Type(700);
    /// `float8`.
    pub const FLOAT8: Type = Type(701);
    /// `unknown`.
    pub const UNKNOWN: Type = Type(705);
    /// `bpchar`, blank-padded `char(n)`.
    pub const BPCHAR: Type = Type(1042);
    /// `varchar`.
    pub const VARCHAR: Type = Type(1043);
    /// `date`.
    pub const DATE: Type = Type(1082);
    /// `time`.
    pub const TIME: Type = Type(1083);
    /// `timestamp` (without time zone).
    pub const TIMESTAMP: Type = Type(1114);
    /// `timestamptz`.
    pub const TIMESTAMPTZ: Type = Type(1184);
    /// `interval`.
    pub const INTERVAL: Type = Type(1186);
    /// `numeric`.
    pub const NUMERIC: Type = Type(1700);
    /// `void`.
    pub const VOID: Type = Type(2278);
    /// `uuid`.
    pub const UUID: Type = Type(2950);
    /// `jsonb`.
    pub const JSONB: Type = Type(3802);

    /// The type with OID `oid`.
    #[must_use]
    pub const fn from_oid(oid: u32) -> Type {
        Type(oid)
    }

    /// The OID.
    #[must_use]
    pub const fn oid(self) -> u32 {
        self.0
    }

    /// The SQL name for built-in types this crate knows.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Type::BOOL => "bool",
            Type::BYTEA => "bytea",
            Type::CHAR => "char",
            Type::NAME => "name",
            Type::INT8 => "int8",
            Type::INT2 => "int2",
            Type::INT4 => "int4",
            Type::TEXT => "text",
            Type::OID => "oid",
            Type::JSON => "json",
            Type::FLOAT4 => "float4",
            Type::FLOAT8 => "float8",
            Type::UNKNOWN => "unknown",
            Type::BPCHAR => "bpchar",
            Type::VARCHAR => "varchar",
            Type::DATE => "date",
            Type::TIME => "time",
            Type::TIMESTAMP => "timestamp",
            Type::TIMESTAMPTZ => "timestamptz",
            Type::INTERVAL => "interval",
            Type::NUMERIC => "numeric",
            Type::VOID => "void",
            Type::UUID => "uuid",
            Type::JSONB => "jsonb",
            _ => return None,
        })
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "oid {}", self.0),
        }
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Type({self})")
    }
}

/// Whether an encoded parameter is SQL NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsNull {
    /// The value is NULL; nothing was written.
    Yes,
    /// The value was written.
    No,
}

/// Why a parameter could not be encoded. The message names the problem,
/// never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError(pub(crate) &'static str);

impl EncodeError {
    /// An error with a fixed description.
    #[must_use]
    pub const fn new(message: &'static str) -> Self {
        Self(message)
    }

    /// The description.
    #[must_use]
    pub fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for EncodeError {}

/// Why a column value could not be decoded. The message names the
/// problem, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub(crate) &'static str);

impl DecodeError {
    /// An error with a fixed description.
    #[must_use]
    pub const fn new(message: &'static str) -> Self {
        Self(message)
    }

    /// The value is NULL but the Rust type cannot hold NULL. Use `Option`.
    pub const UNEXPECTED_NULL: DecodeError =
        DecodeError("unexpected NULL; read the column as an Option");

    /// The description.
    #[must_use]
    pub fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DecodeError {}

/// A Rust value that can be sent as a parameter in the binary format.
///
/// The methods take `&self` so that parameters can be passed as
/// `&[&(dyn ToSql + Sync)]`.
pub trait ToSql {
    /// True when this value may be sent for a parameter of type `ty`.
    fn accepts(&self, ty: Type) -> bool;

    /// The Rust type name, for error messages.
    fn rust_type(&self) -> &'static str;

    /// Appends the binary encoding for type `ty` to `out`, or returns
    /// [`IsNull::Yes`] without writing anything.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] when the value cannot be represented, for
    /// example text with a NUL character.
    fn to_sql(&self, ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError>;
}

/// A Rust value that can be read from a column in the binary format.
pub trait FromSql: Sized {
    /// True when a column of type `ty` may be read as this type.
    fn accepts(ty: Type) -> bool;

    /// Decodes a non-NULL value of type `ty`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for any malformed value.
    fn from_sql(ty: Type, raw: &[u8]) -> Result<Self, DecodeError>;

    /// Decodes SQL NULL. Only `Option` accepts it.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UNEXPECTED_NULL`] by default.
    fn from_sql_null(ty: Type) -> Result<Self, DecodeError> {
        let _ = ty;
        Err(DecodeError::UNEXPECTED_NULL)
    }

    /// Decodes a value that may be NULL.
    ///
    /// # Errors
    ///
    /// As for [`FromSql::from_sql`] and [`FromSql::from_sql_null`].
    fn from_sql_nullable(ty: Type, raw: Option<&[u8]>) -> Result<Self, DecodeError> {
        match raw {
            Some(raw) => Self::from_sql(ty, raw),
            None => Self::from_sql_null(ty),
        }
    }
}

impl<T: ToSql + ?Sized> ToSql for &T {
    fn accepts(&self, ty: Type) -> bool {
        (**self).accepts(ty)
    }

    fn rust_type(&self) -> &'static str {
        (**self).rust_type()
    }

    fn to_sql(&self, ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        (**self).to_sql(ty, out)
    }
}

impl<T: ToSql + ToSqlType> ToSql for Option<T> {
    fn accepts(&self, ty: Type) -> bool {
        match self {
            Some(v) => v.accepts(ty),
            None => <T as ToSqlType>::accepts_null(ty),
        }
    }

    fn rust_type(&self) -> &'static str {
        match self {
            Some(v) => v.rust_type(),
            None => "Option::None",
        }
    }

    fn to_sql(&self, ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        match self {
            Some(v) => v.to_sql(ty, out),
            None => Ok(IsNull::Yes),
        }
    }
}

impl<T: FromSql> FromSql for Option<T> {
    fn accepts(ty: Type) -> bool {
        T::accepts(ty)
    }

    fn from_sql(ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        T::from_sql(ty, raw).map(Some)
    }

    fn from_sql_null(_ty: Type) -> Result<Self, DecodeError> {
        Ok(None)
    }
}

/// The static type set of a `ToSql` type, so that `None::<T>` is checked
/// against the same types as `Some(T)`.
pub trait ToSqlType {
    /// True when a NULL of this Rust type may be sent for type `ty`.
    fn accepts_null(ty: Type) -> bool;
}

impl<T: ToSqlType> ToSqlType for Option<T> {
    fn accepts_null(ty: Type) -> bool {
        T::accepts_null(ty)
    }
}

impl<T: ToSqlType + ?Sized> ToSqlType for &T {
    fn accepts_null(ty: Type) -> bool {
        T::accepts_null(ty)
    }
}

/// Implements [`ToSqlType`] for a sized `ToSql` type: its accepted types.
macro_rules! accepts {
    ($t:ty, $($pg:path),+) => {
        impl $crate::types::ToSqlType for $t {
            fn accepts_null(ty: $crate::types::Type) -> bool {
                matches!(ty, $($pg)|+)
            }
        }
    };
}
pub(crate) use accepts;

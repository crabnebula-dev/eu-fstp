//! Typed mapping between Rust values and [`Value`], without serde.
//!
//! [`ToJson`] and [`FromJson`] cover booleans, every integer type (exact and
//! range-checked), strings, [`Vec`], [`Option`], [`BTreeMap`] with string
//! keys, [`Number`], [`Decimal`] and [`Value`] itself. The
//! [`json_struct!`](crate::json_struct) macro maps structs with named fields.
//!
//! A [`FromJsonError`] carries the path to the failing value, such as
//! `$.calls[2].deadline`.

use core::fmt;
use std::collections::BTreeMap;

use crate::number::{Decimal, Number};
use crate::object::Object;
use crate::path::{Path, Segment};
use crate::value::{Array, Value};

/// Converts a Rust value to a JSON [`Value`].
pub trait ToJson {
    /// Builds the JSON value.
    fn to_json(&self) -> Value;
}

/// Builds a Rust value from a JSON [`Value`].
pub trait FromJson: Sized {
    /// Converts `value`, or reports where and why it does not fit.
    fn from_json(value: &Value) -> Result<Self, FromJsonError>;
}

/// Why a value did not map to the requested type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromJsonErrorKind {
    /// The value has the wrong JSON type.
    WrongType {
        /// What the target type needs, such as `"a string"`.
        expected: &'static str,
        /// The JSON type found, such as `"number"`.
        found: &'static str,
    },
    /// The number has a fraction or exponent where an integer is needed.
    NotAnInteger,
    /// The integer does not fit the target type.
    OutOfRange {
        /// The target type, such as `"u8"`.
        target: &'static str,
    },
    /// A required member is absent.
    MissingField,
    /// The object has a member the target type does not define.
    UnknownField,
    /// A value that fails a rule of the target type. The message must not
    /// contain input content (R-NF-02).
    Invalid(&'static str),
}

/// A failed mapping with the path to the failing value.
///
/// `Display` and `Debug` mask member names taken from the input, such as map
/// keys and unknown member names (R-NF-02). Use [`FromJsonError::path`] for
/// the full path.
#[derive(Clone, PartialEq, Eq)]
pub struct FromJsonError {
    kind: FromJsonErrorKind,
    /// Segments from the leaf up; reversed when the path is read.
    reversed: Vec<Segment>,
}

impl FromJsonError {
    /// An error at the current value.
    pub fn new(kind: FromJsonErrorKind) -> FromJsonError {
        FromJsonError {
            kind,
            reversed: Vec::new(),
        }
    }

    /// A wrong-type error for `found`.
    pub fn wrong_type(expected: &'static str, found: &Value) -> FromJsonError {
        FromJsonError::new(FromJsonErrorKind::WrongType {
            expected,
            found: found.type_name(),
        })
    }

    /// An error for a value that breaks a rule of the target type.
    pub fn invalid(message: &'static str) -> FromJsonError {
        FromJsonError::new(FromJsonErrorKind::Invalid(message))
    }

    /// Prefixes the path with an array index.
    pub fn at_index(mut self, index: usize) -> FromJsonError {
        self.reversed.push(Segment::Index(index));
        self
    }

    /// Prefixes the path with a schema field name.
    pub fn at_field(mut self, name: &'static str) -> FromJsonError {
        self.reversed.push(Segment::Field(name));
        self
    }

    /// Prefixes the path with a member name taken from the input.
    pub fn at_key(mut self, key: &str) -> FromJsonError {
        self.reversed.push(Segment::Key(key.to_owned()));
        self
    }

    /// What went wrong.
    pub fn kind(&self) -> &FromJsonErrorKind {
        &self.kind
    }

    /// The path from the root to the failing value.
    pub fn path(&self) -> Path {
        Path::from_segments(self.reversed.iter().rev().cloned().collect())
    }

    fn message(&self) -> String {
        match &self.kind {
            FromJsonErrorKind::WrongType { expected, found } => {
                format!("expected {expected}, found {found}")
            }
            FromJsonErrorKind::NotAnInteger => "expected an integer lexeme".to_owned(),
            FromJsonErrorKind::OutOfRange { target } => {
                format!("integer out of range for {target}")
            }
            FromJsonErrorKind::MissingField => "missing required member".to_owned(),
            FromJsonErrorKind::UnknownField => "unknown member".to_owned(),
            FromJsonErrorKind::Invalid(message) => (*message).to_owned(),
        }
    }
}

impl fmt::Display for FromJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path().redacted(), self.message())
    }
}

impl fmt::Debug for FromJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FromJsonError")
            .field("kind", &self.kind)
            .field("path", &self.path().redacted())
            .finish()
    }
}

impl std::error::Error for FromJsonError {}

/// The member name for a struct field identifier, as `json_struct!` uses it.
///
/// A raw identifier such as `r#type` gives `type`. Any other name comes back
/// unchanged.
///
/// ```
/// use fstp_json::typed::field_name;
/// assert_eq!(field_name(stringify!(r#type)), "type");
/// assert_eq!(field_name("deadline"), "deadline");
/// ```
pub const fn field_name(ident: &'static str) -> &'static str {
    match ident.as_bytes() {
        [b'r', b'#', ..] => match ident.split_at_checked(2) {
            Some((_, rest)) => rest,
            None => ident,
        },
        _ => ident,
    }
}

/// Returns the object inside `value`, or a wrong-type error.
pub fn expect_object(value: &Value) -> Result<&Object, FromJsonError> {
    value
        .as_object()
        .ok_or_else(|| FromJsonError::wrong_type("an object", value))
}

/// Reads a required member. A missing member is an error at `$.key`.
pub fn required_field<T: FromJson>(object: &Object, key: &'static str) -> Result<T, FromJsonError> {
    match object.get(key) {
        Some(v) => T::from_json(v).map_err(|e| e.at_field(key)),
        None => Err(FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key)),
    }
}

/// Reads an optional member. An absent member and `null` both give `None`.
pub fn optional_field<T: FromJson>(
    object: &Object,
    key: &'static str,
) -> Result<Option<T>, FromJsonError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => T::from_json(v).map(Some).map_err(|e| e.at_field(key)),
    }
}

/// Fails on the first member whose name is not in `fields`.
pub fn reject_unknown(object: &Object, fields: &[&str]) -> Result<(), FromJsonError> {
    match object.keys().find(|k| !fields.contains(k)) {
        Some(k) => Err(FromJsonError::new(FromJsonErrorKind::UnknownField).at_key(k)),
        None => Ok(()),
    }
}

impl ToJson for Value {
    fn to_json(&self) -> Value {
        self.clone()
    }
}

impl FromJson for Value {
    fn from_json(value: &Value) -> Result<Value, FromJsonError> {
        Ok(value.clone())
    }
}

impl ToJson for bool {
    fn to_json(&self) -> Value {
        Value::Bool(*self)
    }
}

impl FromJson for bool {
    fn from_json(value: &Value) -> Result<bool, FromJsonError> {
        value
            .as_bool()
            .ok_or_else(|| FromJsonError::wrong_type("a boolean", value))
    }
}

impl ToJson for str {
    fn to_json(&self) -> Value {
        Value::String(self.to_owned())
    }
}

impl ToJson for String {
    fn to_json(&self) -> Value {
        Value::String(self.clone())
    }
}

impl FromJson for String {
    fn from_json(value: &Value) -> Result<String, FromJsonError> {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| FromJsonError::wrong_type("a string", value))
    }
}

impl ToJson for Number {
    fn to_json(&self) -> Value {
        Value::Number(self.clone())
    }
}

impl FromJson for Number {
    fn from_json(value: &Value) -> Result<Number, FromJsonError> {
        value
            .as_number()
            .cloned()
            .ok_or_else(|| FromJsonError::wrong_type("a number", value))
    }
}

impl ToJson for Decimal {
    fn to_json(&self) -> Value {
        Value::Number(Number::from_decimal(self))
    }
}

impl FromJson for Decimal {
    fn from_json(value: &Value) -> Result<Decimal, FromJsonError> {
        let n = value
            .as_number()
            .ok_or_else(|| FromJsonError::wrong_type("a number", value))?;
        n.as_decimal()
            .map_err(|_| FromJsonError::invalid("decimal exponent out of range"))
    }
}

impl ToJson for Object {
    fn to_json(&self) -> Value {
        Value::Object(self.clone())
    }
}

impl FromJson for Object {
    fn from_json(value: &Value) -> Result<Object, FromJsonError> {
        expect_object(value).cloned()
    }
}

/// Reads an integer number: integer lexeme first, then the range.
fn integer<T: TryFrom<i128> + TryFrom<u128>>(
    value: &Value,
    target: &'static str,
) -> Result<T, FromJsonError> {
    let n = value
        .as_number()
        .ok_or_else(|| FromJsonError::wrong_type("an integer", value))?;
    if !n.is_integer() {
        return Err(FromJsonError::new(FromJsonErrorKind::NotAnInteger));
    }
    let out_of_range = || FromJsonError::new(FromJsonErrorKind::OutOfRange { target });
    match n.as_i128() {
        Some(i) => T::try_from(i).map_err(|_| out_of_range()),
        None => n
            .as_u128()
            .and_then(|u| T::try_from(u).ok())
            .ok_or_else(out_of_range),
    }
}

macro_rules! integer_impls {
    ($($t:ident),*) => {
        $(
            impl ToJson for $t {
                fn to_json(&self) -> Value {
                    Value::Number(Number::from(*self))
                }
            }

            impl FromJson for $t {
                fn from_json(value: &Value) -> Result<$t, FromJsonError> {
                    integer(value, stringify!($t))
                }
            }
        )*
    };
}

integer_impls!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);

impl<T: ToJson> ToJson for [T] {
    fn to_json(&self) -> Value {
        Value::Array(self.iter().map(ToJson::to_json).collect())
    }
}

impl<T: ToJson, const N: usize> ToJson for [T; N] {
    fn to_json(&self) -> Value {
        self.as_slice().to_json()
    }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> Value {
        self.as_slice().to_json()
    }
}

impl<T: FromJson> FromJson for Vec<T> {
    fn from_json(value: &Value) -> Result<Vec<T>, FromJsonError> {
        let items: &Array = value
            .as_array()
            .ok_or_else(|| FromJsonError::wrong_type("an array", value))?;
        items
            .iter()
            .enumerate()
            .map(|(i, item)| T::from_json(item).map_err(|e| e.at_index(i)))
            .collect()
    }
}

/// `None` maps to `null`. Inside [`json_struct!`](crate::json_struct), an
/// optional field with `None` is omitted instead.
impl<T: ToJson> ToJson for Option<T> {
    fn to_json(&self) -> Value {
        match self {
            Some(v) => v.to_json(),
            None => Value::Null,
        }
    }
}

/// `null` maps to `None`.
impl<T: FromJson> FromJson for Option<T> {
    fn from_json(value: &Value) -> Result<Option<T>, FromJsonError> {
        match value {
            Value::Null => Ok(None),
            v => T::from_json(v).map(Some),
        }
    }
}

impl<T: ToJson> ToJson for BTreeMap<String, T> {
    fn to_json(&self) -> Value {
        let mut object = Object::with_capacity(self.len());
        for (k, v) in self {
            // Map keys are unique, so no name repeats.
            object.push_new(k.clone(), v.to_json());
        }
        Value::Object(object)
    }
}

impl<T: FromJson> FromJson for BTreeMap<String, T> {
    fn from_json(value: &Value) -> Result<BTreeMap<String, T>, FromJsonError> {
        let object = expect_object(value)?;
        let mut out = BTreeMap::new();
        for (k, v) in object.iter() {
            let item = T::from_json(v).map_err(|e| e.at_key(k))?;
            out.insert(k.to_owned(), item);
        }
        Ok(out)
    }
}

impl<T: ToJson + ?Sized> ToJson for &T {
    fn to_json(&self) -> Value {
        (**self).to_json()
    }
}

impl<T: ToJson + ?Sized> ToJson for Box<T> {
    fn to_json(&self) -> Value {
        (**self).to_json()
    }
}

impl<T: FromJson> FromJson for Box<T> {
    fn from_json(value: &Value) -> Result<Box<T>, FromJsonError> {
        T::from_json(value).map(Box::new)
    }
}

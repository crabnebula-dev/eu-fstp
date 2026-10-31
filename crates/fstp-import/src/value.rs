//! `UntrustedValue`: a proposed value, held as data (TH-47, I-65).
//!
//! A proposed value comes from an untrusted document through a proposer.
//! It may be any JSON value: a string that spells JSON members, an
//! injection phrase, a number with any lexeme. The type keeps it unchanged
//! and offers no implicit string view, so it cannot be formatted or pasted
//! into an instruction by accident.
//!
//! Every value has one normal text: compact JSON with object members
//! sorted by UTF-16 code units, as RFC 8785 sorts them, string escapes as
//! the in-house serializer writes them, and every number lexeme unchanged.
//! Two values are equal exactly when their normal texts are equal, which is
//! `fstp_json::Value` equality. The normal text is what the shell stores in
//! the text store, behind a [`crate::ValueTextRef`], and what it hashes into
//! a [`crate::ValueDigest`]. No ledger body holds it (ADR-007).
//!
//! Number lexemes stay as given, so a value such as
//! `12345678901234567890` survives byte for byte. RFC 8785 itself would
//! change it, so the text store holds the normal text as it is.
//!
//! Interim, pending Daniel: the bounds [`MAX_VALUE_BYTES`],
//! [`MAX_VALUE_DEPTH`] and [`MAX_VALUE_NODES`]. They bound what one
//! proposer batch and one stored text may hold.

use fstp_json::{Array, Object, ParseLimits, Value, cmp_utf16, to_compact};

use crate::error::ImportError;

/// The longest normal text of one value, in bytes.
pub const MAX_VALUE_BYTES: usize = 16_384;
/// The deepest nesting of one value. A scalar has depth 0, `[[]]` depth 2.
pub const MAX_VALUE_DEPTH: usize = 16;
/// The most JSON values in one value, containers included.
pub const MAX_VALUE_NODES: usize = 1_024;

/// A proposed value. Never `Display`, never `Deref`. `Debug` shows the
/// length only, so a log line never carries the content.
#[derive(Clone)]
pub struct UntrustedValue {
    /// The normal text.
    text: String,
    /// The value with sorted members, parsed from or giving `text`.
    value: Value,
}

impl UntrustedValue {
    /// Wraps `value`. Members are sorted. Nothing else changes: no string
    /// is trimmed or normalised and no number lexeme is rewritten. Refused
    /// above the bounds of this module.
    pub fn new(value: &Value) -> Result<UntrustedValue, ImportError> {
        let mut nodes = 0usize;
        let sorted = sort(value, 0, &mut nodes)?;
        let text = to_compact(&sorted);
        if text.len() > MAX_VALUE_BYTES {
            return Err(ImportError::ValueOutOfBounds);
        }
        Ok(UntrustedValue {
            text,
            value: sorted,
        })
    }

    /// Parses `text` as one JSON value within this module's bounds and
    /// wraps it. The text may be in any JSON spelling.
    pub fn parse(text: &[u8]) -> Result<UntrustedValue, ImportError> {
        let v = fstp_json::parse_with(text, &parse_limits()).map_err(|_| ImportError::NotJson)?;
        UntrustedValue::new(&v)
    }

    /// Parses a stored normal text. Any other spelling of the same value is
    /// refused, so a stored value has exactly one form.
    pub fn from_normal_text(text: &str) -> Result<UntrustedValue, ImportError> {
        let v = UntrustedValue::parse(text.as_bytes())?;
        if v.text == text {
            Ok(v)
        } else {
            Err(ImportError::Malformed("value: not in normal form"))
        }
    }

    /// The normal text, as data. Pass it only through a data channel.
    /// Never concatenate it into an instruction for a model.
    pub fn as_data(&self) -> &str {
        &self.text
    }

    /// A copy of the value, as data, for a strict per-field decoder.
    pub fn data_value(&self) -> Value {
        self.value.clone()
    }
}

impl PartialEq for UntrustedValue {
    fn eq(&self, other: &UntrustedValue) -> bool {
        self.text == other.text
    }
}

impl Eq for UntrustedValue {}

impl core::hash::Hash for UntrustedValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl core::fmt::Debug for UntrustedValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UntrustedValue")
            .field("bytes", &self.text.len())
            .finish()
    }
}

/// The parse limits of one value's text.
fn parse_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_VALUE_BYTES)
        .with_max_depth(MAX_VALUE_DEPTH)
        .with_max_string_bytes(MAX_VALUE_BYTES)
        .with_max_container_len(MAX_VALUE_NODES)
        .with_max_nodes(MAX_VALUE_NODES)
}

/// `v` with every object's members sorted by UTF-16 code units. The
/// recursion is bounded by [`MAX_VALUE_DEPTH`], and `nodes` counts every
/// value against [`MAX_VALUE_NODES`].
fn sort(v: &Value, depth: usize, nodes: &mut usize) -> Result<Value, ImportError> {
    *nodes = nodes.checked_add(1).ok_or(ImportError::ValueOutOfBounds)?;
    if *nodes > MAX_VALUE_NODES {
        return Err(ImportError::ValueOutOfBounds);
    }
    match v {
        Value::Array(a) => {
            let depth = deeper(depth)?;
            let mut out = Array::with_capacity(a.len());
            for x in a.iter() {
                out.push(sort(x, depth, nodes)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(o) => {
            let depth = deeper(depth)?;
            let mut members: Vec<(&str, &Value)> = o.iter().collect();
            members.sort_by(|a, b| cmp_utf16(a.0, b.0));
            let mut out = Object::with_capacity(members.len());
            for (k, x) in members {
                out.insert(k, sort(x, depth, nodes)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// One level deeper, refused beyond [`MAX_VALUE_DEPTH`].
fn deeper(depth: usize) -> Result<usize, ImportError> {
    let d = depth.checked_add(1).ok_or(ImportError::ValueOutOfBounds)?;
    if d > MAX_VALUE_DEPTH {
        Err(ImportError::ValueOutOfBounds)
    } else {
        Ok(d)
    }
}

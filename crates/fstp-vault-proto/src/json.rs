//! Canonical JSON helpers shared by the codecs of this crate and of the
//! vault crates (RFC 8785, ADR-006, H-05).
//!
//! A message has one spelling. A decoder parses the bytes within its
//! limits, writes the value back in RFC 8785 form, and refuses the input
//! unless both are the same bytes. Then it reads each member by name and
//! refuses any member set other than the expected one.
//!
//! - Ids are decimal strings with no sign and no leading zero, within
//!   `u128`.
//! - Integers are JSON integers within plus or minus 2^53 - 1, the range
//!   RFC 8785 writes exactly.
//! - Sets are arrays in strictly ascending order.
//! - Amounts are `{"amount":"<ADR-006 text>","currency":"EUR"}`.

use std::collections::{BTreeMap, BTreeSet};

use fstp_json::{Array, Number, Object, ParseLimits, Value};
use fstp_money::{Amount, Currency};

use crate::ProtoError;

/// The largest integer RFC 8785 writes exactly: 2^53 - 1.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// [`MAX_SAFE_INTEGER`] as a signed integer.
pub const MAX_SAFE_INTEGER_I64: i64 = 9_007_199_254_740_991;

/// The parse limits of a vault message: 1 MiB, depth 8, 10 000 members or
/// elements per container.
pub fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(1 << 20)
        .with_max_depth(8)
        .with_max_string_bytes(64 << 10)
        .with_max_number_len(32)
        .with_max_container_len(10_000)
        .with_max_nodes(100_000)
        .with_max_memory_bytes(8 << 20)
}

/// The most account ids in one vault response, over all its answers. The
/// vault cuts a `ChangedSince` answer to stay within it (NOTE 5), and a
/// write that touches more accounts is refused. An interim constant with
/// no P- id.
pub const MAX_ANSWER_ACCOUNTS: usize = 100_000;

/// The longest vault response, in bytes: room for
/// [`MAX_ANSWER_ACCOUNTS`] ids of 39 digits and 10 000 answers.
pub const MAX_RESPONSE_LEN: usize = 8 << 20;

/// The parse limits of a vault response and of a stored account set. They
/// admit every response the vault emits: [`MAX_ANSWER_ACCOUNTS`] ids in
/// one array, within [`MAX_RESPONSE_LEN`] bytes.
pub fn response_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_RESPONSE_LEN)
        .with_max_depth(8)
        .with_max_string_bytes(64 << 10)
        .with_max_number_len(32)
        .with_max_container_len(MAX_ANSWER_ACCOUNTS)
        .with_max_nodes(2 * MAX_ANSWER_ACCOUNTS)
        .with_max_memory_bytes(32 << 20)
}

/// Parses `bytes` within `limits` and refuses any spelling other than the
/// RFC 8785 one.
///
/// # Errors
///
/// [`ProtoError::Json`] for input that is not JSON within the limits, and
/// [`ProtoError::NotCanonical`] for another spelling.
pub fn parse_canonical(bytes: &[u8], limits: &ParseLimits) -> Result<Value, ProtoError> {
    let v = fstp_json::parse_with(bytes, limits).map_err(|_| ProtoError::Json)?;
    let c = fstp_json::to_canonical(&v).map_err(|_| ProtoError::NotCanonical)?;
    if c.as_bytes() == bytes {
        Ok(v)
    } else {
        Err(ProtoError::NotCanonical)
    }
}

/// The RFC 8785 bytes of `v`.
///
/// # Errors
///
/// [`ProtoError::NotCanonical`] when `v` holds a number with no exact
/// canonical form.
pub fn to_canonical(v: &Value) -> Result<Vec<u8>, ProtoError> {
    fstp_json::to_canonical(v)
        .map(String::into_bytes)
        .map_err(|_| ProtoError::NotCanonical)
}

/// The object `v`, which must hold exactly the members `names`.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn object<'a>(
    v: &'a Value,
    names: &[&str],
    what: &'static str,
) -> Result<&'a Object, ProtoError> {
    let o = v.as_object().ok_or(ProtoError::Shape(what))?;
    if o.len() != names.len() || !names.iter().all(|n| o.contains_key(n)) {
        return Err(ProtoError::Shape(what));
    }
    Ok(o)
}

/// Member `name` of `o`.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` when it is missing.
pub fn member<'a>(o: &'a Object, name: &str, what: &'static str) -> Result<&'a Value, ProtoError> {
    o.get(name).ok_or(ProtoError::Shape(what))
}

/// The `type` member of an object, before its other members are read.
///
/// # Errors
///
/// [`ProtoError::Shape`] when it is missing or not a string.
pub fn type_of<'a>(v: &'a Value, what: &'static str) -> Result<&'a str, ProtoError> {
    v.as_object()
        .and_then(|o| o.get("type"))
        .and_then(Value::as_str)
        .ok_or(ProtoError::Shape(what))
}

/// A string member.
///
/// # Errors
///
/// [`ProtoError::Shape`] when it is missing or not a string.
pub fn string<'a>(o: &'a Object, name: &str, what: &'static str) -> Result<&'a str, ProtoError> {
    member(o, name, what)?
        .as_str()
        .ok_or(ProtoError::Shape(what))
}

/// A boolean member.
///
/// # Errors
///
/// [`ProtoError::Shape`] when it is missing or not a boolean.
pub fn boolean(o: &Object, name: &str, what: &'static str) -> Result<bool, ProtoError> {
    member(o, name, what)?
        .as_bool()
        .ok_or(ProtoError::Shape(what))
}

/// A decimal id with no sign and no leading zero, within `u128`.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn parse_id(s: &str, what: &'static str) -> Result<u128, ProtoError> {
    let digits = !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let leading_zero = s.len() > 1 && s.starts_with('0');
    if !digits || leading_zero {
        return Err(ProtoError::Shape(what));
    }
    s.parse::<u128>().map_err(|_| ProtoError::Shape(what))
}

/// An id value: a decimal string.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn id_value(v: &Value, what: &'static str) -> Result<u128, ProtoError> {
    parse_id(v.as_str().ok_or(ProtoError::Shape(what))?, what)
}

/// An id member.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn id(o: &Object, name: &str, what: &'static str) -> Result<u128, ProtoError> {
    id_value(member(o, name, what)?, what)
}

/// An id member that may be `null`.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn opt_id(o: &Object, name: &str, what: &'static str) -> Result<Option<u128>, ProtoError> {
    let v = member(o, name, what)?;
    if v.is_null() {
        Ok(None)
    } else {
        id_value(v, what).map(Some)
    }
}

/// An array of ids in strictly ascending order.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn id_list_value(v: &Value, what: &'static str) -> Result<Vec<u128>, ProtoError> {
    let a = v.as_array().ok_or(ProtoError::Shape(what))?;
    let mut out: Vec<u128> = Vec::with_capacity(a.len());
    for item in a.iter() {
        let n = id_value(item, what)?;
        if out.last().is_some_and(|last| *last >= n) {
            return Err(ProtoError::Shape(what));
        }
        out.push(n);
    }
    Ok(out)
}

/// A member that holds a set of ids, as an ascending array.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn id_set<T: Ord>(
    o: &Object,
    name: &str,
    what: &'static str,
    wrap: impl Fn(u128) -> T,
) -> Result<BTreeSet<T>, ProtoError> {
    Ok(id_list_value(member(o, name, what)?, what)?
        .into_iter()
        .map(wrap)
        .collect())
}

/// An unsigned integer within [`MAX_SAFE_INTEGER`].
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn uint_value(v: &Value, what: &'static str) -> Result<u64, ProtoError> {
    let n = v.as_number().ok_or(ProtoError::Shape(what))?;
    match n.as_u64() {
        Some(x) if n.is_integer() && x <= MAX_SAFE_INTEGER => Ok(x),
        _ => Err(ProtoError::Shape(what)),
    }
}

/// An unsigned integer member.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn uint(o: &Object, name: &str, what: &'static str) -> Result<u64, ProtoError> {
    uint_value(member(o, name, what)?, what)
}

/// An unsigned integer member that may be `null`.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn opt_uint(o: &Object, name: &str, what: &'static str) -> Result<Option<u64>, ProtoError> {
    let v = member(o, name, what)?;
    if v.is_null() {
        Ok(None)
    } else {
        uint_value(v, what).map(Some)
    }
}

/// A signed integer member within plus or minus [`MAX_SAFE_INTEGER`].
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn int(o: &Object, name: &str, what: &'static str) -> Result<i64, ProtoError> {
    let n = member(o, name, what)?
        .as_number()
        .ok_or(ProtoError::Shape(what))?;
    match n.as_i64() {
        Some(x)
            if n.is_integer() && (-MAX_SAFE_INTEGER_I64..=MAX_SAFE_INTEGER_I64).contains(&x) =>
        {
            Ok(x)
        }
        _ => Err(ProtoError::Shape(what)),
    }
}

/// A `u16` member, written as a JSON integer.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn small(o: &Object, name: &str, what: &'static str) -> Result<u16, ProtoError> {
    u16::try_from(uint(o, name, what)?).map_err(|_| ProtoError::Shape(what))
}

/// An ADR-006 amount value in EUR.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` for any other spelling.
pub fn amount_value(v: &Value, what: &'static str) -> Result<Amount, ProtoError> {
    let o = object(v, &["amount", "currency"], what)?;
    let currency =
        Currency::from_code(string(o, "currency", what)?).map_err(|_| ProtoError::Shape(what))?;
    Amount::parse(string(o, "amount", what)?, currency).map_err(|_| ProtoError::Shape(what))
}

/// An amount member.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn amount(o: &Object, name: &str, what: &'static str) -> Result<Amount, ProtoError> {
    amount_value(member(o, name, what)?, what)
}

/// A member that maps ids to amounts.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn amount_map<T: Ord>(
    o: &Object,
    name: &str,
    what: &'static str,
    wrap: impl Fn(u128) -> T,
) -> Result<BTreeMap<T, Amount>, ProtoError> {
    let m = member(o, name, what)?
        .as_object()
        .ok_or(ProtoError::Shape(what))?;
    let mut out = BTreeMap::new();
    for (k, v) in m.iter() {
        let key = wrap(parse_id(k, what)?);
        if out.insert(key, amount_value(v, what)?).is_some() {
            return Err(ProtoError::Shape(what));
        }
    }
    Ok(out)
}

/// Lowercase hex digits of exactly `N` bytes.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn hex_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N], ProtoError> {
    let v = unhex(s, what)?;
    <[u8; N]>::try_from(v.as_slice()).map_err(|_| ProtoError::Shape(what))
}

/// Lowercase hex digits of any even length.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` otherwise.
pub fn unhex(s: &str, what: &'static str) -> Result<Vec<u8>, ProtoError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(ProtoError::Shape(what));
    }
    let nibble = |c: u8| -> Result<u8, ProtoError> {
        match c {
            b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
            b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
            _ => Err(ProtoError::Shape(what)),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        if let [hi, lo] = pair {
            out.push((nibble(*hi)? << 4) | nibble(*lo)?);
        }
    }
    Ok(out)
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Builders.

/// An object from members. The canonical writer sorts them.
///
/// # Errors
///
/// [`ProtoError::Shape`] on a repeated member name.
pub fn obj(members: Vec<(&str, Value)>) -> Result<Value, ProtoError> {
    let members: Vec<(String, Value)> = members
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    Object::from_members(members)
        .map(Value::Object)
        .map_err(|_| ProtoError::Shape("a repeated member"))
}

/// The id value of `n`.
pub fn id_json(n: u128) -> Value {
    Value::String(n.to_string())
}

/// An id value, or `null`.
pub fn opt_id_json(n: Option<u128>) -> Value {
    n.map_or(Value::Null, id_json)
}

/// An ascending array of ids.
pub fn id_list_json(ids: impl IntoIterator<Item = u128>) -> Value {
    Value::Array(ids.into_iter().map(id_json).collect::<Array>())
}

/// An unsigned integer value within [`MAX_SAFE_INTEGER`].
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` beyond it.
pub fn uint_json(n: u64, what: &'static str) -> Result<Value, ProtoError> {
    if n > MAX_SAFE_INTEGER {
        return Err(ProtoError::Shape(what));
    }
    Ok(Value::Number(Number::from(n)))
}

/// A signed integer value within plus or minus [`MAX_SAFE_INTEGER`].
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` beyond it.
pub fn int_json(n: i64, what: &'static str) -> Result<Value, ProtoError> {
    if !(-MAX_SAFE_INTEGER_I64..=MAX_SAFE_INTEGER_I64).contains(&n) {
        return Err(ProtoError::Shape(what));
    }
    Ok(Value::Number(Number::from(n)))
}

/// The ADR-006 value of `a`. A negative amount has no ADR-006 spelling.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` for a negative amount.
pub fn amount_json(a: Amount, what: &'static str) -> Result<Value, ProtoError> {
    if a.minor() < 0 {
        return Err(ProtoError::Shape(what));
    }
    obj(vec![
        ("amount", Value::String(a.to_string())),
        ("currency", Value::String(a.currency().code().to_owned())),
    ])
}

/// The value of a map from ids to amounts.
///
/// # Errors
///
/// [`ProtoError::Shape`] with `what` for a negative amount.
pub fn amount_map_json(
    m: impl IntoIterator<Item = (u128, Amount)>,
    what: &'static str,
) -> Result<Value, ProtoError> {
    let mut members = Vec::new();
    for (k, a) in m {
        members.push((k.to_string(), amount_json(a, what)?));
    }
    Object::from_members(members)
        .map(Value::Object)
        .map_err(|_| ProtoError::Shape(what))
}

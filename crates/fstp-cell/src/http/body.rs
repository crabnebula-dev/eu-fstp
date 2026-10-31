//! Request body decoding shared by every cell route (TH-26, I-18,
//! R-NF-02, design sections 8.7 and 15).
//!
//! Every route body is one JSON object in its RFC 8785 canonical text, as
//! the cell's records and commands are (ADR-007). So each body has one
//! spelling, and no two parsers can read it differently.
//!
//! - The size limit is checked before any byte is parsed.
//! - `fstp-json` parses under fixed limits. It never recurses, so deep
//!   nesting cannot exhaust the stack.
//! - The parsed value is written again in canonical form, and the body
//!   must equal it byte for byte. White space, member order, escapes such
//!   as `0` and every other second spelling are refused.
//! - A member named `minor` is refused at any depth (I-18, NOTE 14). The
//!   flag never comes from a request. Names are compared after JSON
//!   unescaping, so an escaped spelling is caught too.
//! - Each schema lists its members. A missing member and an unknown member
//!   are refused. Byte strings are lowercase hexadecimal of their exact
//!   length, as in the `fstp-auth` codecs.
//!
//! A refusal names a kind or a schema member, never request content.

use std::fmt;

use fstp_json::{Object, ParseLimits, Value};

/// The deepest nesting a route body may use. A cell command such as a
/// programme policy nests well below it.
pub const MAX_BODY_DEPTH: usize = 32;

/// Why a request body was refused. No variant carries request content
/// (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyRefusal {
    /// The body is longer than the route's limit.
    TooLarge,
    /// The body is not one JSON text within the parse limits.
    NotJson,
    /// The body is JSON but not its RFC 8785 canonical text.
    NotCanonical,
    /// The body is not a JSON object.
    NotAnObject,
    /// A member named `minor` appears somewhere in the body (I-18).
    MinorMember,
    /// A member that the route's schema does not list.
    UnknownMember,
    /// A schema member is missing or malformed. It names the member.
    Member(&'static str),
    /// The `command` member does not decode as a cell command.
    Command,
}

impl BodyRefusal {
    /// A fixed description of the refusal.
    pub const fn description(self) -> &'static str {
        match self {
            BodyRefusal::TooLarge => "the body is over the route's limit",
            BodyRefusal::NotJson => "the body is not JSON within the limits",
            BodyRefusal::NotCanonical => "the body is not canonical JSON",
            BodyRefusal::NotAnObject => "the body is not a JSON object",
            BodyRefusal::MinorMember => "the body names a minor member",
            BodyRefusal::UnknownMember => "the body holds a member its schema does not list",
            BodyRefusal::Member(_) => "a schema member is missing or malformed",
            BodyRefusal::Command => "the command member is not a cell command",
        }
    }
}

impl fmt::Display for BodyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyRefusal::Member(name) => write!(f, "{}: {name}", self.description()),
            other => f.write_str(other.description()),
        }
    }
}

impl std::error::Error for BodyRefusal {}

/// The parse limits of a body of at most `limit` bytes.
fn limits(limit: usize) -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(limit)
        .with_max_depth(MAX_BODY_DEPTH)
        .with_max_string_bytes(limit)
        .with_max_nodes(limit)
        .with_max_container_len(limit)
        .with_max_memory_bytes(limit.saturating_mul(16))
}

/// Parses `bytes` as one canonical JSON object of at most `limit` bytes,
/// with no `minor` member at any depth.
///
/// # Errors
///
/// The first [`BodyRefusal`] that applies, in the order of the module
/// documentation.
pub fn object(bytes: &[u8], limit: usize) -> Result<Object, BodyRefusal> {
    if bytes.len() > limit {
        return Err(BodyRefusal::TooLarge);
    }
    let value = fstp_json::parse_with(bytes, &limits(limit)).map_err(|_| BodyRefusal::NotJson)?;
    let canonical = fstp_json::to_canonical(&value).map_err(|_| BodyRefusal::NotCanonical)?;
    if canonical.as_bytes() != bytes {
        return Err(BodyRefusal::NotCanonical);
    }
    if names_minor(&value) {
        return Err(BodyRefusal::MinorMember);
    }
    match value {
        Value::Object(o) => Ok(o),
        _ => Err(BodyRefusal::NotAnObject),
    }
}

/// Whether any object in `value`, at any depth, has a member named
/// `minor`. The walk keeps its own stack, so it never recurses.
fn names_minor(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(o) => {
                for (name, inner) in o.iter() {
                    if name == "minor" {
                        return true;
                    }
                    stack.push(inner);
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    false
}

/// Checks that `o` holds every member of `required`, and no member
/// outside `required` and `optional`.
///
/// # Errors
///
/// [`BodyRefusal::UnknownMember`] for a member the schema does not list,
/// then [`BodyRefusal::Member`] for the first missing required member.
pub fn members(
    o: &Object,
    required: &[&'static str],
    optional: &[&'static str],
) -> Result<(), BodyRefusal> {
    for (name, _) in o.iter() {
        if !required.contains(&name) && !optional.contains(&name) {
            return Err(BodyRefusal::UnknownMember);
        }
    }
    for name in required {
        if !o.contains_key(name) {
            return Err(BodyRefusal::Member(name));
        }
    }
    Ok(())
}

/// The value of hex digit `c`, lowercase only.
const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => match c.checked_sub(b'a') {
            Some(v) => v.checked_add(10),
            None => None,
        },
        _ => None,
    }
}

/// Decodes lowercase hexadecimal of exactly `N` bytes.
pub fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let (hi, lo) = match pair {
            [h, l] => (nibble(*h)?, nibble(*l)?),
            _ => return None,
        };
        *slot = hi.checked_shl(4)? | lo;
    }
    Some(out)
}

/// Decodes lowercase hexadecimal of 1 to `max` bytes.
pub fn hex_vec(s: &str, max: usize) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) || bytes.len() / 2 > max {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let (hi, lo) = match pair {
            [h, l] => (nibble(*h)?, nibble(*l)?),
            _ => return None,
        };
        out.push(hi.checked_shl(4)? | lo);
    }
    Some(out)
}

/// Lowercase hexadecimal of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                out.push(char::from(*d));
            }
        }
    }
    out
}

/// The string member `name` of `o`.
///
/// # Errors
///
/// [`BodyRefusal::Member`] when the member is absent or not a string.
pub fn string<'a>(o: &'a Object, name: &'static str) -> Result<&'a str, BodyRefusal> {
    o.get(name)
        .and_then(Value::as_str)
        .ok_or(BodyRefusal::Member(name))
}

/// The member `name` of `o` as lowercase hexadecimal of `N` bytes.
///
/// # Errors
///
/// [`BodyRefusal::Member`] when the member is absent, not a string, or
/// another spelling.
pub fn hex_member<const N: usize>(o: &Object, name: &'static str) -> Result<[u8; N], BodyRefusal> {
    hex_array::<N>(string(o, name)?).ok_or(BodyRefusal::Member(name))
}

/// The optional member `name` of `o` as lowercase hexadecimal of `N`
/// bytes. `null` is not a spelling of absent.
///
/// # Errors
///
/// [`BodyRefusal::Member`] when the member is present but not the
/// hexadecimal of `N` bytes.
pub fn optional_hex<const N: usize>(
    o: &Object,
    name: &'static str,
) -> Result<Option<[u8; N]>, BodyRefusal> {
    match o.get(name) {
        None => Ok(None),
        Some(_) => hex_member::<N>(o, name).map(Some),
    }
}

/// The member `name` of `o` as lowercase hexadecimal of 1 to `max` bytes.
///
/// # Errors
///
/// [`BodyRefusal::Member`] when the member is absent or malformed.
pub fn bytes_member(o: &Object, name: &'static str, max: usize) -> Result<Vec<u8>, BodyRefusal> {
    hex_vec(string(o, name)?, max).ok_or(BodyRefusal::Member(name))
}

/// Requires an empty body, for a route that takes none.
///
/// # Errors
///
/// [`BodyRefusal::TooLarge`] for any byte.
pub fn empty(bytes: &[u8]) -> Result<(), BodyRefusal> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(BodyRefusal::TooLarge)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// TH-26: hex has one spelling.
    #[test]
    fn th_26_hex_has_one_spelling() {
        assert_eq!(hex_array::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(hex_array::<2>("0AFF"), None);
        assert_eq!(hex_array::<2>("0af"), None);
        assert_eq!(hex_array::<2>("0aff0"), None);
        assert_eq!(hex_array::<1>("g0"), None);
        assert_eq!(hex_vec("", 4), None);
        assert_eq!(hex_vec("00", 0), None);
        assert_eq!(hex_vec("0001", 2), Some(vec![0, 1]));
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
    }

    /// TH-26, I-18: the body rules in order.
    #[test]
    fn th_26_object_refuses_second_spellings_and_minor() {
        assert_eq!(object(b"{\"a\":1}", 4), Err(BodyRefusal::TooLarge));
        assert_eq!(object(b"{\"a\":", 64), Err(BodyRefusal::NotJson));
        assert_eq!(object(b"{ \"a\":1}", 64), Err(BodyRefusal::NotCanonical));
        assert_eq!(
            object(b"{\"b\":1,\"a\":1}", 64),
            Err(BodyRefusal::NotCanonical)
        );
        assert_eq!(object(b"[1]", 64), Err(BodyRefusal::NotAnObject));
        assert_eq!(
            object(b"{\"a\":[{\"minor\":false}]}", 64),
            Err(BodyRefusal::MinorMember)
        );
        assert!(object(b"{\"a\":1}", 64).is_ok());
    }
}

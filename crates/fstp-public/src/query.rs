//! Query strings of the public tools (`fstp_public::tools::select`).
//!
//! The grammar, interim, pending Daniel, pinned by
//! `tests/th26_public_query.rs`:
//!
//! - At most [`MAX_QUERY_BYTES`] bytes, all ASCII. Pairs are separated by
//!   `&`, and each pair is `key=value` with a non-empty key.
//! - Values are percent-decoded (`%` and two hex digits of either case),
//!   and `+` decodes to a space. A decoded value must be UTF-8.
//! - `part` is required, once: one of `programme`, `open_calls`, `call`,
//!   `guide`, `deadlines`, `eligibility`, `funded` and `finished`.
//! - `call` is required with `call` and `guide`, and refused otherwise:
//!   a call id in decimal, 1 to 38 digits with no leading zero.
//! - `q` is allowed only with `open_calls`: 1 to [`MAX_SEARCH_BYTES`]
//!   bytes after decoding, with no control character.
//! - Every key appears at most once. Any other key is refused.
//!
//! [`PublicQuery::to_query_string`] writes the canonical spelling:
//! `part`, then `call`, then `q`, with every byte of `q` outside
//! `A-Z a-z 0-9 - . _ ~` written as `%` and two upper-case hex digits.
//! Parsing it gives an equal query (fuzzed, `public_query_parse`).

use crate::PublicError;

/// The longest query string, in bytes.
pub const MAX_QUERY_BYTES: usize = 1024;

/// The longest search text after decoding, in bytes.
pub const MAX_SEARCH_BYTES: usize = 200;

/// The part of a public view a tool selects.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicPart {
    /// The programme.
    Programme,
    /// The open calls.
    OpenCalls,
    /// One open call, by its public identifier.
    Call(String),
    /// The Guide of one open call, by its public identifier.
    Guide(String),
    /// The deadlines of the open calls.
    Deadlines,
    /// The eligibility rules of the open calls.
    Eligibility,
    /// The funded grants.
    Funded,
    /// The finished grants.
    Finished,
}

/// A parsed public query.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicQuery {
    /// The part selected.
    pub part: PublicPart,
    /// The search text over open call titles, with [`PublicPart::OpenCalls`]
    /// only. A call matches when its title contains the text, ignoring
    /// ASCII case.
    pub search: Option<String>,
}

/// The longest call id, in digits (`u128::MAX` has 39).
const MAX_CALL_DIGITS: usize = 38;

fn refuse(rule: &'static str) -> PublicError {
    PublicError::Query(rule)
}

/// Whether `id` is a call id of the grammar: 1 to 38 decimal digits with
/// no leading zero.
fn is_call_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CALL_DIGITS
        && id.bytes().all(|b| b.is_ascii_digit())
        && !id.starts_with('0')
}

/// Whether `s` is a search text of the grammar: 1 to
/// [`MAX_SEARCH_BYTES`] bytes with no control character.
fn is_search(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SEARCH_BYTES && !s.chars().any(char::is_control)
}

/// Whether `b` may stand unescaped in a canonical value.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

impl PublicQuery {
    /// The canonical query string of the query (module documentation). A
    /// query outside the grammar, such as an empty search text, is
    /// refused, so every string it writes parses back.
    pub fn to_query_string(&self) -> Result<String, PublicError> {
        let (part, call) = match &self.part {
            PublicPart::Programme => ("programme", None),
            PublicPart::OpenCalls => ("open_calls", None),
            PublicPart::Call(id) => ("call", Some(id)),
            PublicPart::Guide(id) => ("guide", Some(id)),
            PublicPart::Deadlines => ("deadlines", None),
            PublicPart::Eligibility => ("eligibility", None),
            PublicPart::Funded => ("funded", None),
            PublicPart::Finished => ("finished", None),
        };
        let mut out = format!("part={part}");
        if let Some(id) = call {
            if !is_call_id(id) {
                return Err(refuse("the call is not a call id"));
            }
            out.push_str("&call=");
            out.push_str(id);
        }
        if let Some(q) = &self.search {
            if self.part != PublicPart::OpenCalls {
                return Err(refuse("a search text goes only with open_calls"));
            }
            if !is_search(q) {
                return Err(refuse(
                    "the search text is empty, too long or holds a control",
                ));
            }
            out.push_str("&q=");
            for b in q.bytes() {
                if is_unreserved(b) {
                    out.push(char::from(b));
                } else {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
        if out.len() > MAX_QUERY_BYTES {
            return Err(refuse("the query is too long"));
        }
        Ok(out)
    }
}

/// The value of one hex digit.
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => b.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}

/// Percent-decodes `raw`, with `+` as a space. Only unreserved bytes,
/// `+` and escapes may stand in a value.
fn decode(raw: &[u8]) -> Result<String, PublicError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0_usize;
    while let Some(&b) = raw.get(i) {
        i = i.saturating_add(1);
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = raw.get(i).copied().and_then(hex);
                let lo = raw.get(i.saturating_add(1)).copied().and_then(hex);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(refuse("a percent escape is not two hex digits"));
                };
                out.push(
                    hi.checked_mul(16)
                        .and_then(|h| h.checked_add(lo))
                        .unwrap_or(0),
                );
                i = i.saturating_add(2);
            }
            b if is_unreserved(b) => out.push(b),
            _ => return Err(refuse("a value holds a byte that must be escaped")),
        }
    }
    String::from_utf8(out).map_err(|_| refuse("a decoded value is not UTF-8"))
}

/// Parses the query string of a public tool. Fuzzed (`public_query_parse`).
pub fn parse_public_query(bytes: &[u8]) -> Result<PublicQuery, PublicError> {
    if bytes.len() > MAX_QUERY_BYTES {
        return Err(refuse("the query is too long"));
    }
    if !bytes.is_ascii() {
        return Err(refuse("the query is not ASCII"));
    }
    let mut part: Option<String> = None;
    let mut call: Option<String> = None;
    let mut search: Option<String> = None;
    for pair in bytes.split(|b| *b == b'&') {
        let Some(eq) = pair.iter().position(|b| *b == b'=') else {
            return Err(refuse("a pair has no ="));
        };
        let (key, value) = pair.split_at(eq);
        let value = value.get(1..).unwrap_or(&[]);
        let slot = match key {
            b"part" => &mut part,
            b"call" => &mut call,
            b"q" => &mut search,
            b"" => return Err(refuse("a pair has an empty key")),
            _ => return Err(refuse("an unknown key")),
        };
        if slot.is_some() {
            return Err(refuse("a key appears twice"));
        }
        *slot = Some(decode(value)?);
    }
    let part = part.ok_or(refuse("no part"))?;
    let needs_call = matches!(part.as_str(), "call" | "guide");
    if needs_call != call.is_some() {
        return Err(refuse(
            "a call goes with call and guide, and only with them",
        ));
    }
    let call = match call {
        Some(id) if is_call_id(&id) => Some(id),
        Some(_) => return Err(refuse("the call is not a call id")),
        None => None,
    };
    if search.is_some() && part != "open_calls" {
        return Err(refuse("a search text goes only with open_calls"));
    }
    if let Some(q) = &search
        && !is_search(q)
    {
        return Err(refuse(
            "the search text is empty, too long or holds a control",
        ));
    }
    let part = match (part.as_str(), call) {
        ("programme", None) => PublicPart::Programme,
        ("open_calls", None) => PublicPart::OpenCalls,
        ("call", Some(id)) => PublicPart::Call(id),
        ("guide", Some(id)) => PublicPart::Guide(id),
        ("deadlines", None) => PublicPart::Deadlines,
        ("eligibility", None) => PublicPart::Eligibility,
        ("funded", None) => PublicPart::Funded,
        ("finished", None) => PublicPart::Finished,
        _ => return Err(refuse("an unknown part")),
    };
    Ok(PublicQuery { part, search })
}

//! Small wire helpers of the e2e cell: JSON replies, hex, base64url and
//! request bodies.

use fstp_http::{Request, Response, StatusCode};
use fstp_json::{Number, Object, Value};

/// A JSON reply with `Cache-Control: no-store`.
pub(crate) fn json(status: StatusCode, v: &Value) -> Response {
    let mut r = Response::with_body(status, "application/json", v.to_compact().into_bytes());
    let _ = r.headers.try_insert("cache-control", "no-store");
    r
}

/// `{}` with status 200.
pub(crate) fn ok_empty() -> Response {
    json(StatusCode::OK, &Value::Object(Object::new()))
}

/// A refusal `{"code": code}` with `status`. It names no account.
pub(crate) fn refuse(status: StatusCode, code: &str) -> Response {
    let mut o = Object::new();
    let _ = o.insert("code", Value::from(code));
    json(status, &Value::Object(o))
}

/// 400 `{"code": "bad_request", "rule": why}`.
pub(crate) fn bad(why: &str) -> Response {
    let mut o = Object::new();
    let _ = o.insert("code", Value::from("bad_request"));
    let _ = o.insert("rule", Value::from(why));
    json(StatusCode::BAD_REQUEST, &Value::Object(o))
}

/// 404 with no body.
pub(crate) fn not_found() -> Response {
    Response::new(StatusCode::NOT_FOUND)
}

/// A decimal string value.
pub(crate) fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// A JSON integer value of `n`.
pub(crate) fn int(n: i64) -> Value {
    Number::from_lexeme(&n.to_string()).map_or(Value::Null, Value::from)
}

/// An object from `members`, in the given order.
pub(crate) fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// The body of `req` as a JSON object. An empty body is the empty object.
pub(crate) fn body(req: &Request) -> Option<Object> {
    if req.body.is_empty() {
        return Some(Object::new());
    }
    match fstp_json::parse(&req.body) {
        Ok(Value::Object(o)) => Some(o),
        _ => None,
    }
}

/// The string member `name` of `o`.
pub(crate) fn str_member<'a>(o: &'a Object, name: &str) -> Option<&'a str> {
    o.get(name)?.as_str()
}

/// The decimal string member `name` of `o`, as an integer.
pub(crate) fn dec_member(o: &Object, name: &str) -> Option<i128> {
    let s = str_member(o, name)?;
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return None;
    }
    s.parse().ok()
}

/// The value of query parameter `name`, percent-decoded as UTF-8.
pub(crate) fn query_param(req: &Request, name: &str) -> Option<String> {
    let q = req.query()?;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            return percent_decode(v);
        }
    }
    None
}

/// `s` with `%XX` escapes and `+` decoded, or `None` when an escape is
/// malformed or the result is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        match c {
            b'%' => {
                let hi = nibble(*b.get(i.checked_add(1)?)?)?;
                let lo = nibble(*b.get(i.checked_add(2)?)?)?;
                out.push((hi << 4) | lo);
                i = i.checked_add(3)?;
            }
            b'+' => {
                out.push(b' ');
                i = i.checked_add(1)?;
            }
            _ => {
                out.push(c);
                i = i.checked_add(1)?;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The value of one hexadecimal digit, either case.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => c.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Lowercase hexadecimal of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
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

/// The bytes of a lowercase hexadecimal string, or `None`.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    b.chunks_exact(2)
        .map(|p| match p {
            [hi, lo] => Some((nibble(*hi)? << 4) | nibble(*lo)?),
            _ => None,
        })
        .collect()
}

/// Unpadded base64url of `bytes` (RFC 4648 section 5), as WebAuthn JSON
/// options spell binary members.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let sym = |i: usize| A.get(i & 63).map_or('A', |c| char::from(*c));
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(3) {
        let at = |i: usize| chunk.get(i).map_or(0usize, |b| usize::from(*b));
        let n = (at(0) << 16) | (at(1) << 8) | at(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        if chunk.len() > 1 {
            out.push(sym(n >> 6));
        }
        if chunk.len() > 2 {
            out.push(sym(n));
        }
    }
    out
}

/// Fresh random bytes from the operating system.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], String> {
    fstp_crypto::random_array::<N>().map_err(|e| format!("random bytes: {e:?}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// RFC 4648 section 10 vectors, in the unpadded URL alphabet.
    #[test]
    fn e2e_cell_base64url_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64url(input.as_bytes()), want);
        }
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    /// Hex round trips, and upper case or odd lengths are refused.
    #[test]
    fn e2e_cell_hex_round_trip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&b)).unwrap(), b);
        assert_eq!(unhex("ABCD"), None);
        assert_eq!(unhex("abc"), None);
    }

    /// Query values are percent-decoded, and a bad escape is refused.
    #[test]
    fn e2e_cell_percent_decoding() {
        assert_eq!(percent_decode("a%40b.invalid").unwrap(), "a@b.invalid");
        assert_eq!(percent_decode("a%4"), None);
    }
}

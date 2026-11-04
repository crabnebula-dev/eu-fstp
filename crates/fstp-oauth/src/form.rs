//! The `application/x-www-form-urlencoded` decoder for OAuth bodies and
//! queries (design section 9). Duplicate parameters are refused, as RFC
//! 6749 section 3.1 requires.

use crate::OauthError;

/// The largest form or query [`decode_form_urlencoded`] reads, in bytes.
pub const MAX_FORM_BYTES: usize = 16 * 1024;
/// The most parameters one form may hold.
pub const MAX_FORM_PAIRS: usize = 64;

/// A decoded form body or query: names unique, in written order.
#[derive(Clone, PartialEq, Eq)]
pub struct Form {
    pairs: Vec<(String, String)>,
}

impl Form {
    /// The value of `name`, if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The pairs, in written order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// The number of parameters.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether the form holds no parameter.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

impl std::fmt::Debug for Form {
    /// Names only: values can be codes, verifiers or tokens.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.pairs.iter().map(|(k, _)| k))
            .finish()
    }
}

fn unhex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => b.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}

fn decode_part(part: &[u8]) -> Result<String, OauthError> {
    let mut out = Vec::with_capacity(part.len());
    let mut i = 0usize;
    while let Some(&b) = part.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = part.get(i.saturating_add(1)).copied().and_then(unhex);
                let lo = part.get(i.saturating_add(2)).copied().and_then(unhex);
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push(h.wrapping_mul(16) | l),
                    _ => return Err(OauthError::BadPercentEncoding),
                }
                i = i.saturating_add(2);
            }
            _ => out.push(b),
        }
        i = i.saturating_add(1);
    }
    String::from_utf8(out).map_err(|_| OauthError::NotUtf8)
}

/// Decodes an `application/x-www-form-urlencoded` body. Duplicate parameters are refused. Fuzzed (`form_urlencoded_decode`).
///
/// An empty input has no parameters. Raw bytes outside visible ASCII, an
/// empty segment, a segment without `=`, an empty name, bad
/// percent-encoding, invalid UTF-8, more than [`MAX_FORM_PAIRS`]
/// parameters and more than [`MAX_FORM_BYTES`] bytes are refused.
pub fn decode_form_urlencoded(bytes: &[u8]) -> Result<Form, OauthError> {
    if bytes.len() > MAX_FORM_BYTES {
        return Err(OauthError::TooLong);
    }
    if !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(OauthError::MalformedForm);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    if bytes.is_empty() {
        return Ok(Form { pairs });
    }
    for segment in bytes.split(|&b| b == b'&') {
        if pairs.len() >= MAX_FORM_PAIRS {
            return Err(OauthError::TooManyParameters);
        }
        let eq = segment
            .iter()
            .position(|&b| b == b'=')
            .ok_or(OauthError::MalformedForm)?;
        let (k, v) = segment.split_at(eq);
        let v = v.get(1..).unwrap_or(&[]);
        if k.is_empty() {
            return Err(OauthError::MalformedForm);
        }
        let name = decode_part(k)?;
        if pairs.iter().any(|(n, _)| *n == name) {
            return Err(OauthError::DuplicateParameter);
        }
        pairs.push((name, decode_part(v)?));
    }
    Ok(Form { pairs })
}

/// Appends `s` to `out`, percent-encoded for a query or form value:
/// unreserved characters stay, every other byte becomes `%XX`.
pub(crate) fn push_encoded(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(
                HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
            ));
            out.push(char::from(
                HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'),
            ));
        }
    }
}

/// Encodes `pairs` as a form body or query. The inverse of
/// [`decode_form_urlencoded`] for unique names.
pub fn encode_form_urlencoded(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        push_encoded(&mut out, k);
        out.push('=');
        push_encoded(&mut out, v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Design section 9: decoding inverts encoding for unique names.
    #[test]
    fn adr013_form_round_trips() {
        fstp_prop::check("adr013_form_round_trips", |g| {
            let n = g.usize_in(0..=6);
            let mut names: Vec<String> = Vec::new();
            let mut values: Vec<String> = Vec::new();
            for i in 0..n {
                names.push(format!("k{i}"));
                let v: String = g
                    .vec(0..=12, |g| {
                        *g.pick(&['a', ' ', '&', '=', '%', '+', '\u{e9}'])
                    })
                    .into_iter()
                    .collect();
                values.push(v);
            }
            let pairs: Vec<(&str, &str)> = names
                .iter()
                .map(String::as_str)
                .zip(values.iter().map(String::as_str))
                .collect();
            let text = encode_form_urlencoded(&pairs);
            let form = decode_form_urlencoded(text.as_bytes()).map_err(|e| e.to_string())?;
            fstp_prop::prop_assert_eq!(form.len(), n);
            for (k, v) in &pairs {
                fstp_prop::prop_assert_eq!(form.get(k), Some(*v));
            }
            Ok(())
        });
    }

    /// Design section 9: a percent-encoded duplicate name is a duplicate.
    #[test]
    fn adr013_form_refuses_encoded_duplicates() {
        assert_eq!(
            decode_form_urlencoded(b"code=a&c%6Fde=b"),
            Err(OauthError::DuplicateParameter)
        );
        assert_eq!(
            decode_form_urlencoded(b"a=1&&b=2"),
            Err(OauthError::MalformedForm)
        );
        assert_eq!(decode_form_urlencoded(b"a"), Err(OauthError::MalformedForm));
        assert_eq!(
            decode_form_urlencoded(b"a=1 "),
            Err(OauthError::MalformedForm)
        );
    }
}

//! Byte classes from RFC 9110, RFC 9112 and RFC 3986.

/// `tchar` from RFC 9110 section 5.6.2.
pub(crate) const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

/// `token = 1*tchar`.
pub(crate) fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| is_tchar(b))
}

/// Number of leading `tchar` bytes in `s` from `from`.
pub(crate) fn token_len(s: &[u8], from: usize) -> usize {
    s.get(from..)
        .map(|rest| rest.iter().take_while(|&&b| is_tchar(b)).count())
        .unwrap_or(0)
}

/// `OWS` member: space or horizontal tab.
pub(crate) const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Index of the first byte at or after `from` that is not `OWS`.
pub(crate) fn skip_ows(s: &[u8], from: usize) -> usize {
    let n = s
        .get(from..)
        .map(|rest| rest.iter().take_while(|&&b| is_ows(b)).count())
        .unwrap_or(0);
    from.saturating_add(n)
}

/// `VCHAR / obs-text`: a visible byte allowed inside a field value.
pub(crate) const fn is_field_vchar(b: u8) -> bool {
    matches!(b, 0x21..=0x7E | 0x80..=0xFF)
}

/// A byte allowed anywhere inside a field value: `VCHAR`, `obs-text`, `SP`
/// or `HTAB`. Every control byte other than `HTAB` is excluded, including
/// NUL, CR, LF and DEL.
pub(crate) const fn is_field_byte(b: u8) -> bool {
    is_field_vchar(b) || is_ows(b)
}

/// Trims leading and trailing `OWS`.
pub(crate) fn trim_ows(s: &[u8]) -> &[u8] {
    let start = s.iter().take_while(|&&b| is_ows(b)).count();
    let rest = s.get(start..).unwrap_or_default();
    let end = rest
        .len()
        .saturating_sub(rest.iter().rev().take_while(|&&b| is_ows(b)).count());
    rest.get(..end).unwrap_or_default()
}

/// RFC 3986 `unreserved`.
pub(crate) const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986 `sub-delims`.
pub(crate) const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// RFC 3986 `pchar`, without the `pct-encoded` alternative, which callers
/// check separately.
pub(crate) const fn is_pchar_plain(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || b == b':' || b == b'@'
}

/// Value of an ASCII hex digit.
pub(crate) const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Checks that every `%` in `s` starts a valid `pct-encoded` triple and
/// that every other byte satisfies `allowed`.
pub(crate) fn valid_pct_str(s: &[u8], allowed: impl Fn(u8) -> bool) -> bool {
    let mut i = 0usize;
    while let Some(&b) = s.get(i) {
        if b == b'%' {
            let h1 = s.get(i.saturating_add(1)).copied().and_then(hex_val);
            let h2 = s.get(i.saturating_add(2)).copied().and_then(hex_val);
            if h1.is_none() || h2.is_none() {
                return false;
            }
            i = i.saturating_add(3);
        } else if allowed(b) {
            i = i.saturating_add(1);
        } else {
            return false;
        }
    }
    true
}

/// True when `s` holds a `%` followed by two hex digits anywhere.
pub(crate) fn has_pct_triple(s: &[u8]) -> bool {
    s.windows(3).any(|w| match w {
        [b'%', h1, h2] => hex_val(*h1).is_some() && hex_val(*h2).is_some(),
        _ => false,
    })
}

/// Decodes `pct-encoded` triples. Returns `None` on a malformed triple.
pub(crate) fn pct_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while let Some(&b) = s.get(i) {
        if b == b'%' {
            let h1 = s.get(i.saturating_add(1)).copied().and_then(hex_val)?;
            let h2 = s.get(i.saturating_add(2)).copied().and_then(hex_val)?;
            out.push(h1.wrapping_shl(4) | h2);
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rules() {
        assert!(is_token(b"Content-Length"));
        assert!(is_token(b"x!#$%&'*+-.^_`|~9"));
        assert!(!is_token(b""));
        assert!(!is_token(b"a b"));
        assert!(!is_token(b"a:b"));
        assert!(!is_token(b"a\x00"));
        assert!(!is_token(b"\xC3\xA9"));
    }

    #[test]
    fn field_bytes() {
        assert!(is_field_byte(b'\t'));
        assert!(is_field_byte(b' '));
        assert!(is_field_byte(0x80));
        for b in [0u8, b'\r', b'\n', 0x7F, 0x01, 0x1F] {
            assert!(!is_field_byte(b), "{b:#x}");
        }
    }

    #[test]
    fn trimming() {
        assert_eq!(trim_ows(b" \t a b \t"), b"a b");
        assert_eq!(trim_ows(b"   "), b"");
        assert_eq!(trim_ows(b""), b"");
    }

    #[test]
    fn pct() {
        assert!(valid_pct_str(b"a%20b", is_pchar_plain));
        assert!(!valid_pct_str(b"a%2", is_pchar_plain));
        assert!(!valid_pct_str(b"a%zz", is_pchar_plain));
        assert_eq!(pct_decode(b"a%2Fb%41").unwrap(), b"a/bA");
        assert!(pct_decode(b"%").is_none());
        assert!(has_pct_triple(b"a%2Fb"));
        assert!(has_pct_triple(b"%aF"));
        assert!(!has_pct_triple(b"100%"));
        assert!(!has_pct_triple(b"%2"));
        assert!(!has_pct_triple(b"%g1"));
        assert!(!has_pct_triple(b""));
    }
}

//! Transfer encodings, written in-house (M6 design section 9):
//!
//! - base64 (RFC 4648 section 4), wrapped at 76 characters for MIME.
//! - quoted-printable (RFC 2045 section 6.7) for the text and HTML parts.
//! - RFC 2047 encoded words, `B` encoding in UTF-8, for header text that
//!   is not printable ASCII.
//!
//! Every decoder is strict and bounded, and the `mime_parse` fuzz target
//! reaches each one.

use crate::MailError;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The longest encoded line of a base64 MIME body (RFC 2045 section 6.8).
pub const BASE64_LINE: usize = 76;

/// The longest encoded line of a quoted-printable body, soft break
/// included (RFC 2045 section 6.7, rule 5).
pub const QP_LINE: usize = 76;

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.push(char::from(
                H.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    s
}

/// Base64 of `bytes` on one line, with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextet = |shift: u32| {
            let i = ((n >> shift) & 0x3f) as usize;
            char::from(B64.get(i).copied().unwrap_or(b'A'))
        };
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

/// Base64 of `bytes` in lines of [`BASE64_LINE`] characters, each ended
/// with CRLF.
pub fn base64_encode_wrapped(bytes: &[u8]) -> String {
    let flat = base64_encode(bytes);
    let mut out = String::with_capacity(flat.len().saturating_add(flat.len() / 38));
    for line in flat.as_bytes().chunks(BASE64_LINE) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push_str("\r\n");
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.wrapping_sub(b'A'),
        b'a'..=b'z' => c.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => c.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes base64. CR, LF, space and tab are skipped. Padding must be
/// canonical and come only at the end, and the unused bits must be zero.
///
/// # Errors
///
/// [`MailError::Malformed`] for any other byte, a bad length or bad padding.
pub fn base64_decode(input: &[u8]) -> Result<Vec<u8>, MailError> {
    let bad = MailError::Malformed("base64");
    let clean: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
        .collect();
    if !clean.len().is_multiple_of(4) {
        return Err(bad);
    }
    let mut out = Vec::with_capacity(clean.len());
    let quads = clean.chunks(4);
    let last = clean.len() / 4;
    for (i, q) in quads.enumerate() {
        let is_last = i.saturating_add(1) == last;
        let pad = q.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 || (pad > 0 && !is_last) {
            return Err(bad);
        }
        let mut n: u32 = 0;
        for (j, c) in q.iter().enumerate() {
            let v = if j >= 4usize.saturating_sub(pad) {
                0
            } else {
                b64_value(*c).ok_or(MailError::Malformed("base64"))?
            };
            n = (n << 6) | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        match pad {
            0 => out.extend_from_slice(&bytes),
            1 => {
                if bytes[2] != 0 {
                    return Err(bad);
                }
                out.extend_from_slice(&bytes[..2]);
            }
            _ => {
                if bytes[1] != 0 || bytes[2] != 0 {
                    return Err(bad);
                }
                out.push(bytes[0]);
            }
        }
    }
    Ok(out)
}

fn qp_literal(b: u8) -> bool {
    (33..=126).contains(&b) && b != b'='
}

/// Quoted-printable of `text`. A `\n` in `text` is a line break and
/// becomes CRLF. Encoded lines hold at most [`QP_LINE`] characters, so a
/// long line gets soft breaks. Space and tab are kept except at a line
/// end, and a `.` that would start a line is encoded.
pub fn qp_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(text.len() / 8));
    let mut first = true;
    for line in text.split('\n') {
        if !first {
            out.push_str("\r\n");
        }
        first = false;
        let bytes = line.as_bytes();
        let mut col = 0usize;
        for (i, b) in bytes.iter().copied().enumerate() {
            let at_end = i.saturating_add(1) == bytes.len();
            let token = if qp_literal(b) && !(b == b'.' && col == 0)
                || ((b == b' ' || b == b'\t') && !at_end)
            {
                char::from(b).to_string()
            } else {
                format!("={b:02X}")
            };
            // Keep room for a soft break "=" unless this is the line's last token.
            let room = if at_end { QP_LINE } else { QP_LINE - 1 };
            if col.saturating_add(token.len()) > room {
                out.push_str("=\r\n");
                col = 0;
                if token == "." {
                    out.push_str("=2E");
                    col = 3;
                    continue;
                }
            }
            out.push_str(&token);
            col = col.saturating_add(token.len());
        }
    }
    out
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes quoted-printable. Lines are CRLF-separated. Trailing space or
/// tab on a line is dropped, `=` at a line end is a soft break, and hard
/// breaks come out as CRLF.
///
/// # Errors
///
/// [`MailError::Malformed`] for a bare CR or LF, a bad `=XX` escape or a
/// byte outside printable ASCII, space and tab.
pub fn qp_decode(input: &[u8]) -> Result<Vec<u8>, MailError> {
    let bad = MailError::Malformed("quoted-printable");
    let mut out = Vec::with_capacity(input.len());
    let lines = split_crlf(input).ok_or(MailError::Malformed("quoted-printable"))?;
    let count = lines.len();
    for (n, line) in lines.into_iter().enumerate() {
        let mut end = line.len();
        while end > 0 && matches!(line.get(end.saturating_sub(1)), Some(b' ' | b'\t')) {
            end = end.saturating_sub(1);
        }
        let line = line
            .get(..end)
            .ok_or(MailError::Malformed("quoted-printable"))?;
        let mut i = 0usize;
        let mut soft = false;
        while let Some(&b) = line.get(i) {
            if b == b'=' {
                if i.saturating_add(1) == line.len() {
                    soft = true;
                    break;
                }
                let h = line.get(i.saturating_add(1)).copied().and_then(hex_value);
                let l = line.get(i.saturating_add(2)).copied().and_then(hex_value);
                match (h, l) {
                    (Some(h), Some(l)) => out.push((h << 4) | l),
                    _ => return Err(bad),
                }
                i = i.saturating_add(3);
            } else if (33..=126).contains(&b) || b == b' ' || b == b'\t' {
                out.push(b);
                i = i.saturating_add(1);
            } else {
                return Err(bad);
            }
        }
        if !soft && n.saturating_add(1) < count {
            out.extend_from_slice(b"\r\n");
        }
    }
    Ok(out)
}

/// Splits `input` on CRLF. A bare CR or LF gives `None`.
pub(crate) fn split_crlf(input: &[u8]) -> Option<Vec<&[u8]>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        match b {
            b'\r' => {
                if input.get(i.saturating_add(1)) != Some(&b'\n') {
                    return None;
                }
                lines.push(input.get(start..i)?);
                i = i.saturating_add(2);
                start = i;
            }
            b'\n' => return None,
            _ => i = i.saturating_add(1),
        }
    }
    lines.push(input.get(start..)?);
    Some(lines)
}

/// The longest encoded word (RFC 2047 section 2).
const WORD_MAX: usize = 75;

/// Header text for an unstructured field such as `Subject`, or for a
/// display name. Printable ASCII and spaces stay as they are. Anything
/// else becomes UTF-8 `B` encoded words of at most 75 characters,
/// separated by CRLF and a space, so each one sits on its own folded line.
pub fn encode_unstructured(text: &str) -> String {
    if text.bytes().all(|b| (32..=126).contains(&b)) && !text.contains("=?") {
        return text.to_owned();
    }
    encoded_words(text)
}

/// A display name for an address header. Letters, digits and spaces stay
/// as they are. Any other name becomes encoded words, so no quoting rule
/// of RFC 5322 applies.
pub fn encode_phrase(name: &str) -> String {
    if name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ') {
        return name.to_owned();
    }
    encoded_words(name)
}

/// UTF-8 `B` encoded words for `text`, joined by CRLF and a space.
fn encoded_words(text: &str) -> String {
    // "=?UTF-8?B?" plus "?=" is 12 characters, so 63 remain: 45 bytes.
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len().saturating_add(c.len_utf8()) > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(chunk);
    }
    let encoded: Vec<String> = words
        .iter()
        .map(|w| format!("=?UTF-8?B?{}?=", base64_encode(w.as_bytes())))
        .collect();
    debug_assert!(encoded.iter().all(|w| w.len() <= WORD_MAX));
    encoded.join("\r\n ")
}

/// Decodes an unfolded unstructured header value. UTF-8 or US-ASCII `B`
/// and `Q` encoded words are decoded. White space between two adjacent
/// encoded words is dropped (RFC 2047 section 6.2).
///
/// # Errors
///
/// [`MailError::Malformed`] for a malformed encoded word or a decoded
/// text that is not UTF-8.
pub fn decode_unstructured(value: &str) -> Result<String, MailError> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut last_was_word = false;
    while !rest.is_empty() {
        let Some(start) = rest.find("=?") else {
            out.push_str(rest);
            break;
        };
        let (before, word_on) = rest.split_at(start);
        let Some((word, after)) = split_word(word_on) else {
            out.push_str(rest);
            break;
        };
        if !(last_was_word && before.chars().all(|c| c == ' ' || c == '\t')) {
            out.push_str(before);
        }
        out.push_str(&decode_word(word)?);
        last_was_word = true;
        rest = after;
    }
    Ok(out)
}

/// Splits `=?charset?enc?text?=` off the front of `s`.
fn split_word(s: &str) -> Option<(&str, &str)> {
    let body = s.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    let rest = body.get(q1.saturating_add(1)..)?;
    let q2 = rest.find('?')?;
    let text = rest.get(q2.saturating_add(1)..)?;
    let end = text.find("?=")?;
    let len = 2usize
        .saturating_add(q1)
        .saturating_add(1)
        .saturating_add(q2)
        .saturating_add(1)
        .saturating_add(end)
        .saturating_add(2);
    Some((s.get(..len)?, s.get(len..)?))
}

fn decode_word(word: &str) -> Result<String, MailError> {
    let bad = MailError::Malformed("encoded word");
    let inner = word
        .strip_prefix("=?")
        .and_then(|w| w.strip_suffix("?="))
        .ok_or(MailError::Malformed("encoded word"))?;
    let mut it = inner.splitn(3, '?');
    let charset = it.next().unwrap_or("");
    let enc = it.next().unwrap_or("");
    let text = it.next().ok_or(MailError::Malformed("encoded word"))?;
    if !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("us-ascii") {
        return Err(bad);
    }
    let bytes = if enc.eq_ignore_ascii_case("b") {
        base64_decode(text.as_bytes())?
    } else if enc.eq_ignore_ascii_case("q") {
        let mut v = Vec::with_capacity(text.len());
        let t = text.as_bytes();
        let mut i = 0usize;
        while let Some(&b) = t.get(i) {
            match b {
                b'_' => v.push(b' '),
                b'=' => {
                    let h = t.get(i.saturating_add(1)).copied().and_then(hex_value);
                    let l = t.get(i.saturating_add(2)).copied().and_then(hex_value);
                    match (h, l) {
                        (Some(h), Some(l)) => v.push((h << 4) | l),
                        _ => return Err(bad),
                    }
                    i = i.saturating_add(2);
                }
                _ => v.push(b),
            }
            i = i.saturating_add(1);
        }
        v
    } else {
        return Err(bad);
    };
    String::from_utf8(bytes).map_err(|_| MailError::Malformed("encoded word"))
}

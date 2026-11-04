//! The value rules shared by the form decoder, `decide`, the fold and
//! the record codec. One rule set means a value the form accepts is a
//! value every later stage accepts, and nothing else is.

/// The largest text value after percent-decoding, in bytes.
pub const MAX_FIELD_BYTES: usize = 512;

/// Why a text value is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TextFault {
    /// More than [`MAX_FIELD_BYTES`] bytes.
    TooLong,
    /// Empty, or holding a refused character.
    Bad,
}

/// True for every character of Unicode General Category `Cf` (format),
/// as of Unicode 16.0. Each is invisible or changes how its neighbours
/// render, so two values that render alike could still differ. They are
/// refused in every text value, so a legal name cannot render as another
/// organisation's name (TH-46). The table covers the bidirectional
/// controls, zero width characters, the soft hyphen, the byte order mark,
/// interlinear annotation marks and the tag characters. Interim strict
/// reading, pending Daniel.
const fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// True for U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR. The
/// CR LF pair is the only line break a value may hold, and only where
/// the field allows it (TH-26).
const fn is_unicode_line_break(c: char) -> bool {
    matches!(c, '\u{2028}' | '\u{2029}')
}

/// Checks a text value: 1 to [`MAX_FIELD_BYTES`] bytes, no Unicode `Cc`
/// control, no `Cf` format character, no U+2028 or U+2029, and no
/// whitespace at either end. When `line_breaks` holds, CR LF pairs may
/// appear inside the value, and a lone CR or LF is still refused.
pub(crate) fn check_text(s: &str, line_breaks: bool) -> Result<(), TextFault> {
    if s.len() > MAX_FIELD_BYTES {
        return Err(TextFault::TooLong);
    }
    let starts_blank = s.chars().next().is_none_or(char::is_whitespace);
    let ends_blank = s.chars().next_back().is_none_or(char::is_whitespace);
    if starts_blank || ends_blank {
        return Err(TextFault::Bad);
    }
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if line_breaks && c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
            continue;
        }
        if c.is_control() || is_format_char(c) || is_unicode_line_break(c) {
            return Err(TextFault::Bad);
        }
    }
    Ok(())
}

/// A canonical decimal agreement version: 1 to `u32::MAX`, digits only,
/// no leading zero.
pub(crate) fn parse_version(s: &str) -> Option<u32> {
    let canonical = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0');
    if canonical {
        s.parse::<u32>().ok()
    } else {
        None
    }
}

/// A 128-bit id as exactly 32 lower-case hex digits.
pub(crate) fn parse_id_hex(s: &str) -> Option<u128> {
    let canonical = s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if canonical {
        u128::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

/// The 32 lower-case hex digits of a 128-bit id.
pub(crate) fn id_hex(raw: u128) -> String {
    format!("{raw:032x}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The first and last code point of every `Cf` range of the table.
    const FORMAT_EDGES: &[char] = &[
        '\u{00ad}',
        '\u{0600}',
        '\u{0605}',
        '\u{061c}',
        '\u{06dd}',
        '\u{070f}',
        '\u{0890}',
        '\u{0891}',
        '\u{08e2}',
        '\u{180e}',
        '\u{200b}',
        '\u{200f}',
        '\u{202a}',
        '\u{202e}',
        '\u{2060}',
        '\u{2064}',
        '\u{2066}',
        '\u{206f}',
        '\u{feff}',
        '\u{fff9}',
        '\u{fffb}',
        '\u{110bd}',
        '\u{110cd}',
        '\u{13430}',
        '\u{1343f}',
        '\u{1bca0}',
        '\u{1bca3}',
        '\u{1d173}',
        '\u{1d17a}',
        '\u{e0001}',
        '\u{e0020}',
        '\u{e007f}',
    ];

    /// TH-46: every format character is refused inside a value, at its
    /// start and at its end, in a field with or without line breaks.
    #[test]
    fn th46_every_format_char_is_refused() {
        for c in FORMAT_EDGES {
            for v in [
                format!("Synthetic{c}Org"),
                format!("{c}Org"),
                format!("Org{c}"),
            ] {
                for line_breaks in [false, true] {
                    assert_eq!(check_text(&v, line_breaks), Err(TextFault::Bad), "{c:?}");
                }
            }
        }
    }

    /// TH-26: U+2028 and U+2029 are refused even where CR LF is allowed.
    #[test]
    fn th26_unicode_line_separators_are_refused_in_every_field() {
        for c in ['\u{2028}', '\u{2029}'] {
            for line_breaks in [false, true] {
                let v = format!("1 Synthetic Street{c}0000 Testville");
                assert_eq!(check_text(&v, line_breaks), Err(TextFault::Bad));
            }
        }
        assert_eq!(check_text("1 Street\r\n0000 Testville", true), Ok(()));
    }

    /// TH-46: characters next to the table's ranges are not refused, so
    /// the table is not wider than `Cf`.
    #[test]
    fn th46_neighbours_of_format_chars_are_kept() {
        for c in ['\u{00ac}', '\u{0606}', '\u{2065}', '\u{fffc}', '\u{e0002}'] {
            assert_eq!(
                check_text(&format!("Synthetic{c}Org"), false),
                Ok(()),
                "{c:?}"
            );
        }
    }
}

//! Fuzz target `guide_markdown_parse` of `fstp-guide` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics; constructs outside the subset are refused, never passed through.
//!
//! The target checks, over arbitrary bytes:
//!
//! - `parse_markdown` never panics, and two parses give the same result;
//! - an accepted input holds no construct outside the subset. The oracle
//!   below spots each construct the subset tests refuse, by its marker:
//!   HTML and autolinks, fences, block quotes, indented code, setext
//!   underlines, images, references and footnotes, strikethrough,
//!   character references, backslash escapes and hard breaks. The scan
//!   covers code spans too, because the subset refuses those markers
//!   everywhere, code spans included (`th26_markdown_subset.rs`);
//! - an accepted input round-trips: parsing `MarkdownDoc::to_markdown`
//!   gives an equal document, whose spelling is the same again.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Whether the character reference `&...;` starts at the `&` of `rest`.
fn reference_at(rest: &str) -> bool {
    let body = rest
        .strip_prefix('#')
        .map_or(rest, |r| r.strip_prefix(['x', 'X']).unwrap_or(r));
    let name = body.bytes().take_while(u8::is_ascii_alphanumeric).count();
    name > 0 && body[name..].starts_with(';')
}

/// Whether `line` holds an HTML tag or an autolink: a `<` followed by a
/// letter, `/`, `!` or `?`, and a later `>`.
fn tag_in(line: &str) -> bool {
    line.match_indices('<').any(|(at, _)| {
        let rest = &line[at + 1..];
        rest.bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, b'/' | b'!' | b'?'))
            && rest.contains('>')
    })
}

/// Whether `data` holds a marker of a construct outside the subset.
fn outside_subset(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return true;
    };
    let inline = text.as_bytes().windows(2).any(|w| {
        (w[0] == b'!' && w[1] == b'[')
            || (w[0] == b'[' && w[1] == b'^')
            || (w[0] == b'~' && w[1] == b'~')
            || (w[0] == b'\\' && w[1].is_ascii_punctuation())
    }) || text
        .match_indices('&')
        .any(|(at, _)| reference_at(&text[at + 1..]));
    let mut prev_blank = true;
    for line in text.split('\n') {
        let blank = line.trim().is_empty();
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        let head = indent <= 3;
        let bare = trimmed.trim_end();
        let underline = !bare.is_empty()
            && (bare.bytes().all(|c| c == b'=') || bare.bytes().all(|c| c == b'-'));
        let definition = trimmed.starts_with('[')
            && trimmed
                .find(']')
                .is_some_and(|end| trimmed[end + 1..].starts_with(':'));
        if tag_in(line)
            || (head && (trimmed.starts_with('>') || trimmed.starts_with("```")))
            || (head && definition)
            || (!blank && (indent >= 4 || trimmed.starts_with('\t')))
            || (!blank && (line.ends_with("  ") || line.ends_with('\\')))
            || (head && underline && !prev_blank)
        {
            return true;
        }
        prev_blank = blank;
    }
    inline
}

fuzz_target!(|data: &[u8]| {
    let first = fstp_guide::parse_markdown(data);
    let again = fstp_guide::parse_markdown(data);
    assert_eq!(first, again, "parse_markdown is not deterministic");
    if let Ok(doc) = first {
        assert!(
            !outside_subset(data),
            "accepted a construct outside the subset: {:?}",
            String::from_utf8_lossy(data)
        );
        let spelled = doc.to_markdown();
        let back = fstp_guide::parse_markdown(spelled.as_bytes())
            .expect("the canonical spelling of a document parses");
        assert_eq!(back, doc, "the document does not round-trip");
        assert_eq!(
            back.to_markdown(),
            spelled,
            "the canonical spelling is not stable"
        );
    }
});

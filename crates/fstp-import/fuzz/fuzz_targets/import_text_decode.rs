//! Fuzz target `import_text_decode` of `fstp-import` (TH-16, TH-26, H-05,
//! M4 design section 9, T-FUZZ-IMPORT, T-FUZZ-UPLOAD).
//!
//! Arbitrary bytes per media type. The first byte selects the media type
//! and a small or the standard limit. An accepted text is non-empty,
//! within the limit, free of CR and of controls other than TAB and LF,
//! and its own fixed point. Spans drawn from the input are checked: a span
//! the text accepts lies inside it on character boundaries.

#![no_main]

use fstp_import::{ImportLimits, ImportMedia, Span, normalise};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&head, body)) = data.split_first() else {
        return;
    };
    let media = if head % 2 == 1 {
        ImportMedia::TextMarkdown
    } else {
        ImportMedia::TextPlain
    };
    let limits = if head & 2 == 2 {
        ImportLimits::new(usize::from(head >> 2).saturating_add(1))
    } else {
        ImportLimits::standard()
    };
    assert!(limits.is_ok(), "the limits of the target are valid");
    let Ok(limits) = limits else {
        return;
    };
    let Ok(text) = normalise(body, media, limits) else {
        return;
    };
    let s = text.untrusted().as_data();
    assert!(!s.is_empty() && s.len() <= limits.max_bytes());
    assert!(s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'));
    assert!(!s.starts_with('\u{feff}'));
    let again = normalise(s.as_bytes(), media, limits);
    assert_eq!(
        again.map(|t| t.untrusted().as_data().to_owned()).as_deref(),
        Ok(s)
    );
    for pair in body.chunks_exact(2) {
        let (a, b) = match pair {
            [a, b] => (u32::from(*a), u32::from(*b)),
            _ => continue,
        };
        let span = Span { start: a, end: b };
        if text.check_span(span).is_ok() {
            let piece = text.evidence(span);
            assert!(piece.is_some_and(|p| !p.as_data().is_empty()));
            assert!(span.end <= text.byte_len());
        }
    }
});

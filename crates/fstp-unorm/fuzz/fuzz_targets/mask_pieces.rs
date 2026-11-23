//! Fuzz target for the pieces of a long text under the vault name mask
//! (M7 Q4, ADR-033 record of lane L40, TH-26).
//!
//! The first byte sets the piece size, 4 to 259 bytes. The rest splits at
//! its first two zero bytes into a family name, a given name and a text.
//! For any input the split never panics. When it cuts, the pieces cover
//! the text in order, each fits the size, and the joined spans of the
//! pieces equal the spans of the whole text.

#![no_main]

use fstp_unorm::mask::{MaskPerson, join_piece_spans, mask_pieces, mask_spans};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((size, rest)) = data.split_first() else {
        return;
    };
    let max = usize::from(*size) + 4;
    let mut parts = rest.splitn(3, |b| *b == 0);
    let family = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let given = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let text = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let people = [MaskPerson::new(&family, &given, Some("2001-12-31"))];
    let Some(pieces) = mask_pieces(&text, max) else {
        return;
    };
    let mut at = 0usize;
    for r in &pieces {
        assert_eq!(r.start, at);
        assert!(r.end - r.start <= max);
        at = r.end;
    }
    assert_eq!(at, text.len());
    let spans: Vec<_> = pieces
        .iter()
        .map(|r| mask_spans(&text[r.clone()], &people))
        .collect();
    assert_eq!(
        join_piece_spans(&text, &pieces, &spans),
        Some(mask_spans(&text, &people))
    );
});

//! Fuzz target for the vault name mask (M7 Q4, ADR-033 record of lane L31,
//! TH-26).
//!
//! The input splits at its first two zero bytes into a family name, a given
//! name and a text. For any input the mask never panics, and its spans lie
//! on character boundaries inside the text, sorted and disjoint, each with
//! a person of the request.

#![no_main]

use fstp_vault_core::mask::{MaskPerson, mask_spans};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |b| *b == 0);
    let family = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let given = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let text = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let people = [MaskPerson::new(&family, &given, Some("2001-12-31"))];
    let spans = mask_spans(&text, &people);
    let mut last = 0u32;
    for s in &spans {
        assert!(s.start < s.end && s.start >= last);
        assert!((s.end as usize) <= text.len());
        assert!(text.is_char_boundary(s.start as usize) && text.is_char_boundary(s.end as usize));
        assert_eq!(s.person, 0);
        last = s.end;
    }
});

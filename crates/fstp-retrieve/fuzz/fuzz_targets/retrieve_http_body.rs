//! TH-12: the body decoder (Content-Type field, charset, conversion)
//! against arbitrary field values and bodies.
//!
//! Properties checked beyond "no panic":
//!
//! - accepted text never exceeds the limit and holds no control character
//!   other than a line feed;
//! - an accepted field names a text media type the converter reads.

#![no_main]

use fstp_retrieve::decode_body;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let at = usize::from(split).min(rest.len());
    let (ct, body) = rest.split_at(at);
    let max = usize::from(split) * 8;
    let field = if split == 0 { None } else { Some(ct) };
    if let Ok(t) = decode_body(field, body, max) {
        assert!(t.text.len() <= max, "over the limit");
        assert!(
            t.text.chars().all(|c| c == '\n' || !c.is_control()),
            "control character in the text"
        );
        if let Some(ct) = field {
            let lower = String::from_utf8_lossy(ct).to_ascii_lowercase();
            assert!(
                ["text/html", "application/xhtml+xml", "text/plain", "text/markdown", "text/x-markdown"]
                    .iter()
                    .any(|m| lower.contains(m)),
                "accepted another media type"
            );
        }
    }
});

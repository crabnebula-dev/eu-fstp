//! TH-12, TH-01: the HTML-to-text converter against arbitrary input.
//!
//! Properties checked beyond "no panic":
//!
//! - the text never exceeds the byte limit;
//! - the text holds no control character other than a line feed;
//! - a smaller limit gives a prefix of the text under a larger one;
//! - a canary inside a script, style or comment never reaches the text.

#![no_main]

use fstp_retrieve::html_to_text;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&m, rest)) = data.split_first() else {
        return;
    };
    let max = usize::from(m) * 16;
    let html = String::from_utf8_lossy(rest);
    let out = html_to_text(&html, max);
    assert!(out.text.len() <= max, "over the limit");
    assert!(
        out.text.chars().all(|c| c == '\n' || !c.is_control()),
        "control character in the text"
    );

    let wide = html_to_text(&html, 1 << 20);
    if !wide.truncated {
        assert!(wide.text.starts_with(&out.text), "the limit changed the text");
        let canary = "QZXCANARYQZX";
        if !html.contains("QZX") && !html.to_ascii_lowercase().contains("<script") {
            for wrapped in [
                format!("<script>{canary}</script>{html}"),
                format!("<style>{canary}</style>{html}"),
                format!("<!--{canary}-->{html}"),
            ] {
                let t = html_to_text(&wrapped, 1 << 20);
                assert!(!t.text.contains(canary), "hidden content leaked");
            }
        }
    }
});

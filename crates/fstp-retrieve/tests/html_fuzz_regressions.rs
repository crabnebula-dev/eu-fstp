//! TH-12, TH-01: inputs the `retrieve_html_text` fuzz target found, kept
//! as regression tests. Each runs the target's own checks.

use fstp_retrieve::html_to_text;

/// The checks of `fuzz/fuzz_targets/retrieve_html_text.rs`, on one input.
fn check(data: &[u8]) {
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
        assert!(
            wide.text.starts_with(&out.text),
            "the limit changed the text"
        );
        let canary = "QZXCANARYQZX";
        if !html.contains("QZX") && !html.to_ascii_lowercase().contains("<script") {
            for wrapped in [
                format!("<script>{canary}</script>{html}"),
                format!("<style>{canary}</style>{html}"),
                format!("<!--{canary}-->{html}"),
            ] {
                let t = html_to_text(&wrapped, 1 << 20);
                assert!(
                    t.text.matches(canary).count() <= wide.text.matches(canary).count(),
                    "hidden content leaked"
                );
            }
        }
    }
}

/// TH-12: the crash of CI run 44047706424, fuzz smoke shard 2/4
/// (crash-60f8844387325c0bfbbff28ea1349dc5e6125fab). No hidden content
/// leaked. The visible text `QZ\x1aXCANARYQZ\0X` loses its control
/// characters, as it must, and so spells the canary itself. The check
/// now counts the canary in the text with and without the hidden part.
#[test]
fn th12_retrieve_html_text_crash_60f88443() {
    let data: &[u8] = &[
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6a, 0x0, 0x0, 0x6a, 0x6a, 0x0, 0x51, 0x5a, 0x1a,
        0x58, 0x43, 0x41, 0x4e, 0x41, 0x52, 0x59, 0x51, 0x5a, 0x0, 0x58, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x69, 0x70, 0x3e, 0x20, 0x72, 0x65, 0x62, 0x3c,
        0x3e, 0x63, 0x41, 0x3c, 0x2f, 0x70, 0x6d, 0x65, 0x20, 0xc0, 0xc1,
    ];
    check(data);
}

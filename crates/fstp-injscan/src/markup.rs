//! The literal and structural detectors: hidden markup, role tokens,
//! tool-call and schema payloads, exfiltration links, encoded blobs and
//! confusable words (ADR-035, "Detectors").

use crate::view::View;
use crate::{Detection, Reason};

fn push(out: &mut Vec<Detection>, v: &View, a: usize, b: usize, reason: Reason) {
    if let Some((start, end)) = v.span(a, b) {
        out.push(Detection { start, end, reason });
    }
}

/// Every byte offset of `needle` in `hay`.
fn find_all<'a>(hay: &'a str, needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    hay.match_indices(needle).map(|(i, _)| i)
}

/// Literal markers on the compact view (no white space).
const LITERALS: &[(&str, Reason)] = &[
    ("<|im_start|>", Reason::RoleMarker),
    ("<|im_end|>", Reason::RoleMarker),
    ("<|system|>", Reason::RoleMarker),
    ("<|user|>", Reason::RoleMarker),
    ("<|assistant|>", Reason::RoleMarker),
    ("<|endoftext|>", Reason::RoleMarker),
    ("<|eot_id|>", Reason::RoleMarker),
    ("<|start_header_id|>", Reason::RoleMarker),
    ("[inst]", Reason::RoleMarker),
    ("[/inst]", Reason::RoleMarker),
    ("<<sys>>", Reason::RoleMarker),
    ("<</sys>>", Reason::RoleMarker),
    ("<system>", Reason::RoleMarker),
    ("</system>", Reason::RoleMarker),
    ("<system_prompt", Reason::RoleMarker),
    ("beginsystemprompt", Reason::RoleMarker),
    ("<!--", Reason::HiddenMarkup),
    ("<tool_call", Reason::ToolCall),
    ("</tool_call", Reason::ToolCall),
    ("<function_calls", Reason::ToolCall),
    ("<invoke", Reason::ToolCall),
    ("\"tool_use\"", Reason::ToolCall),
    ("\"tool_calls\"", Reason::ToolCall),
    ("\"function_call\"", Reason::ToolCall),
    ("\"type\":\"function\"", Reason::ToolCall),
    ("fstp_", Reason::ToolCall),
    ("\"$schema\"", Reason::SchemaPayload),
    ("\"findings\":[", Reason::SchemaPayload),
];

/// The CSS or attribute value after a property name at byte `at` of the
/// compact view: past `:` or `=` and quotes, up to `;`, a quote, `>` or
/// 24 bytes.
fn value_after(s: &str, at: usize) -> Option<&str> {
    let rest = s.get(at..)?.trim_start_matches(' ');
    let rest = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?;
    let rest = rest.trim_start_matches([' ', '"', '\'']);
    let end = rest
        .char_indices()
        .find(|(i, c)| matches!(c, ';' | '"' | '\'' | '>' | '}' | '!' | '<') || *i >= 24)
        .map_or(rest.len(), |(i, _)| i);
    rest.get(..end)
}

/// The leading number of `v`, in thousandths, and whether it was negative.
fn number(v: &str) -> Option<(bool, u64)> {
    let (neg, v) = match v.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, v),
    };
    let mut whole: u64 = 0;
    let mut frac: u64 = 0;
    let mut scale: u64 = 1000;
    let mut digits = 0usize;
    let mut dot = false;
    for c in v.chars() {
        match c {
            '0'..='9' => {
                let d = u64::from(c.to_digit(10)?);
                digits = digits.saturating_add(1);
                if dot {
                    scale /= 10;
                    frac = frac.saturating_add(d.saturating_mul(scale));
                } else {
                    whole = whole.saturating_mul(10).saturating_add(d);
                }
            }
            '.' if !dot => dot = true,
            _ => break,
        }
    }
    (digits > 0).then(|| (neg, whole.saturating_mul(1000).saturating_add(frac)))
}

/// Whether a colour value is white or nearly white.
fn near_white(v: &str) -> bool {
    if matches!(
        v,
        "white" | "snow" | "ivory" | "ghostwhite" | "whitesmoke" | "transparent"
    ) {
        return true;
    }
    if let Some(hex) = v.strip_prefix('#') {
        let hex: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
        let parts: Vec<u32> = match hex.len() {
            3 | 4 => hex
                .chars()
                .take(3)
                .filter_map(|c| c.to_digit(16))
                .map(|d| d.saturating_mul(17))
                .collect(),
            6 | 8 => (0usize..3)
                .filter_map(|k| {
                    let a = k.saturating_mul(2);
                    hex.get(a..a.saturating_add(2))
                        .and_then(|p| u32::from_str_radix(p, 16).ok())
                })
                .collect(),
            _ => return false,
        };
        return parts.len() == 3 && parts.iter().all(|p| *p >= 0xf0);
    }
    if let Some(inner) = v.strip_prefix("rgb(").or_else(|| v.strip_prefix("rgba(")) {
        let parts: Vec<u64> = inner
            .split(',')
            .take(3)
            .filter_map(|p| number(p).map(|(_, n)| n / 1000))
            .collect();
        return parts.len() == 3 && parts.iter().all(|p| *p >= 240);
    }
    false
}

/// Styles that hide text, on the compact view.
fn styles(c: &View, out: &mut Vec<Detection>) {
    let s = &c.s;
    for (name, kind) in [
        ("display", 0u8),
        ("visibility", 1),
        ("opacity", 2),
        ("font-size", 3),
        ("color", 4),
        ("left", 5),
        ("top", 5),
        ("text-indent", 5),
        ("margin-left", 5),
        ("margin-top", 5),
    ] {
        for at in find_all(s, name) {
            // A property name stands alone: `background-color` and
            // `topic` are not `color` and `top`.
            let before = s.get(..at).and_then(|b| b.chars().next_back());
            if before.is_some_and(|b| b.is_alphanumeric() || b == '-' || b == '_') {
                continue;
            }
            let end = at.saturating_add(name.len());
            let Some(v) = value_after(s, end) else {
                continue;
            };
            let full = v;
            let v = v.split(' ').next().unwrap_or("");
            let hidden = match kind {
                0 => v.starts_with("none"),
                1 => v.starts_with("hidden") || v.starts_with("collapse"),
                2 => number(v).is_some_and(|(_, n)| n <= 50),
                3 => tiny(v),
                4 => near_white(v) || near_white(&full.replace(' ', "")),
                _ => number(v).is_some_and(|(neg, n)| neg && n >= 500_000),
            };
            if hidden {
                let b = end
                    .saturating_add(1)
                    .saturating_add(full.len())
                    .min(s.len());
                push(out, c, at, b, Reason::HiddenMarkup);
            }
        }
    }
}

/// A JSON object with `name` and `arguments` members within 300 bytes.
fn tool_json(c: &View, out: &mut Vec<Detection>) {
    let s = &c.s;
    for at in find_all(s, "\"arguments\":") {
        let from = at.saturating_sub(300);
        let window = (from..at).find(|i| s.is_char_boundary(*i)).unwrap_or(at);
        if s.get(window..at).is_some_and(|w| w.contains("\"name\":")) {
            push(out, c, at, at.saturating_add(12), Reason::ToolCall);
        }
    }
    for at in find_all(s, "\"statement\":") {
        let from = at.saturating_sub(300);
        let window = (from..at).find(|i| s.is_char_boundary(*i)).unwrap_or(at);
        if s.get(window..at)
            .is_some_and(|w| w.contains("\"severity\":"))
        {
            push(out, c, at, at.saturating_add(12), Reason::SchemaPayload);
        }
    }
}

/// Links that could carry data out, on the folded view.
fn links(v: &View, out: &mut Vec<Detection>) {
    let s = &v.s;
    for scheme in ["https://", "http://"] {
        for at in find_all(s, scheme) {
            // `https://` also holds no `http://`, so each link counts once.
            let rest = s.get(at..).unwrap_or("");
            let len = rest
                .char_indices()
                .find(|(_, c)| c.is_whitespace() || matches!(c, ')' | ']' | '>' | '"' | '\'' | '<'))
                .map_or(rest.len(), |(i, _)| i);
            let url = rest.get(..len).unwrap_or("");
            let query = url.split_once('?').map(|(_, q)| q);
            let template = url.contains("{{")
                || url.contains("%7b%7b")
                || url.contains("${")
                || url.contains("%24%7b");
            let before = s.get(..at).unwrap_or("");
            let image = before.ends_with("](")
                && before
                    .rfind("![")
                    .is_some_and(|i| !before.get(i..).unwrap_or("").contains('\n'))
                || before.ends_with("src=\"")
                || before.ends_with("src='")
                || before.ends_with("src=");
            let flagged = template
                || query.is_some_and(|q| q.len() >= 48)
                || (image && query.is_some_and(|q| !q.is_empty()));
            if flagged {
                push(out, v, at, at.saturating_add(len), Reason::ExfilLink);
            }
        }
    }
}

/// Literal, style, JSON and link detectors.
pub(crate) fn detect(folded: &View, compact: &View, out: &mut Vec<Detection>) {
    for (lit, reason) in LITERALS {
        for at in find_all(&compact.s, lit) {
            push(out, compact, at, at.saturating_add(lit.len()), *reason);
        }
    }
    styles(folded, out);
    tool_json(compact, out);
    links(folded, out);
}

/// Long base64 or hex runs of the original text (ASCII only).
pub(crate) fn blobs(text: &str, out: &mut Vec<Detection>) {
    let b = text.as_bytes();
    let b64 = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_');
    let mut i = 0usize;
    while i < b.len() {
        if !b.get(i).copied().is_some_and(b64) {
            i = i.saturating_add(1);
            continue;
        }
        let mut j = i;
        let (mut up, mut low, mut digit, mut hex) = (false, false, false, true);
        while let Some(&c) = b.get(j) {
            if !b64(c) {
                break;
            }
            up |= c.is_ascii_uppercase();
            low |= c.is_ascii_lowercase();
            digit |= c.is_ascii_digit();
            hex &= c.is_ascii_hexdigit();
            j = j.saturating_add(1);
        }
        let n = j.saturating_sub(i);
        if (hex && n >= 128) || (!hex && n >= 120 && up && low && digit) {
            out.push(Detection {
                start: i,
                end: j,
                reason: Reason::EncodedBlob,
            });
        }
        i = j;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Wide,
    Other,
}

fn script(c: char) -> Script {
    let u = u32::from(c);
    match u {
        0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Script::Latin,
        0x400..=0x52f | 0x1c80..=0x1c8f | 0x2de0..=0x2dff | 0xa640..=0xa69f => Script::Cyrillic,
        0x370..=0x3ff | 0x1f00..=0x1fff => Script::Greek,
        0xff21..=0xff3a | 0xff41..=0xff5a | 0x1d400..=0x1d7ff => Script::Wide,
        _ => Script::Other,
    }
}

/// Words that mix Latin with Cyrillic or Greek letters, or use full-width
/// or mathematical letters (ADR-035 `confusable`).
pub(crate) fn confusables(text: &str, out: &mut Vec<Detection>) {
    let mut start: Option<usize> = None;
    let mut seen = [false; 4];
    let mut flush = |start: &mut Option<usize>, seen: &mut [bool; 4], end: usize| {
        if let Some(a) = start.take() {
            let [latin, cyr, greek, wide] = *seen;
            if wide || (latin && (cyr || greek)) {
                out.push(Detection {
                    start: a,
                    end,
                    reason: Reason::Confusable,
                });
            }
        }
        *seen = [false; 4];
    };
    for (i, c) in text.char_indices() {
        // Hidden characters inside a word do not split it.
        if c.is_alphabetic() || crate::hidden::is_removed(c) {
            if start.is_none() {
                start = Some(i);
            }
            let k = match script(c) {
                Script::Latin => Some(0),
                Script::Cyrillic => Some(1),
                Script::Greek => Some(2),
                Script::Wide => Some(3),
                Script::Other => None,
            };
            if let Some(slot) = k.and_then(|k| seen.get_mut(k)) {
                *slot = true;
            }
        } else {
            flush(&mut start, &mut seen, i);
        }
    }
    flush(&mut start, &mut seen, text.len());
}

/// Whether a `font-size` value is tiny: at most 2 px or pt, 0.2 em or rem,
/// or 20 percent.
fn tiny(v: &str) -> bool {
    let Some((neg, n)) = number(v) else {
        return false;
    };
    let unit = v.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-');
    let limit = if unit.starts_with("em") || unit.starts_with("rem") {
        200
    } else if unit.starts_with('%') {
        20_000
    } else {
        2000
    };
    !neg && n <= limit
}

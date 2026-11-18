//! Character rules shared by every context, and hostile strings.
//!
//! Interim reading, pending Daniel: a document of the writer's subset holds
//! only "plain" characters, raw or as character references. A plain
//! character is TAB, LF, or any scalar value from U+0020 up that is not
//! DEL, a C1 control or a noncharacter. CR is not plain, because the HTML
//! parser rewrites it, so a text holding CR cannot round-trip.
//!
//! The writer either refuses a dynamic string that holds a character that
//! is not plain, or writes U+FFFD in its place. Every plain string must be
//! accepted in every text and attribute context.

use fstp_html::HtmlError;
use fstp_prop::Gen;

/// Whether `c` is a noncharacter (U+FDD0 to U+FDEF, or the last two code
/// points of any plane).
pub(crate) fn is_nonchar(c: char) -> bool {
    let cp = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

/// Whether `c` is plain (see the module documentation).
pub(crate) fn is_plain(c: char) -> bool {
    match c {
        '\t' | '\n' => true,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => false,
        _ => !is_nonchar(c),
    }
}

/// Whether every character of `s` is plain.
pub(crate) fn all_plain(s: &str) -> bool {
    s.chars().all(is_plain)
}

/// `s` with every character that is not plain replaced by U+FFFD.
pub(crate) fn replace_nonplain(s: &str) -> String {
    s.chars()
        .map(|c| if is_plain(c) { c } else { '\u{FFFD}' })
        .collect()
}

/// `s` with every character that is not plain replaced by `x`, so the
/// result is plain and keeps the hostile structure.
pub(crate) fn make_plain(s: &str) -> String {
    s.chars()
        .map(|c| if is_plain(c) { c } else { 'x' })
        .collect()
}

/// Whether `e` is a typed refusal, not the W0 stub's `NotImplemented`.
pub(crate) fn is_typed(e: &HtmlError) -> bool {
    !e.to_string().ends_with("is not implemented yet")
}

/// Whether a decoded URL attribute value is safe.
///
/// Interim reading, pending Daniel, after ADR-014 `safeUrl`: a URL is a
/// same-origin path or an `https:` URL. It holds only ASCII graphic
/// characters and no backslash, so no browser rewrites it into another
/// origin. A path starts with one `/`. An `https:` URL starts with
/// `https://` and a host.
///
/// Issue 6 L21: the reference follows the grammar of the frontend
/// `safeUrl` (`web/src/core/dom.ts`), so the writer accepts no URL the
/// frontend refuses. Each `%` is followed by two hex digits. The host is
/// lower-case LDH labels, with an optional port of one to five digits and
/// no userinfo. A host whose last label is all digits, or `0x` and hex
/// digits, is an IPv4 form and is unsafe. The frontend's fragment-only
/// link stays unsafe here, which is stricter.
pub(crate) fn is_safe_url(u: &str) -> bool {
    if u.is_empty() || !u.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\') {
        return false;
    }
    // Every `%` opens a two-digit hex escape.
    let bytes = u.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'%' {
            let pair = bytes.get(i + 1..i + 3);
            if !pair.is_some_and(|p| p.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
        }
    }
    if let Some(rest) = u.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        return safe_authority(authority);
    }
    bytes.first() == Some(&b'/') && bytes.get(1).is_none_or(|&c| c != b'/')
}

/// The authority rule of the frontend `safeUrl`, written from its text.
fn safe_authority(authority: &str) -> bool {
    let mut parts = authority.splitn(2, ':');
    let host = parts.next().unwrap_or("");
    if let Some(port) = parts.next()
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let ldh = |l: &&str| {
        let alnum = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
        !l.is_empty()
            && l.starts_with(alnum)
            && l.ends_with(alnum)
            && l.chars().all(|c| alnum(c) || c == '-')
    };
    if !labels.iter().all(ldh) {
        return false;
    }
    let last = labels.last().copied().unwrap_or("");
    let digits = last.chars().all(|c| c.is_ascii_digit());
    let hex = last.strip_prefix("0x").is_some_and(|h| {
        h.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    });
    !digits && !hex
}

/// Fragments that break naive escaping in some context.
pub(crate) const HOSTILE: &[&str] = &[
    "<",
    ">",
    "&",
    "\"",
    "'",
    "`",
    "=",
    "/",
    "</p>",
    "</title>",
    "</TITLE >",
    "</textarea>",
    "</option>",
    "</td>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\" onmouseover=\"alert(1)",
    "' onfocus='alert(1)",
    "\"><svg onload=alert(1)>",
    "&amp;",
    "&lt;",
    "&#60;",
    "&#x3C;",
    "&#",
    "&nbsp",
    "&quot;",
    "<!--",
    "-->",
    "<![CDATA[",
    "]]>",
    "<?php ?>",
    "<!DOCTYPE html>",
    "javascript:alert(1)",
    "\n",
    "\n\n",
    "\t",
    "\r",
    "\r\n",
    "\u{0}",
    "\u{1}",
    "\u{c}",
    "\u{7f}",
    "\u{85}",
    "\u{a0}",
    "\u{200b}",
    "\u{202e}",
    "\u{feff}",
    "\u{fffd}",
    "\u{fffe}",
    "\u{fdd0}",
    "\u{1fffe}",
    "\u{10ffff}",
    "\u{1F600}",
    "{name}",
    "{{",
    "}}",
    "CANARY-ID-7f3a",
];

/// A string built from hostile fragments and arbitrary characters. It may
/// hold characters that are not plain.
pub(crate) fn hostile(g: &mut Gen) -> String {
    let parts = g.vec(0..=5, |g| {
        if g.u8_in(0..=2) == 0 {
            g.string(0..=6)
        } else {
            (*g.pick(HOSTILE)).to_owned()
        }
    });
    parts.concat()
}

/// A plain string built from hostile fragments.
pub(crate) fn hostile_plain(g: &mut Gen) -> String {
    make_plain(&hostile(g))
}

/// A dynamic string: plain three times in four, so both writer outcomes
/// for characters that are not plain are exercised.
pub(crate) fn dynamic(g: &mut Gen) -> String {
    if g.u8_in(0..=3) == 0 {
        hostile(g)
    } else {
        hostile_plain(g)
    }
}

/// Characters that are safe inside a URL path.
const URL_SAFE: &[u8] = b"abcxyzABZ0189-._~!$&'()*+,;=:@/?#%\"<>[]^`{|}";

/// A URL attribute value: safe about half the time, otherwise built to
/// probe one way a URL can leave the origin or run script.
pub(crate) fn url(g: &mut Gen) -> String {
    const UNSAFE: &[&str] = &[
        "",
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        " javascript:alert(1)",
        "jav\tascript:alert(1)",
        "java\nscript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:image/png;base64,AAAA",
        "//evil.example/",
        "/\\evil.example/",
        "\\\\evil.example/",
        "/\t/evil.example/",
        "/\n/evil.example/",
        " /x",
        "/x ",
        "/a b",
        "http://example.org/",
        "HTTPS://example.org/",
        "https:/example.org/",
        "https:///example.org/",
        "https://",
        "mailto:a@example.org",
        "evil.example",
        "x/y",
        "#top",
        "?q=1",
        "/\u{e9}",
        "/\u{0}",
        "/\u{7f}",
        "/\u{85}",
    ];
    match g.u8_in(0..=5) {
        0 => (*g.pick(UNSAFE)).to_owned(),
        1 => {
            let mut s = (*g.pick(UNSAFE)).to_owned();
            s.push_str(&hostile(g));
            s
        }
        2 => format!("/{}", g.ascii_string(0..=8)),
        3 => {
            let tail: String = g
                .vec(0..=12, |g| char::from(*g.pick(URL_SAFE)))
                .into_iter()
                .collect();
            format!("https://example.org/{tail}")
        }
        _ => {
            let tail: String = g
                .vec(0..=12, |g| char::from(*g.pick(URL_SAFE)))
                .into_iter()
                .collect();
            format!("/p/{tail}")
        }
    }
}

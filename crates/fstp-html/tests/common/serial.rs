//! Reference serializer into the writer's subset.
//!
//! It writes a decoded tree back to bytes. The generator draws each
//! spelling choice the subset allows: the doctype case, character
//! references, boolean attribute forms, and attribute order and
//! separators. It also draws `/>` on void elements, layout whitespace in
//! containers, and the line feed after `<pre>` and `<textarea>`. A correct
//! checker accepts every one of these documents.

use fstp_prop::Gen;

use super::reference::{DROPS_LEADING_LF, REl, RNode, VOID};

const CONTAINERS: &[&str] = &[
    "html", "head", "table", "thead", "tbody", "tfoot", "tr", "ul", "ol", "dl", "select",
];

/// Serializes `html` as a whole document.
pub(crate) fn document(g: &mut Gen, html: &REl) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(if g.bool() {
        "<!DOCTYPE html>"
    } else {
        "<!doctype html>"
    });
    if g.u8_in(0..=3) == 0 {
        out.push('\n');
    }
    element(g, html, &mut out);
    out.into_bytes()
}

fn numeric(g: &mut Gen, c: char) -> String {
    let cp = u32::from(c);
    match g.u8_in(0..=3) {
        0 => format!("&#{cp};"),
        1 => format!("&#00{cp};"),
        2 => format!("&#x{cp:x};"),
        _ => format!("&#X{cp:X};"),
    }
}

fn pick(g: &mut Gen, options: &[&str]) -> String {
    (*g.pick(options)).to_owned()
}

/// Escapes text content (normal, RCDATA and option text alike).
fn text(g: &mut Gen, s: &str, out: &mut String) {
    for c in s.chars() {
        let piece = match c {
            '&' => pick(g, &["&amp;", "&#38;", "&#x26;"]),
            '<' => pick(g, &["&lt;", "&#60;", "&#x3C;", "&#X3c;"]),
            '>' => pick(g, &[">", "&gt;", "&#62;"]),
            '"' => pick(g, &["\"", "&quot;", "&#34;"]),
            '\'' => pick(g, &["'", "&apos;", "&#39;", "&#x27;"]),
            _ if g.u8_in(0..=15) == 0 => numeric(g, c),
            _ => c.to_string(),
        };
        out.push_str(&piece);
    }
}

/// Escapes a double-quoted attribute value.
fn attr(g: &mut Gen, s: &str, out: &mut String) {
    for c in s.chars() {
        let piece = match c {
            '&' => pick(g, &["&amp;", "&#38;"]),
            '"' => pick(g, &["&quot;", "&#34;", "&#x22;"]),
            '<' => pick(g, &["<", "&lt;"]),
            '>' => pick(g, &[">", "&gt;"]),
            '\'' => pick(g, &["'", "&apos;", "&#39;"]),
            _ if g.u8_in(0..=15) == 0 => numeric(g, c),
            _ => c.to_string(),
        };
        out.push_str(&piece);
    }
}

fn element(g: &mut Gen, el: &REl, out: &mut String) {
    out.push('<');
    out.push_str(&el.name);
    let mut attrs: Vec<(&String, &String)> = el.attrs.iter().collect();
    g.shuffle(&mut attrs);
    for (name, value) in attrs {
        out.push_str(&pick(g, &[" ", " ", "\n", "\t", "  "]));
        out.push_str(name);
        if value.is_empty() && g.bool() {
            continue;
        }
        out.push_str("=\"");
        attr(g, value, out);
        out.push('"');
    }
    let void = VOID.contains(&el.name.as_str());
    if void {
        out.push_str(&pick(g, &[">", "/>", " />", " >"]));
        return;
    }
    out.push_str(&pick(g, &[">", ">", " >"]));
    let first_is_lf = matches!(el.children.first(), Some(RNode::Text(t)) if t.starts_with('\n'));
    if DROPS_LEADING_LF.contains(&el.name.as_str()) && (first_is_lf || g.u8_in(0..=3) == 0) {
        out.push_str(&pick(g, &["\n", "&#10;", "&#xA;"]));
    }
    let container = CONTAINERS.contains(&el.name.as_str());
    for child in &el.children {
        if container && g.u8_in(0..=2) == 0 {
            out.push_str(&pick(g, &[" ", "\n", "\n  ", "\t"]));
        }
        match child {
            RNode::Text(t) => text(g, t, out),
            RNode::El(e) => element(g, e, out),
        }
    }
    if container && g.u8_in(0..=2) == 0 {
        out.push('\n');
    }
    out.push_str("</");
    out.push_str(&el.name);
    out.push('>');
}

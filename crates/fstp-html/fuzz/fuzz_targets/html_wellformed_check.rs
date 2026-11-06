//! Fuzz target `html_wellformed_check` of `fstp-html` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: the checker never panics on arbitrary bytes; it accepts
//! every document the writer produces.
//!
//! This target checks that no input panics, that the verdict is the same
//! twice, and that an accepted input has the outer shape of the subset:
//! UTF-8, the doctype first, `</html>` last, and no NUL or CR. The tests
//! in `crates/fstp-html/tests/wellformed.rs` compare the checker with
//! the full reference.
//!
//! For the second design check, the same input also drives a small page
//! builder over the writer API: elements, attributes, texts, URLs,
//! catalogue messages and `<meta>` items, valid or not. When the writer
//! accepts the page, the checker must accept its output, and the traced
//! and untraced renders must give the same bytes.

#![no_main]

use std::sync::OnceLock;

use fstp_html::{
    ApprovedText, CatalogueSource, Catalogues, Document, Element, EntrySource, Label, MessageKind,
    Node, SafeUrl,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_html::check_wellformed(data);
    assert_eq!(first, fstp_html::check_wellformed(data));
    match first {
        Ok(()) => {
            let s = std::str::from_utf8(data).ok();
            assert!(s.is_some(), "accepted bytes that are not UTF-8");
            let s = s.unwrap_or_default();
            assert!(
                s.starts_with("<!DOCTYPE html>") || s.starts_with("<!doctype html>"),
                "accepted a document without the doctype"
            );
            assert!(s.ends_with("</html>"), "accepted content after </html>");
            assert!(!s.contains('\0') && !s.contains('\r'), "accepted NUL or CR");
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
    writer_output_is_accepted(data);
});

/// Tags the builder draws, including some the writer must refuse.
const TAGS: &[&str] = &[
    "p",
    "div",
    "span",
    "a",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "caption",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "strong",
    "em",
    "code",
    "time",
    "br",
    "hr",
    "img",
    "form",
    "label",
    "input",
    "button",
    "select",
    "option",
    "textarea",
    "pre",
    "h1",
    "h2",
    "nav",
    "section",
    "details",
    "summary",
    "blockquote",
    "script",
    "style",
    "body",
    "title",
    "meta",
    // The closed SVG subset (lane j3, ADR-015), and SVG elements outside it.
    "svg",
    "g",
    "rect",
    "circle",
    "path",
    "line",
    "text",
    "tspan",
    "desc",
    "defs",
    "marker",
    "foreignobject",
    "animate",
    "use",
];

/// Attributes the builder draws, including some the writer must refuse.
const ATTRS: &[&str] = &[
    "title",
    "aria-label",
    "id",
    "class",
    "href",
    "src",
    "action",
    "alt",
    "value",
    "placeholder",
    "required",
    "disabled",
    "selected",
    "datetime",
    "lang",
    "onclick",
    "style",
    // SVG attributes (lane j3, ADR-015), allowed and refused.
    "viewbox",
    "x",
    "y1",
    "rx",
    "d",
    "marker-end",
    "fill",
    "stroke",
    "text-anchor",
    "aria-hidden",
    "role",
    "onload",
];

/// `<meta name>` values the builder draws, including some the writer must
/// refuse.
const META_NAMES: &[&str] = &[
    "description",
    "viewport",
    "robots",
    "color-scheme",
    "refresh",
    "referrer",
    "http-equiv",
    "",
];

/// Message ids the builder draws, with their kind and placeholder.
const MESSAGES: &[(&str, MessageKind, Option<&str>)] = &[
    ("nav.home", MessageKind::Label, None),
    ("call.deadline", MessageKind::Label, Some("date")),
    ("notice.synthetic", MessageKind::Approved, Some("org")),
    ("no.such.id", MessageKind::Label, None),
];

fn catalogues() -> Option<&'static Catalogues> {
    static CATS: OnceLock<Option<Catalogues>> = OnceLock::new();
    CATS.get_or_init(|| {
        let en = [
            EntrySource {
                id: "nav.home",
                kind: MessageKind::Label,
                message: "Home & <away>",
            },
            EntrySource {
                id: "call.deadline",
                kind: MessageKind::Label,
                message: "Deadline: {date} \"{{x}}\"",
            },
            EntrySource {
                id: "notice.synthetic",
                kind: MessageKind::Approved,
                message: "SYNTHETIC TEST WORDING for {org}. NOT LEGAL TEXT.",
            },
        ];
        let fr = [
            EntrySource {
                id: "nav.home",
                kind: MessageKind::Label,
                message: "Accueil",
            },
            EntrySource {
                id: "call.deadline",
                kind: MessageKind::Label,
                message: "{date} <{date}>",
            },
            EntrySource {
                id: "notice.synthetic",
                kind: MessageKind::Approved,
                message: "TEXTE DE TEST pour {org}.",
            },
        ];
        Catalogues::new(
            &CatalogueSource {
                locale: "en",
                entries: &en,
            },
            &[CatalogueSource {
                locale: "fr",
                entries: &fr,
            }],
        )
        .ok()
    })
    .as_ref()
}

/// Reads the input as builder instructions.
struct Ops<'a> {
    data: &'a [u8],
    at: usize,
}

impl Ops<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.at).copied();
        self.at = self.at.saturating_add(1);
        b
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> Option<T> {
        let b = usize::from(self.byte()?);
        from.get(b % from.len().max(1)).copied()
    }

    /// A string of up to 15 input bytes, decoded lossily.
    fn chunk(&mut self) -> String {
        let n = usize::from(self.byte().unwrap_or(0) % 16);
        let start = self.at.min(self.data.len());
        let end = start.saturating_add(n).min(self.data.len());
        self.at = end;
        String::from_utf8_lossy(self.data.get(start..end).unwrap_or(&[])).into_owned()
    }

    fn message(&mut self) -> Option<Node> {
        let (id, kind, arg) = self.pick(MESSAGES)?;
        let value = self.chunk();
        let args: Vec<(&str, &str)> = arg.map(|a| (a, value.as_str())).into_iter().collect();
        Some(match kind {
            MessageKind::Label => Node::label(&Label::new(id), &args),
            MessageKind::Approved => Node::approved(&ApprovedText::new(id), &args),
        })
    }
}

fn attach(stack: &mut [Element], body: &mut Vec<Node>, node: Node) {
    match stack.last_mut() {
        Some(top) => top.push_child(node),
        None => body.push(node),
    }
}

fn build(data: &[u8]) -> Document {
    let mut ops = Ops { data, at: 0 };
    let locale = if ops.byte().unwrap_or(0).is_multiple_of(2) {
        "en"
    } else {
        "fr"
    };
    let mut doc = Document::new(locale).title(Node::text(&ops.chunk()));
    let mut stack: Vec<Element> = Vec::new();
    let mut body: Vec<Node> = Vec::new();
    while let Some(op) = ops.byte() {
        match op % 10 {
            0 if stack.len() < 32 => {
                if let Some(tag) = ops.pick(TAGS) {
                    stack.push(Element::new(tag));
                }
            }
            1 => {
                if let Some(done) = stack.pop() {
                    attach(&mut stack, &mut body, done.into());
                }
            }
            2 => {
                let t = ops.chunk();
                attach(&mut stack, &mut body, Node::text(&t));
            }
            3 => {
                if let (Some(name), Some(top)) = (ops.pick(ATTRS), stack.pop()) {
                    stack.push(top.attr(name, &ops.chunk()));
                }
            }
            4 => {
                let u = ops.chunk();
                if let (Some(name), Ok(url), Some(top)) =
                    (ops.pick(ATTRS), SafeUrl::new(&u), stack.pop())
                {
                    stack.push(top.attr_url(name, url));
                }
            }
            5 => {
                if let (Some(name), Some(top)) = (ops.pick(ATTRS), stack.pop()) {
                    stack.push(top.flag(name));
                }
            }
            6 => {
                if let Some(m) = ops.message() {
                    attach(&mut stack, &mut body, m);
                }
            }
            7 => {
                if let Some(m) = ops.message() {
                    doc = doc.title(m);
                }
            }
            8 => {
                if let Ok(url) = SafeUrl::new(&ops.chunk()) {
                    doc = doc.stylesheet(url);
                }
            }
            9 => {
                if let Some(name) = ops.pick(META_NAMES) {
                    doc = doc.meta(name, &ops.chunk());
                }
            }
            _ => {}
        }
    }
    while let Some(done) = stack.pop() {
        attach(&mut stack, &mut body, done.into());
    }
    for n in body {
        doc.push_body(n);
    }
    doc
}

fn writer_output_is_accepted(data: &[u8]) {
    let Some(cats) = catalogues() else {
        return;
    };
    let doc = build(data);
    let plain = doc.render(cats);
    let traced = doc.render_traced(cats).map(|(d, _)| d);
    assert_eq!(plain, traced, "the trace changed the output");
    if let Ok(out) = plain {
        assert_eq!(
            fstp_html::check_wellformed(out.as_bytes()),
            Ok(()),
            "the checker refused a document the writer produced: {}",
            out.as_str()
        );
    }
}

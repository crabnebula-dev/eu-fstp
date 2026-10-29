//! The writer has no raw-insertion API (I-68, M4 design section 1.1).
//!
//! I-68 says no tenant-supplied markup executes. If the crate offered any
//! way to put a caller's string into the output unescaped, one call would
//! undo every escaping property. Rust has no reflection, so this is a
//! source scan of `crates/fstp-html/src/**`, the same kind of guard as the
//! `web_scan` of ADR-014 for the TypeScript side. A compile-fail twin in
//! `src/` would be stronger, and is recorded as a gap for the implementer.
//!
//! The scan refuses:
//!
//! - a public function, method, type or constant whose name holds a word
//!   that signals unescaped output (`raw`, `unescaped`, `unchecked`,
//!   `dangerous`, `trusted`, `verbatim`, `inner_html`, `html_str`,
//!   `from_html`, `push_html`, `write_html`, `insert_html`);
//! - a public function that returns `&mut String` or `&mut Vec<u8>`,
//!   which would hand out the output buffer;
//! - an `impl` of `fmt::Write` or `io::Write`, through which `write!`
//!   would bypass escaping.
//!
//! Green against the W0 stub, which has no writer. It guards the writer
//! the implementer adds.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

const BANNED_WORDS: &[&str] = &[
    "raw",
    "unescaped",
    "unchecked",
    "dangerous",
    "trusted",
    "verbatim",
    "inner_html",
    "html_str",
    "from_html",
    "push_html",
    "write_html",
    "insert_html",
];

const PUB_ITEMS: &[&str] = &[
    "pub fn ",
    "pub const fn ",
    "pub struct ",
    "pub enum ",
    "pub trait ",
    "pub type ",
    "pub const ",
    "pub static ",
];

const WRITE_IMPLS: &[&str] = &[
    "fmt::Write for",
    "io::Write for",
    "impl Write for",
    "core::fmt::Write for",
];

/// The breaches of the rules in one source file, one line each.
fn scan(name: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let at = format!("{name}:{}", i + 1);
        for item in PUB_ITEMS {
            if let Some(rest) = code.split(item).nth(1) {
                let ident: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let lower = ident.to_ascii_lowercase();
                let words: Vec<&str> = lower.split('_').collect();
                for w in BANNED_WORDS {
                    let hit = if w.contains('_') {
                        lower.contains(w)
                    } else {
                        words.contains(w) || camel_words(&ident).iter().any(|c| c == w)
                    };
                    if hit {
                        out.push(format!("{at}: public item {ident} names {w:?}"));
                    }
                }
            }
        }
        if code.contains("pub fn ")
            && (code.contains("-> &mut String") || code.contains("-> &mut Vec<u8>"))
        {
            out.push(format!("{at}: public function hands out a buffer"));
        }
        for w in WRITE_IMPLS {
            if code.contains(w) {
                out.push(format!("{at}: implements {w}"));
            }
        }
    }
    out
}

/// The lower-cased words of a `CamelCase` identifier.
fn camel_words(ident: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in ident.chars() {
        if c.is_uppercase() || out.is_empty() {
            out.push(String::new());
        }
        if let Some(last) = out.last_mut() {
            last.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// I-68: no file of `crates/fstp-html/src` offers a raw-insertion API.
#[test]
fn i68_no_raw_insertion_api() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty(), "no source under {}", src.display());
    let mut breaches = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        breaches.extend(scan(&f.display().to_string(), &text));
    }
    assert!(breaches.is_empty(), "{}", breaches.join("\n"));
}

/// I-68: the scan has teeth. Each seeded breach is found, and ordinary
/// writer names pass.
#[test]
fn i68_no_raw_insertion_api_scan_has_teeth() {
    let seeded = [
        "pub fn push_raw(&mut self, s: &str) {}",
        "    pub fn raw(&mut self, s: &str) -> &mut Self { self }",
        "pub fn text_unescaped(&mut self, s: &str) {}",
        "pub struct RawHtml(String);",
        "pub struct TrustedHtml(String);",
        "pub fn from_html_string(s: String) -> Html { Html(s) }",
        "pub fn buffer(&mut self) -> &mut String { &mut self.out }",
        "pub fn bytes_mut(&mut self) -> &mut Vec<u8> { &mut self.out }",
        "impl std::fmt::Write for Writer {",
        "impl Write for Writer {",
        "pub const fn dangerous_insert() {}",
    ];
    for s in seeded {
        assert!(!scan("seeded", s).is_empty(), "the scan misses {s:?}");
    }
    let clean = [
        "pub fn text(&mut self, s: &str) {}",
        "pub fn attr_text(&mut self, name: AttrName, value: &str) {}",
        "pub fn label(&mut self, l: &Label) {}",
        "pub fn approved(&mut self, t: &ApprovedText) {}",
        "pub struct Drawer;",
        "pub fn finish(self) -> HtmlDocument { todo }",
        "// pub fn raw(&mut self) is not offered",
    ];
    for s in clean {
        assert!(scan("clean", s).is_empty(), "the scan refuses {s:?}");
    }
}

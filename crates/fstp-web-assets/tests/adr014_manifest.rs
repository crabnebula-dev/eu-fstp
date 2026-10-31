//! The asset manifest decoder (ADR-014 "Shell, assets and headers", M4
//! design sections 1.1, 3.9 and 9, TH-26, H-05).
//!
//! The manifest is the list `fstp-web-assets` verifies the compiled
//! frontend against at start. `assets_common` states the grammar these
//! tests read. Lane W4e's test author wrote them before the decoder
//! exists, so each is red because the W0 stub refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod assets_common;

use assets_common::{SCHEMA, decode, manifest_json, refused};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// A hash text that is well formed. Synthetic.
const H1: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// A second well-formed hash text. Synthetic.
const H2: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

/// A well-formed manifest with an entry, a nested module and a stylesheet.
fn good() -> String {
    manifest_json(
        "main.js",
        &[("main.js", H1), ("core/dom.js", H2), ("styles/app.css", H2)],
    )
}

/// ADR-014: a well-formed manifest decodes, in compact and in
/// pretty-printed form, and both forms decode to the same value.
#[test]
fn adr014_manifest_accepts_a_wellformed_manifest() {
    let compact = decode(good().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let pretty = format!(
        "{{\n  \"schema\": \"{SCHEMA}\",\n  \"entry\": \"main.js\",\n  \"assets\": {{\n    \
         \"main.js\": \"{H1}\",\n    \"core/dom.js\": \"{H2}\",\n    \"styles/app.css\": \"{H2}\"\n  }}\n}}\n"
    );
    let pretty = decode(pretty.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(compact, pretty);
}

/// ADR-014: two paths may share one hash, because `tsc` writes the same
/// `export {};` for every module with types only.
#[test]
fn adr014_manifest_allows_two_paths_with_one_hash() {
    let text = manifest_json(
        "main.js",
        &[("main.js", H1), ("core/types.js", H2), ("gen/empty.js", H2)],
    );
    decode(text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
}

/// ADR-014, TH-26: every malformed manifest is refused with a typed error.
/// Each case changes one thing in a well-formed manifest.
#[test]
fn adr014_manifest_refuses_every_malformed_manifest() {
    let long_path = format!("{}.js", "a".repeat(198));
    let entry_assets = |entry: &str, path: &str| manifest_json(entry, &[(path, H1)]);
    let cases: Vec<(&str, String)> = vec![
        ("not JSON", "{".to_owned()),
        ("empty input", String::new()),
        ("an array", "[]".to_owned()),
        ("trailing bytes", format!("{} x", good())),
        (
            "an unknown member",
            good().replacen("{\"assets\"", "{\"extra\":\"x\",\"assets\"", 1),
        ),
        (
            "no schema",
            format!("{{\"assets\":{{\"main.js\":\"{H1}\"}},\"entry\":\"main.js\"}}"),
        ),
        (
            "no entry",
            format!("{{\"assets\":{{\"main.js\":\"{H1}\"}},\"schema\":\"{SCHEMA}\"}}"),
        ),
        (
            "no assets",
            format!("{{\"entry\":\"main.js\",\"schema\":\"{SCHEMA}\"}}"),
        ),
        (
            "another schema",
            good().replace(SCHEMA, "fstp.web-assets/2"),
        ),
        ("empty assets", manifest_json("main.js", &[])),
        (
            "a duplicated path",
            manifest_json("main.js", &[("main.js", H1), ("main.js", H2)]),
        ),
        (
            "a duplicated top-level member",
            good().replacen("{\"assets\"", "{\"entry\":\"main.js\",\"assets\"", 1),
        ),
        (
            "uppercase hash digits",
            manifest_json("main.js", &[("main.js", &H1.to_ascii_uppercase())]),
        ),
        (
            "63 hash digits",
            manifest_json("main.js", &[("main.js", &H1[..63])]),
        ),
        (
            "65 hash digits",
            manifest_json("main.js", &[("main.js", &format!("{H1}0"))]),
        ),
        (
            "a non-hexadecimal digit",
            manifest_json("main.js", &[("main.js", &format!("g{}", &H1[1..]))]),
        ),
        (
            "a number as hash",
            format!(
                "{{\"assets\":{{\"main.js\":1}},\"entry\":\"main.js\",\"schema\":\"{SCHEMA}\"}}"
            ),
        ),
        ("a parent segment", entry_assets("main.js", "../main.js")),
        ("a leading slash", entry_assets("/main.js", "/main.js")),
        (
            "an empty segment",
            entry_assets("core//main.js", "core//main.js"),
        ),
        ("a trailing slash", entry_assets("main.js/", "main.js/")),
        ("a dot segment", entry_assets("./main.js", "./main.js")),
        ("a leading dot", entry_assets(".main.js", ".main.js")),
        ("two dots inside", entry_assets("ma..in.js", "ma..in.js")),
        (
            "an escaped backslash",
            entry_assets("core\\\\main.js", "core\\\\main.js"),
        ),
        (
            "an escaped letter",
            entry_assets("\\u006dain.js", "\\u006dain.js"),
        ),
        (
            "an escaped slash",
            entry_assets("core\\/main.js", "core\\/main.js"),
        ),
        (
            "a percent sign",
            entry_assets("%2e%2e/main.js", "%2e%2e/main.js"),
        ),
        ("a space", entry_assets("ma in.js", "ma in.js")),
        (
            "a non-ASCII letter",
            entry_assets("m\u{e4}in.js", "m\u{e4}in.js"),
        ),
        ("a TypeScript source", entry_assets("main.ts", "main.ts")),
        ("no extension", entry_assets("main", "main")),
        ("an empty path", entry_assets("", "")),
        (
            "a path over 200 bytes",
            entry_assets(&long_path, &long_path),
        ),
        (
            "seventeen segments",
            entry_assets(
                &format!("{}main.js", "a/".repeat(16)),
                &format!("{}main.js", "a/".repeat(16)),
            ),
        ),
        (
            "an entry that is not listed",
            manifest_json("other.js", &[("main.js", H1)]),
        ),
        (
            "a stylesheet as entry",
            manifest_json("app.css", &[("main.js", H1), ("app.css", H2)]),
        ),
    ];
    let mut failures = Vec::new();
    for (label, text) in &cases {
        if let Err(why) = refused(decode(text.as_bytes())) {
            failures.push(format!("{label}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A path segment from the allowed alphabet that does not start with a dot.
fn segment(g: &mut Gen) -> String {
    const FIRST: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    let len = g.usize_in(1..=8);
    let mut s = String::new();
    for i in 0..len {
        let b = *g.pick(FIRST);
        s.push(char::from(b));
        if i + 1 < len && g.u8_in(0..=9) == 0 {
            s.push('.');
        }
    }
    s
}

/// A well-formed path with 1 to 4 segments and a `.js` or `.css` ending.
fn path(g: &mut Gen, ext: &str) -> String {
    let mut segs = g.vec(0..=3, segment);
    segs.push(format!("{}{ext}", segment(g)));
    segs.join("/")
}

/// A hash text of 64 lowercase hexadecimal digits.
fn hash(g: &mut Gen) -> String {
    assets_common::hex(&g.bytes(32..=32))
}

/// A generated well-formed manifest: its entry and its assets, without
/// repeated paths.
fn manifest_parts(g: &mut Gen) -> (String, Vec<(String, String)>) {
    let entry = path(g, ".js");
    let mut assets = vec![(entry.clone(), hash(g))];
    for _ in 0..g.usize_in(0..=5) {
        let ext = if g.bool() { ".js" } else { ".css" };
        let p = path(g, ext);
        if assets.iter().all(|(q, _)| *q != p) {
            assets.push((p, hash(g)));
        }
    }
    (entry, assets)
}

/// ADR-014: generated well-formed manifests decode, and the decoded value
/// does not depend on the order of the asset members.
#[test]
fn adr014_manifest_decode_ignores_member_order() {
    fstp_prop::check("adr014_manifest_decode_ignores_member_order", |g| {
        let (entry, mut assets) = manifest_parts(g);
        let pairs: Vec<(&str, &str)> = assets
            .iter()
            .map(|(p, h)| (p.as_str(), h.as_str()))
            .collect();
        let first = decode(manifest_json(&entry, &pairs).as_bytes());
        g.shuffle(&mut assets);
        let pairs: Vec<(&str, &str)> = assets
            .iter()
            .map(|(p, h)| (p.as_str(), h.as_str()))
            .collect();
        let second = decode(manifest_json(&entry, &pairs).as_bytes());
        prop_assert!(first.is_ok(), "{first:?}");
        prop_assert_eq!(first, second);
        Ok(())
    });
}

/// ADR-014, TH-26: one forbidden byte put into a path of a well-formed
/// manifest makes it refused, wherever it lands in the path.
#[test]
fn adr014_manifest_refuses_a_forbidden_byte_in_any_path() {
    fstp_prop::check(
        "adr014_manifest_refuses_a_forbidden_byte_in_any_path",
        |g| {
            const FORBIDDEN: &[&str] = &[
                " ", "%", "\\\\", "\\u0041", ":", "?", "#", "*", "~", "+", "=", "&", "\u{e9}",
                "\u{0130}", "..", "//",
            ];
            let (entry, mut assets) = manifest_parts(g);
            let at = g.usize_in(0..=assets.len() - 1);
            let target = assets[at].0.clone();
            let cut = g.usize_in(0..=target.len());
            let bad = *g.pick(FORBIDDEN);
            let mut changed = String::new();
            changed.push_str(&target[..cut]);
            changed.push_str(bad);
            changed.push_str(&target[cut..]);
            g.note("path", &changed);
            assets[at].0 = changed.clone();
            let entry = if target == entry { changed } else { entry };
            let pairs: Vec<(&str, &str)> = assets
                .iter()
                .map(|(p, h)| (p.as_str(), h.as_str()))
                .collect();
            refused(decode(manifest_json(&entry, &pairs).as_bytes()))
        },
    );
}

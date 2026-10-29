//! Loading and serving the compiled frontend (ADR-014 "Shell, assets and
//! headers", M4 design sections 1.1 and 3.9).
//!
//! `fstp-web-assets` loads the compiled frontend from a directory and
//! verifies it against the SHA-256 manifest at start. It then serves each
//! asset at its content-addressed path with fixed headers, immutable.
//! `assets_common` states the layout and headers these tests read. Lane
//! W4e's test author wrote them before the loader exists, so each is red
//! because the loader seam refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod assets_common;

use assets_common::{
    ASSET_HEADERS_CSS, ASSET_HEADERS_JS, ASSET_PREFIX, MANIFEST_FILE, ScratchDir, entry_path, load,
    manifest_for, manifest_json, refused, sample_files, serve, served_as, sha_hex,
};

/// The request path of the asset with content `content` and extension `ext`.
fn url(content: &[u8], ext: &str) -> String {
    format!("{ASSET_PREFIX}{}{ext}", sha_hex(content))
}

/// The extension of a manifest path, with its dot.
fn ext_of(path: &str) -> &'static str {
    if path.ends_with(".css") {
        ".css"
    } else {
        ".js"
    }
}

/// ADR-014: a verified directory loads, and every listed asset is served
/// at its content-addressed path with its bytes and the fixed headers.
#[test]
fn adr014_load_verifies_and_serves_every_asset() {
    let dir = ScratchDir::new("serves");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let set = load(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let mut failures = Vec::new();
    for (path, content) in &files {
        let ext = ext_of(path);
        let fixed: &[(&str, &str)] = if ext == ".css" {
            &ASSET_HEADERS_CSS
        } else {
            &ASSET_HEADERS_JS
        };
        match serve(&set, &url(content, ext)) {
            Ok(Some(resp)) => {
                if let Err(why) = served_as(&resp, content, fixed) {
                    failures.push(format!("{path}: {why}"));
                }
            }
            Ok(None) => failures.push(format!("{path}: not served")),
            Err(e) => failures.push(format!("{path}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// ADR-014: the entry path is the content-addressed path of the
/// manifest's entry module.
#[test]
fn adr014_load_names_the_entry_by_its_hash() {
    let dir = ScratchDir::new("entry");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let set = load(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let main = &files.iter().find(|(p, _)| p == "main.js").unwrap().1;
    assert_eq!(
        entry_path(&set).unwrap_or_else(|e| panic!("{e}")),
        url(main, ".js")
    );
}

/// ADR-014: one changed byte in any listed file refuses the whole set at
/// start.
#[test]
fn adr014_load_refuses_any_changed_byte() {
    fstp_prop::check("adr014_load_refuses_any_changed_byte", |g| {
        let dir = ScratchDir::new("tamper");
        let files = sample_files();
        let manifest = manifest_for(&files);
        let mut tampered = files.clone();
        let which = g.usize_in(0..=tampered.len() - 1);
        let content = &mut tampered[which].1;
        let at = g.usize_in(0..=content.len() - 1);
        let flip = g.u8_in(1..=255);
        content[at] ^= flip;
        g.note("file", &tampered[which].0);
        dir.write_all(&tampered, &manifest);
        refused(load(dir.path()))
    });
}

/// ADR-014: a listed file that is missing refuses the set at start.
#[test]
fn adr014_load_refuses_a_missing_asset() {
    let dir = ScratchDir::new("missing");
    let files = sample_files();
    let manifest = manifest_for(&files);
    let present: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter(|(p, _)| p != "core/dom.js")
        .cloned()
        .collect();
    dir.write_all(&present, &manifest);
    refused(load(dir.path())).unwrap_or_else(|e| panic!("{e}"));
}

/// ADR-014: a listed path that is a directory, not a file, refuses the
/// set at start.
#[test]
fn adr014_load_refuses_a_directory_in_place_of_an_asset() {
    let dir = ScratchDir::new("isdir");
    let mut files = sample_files();
    files.push(("lib/inner.js".to_owned(), b"export {};\n".to_vec()));
    let manifest = manifest_for(&files);
    let others: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter(|(p, _)| p != "lib/inner.js")
        .cloned()
        .collect();
    dir.write_all(&others, &manifest);
    std::fs::create_dir_all(dir.path().join("lib/inner.js")).unwrap();
    refused(load(dir.path())).unwrap_or_else(|e| panic!("{e}"));
}

/// ADR-014: a directory without a manifest, or with a malformed one,
/// refuses to load.
#[test]
fn adr014_load_refuses_a_missing_or_malformed_manifest() {
    let files = sample_files();
    let none = ScratchDir::new("nomanifest");
    for (p, c) in &files {
        none.write(p, c);
    }
    let bad = ScratchDir::new("badmanifest");
    bad.write_all(&files, "{\"assets\":{}}");
    let mut failures = Vec::new();
    for (label, d) in [("no manifest", &none), ("malformed manifest", &bad)] {
        if let Err(why) = refused(load(d.path())) {
            failures.push(format!("{label}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// ADR-014: a file the manifest does not list is never served, even under
/// its own hash. A listed hash under the other extension is not served
/// either, nor is an unknown hash.
#[test]
fn adr014_load_serves_nothing_outside_the_manifest() {
    let dir = ScratchDir::new("unlisted");
    let files = sample_files();
    dir.write_all(&files, &manifest_for(&files));
    let stray = b"export const stray = 1;\n";
    dir.write("stray.js", stray);
    let set = load(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let main = &files.iter().find(|(p, _)| p == "main.js").unwrap().1;
    let css = &files.iter().find(|(p, _)| p == "styles/app.css").unwrap().1;
    let cases = [
        ("the unlisted file", url(stray, ".js")),
        ("a module under .css", url(main, ".css")),
        ("a stylesheet under .js", url(css, ".js")),
        (
            "an unknown hash",
            format!("{ASSET_PREFIX}{}.js", "ab".repeat(32)),
        ),
        (
            "the manifest by name",
            format!("{ASSET_PREFIX}{MANIFEST_FILE}"),
        ),
        ("a module by its path", "/app/assets/main.js".to_owned()),
    ];
    let mut failures = Vec::new();
    for (label, p) in &cases {
        match serve(&set, p) {
            Ok(None) => {}
            Ok(Some(resp)) => failures.push(format!("{label}: served {}", resp.status.as_u16())),
            Err(e) => failures.push(format!("{label}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// ADR-014: a manifest whose entry hash does not match the entry file
/// refuses the set, however well formed the rest is.
#[test]
fn adr014_load_refuses_a_manifest_with_a_wrong_entry_hash() {
    let dir = ScratchDir::new("wrongentry");
    let files = sample_files();
    let mut pairs: Vec<(String, String)> =
        files.iter().map(|(p, c)| (p.clone(), sha_hex(c))).collect();
    let dom = pairs
        .iter()
        .find(|(p, _)| p == "core/dom.js")
        .unwrap()
        .1
        .clone();
    for (p, h) in &mut pairs {
        if p == "main.js" {
            h.clone_from(&dom);
        }
    }
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(p, h)| (p.as_str(), h.as_str()))
        .collect();
    dir.write_all(&files, &manifest_json("main.js", &borrowed));
    refused(load(dir.path())).unwrap_or_else(|e| panic!("{e}"));
}

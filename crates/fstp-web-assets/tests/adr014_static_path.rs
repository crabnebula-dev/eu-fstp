//! The asset path resolver (ADR-014 "Shell, assets and headers", M4
//! design sections 3.9 and 9, TH-26, H-05).
//!
//! Assets are served at `/app/assets/{sha256}.js`, and by the interim
//! reading of `assets_common` also at `/app/assets/{sha256}.css`. Every
//! other spelling is refused before any lookup, so no request path can
//! name a file outside the manifest. Lane W4e's test author wrote these
//! tests before the resolver exists, so each is red because the W0 stub
//! refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod assets_common;

use assets_common::{ASSET_PREFIX, hex, path_grammar, refused, resolve};
use fstp_prop::{Gen, prop_assert, prop_assert_eq, prop_assert_ne};

/// A well-formed hash text. Synthetic.
const H: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// ADR-014: the content-addressed path of a module and of a stylesheet
/// resolve.
#[test]
fn adr014_static_path_accepts_content_addressed_paths() {
    for ext in [".js", ".css"] {
        let p = format!("{ASSET_PREFIX}{H}{ext}");
        resolve(p.as_bytes()).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
}

/// ADR-014, TH-26: every other spelling of an asset path is refused with a
/// typed error.
#[test]
fn adr014_static_path_refuses_every_other_spelling() {
    let upper = H.to_ascii_uppercase();
    let cases: Vec<String> = vec![
        String::new(),
        "/".to_owned(),
        ASSET_PREFIX.to_owned(),
        format!("{ASSET_PREFIX}{H}"),
        format!("{ASSET_PREFIX}{H}."),
        format!("{ASSET_PREFIX}{upper}.js"),
        format!("{ASSET_PREFIX}{}.js", &H[..63]),
        format!("{ASSET_PREFIX}{H}0.js"),
        format!("{ASSET_PREFIX}{H}.JS"),
        format!("{ASSET_PREFIX}{H}.mjs"),
        format!("{ASSET_PREFIX}{H}.js.map"),
        format!("{ASSET_PREFIX}{H}.html"),
        format!("{ASSET_PREFIX}{H}.js/"),
        format!("{ASSET_PREFIX}{H}.js?v=1"),
        format!("{ASSET_PREFIX}{H}.js#x"),
        format!("{ASSET_PREFIX}{H}%2ejs"),
        format!("{ASSET_PREFIX}../{H}.js"),
        format!("{ASSET_PREFIX}./{H}.js"),
        format!("{ASSET_PREFIX}x/{H}.js"),
        format!("/app/assets//{H}.js"),
        format!("/app//assets/{H}.js"),
        format!("//app/assets/{H}.js"),
        format!("/APP/assets/{H}.js"),
        format!("/app/Assets/{H}.js"),
        format!("app/assets/{H}.js"),
        format!("/app/assets%2f{H}.js"),
        format!("/app/assets\\{H}.js"),
        format!(" {ASSET_PREFIX}{H}.js"),
        format!("{ASSET_PREFIX}{H}.js "),
        format!("{ASSET_PREFIX}{H}.js\0"),
        format!("/p/x/assets/{H}.js"),
        "/app/assets/main.js".to_owned(),
        "/app/assets/core/dom.js".to_owned(),
    ];
    let mut failures = Vec::new();
    for p in &cases {
        if let Err(why) = refused(resolve(p.as_bytes())) {
            failures.push(format!("{p:?}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A request path near the asset grammar: built from its pieces, then
/// sometimes changed by one byte.
fn near_path(g: &mut Gen) -> Vec<u8> {
    const PREFIXES: &[&str] = &[
        "/app/assets/",
        "/app/assets",
        "/app/asset/",
        "/APP/assets/",
        "/app/assets//",
        "",
    ];
    const EXTS: &[&str] = &[".js", ".css", ".JS", ".mjs", "", ".js/", ".cs", ".jss"];
    let mut p = g.pick(PREFIXES).as_bytes().to_vec();
    let digits = g.usize_in(62..=66);
    for _ in 0..digits {
        let alphabet: &[u8] = if g.u8_in(0..=15) == 0 {
            b"ABCDEFGHg/.%"
        } else {
            b"0123456789abcdef"
        };
        p.push(*g.pick(alphabet));
    }
    p.extend_from_slice(g.pick(EXTS).as_bytes());
    if g.u8_in(0..=3) == 0 && !p.is_empty() {
        let at = g.usize_in(0..=p.len() - 1);
        p[at] = g.u8();
    }
    p
}

/// ADR-014, TH-26: a path resolves exactly when it matches the asset
/// grammar, checked both ways over paths near the grammar.
#[test]
fn adr014_static_path_resolves_exactly_the_grammar() {
    fstp_prop::check("adr014_static_path_resolves_exactly_the_grammar", |g| {
        let p = near_path(g);
        g.note("path", &String::from_utf8_lossy(&p));
        let got = resolve(&p);
        if path_grammar(&p) {
            prop_assert!(got.is_ok(), "{got:?}");
            Ok(())
        } else {
            refused(got)
        }
    });
}

/// ADR-014: two asset paths resolve to equal values exactly when their
/// hash and extension are equal.
#[test]
fn adr014_static_path_distinct_hashes_resolve_apart() {
    fstp_prop::check("adr014_static_path_distinct_hashes_resolve_apart", |g| {
        let a = g.bytes(32..=32);
        let b = if g.bool() {
            a.clone()
        } else {
            g.bytes(32..=32)
        };
        let ea = if g.bool() { ".js" } else { ".css" };
        let eb = if g.bool() {
            ea
        } else if ea == ".js" {
            ".css"
        } else {
            ".js"
        };
        let pa = format!("{ASSET_PREFIX}{}{ea}", hex(&a));
        let pb = format!("{ASSET_PREFIX}{}{eb}", hex(&b));
        let ra = resolve(pa.as_bytes());
        let rb = resolve(pb.as_bytes());
        prop_assert!(ra.is_ok() && rb.is_ok(), "{ra:?} {rb:?}");
        if pa == pb {
            prop_assert_eq!(ra, rb);
        } else {
            prop_assert_ne!(ra, rb);
        }
        Ok(())
    });
}

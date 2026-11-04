//! The demo sign-in of lane m4/site (scope item 8, Daniel 2026-11-04)
//! lives in the test-only `fstp-e2e-cell` binary only (layering rule A9,
//! ADR-014). The platform never gains its route, its flag or its bypass.
//!
//! - `fstp-web`, the router every cell mounts, answers 404 on the demo
//!   sign-in route for `GET` and for a `POST` that passes CSRF.
//! - No source file of a platform crate names the route or the flag. The
//!   one place allowed is `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/`.
//!
//! The e2e half, `e2e/site/demo.spec.ts` `demo_signin_absent_without_flag`,
//! checks that the cell started without the flag answers 404 on the
//! route, and that the cell started with it serves it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use std::path::{Path, PathBuf};

use web_common::{TENANT_ORIGIN, get, request, serve};

/// The demo sign-in route of `e2e/site/contract.ts` `DEMO_SIGNIN_PATH`.
const DEMO_SIGNIN_PATH: &str = "/auth/demo-signin";

/// The words that name the demo sign-in in source: the route, the flag
/// and the identifier forms of both.
const NAMES: &[&str] = &[
    "demo-signin",
    "demo_signin",
    "demosignin",
    "DemoSignin",
    "DEMO_SIGNIN",
];

/// The one directory whose sources may name the demo sign-in.
const ALLOWED: &str = "crates/fstp-api-testkit/src/bin/fstp-e2e-cell";

/// The repository root, two levels above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Every `.rs` file below `dir`, depth first.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// A9, ADR-014: `fstp-web` answers 404 on the demo sign-in route, for
/// `GET` and for a `POST` that carries the tenant `Origin` and
/// `X-FSTP-Request`.
#[test]
fn demo_signin_absent_without_flag_in_fstp_web_routes() {
    let g = get(DEMO_SIGNIN_PATH);
    assert_eq!(g.status.as_u16(), 404, "GET {DEMO_SIGNIN_PATH}");
    let raw = request(
        "POST",
        DEMO_SIGNIN_PATH,
        &[
            ("Origin", TENANT_ORIGIN),
            ("X-FSTP-Request", "1"),
            ("Content-Type", "application/json"),
        ],
        br#"{"token":"00"}"#,
    );
    let p = serve(&raw).unwrap_or_else(|e| panic!("POST {DEMO_SIGNIN_PATH}: {e}"));
    assert_eq!(p.status.as_u16(), 404, "POST {DEMO_SIGNIN_PATH}");
}

/// A9: no platform crate names the demo sign-in route or flag. Only the
/// test-only cell binary may.
#[test]
fn demo_signin_absent_without_flag_in_platform_sources() {
    let root = repo();
    let crates = root.join("crates");
    let mut members: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("crates/")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    members.sort();
    assert!(
        members.len() > 10,
        "the workspace crates are found below {}",
        crates.display()
    );
    let allowed = root.join(ALLOWED);
    let mut found = Vec::new();
    let mut scanned = 0usize;
    for m in members {
        let mut files = Vec::new();
        rust_files(&m.join("src"), &mut files);
        for f in files {
            if f.starts_with(&allowed) {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            for n in NAMES {
                if text.contains(n) {
                    found.push(format!(
                        "{} names {n}",
                        f.strip_prefix(&root).unwrap_or(&f).display()
                    ));
                }
            }
        }
    }
    assert!(
        scanned > 100,
        "the platform sources are scanned ({scanned} files)"
    );
    assert!(
        found.is_empty(),
        "A9: the demo sign-in leaks into the platform: {found:#?}"
    );
}

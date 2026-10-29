//! I-19, boundary rule B5 and layering rule 5 (M3 design sections 1.2 and
//! 2.4, ADR-009 "Edge and tunnel"): the edge holds no tenant TLS server.
//!
//! `fstp-edge` depends on `fstp-tls` for its tunnel client only. This
//! scan reads every Rust source file that ships with the crate, which is
//! everything under `src/`, and refuses any name of the TLS server API.
//! It reads raw text, comments included, so it is stricter than the
//! token scan of `tools/deps-check` (`layering-m3-edge-tls`). Tests and
//! fuzz targets do not ship and are not read: they run an `fstp-tls`
//! server as the differential oracle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::path::{Path, PathBuf};

/// Names that only a TLS server needs. Any occurrence is refused.
const SERVER_NAMES: [&str; 5] = [
    "ServerConfig",
    "ServerConnection",
    "ServerConfigBuilder",
    "fstp_tls::accept",
    "rustls::server",
];

/// The `fstp-tls` client API, the only names the edge may reach through
/// `fstp_tls`.
const CLIENT_NAMES: [&str; 12] = [
    "ClientConfig",
    "ClientConfigBuilder",
    "connect",
    "TlsStream",
    "TlsError",
    "TlsErrorKind",
    "PemLimits",
    "MAX_ALPN_LEN",
    "MAX_ALPN_PROTOCOLS",
    "CIPHER_SUITES",
    "KEY_EXCHANGE_GROUPS",
    "MAX_RESUMPTION_AGE",
];

/// One refused occurrence: a line number and what it names.
type Finding = (usize, String);

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The identifier that starts at `text[at..]`, after any whitespace.
fn ident_at(text: &str, at: usize) -> (&str, usize) {
    let bytes = text.as_bytes();
    let mut i = at;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && is_ident_byte(bytes[i]) {
        i += 1;
    }
    (&text[start..i], i)
}

/// Checks the items of a `use fstp_tls::{...}` group that opens at
/// `text[open]`. Each item's first segment must be a client name or a
/// bare `self`. Nested groups and aliases are refused.
fn check_group(text: &str, open: usize, line: usize, out: &mut Vec<Finding>) {
    let Some(len) = text[open..].find('}') else {
        out.push((line, "an unclosed fstp_tls group".to_owned()));
        return;
    };
    let inner = &text[open + 1..open + len];
    if inner.contains('{') {
        out.push((line, "a nested fstp_tls group".to_owned()));
    }
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.split_whitespace().any(|w| w == "as") {
            out.push((line, format!("the aliased fstp_tls item `{item}`")));
            continue;
        }
        let first = item.split("::").next().unwrap_or("").trim();
        if first != "self" && !CLIENT_NAMES.contains(&first) {
            out.push((line, format!("the fstp_tls item `{item}`")));
        }
    }
}

/// Every refused occurrence in one source text.
fn scan_text(text: &str) -> Vec<Finding> {
    let line_of = |at: usize| text[..at].matches('\n').count() + 1;
    let mut out = Vec::new();
    for name in SERVER_NAMES {
        for (at, _) in text.match_indices(name) {
            out.push((line_of(at), format!("`{name}`")));
        }
    }
    let bytes = text.as_bytes();
    for (at, _) in text.match_indices("fstp_tls") {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        if before.is_some_and(is_ident_byte) {
            continue;
        }
        let after = at + "fstp_tls".len();
        if bytes.get(after).copied().is_some_and(is_ident_byte) {
            continue;
        }
        let line = line_of(at);
        let rest = text[after..].trim_start();
        let skipped = text.len() - after - rest.len();
        if let Some(path) = rest.strip_prefix("::") {
            let path_at = after + skipped + 2;
            let trimmed = path.trim_start();
            if trimmed.starts_with('{') {
                let open = path_at + (path.len() - trimmed.len());
                check_group(text, open, line, &mut out);
            } else if trimmed.starts_with('*') {
                out.push((line, "the glob `fstp_tls::*`".to_owned()));
            } else {
                let (name, _) = ident_at(text, path_at);
                if !CLIENT_NAMES.contains(&name) {
                    out.push((line, format!("`fstp_tls::{name}`")));
                }
            }
        } else if rest.starts_with("as")
            && !rest.as_bytes().get(2).copied().is_some_and(is_ident_byte)
        {
            out.push((line, "an alias of fstp_tls".to_owned()));
        }
    }
    out
}

/// Every `.rs` file below `dir`, sorted.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// I-19, B5 (design section 2.4 rule 5): no shipped source file of
/// `fstp-edge` names the TLS server API, and every `fstp_tls` path there
/// names the client API. The crate's manifest does not rename `fstp-tls`,
/// so the scan reads the only name the crate can use for it.
#[test]
fn i19_rule5_edge_sources_name_no_tls_server_api() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let build = root.join("build.rs");
    if build.exists() {
        files.push(build);
    }
    let names: Vec<String> = files
        .iter()
        .map(|p| p.strip_prefix(root).unwrap().display().to_string())
        .collect();
    assert!(names.iter().any(|n| n == "src/lib.rs"), "scanned {names:?}");
    assert!(
        names.iter().any(|n| n == "src/main.rs"),
        "scanned {names:?}"
    );
    let mut findings = Vec::new();
    for (p, n) in files.iter().zip(&names) {
        let text = fs::read_to_string(p).unwrap();
        for (line, what) in scan_text(&text) {
            findings.push(format!("{n}:{line}: {what}"));
        }
    }
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    for line in manifest.lines() {
        if line.contains("package") && line.contains("fstp-tls") {
            findings.push(format!("Cargo.toml renames fstp-tls: {line}"));
        }
    }
    assert!(
        findings.is_empty(),
        "the edge names the TLS server API (I-19, design section 2.4 rule 5):\n{}",
        findings.join("\n")
    );
}

/// I-19 teeth for rule 5: each seeded server construction is found by
/// the scan above, and the client API alone passes it.
#[test]
fn i19_rule5_teeth_seeded_server_api_is_caught() {
    let seeded = [
        "let c = fstp_tls::ServerConfig::new(chain, key);",
        "use fstp_tls::ServerConfig;",
        "use fstp_tls::{connect, accept};",
        "use fstp_tls::{TlsStream,\n    accept as serve};",
        "use fstp_tls::{self as t};",
        "use fstp_tls::{stream::{accept}};",
        "use fstp_tls::*;",
        "use fstp_tls as t;",
        "extern crate fstp_tls as t;",
        "let s = ::fstp_tls::accept(&cfg, io).await;",
        "let b = fstp_tls::ServerConfigBuilder::default();",
        "fn f(c: &rustls::ServerConnection) {}",
        "// Holds a rustls::server::Acceptor.",
        "let x = fstp_tls :: accept;",
    ];
    for text in seeded {
        assert!(!scan_text(text).is_empty(), "not caught: {text:?}");
    }
    let client = "//! The tunnel client.\n\
                  use fstp_tls::{self, ClientConfig, TlsStream, connect};\n\
                  async fn f(c: &ClientConfig) { let _ = fstp_tls::connect; }\n\
                  fn g(e: fstp_tls::TlsError) -> fstp_tls::TlsErrorKind { e.kind() }\n\
                  fn h(my_fstp_tls_count: u8) -> u8 { my_fstp_tls_count }\n";
    assert_eq!(scan_text(client), Vec::<Finding>::new());
}

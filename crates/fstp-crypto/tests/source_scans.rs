//! Source scans for the nonce rule and the hybrid rule (ADR-004 "Nonce
//! rule", R-NF-08, I-75, design section 2.4 rules 8 and 9).
//!
//! These read source text only, with comments removed. They call no
//! `fstp-crypto` code, so they run before the M3 modules exist and keep
//! guarding once they do. The workspace-wide scan
//! `r_nf_08_no_api_takes_a_caller_nonce` of lane W1f covers every crate;
//! the scans here fix the `fstp-crypto` side of it.
//!
//! The scan needles are built with `concat!`, so this file does not name
//! the identifiers it refuses and no other scan reads them here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{lines_naming, rel, repo_root, rust_files, strip_comments};

/// The aws-lc-rs AEAD and cipher names that take or build a caller nonce
/// or IV. ADR-004 "Nonce rule" refuses them outside
/// `crates/fstp-crypto/src/aead.rs`. The two key entries also match the
/// TLS record sealing and opening keys, which take a caller nonce. The
/// last entry covers the caller IVs of the aws-lc-rs cipher module.
const NONCE_NAMES: [&str; 7] = [
    concat!("LessSafe", "Key"),
    concat!("Sealing", "Key"),
    concat!("Opening", "Key"),
    concat!("Nonce", "Sequence"),
    concat!("Nonce", "::"),
    concat!("assume_unique", "_for_key"),
    concat!("Encryption", "Context"),
];

/// The aws-lc-rs modules that hold every AEAD and cipher key, nonce and
/// IV type. ADR-004 "Nonce rule" sends every AES-256-GCM seal through
/// `fstp_crypto::aead`, so no other file names them, as a path or inside
/// an `aws_lc_rs::{..}` group. That also catches a nonce built through
/// `.into()` after a plain import.
const NONCE_MODULES: [&str; 2] = [concat!("ae", "ad"), concat!("ci", "pher")];

/// Whether `c` can continue an identifier.
fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The lines of `code` that name `module` of the crate `krate`: through a
/// path (`krate::module` and then a non-identifier character), or as a
/// top-level item of a `krate::{..}` group, which may span lines. The
/// line reported is the one where `krate` starts. A `krate` right after
/// `::` or an identifier character belongs to another path, such as a
/// module of the same name inside rustls, and is skipped.
fn lines_naming_module(code: &str, krate: &str, module: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(krate) {
        let start = from + at;
        from = start + krate.len();
        let before = &code[..start];
        if before.ends_with("::") || before.chars().next_back().is_some_and(ident_char) {
            continue;
        }
        let Some(rest) = code[from..].strip_prefix("::") else {
            continue;
        };
        let mut hit = false;
        if let Some(after) = rest.strip_prefix(module) {
            hit = !after.chars().next().is_some_and(ident_char);
        } else if let Some(group) = rest.strip_prefix('{') {
            let mut depth = 0usize;
            let mut word = String::new();
            for c in group.chars() {
                if ident_char(c) {
                    word.push(c);
                    continue;
                }
                if depth == 0 && word == module {
                    hit = true;
                }
                word.clear();
                match c {
                    '{' => depth += 1,
                    '}' if depth == 0 => break,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
        }
        if hit {
            out.push(before.matches('\n').count() + 1);
        }
    }
    out
}

/// A finding: the file, the line and the name it uses.
type Finding = (String, usize, &'static str);

/// Every use of a [`NONCE_NAMES`] entry in `files`, except in
/// `crates/fstp-crypto/src/aead.rs`.
fn nonce_findings(files: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, text) in files {
        if path == "crates/fstp-crypto/src/aead.rs" {
            continue;
        }
        for needle in NONCE_NAMES {
            for (line, _) in lines_naming(text, needle) {
                out.push((path.clone(), line, needle));
            }
        }
        let code = strip_comments(text);
        for module in NONCE_MODULES {
            for line in lines_naming_module(&code, "aws_lc_rs", module) {
                out.push((path.clone(), line, module));
            }
        }
    }
    out
}

fn read_all(paths: &[PathBuf]) -> Vec<(String, String)> {
    paths
        .iter()
        .map(|p| (rel(p), fs::read_to_string(p).unwrap()))
        .collect()
}

/// Every `.rs` file of the workspace's crates and tools, without build
/// output.
fn workspace_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = rust_files(&root.join("crates"));
    files.extend(rust_files(&root.join("tools")));
    files
}

fn crypto_src() -> Vec<PathBuf> {
    rust_files(&repo_root().join("crates/fstp-crypto/src"))
}

/// R-NF-08, ADR-004 "Nonce rule": no code in the workspace names an
/// aws-lc-rs AEAD key or nonce constructor outside `fstp_crypto::aead`.
/// Test files of other crates count too, so no test builds a fixed-nonce
/// seal around the rule.
#[test]
fn r_nf_08_aead_nonces_are_built_only_in_fstp_crypto_aead() {
    let files: Vec<PathBuf> = workspace_files()
        .into_iter()
        .filter(|p| !p.starts_with(repo_root().join("crates/fstp-crypto/tests")))
        .collect();
    let found = nonce_findings(&read_all(&files));
    assert!(
        found.is_empty(),
        "nonce constructors outside aead.rs: {found:#?}"
    );
}

/// R-NF-08, teeth: the scan finds a counter nonce in a fixture ledger
/// file, and ignores the same text in a comment and in `aead.rs`.
#[test]
fn r_nf_08_teeth_scan_finds_a_counter_nonce() {
    let body = format!(
        "fn seal_body(seq: u64) {{ let n = {}{}(seq_bytes(seq)); }}\n",
        NONCE_NAMES[4], "assume_unique_for_key"
    );
    let fixture = vec![
        ("crates/fstp-ledger/src/body.rs".to_string(), body.clone()),
        (
            "crates/fstp-ledger/src/doc.rs".to_string(),
            format!("// {body}"),
        ),
        ("crates/fstp-crypto/src/aead.rs".to_string(), body),
    ];
    let found = nonce_findings(&fixture);
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(
        found
            .iter()
            .all(|(p, l, _)| p == "crates/fstp-ledger/src/body.rs" && *l == 1)
    );
}

/// R-NF-08, teeth: the scan finds the TLS record keys, the cipher module
/// and its caller IVs, and an AEAD import whose nonce is built through
/// `.into()`, each in a fixture outside `aead.rs`. It ignores the same
/// text in `aead.rs`, and a rustls module that shares the crate name.
#[test]
fn r_nf_08_teeth_scan_finds_tls_record_keys_and_cipher_ivs() {
    let (aead, cipher) = (NONCE_MODULES[0], NONCE_MODULES[1]);
    let fixtures = [
        format!("let k = TlsRecord{}::new(alg, key);\n", NONCE_NAMES[1]),
        format!("let k = TlsRecord{}::new(alg, key);\n", NONCE_NAMES[2]),
        format!("use aws_lc_rs::{cipher}::PaddedBlockEncryptingKey;\n"),
        format!("let c = {}::Iv128(iv.into());\n", NONCE_NAMES[6]),
        format!("use aws_lc_rs::{aead}::{{Aad, RandomizedNonceKey}};\n"),
        format!("use aws_lc_rs::{{rand, {aead}}};\n"),
        format!("use aws_lc_rs::{{\n    rand,\n    {cipher}::{{self, X}},\n}};\n"),
    ];
    for body in fixtures {
        let files = vec![
            ("crates/fstp-ledger/src/body.rs".to_string(), body.clone()),
            ("crates/fstp-crypto/src/aead.rs".to_string(), body.clone()),
        ];
        let found = nonce_findings(&files);
        assert!(!found.is_empty(), "{body}");
        assert!(
            found
                .iter()
                .all(|(p, l, _)| p == "crates/fstp-ledger/src/body.rs" && *l == 1),
            "{body}: {found:#?}"
        );
    }
    let quiet = vec![(
        "crates/fstp-tls/src/provider.rs".to_string(),
        format!(
            "use rustls::crypto::aws_lc_rs::{{self, {cipher}_suite}};\n\
             use aws_lc_rs::{{digest, hmac}};\nuse aws_lc_rs::{cipher}_x;\n\
             use aws_lc_rs::rand::{{{aead}}};\n"
        ),
    )];
    assert_eq!(nonce_findings(&quiet), Vec::<Finding>::new());
}

/// ADR-004 "Nonce rule": once `aead.rs` exists, it seals through
/// `RandomizedNonceKey`, and no `pub fn seal` in it has a nonce parameter.
/// It stays red until the module exists.
#[test]
fn r_nf_08_crypto_aead_seals_through_randomized_nonce_key() {
    let path = repo_root().join("crates/fstp-crypto/src/aead.rs");
    let text = fs::read_to_string(&path).expect("crates/fstp-crypto/src/aead.rs is missing");
    let code = strip_comments(&text);
    assert!(
        code.contains(concat!("Randomized", "NonceKey")),
        "aead.rs does not use RandomizedNonceKey"
    );
    for (n, line) in code.lines().enumerate() {
        if line.contains("pub fn seal") {
            let sig: String = code.lines().skip(n).take(8).collect::<Vec<_>>().join(" ");
            let params = sig.split(')').next().unwrap_or("").to_lowercase();
            assert!(
                !params.contains("nonce"),
                "aead.rs line {}: a seal function takes a nonce: {params}",
                n + 1
            );
        }
    }
}

/// `code` with each raw-identifier prefix removed, so `r#mlkem` reads as
/// `mlkem`. A raw string such as `r#"x"#` keeps its prefix, and the line
/// breaks stay where they are.
fn unraw(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut prev_ident = false;
    let mut chars = code.chars();
    while let Some(c) = chars.next() {
        if c == 'r' && !prev_ident {
            let mut ahead = chars.clone();
            if ahead.next() == Some('#') && ahead.next().is_some_and(ident_char) {
                chars.next();
                continue;
            }
        }
        prev_ident = ident_char(c);
        out.push(c);
    }
    out
}

/// The identifiers of `code`, in order.
fn words(code: &str) -> impl Iterator<Item = &str> {
    code.split(|c: char| !ident_char(c))
        .filter(|w| !w.is_empty())
}

/// The aws-lc-rs post-quantum names, built so this file does not name
/// them (design section 2.4 rule 9). The two `ML_` entries are prefixes,
/// so every parameter set is covered, not only the ones M3 uses.
fn aws_lc_pq_names() -> [String; 5] {
    [
        format!("ML_{}", "KEM_"),
        format!("ML_{}", "DSA_"),
        format!("Pq{}", "dsa"),
        format!("aws_lc_rs::{}", "kem"),
        format!("aws_lc_rs::{}", "unstable"),
    ]
}

/// The aws-lc-rs modules that hold its post-quantum API.
const AWS_PQ_MODULES: [&str; 2] = ["kem", "unstable"];

/// Every way `files` (path, source) reach the aws-lc-rs post-quantum
/// API: a name of [`aws_lc_pq_names`], a [`AWS_PQ_MODULES`] entry inside
/// an `aws_lc_rs::{..}` group at any depth of nesting below it, or a glob
/// or rename of `aws_lc_rs` that the scan could not follow.
fn aws_pq_findings(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in files {
        let code = unraw(&strip_comments(text));
        for needle in aws_lc_pq_names() {
            for (line, l) in lines_naming(&code, &needle) {
                found.push(format!("{path}:{line}: {l}"));
            }
        }
        for module in AWS_PQ_MODULES {
            for line in lines_naming_module(&code, "aws_lc_rs", module) {
                found.push(format!("{path}:{line}: aws_lc_rs::{{{module}}}"));
            }
        }
        if let Some(why) = indirection(&code, "aws_lc_rs") {
            found.push(format!("{path}: {why}"));
        }
    }
    found
}

/// I-75, ADR-001 A2 and A6: `fstp-crypto` production code never reaches
/// the aws-lc-rs ML-KEM or ML-DSA. moduletto is the post-quantum half, and
/// the aws-lc-rs ML-DSA is a test oracle, never a fallback.
#[test]
fn i75_fstp_crypto_src_uses_no_aws_lc_rs_post_quantum_api() {
    let found = aws_pq_findings(&read_all(&crypto_src()));
    assert!(found.is_empty(), "{found:#?}");
}

/// I-75, teeth: the aws-lc-rs scan sees the post-quantum API through a
/// group, a nested group, a raw identifier, another parameter set and a
/// rename, and lets the classical imports of `fstp-crypto` through.
#[test]
fn i75_teeth_scan_sees_aws_lc_rs_post_quantum_api() {
    let kem = AWS_PQ_MODULES[0];
    let unstable = AWS_PQ_MODULES[1];
    for code in [
        format!("use aws_lc_rs::{{{kem}::{{DecapsulationKey, X}}}};\n"),
        format!("use aws_lc_rs::{{\n    rand,\n    {unstable},\n}};\n"),
        format!("use aws_lc_rs::r#{kem}::DecapsulationKey;\n"),
        format!("let k = {}1024;\n", aws_lc_pq_names()[0]),
        format!("let k = {}44;\n", aws_lc_pq_names()[1]),
        "use aws_lc_rs as lc;\n".to_string(),
        "use aws_lc_rs::*;\n".to_string(),
    ] {
        let files = vec![("crates/fstp-crypto/src/sig.rs".to_string(), code.clone())];
        assert!(!aws_pq_findings(&files).is_empty(), "{code}");
    }
    let quiet = vec![(
        "crates/fstp-crypto/src/lib.rs".to_string(),
        "use aws_lc_rs::{constant_time, digest, hmac, pbkdf2, rand};\n\
         use aws_lc_rs::signature::{ED25519, KeyPair as _};\n\
         let kemx = aws_lc_rs::rand::SystemRandom::new();\n"
            .to_string(),
    )];
    assert_eq!(aws_pq_findings(&quiet), Vec::<String>::new());
}

/// The root uses of `krate` in the squeezed text `flat`. Each is the text
/// right after the name: the `::` segments and `{..}` groups of its path,
/// nested to any depth, up to the first character outside the path. A
/// `krate` with an identifier character on either side is another name.
fn path_trees<'a>(flat: &'a str, krate: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = flat[from..].find(krate) {
        let start = from + at;
        from = start + krate.len();
        let rest = &flat[from..];
        if flat[..start].chars().next_back().is_some_and(ident_char)
            || rest.chars().next().is_some_and(ident_char)
        {
            continue;
        }
        let mut depth = 0usize;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            let keep = match c {
                '{' => {
                    depth += 1;
                    true
                }
                '}' if depth > 0 => {
                    depth -= 1;
                    true
                }
                ',' | ' ' => depth > 0,
                ':' | '*' | '$' => true,
                _ => ident_char(c),
            };
            if !keep {
                end = i;
                break;
            }
        }
        out.push(&rest[..end]);
    }
    out
}

/// Whether `code` names `module` through a path or a `use` group of
/// `fstp_crypto`. Every segment of the path counts, at every depth of
/// nesting, and also a group item renamed with `as`. A raw identifier
/// such as `r#mlkem` counts as `mlkem`.
fn names_crypto_module(code: &str, module: &str) -> bool {
    let flat = squeeze(&unraw(code));
    path_trees(&flat, "fstp_crypto")
        .iter()
        .any(|tree| words(tree).any(|w| w == module))
}

/// How `code` reaches `fstp_crypto` in a way the I-75 scan cannot follow,
/// if it does. See [`indirection`].
fn crypto_indirection(code: &str) -> Option<&'static str> {
    indirection(code, "fstp_crypto")
}

/// How `code` reaches the crate `krate` in a way a source scan cannot
/// follow, if it does: a glob import (`krate::*`, or a top-level `*`
/// inside a `krate::{..}` group), a rename (`krate as x`, also in `extern
/// crate`, or `self as x` inside the group), a path built by a macro (a
/// `$` segment in the path), or `krate` passed bare as a macro argument.
/// A file could then name a module without the text `krate::module`, so
/// the scan refuses these outright. Raw identifiers count as plain ones.
fn indirection(code: &str, krate: &str) -> Option<&'static str> {
    let flat = squeeze(&unraw(code));
    if path_trees(&flat, krate).iter().any(|t| t.contains('$')) {
        return Some("macro-built path below the crate");
    }
    let mut from = 0;
    while let Some(at) = flat[from..].find(krate) {
        let start = from + at;
        from = start + krate.len();
        let before = &flat[..start];
        let rest = &flat[from..];
        // `a::krate` is another path. A leading `::krate` is not, and
        // neither is `use ::krate`, which squeezes to `use::krate`.
        let inner_path = before.strip_suffix("::").is_some_and(|b| {
            let word: String = b.chars().rev().take_while(|c| ident_char(*c)).collect();
            !word.is_empty() && !b.ends_with("use")
        });
        if inner_path
            || before.chars().next_back().is_some_and(ident_char)
            || rest.chars().next().is_some_and(ident_char)
        {
            continue;
        }
        if rest.starts_with(" as ") {
            return Some("rename of the crate");
        }
        if rest.starts_with("::*") {
            return Some("glob import of the crate");
        }
        if rest.starts_with([')', ',', ']', '}']) {
            return Some("the crate passed bare as a token");
        }
        let Some(group) = rest.strip_prefix("::{") else {
            continue;
        };
        // The top-level items of the group: a `*` item is a glob, and a
        // `self as x` item is a rename.
        let mut depth = 0usize;
        let mut item = String::new();
        for c in group.chars() {
            let top = depth == 0;
            match c {
                '{' => depth += 1,
                '}' | ',' if top => {
                    if item == "*" {
                        return Some("glob import of the crate");
                    }
                    if item.starts_with("self as ") {
                        return Some("rename of the crate");
                    }
                    if c == '}' {
                        break;
                    }
                    item.clear();
                    continue;
                }
                '}' => depth -= 1,
                _ => {}
            }
            if top {
                item.push(c);
            }
        }
    }
    None
}

/// `code` with each run of whitespace removed, except one space between
/// two identifier characters. So `fstp_crypto :: { self as x }` becomes
/// `fstp_crypto::{self as x}`.
fn squeeze(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut pending = false;
    for c in code.chars() {
        if c.is_whitespace() {
            pending = true;
            continue;
        }
        if pending && ident_char(c) && out.chars().next_back().is_some_and(ident_char) {
            out.push(' ');
        }
        pending = false;
        out.push(c);
    }
    out
}

/// The Cargo packages whose renames the I-75 scans refuse. A rename
/// would let a file reach the crate under a name no scan reads.
const NO_RENAME: [&str; 3] = ["fstp-crypto", "moduletto", "aws-lc-rs"];

/// The packages of [`NO_RENAME`] that a Cargo manifest renames through a
/// `package = ".."` key, with TOML comments removed.
fn cargo_renames(toml: &str) -> Vec<&'static str> {
    let flat: String = toml
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    NO_RENAME
        .into_iter()
        .filter(|p| {
            flat.contains(&format!("package=\"{p}\"")) || flat.contains(&format!("package='{p}'"))
        })
        .collect()
}

/// Every `Cargo.toml` under `dir`, recursively, without build output.
fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// The modules that only their hybrid may use (I-75).
const SINGLE_HALF: [&str; 2] = ["mlkem", "mldsa"];

/// I-75: outside `fstp-crypto` and the test-only `fstp-celltest`, no
/// crate names moduletto, `fstp_crypto::mlkem` or `fstp_crypto::mldsa`.
/// ML-KEM is reached only through `hybrid_kem`, and ML-DSA only through
/// `composite`, so nothing relies on a moduletto primitive alone.
/// No such file names `mlkem` or `mldsa` as an identifier at all, so a
/// macro or a renamed crate cannot build the path either. A glob import,
/// a rename or a macro-built path of `fstp_crypto` is refused too, and no
/// manifest renames `fstp-crypto`, moduletto or aws-lc-rs.
#[test]
fn i75_moduletto_primitives_are_reached_only_through_the_hybrids() {
    let root = repo_root();
    let skip = [
        root.join("crates/fstp-crypto"),
        root.join("crates/fstp-celltest"),
    ];
    let mut found = Vec::new();
    for p in workspace_files() {
        if skip.iter().any(|s| p.starts_with(s)) {
            continue;
        }
        let code = unraw(&strip_comments(&fs::read_to_string(&p).unwrap()));
        if code.contains("moduletto::") {
            found.push(format!("{}: moduletto", rel(&p)));
        }
        if let Some(why) = crypto_indirection(&code) {
            found.push(format!("{}: {why}", rel(&p)));
        }
        for module in SINGLE_HALF {
            if names_crypto_module(&code, module) {
                found.push(format!("{}: fstp_crypto::{module}", rel(&p)));
            }
            if words(&code).any(|w| w == module) {
                found.push(format!("{}: the identifier {module}", rel(&p)));
            }
        }
    }
    let mut tomls = vec![root.join("Cargo.toml")];
    manifests(&root.join("crates"), &mut tomls);
    manifests(&root.join("tools"), &mut tomls);
    for p in tomls {
        for package in cargo_renames(&fs::read_to_string(&p).unwrap()) {
            found.push(format!("{}: renames {package}", rel(&p)));
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// Which files inside `crates/fstp-crypto/src` may name each guarded
/// identifier, relative to that directory.
const INSIDE_ALLOWED: [(&str, &[&str]); 3] = [
    ("moduletto", &["mlkem.rs", "mldsa.rs"]),
    ("mlkem", &["mlkem.rs", "hybrid_kem.rs"]),
    ("mldsa", &["mldsa.rs", "composite.rs"]),
];

/// The findings of the I-75 rule inside `fstp-crypto` over `files`
/// (path relative to `crates/fstp-crypto/src`, source). Outside its
/// allowed files, a line naming `mlkem` or `mldsa` as an identifier is a
/// finding, as a path segment, a group item or a rename alike. A line
/// containing `moduletto` is too. `lib.rs` may only declare the two
/// modules. A `pub use` that names one of them re-exports it, and is a
/// finding in every file but the module itself.
fn inside_findings(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, text) in files {
        let code = unraw(&strip_comments(text));
        for (n, line) in code.lines().enumerate() {
            for (guarded, allowed) in INSIDE_ALLOWED {
                if allowed.contains(&name.as_str()) {
                    continue;
                }
                let hit = if guarded == "moduletto" {
                    line.contains(guarded)
                } else {
                    words(line).any(|w| w == guarded)
                };
                let declaration = name == "lib.rs" && line.trim() == format!("pub mod {guarded};");
                if hit && !declaration {
                    found.push(format!("{name}:{}: {}", n + 1, line.trim()));
                }
            }
        }
        for statement in pub_uses(&squeeze(&code)) {
            for guarded in SINGLE_HALF {
                let own = name.as_str() == format!("{guarded}.rs");
                if !own && words(statement).any(|w| w == guarded) {
                    found.push(format!("{name}: re-export {statement}"));
                }
            }
        }
    }
    found
}

/// The `use` statements of squeezed `flat` that carry a `pub` visibility,
/// each from `use` to its `;`.
fn pub_uses(flat: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = flat[from..].find("use") {
        let start = from + at;
        from = start + "use".len();
        let before = &flat[..start];
        if before.chars().next_back().is_some_and(ident_char)
            || flat[from..].chars().next().is_some_and(ident_char)
        {
            continue;
        }
        let item_start = before.rfind([';', '{', '}']).map_or(0, |i| i + 1);
        if !words(&before[item_start..]).any(|w| w == "pub") {
            continue;
        }
        let end = flat[start..].find(';').map_or(flat.len(), |i| start + i);
        out.push(&flat[start..end]);
    }
    out
}

/// I-75 inside `fstp-crypto`: moduletto is named only by `mlkem.rs` and
/// `mldsa.rs`, `mlkem` is used only by `hybrid_kem.rs`, and `mldsa` only
/// by `composite.rs`. `lib.rs` may only declare the modules, and nothing
/// re-exports them under another name.
#[test]
fn i75_inside_fstp_crypto_moduletto_sits_behind_the_hybrids() {
    let src = repo_root().join("crates/fstp-crypto/src");
    let files: Vec<(String, String)> = crypto_src()
        .iter()
        .map(|p| {
            let name = p.strip_prefix(&src).unwrap().to_string_lossy();
            (name.replace('\\', "/"), fs::read_to_string(p).unwrap())
        })
        .collect();
    let found = inside_findings(&files);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-75, teeth: inside `fstp-crypto` the scan sees a renamed `mlkem` or
/// `mldsa` import, a raw identifier, a re-export and a nested group, and
/// lets the hybrids and the module declarations through.
#[test]
fn i75_teeth_inside_scan_sees_renames_and_re_exports() {
    for (name, code) in [
        (
            "sig.rs",
            "use crate::{mlkem as m};\nfn f() { m::acvp::x(); }\n",
        ),
        ("sig.rs", "use crate::{x25519, mldsa::{self as d}};\n"),
        ("aead.rs", "fn f() { crate::r#mlkem::generate(); }\n"),
        ("lib.rs", "pub mod mlkem;\npub use mlkem::acvp;\n"),
        (
            "hybrid_kem.rs",
            "use crate::mlkem::{self, X};\npub use crate::{\n    mlkem::acvp,\n};\n",
        ),
        ("composite.rs", "pub(crate) use crate::mldsa as inner;\n"),
        ("x25519.rs", "use moduletto::ml_kem;\n"),
    ] {
        let files = vec![(name.to_string(), code.to_string())];
        assert!(!inside_findings(&files).is_empty(), "{name}: {code}");
    }
    let quiet = vec![
        (
            "lib.rs".to_string(),
            "pub mod mldsa;\npub mod mlkem;\npub use x25519::StaticSecret;\n".to_string(),
        ),
        (
            "hybrid_kem.rs".to_string(),
            "use crate::mlkem::{self, X};\npub const N: usize = mlkem::CIPHERTEXT_LEN;\n"
                .to_string(),
        ),
        (
            "mlkem.rs".to_string(),
            "use moduletto::ml_kem;\npub use self::acvp::decapsulate;\n".to_string(),
        ),
        (
            "sig.rs".to_string(),
            "// mlkem is not named here\nlet mlkem_len = 3;\n".to_string(),
        ),
    ];
    assert_eq!(inside_findings(&quiet), Vec::<String>::new());
}

/// I-75, teeth: the workspace scan sees a direct ML-KEM use in a fixture,
/// as a path, inside a `use` group at any depth, after a nested group,
/// renamed and as a raw identifier.
#[test]
fn i75_teeth_scan_sees_direct_mlkem_use() {
    for (code, module) in [
        ("let k = fstp_crypto::mlkem::generate();", "mlkem"),
        (
            "use fstp_crypto::{aead, mlkem::{self, encapsulate}};",
            "mlkem",
        ),
        (
            "use fstp_crypto::{hybrid_kem::{self, HybridSecretKey}, mlkem};",
            "mlkem",
        ),
        (
            "use fstp_crypto::{\n    composite::{self, verify},\n    mldsa,\n};\n",
            "mldsa",
        ),
        ("use fstp_crypto::{a::{mlkem}};", "mlkem"),
        ("use fstp_crypto::{mlkem as x};", "mlkem"),
        ("use fstp_crypto::{aead, mldsa as d};", "mldsa"),
        (
            "let s = fstp_crypto::r#mlkem::acvp::decapsulate(dk, ct);",
            "mlkem",
        ),
        ("let s = r#fstp_crypto::mlkem::generate();", "mlkem"),
    ] {
        assert!(names_crypto_module(code, module), "{code}");
    }
    for code in [
        "use fstp_crypto::{aead, hybrid_kem};",
        "use fstp_crypto::hybrid_kem;",
        "use fstp_crypto::{hybrid_kem::{self, HybridSecretKey}, sig};",
        "let s = fstp_crypto::hybrid_kem::seal(pk, b\"mlkem\");",
    ] {
        assert!(!names_crypto_module(code, "mlkem"), "{code}");
    }
}

/// I-75, teeth: the identifier rule of the workspace scan sees `mlkem`
/// passed to a macro that builds the path, and a renamed crate.
#[test]
fn i75_teeth_scan_sees_the_bare_identifier() {
    for code in [
        "macro_rules! m { ($x:ident) => { fc::$x::generate() } }\nfn f() { m!(mlkem); }",
        "fn f() { fc::mlkem::acvp::decapsulate(dk, ct); }",
        "fn f() { fc::r#mldsa::generate(); }",
    ] {
        let code = unraw(code);
        assert!(words(&code).any(|w| SINGLE_HALF.contains(&w)), "{code}");
    }
    assert!(!words("let mlkem_len = mldsa_x;").any(|w| SINGLE_HALF.contains(&w)));
}

/// I-75, teeth: the manifest scan refuses a Cargo rename of
/// `fstp-crypto`, moduletto or aws-lc-rs, and ignores plain lines and
/// comments.
#[test]
fn i75_teeth_scan_refuses_cargo_renames() {
    for toml in [
        "[dependencies]\nfc = { package = \"fstp-crypto\", path = \"../fstp-crypto\" }\n",
        "[dependencies.fc]\npackage = 'fstp-crypto'\nworkspace = true\n",
        "[dependencies]\nm = { package = \"moduletto\", git = \"x\" }\n",
        "[dependencies]\nlc.package = \"aws-lc-rs\"\n",
    ] {
        assert!(!cargo_renames(toml).is_empty(), "{toml}");
    }
    for toml in [
        "[package]\nname = \"fstp-crypto\"\n",
        "[dependencies]\nfstp-crypto.workspace = true\n",
        "# fc = { package = \"fstp-crypto\" }\n",
        "[dependencies]\nx = { package = \"fstp-crypto-extra\" }\n",
    ] {
        assert!(cargo_renames(toml).is_empty(), "{toml}");
    }
}

/// I-75, teeth: the scan refuses each way of reaching `fstp_crypto` that
/// hides the module name, and lets plain imports through.
#[test]
fn i75_teeth_scan_refuses_globs_and_renames_of_fstp_crypto() {
    for code in [
        "use fstp_crypto::*;\nfn f() { let _ = mlkem::generate(); }",
        "use fstp_crypto::{self as fc};\nfn f() { fc::mlkem::generate(); }",
        "use fstp_crypto::{aead, self as fc};",
        "use fstp_crypto as fc;\nfn f() { fc::mlkem::generate(); }",
        "extern crate fstp_crypto as fc;",
        "use fstp_crypto::{aead, *};",
        "use fstp_crypto::{\n    aead,\n    *,\n};",
        "pub use fstp_crypto :: * ;",
        "use ::fstp_crypto as fc;",
        "use r#fstp_crypto as fc;",
        "macro_rules! m { ($x:ident) => { fstp_crypto::$x::generate() } }",
        "macro_rules! m { ($x:ident) => { use fstp_crypto::{aead, $x}; } }",
        "macro_rules! m { ($k:ident) => { $k::x::generate() } }\nfn f() { m!(fstp_crypto); }",
        "fn f() { m!(a, fstp_crypto, b); }",
    ] {
        assert!(crypto_indirection(code).is_some(), "{code}");
    }
    for code in [
        "use fstp_crypto::{aead, hybrid_kem};",
        "use fstp_crypto::{sig::{self, EcdsaP256KeyPair}, hybrid_kem};",
        "use fstp_crypto::{aead::*, sig};",
        "use fstp_crypto::aead::*;",
        "use my_fstp_crypto as other;",
        "use fstp_crypto_extra as other;",
        "let x = a * b; use fstp_crypto::sha256;",
        "extern crate fstp_crypto;",
        "fn fstp_crypto() {}",
        "let s = \"fstp_crypto ECDSA P-256 verify\";",
    ] {
        assert!(crypto_indirection(code).is_none(), "{code}");
    }
}

/// Review reproducer (I-75, design section 2.4 rule 8). The group reader
/// of [`names_crypto_module`] stops at the first `}`, so a nested group
/// before the module name ends the search early. The rustfmt-ordered
/// import `use fstp_crypto::{hybrid_kem::{self, X}, mlkem};` then passes
/// the workspace scan, and the file can call `mlkem::acvp::decapsulate`,
/// a single-half decapsulation, unseen. Fails until the reader tracks
/// brace depth.
#[test]
fn review_i75_scan_sees_mlkem_after_a_nested_use_group() {
    for (code, module) in [
        (
            "use fstp_crypto::{hybrid_kem::{self, HybridSecretKey}, mlkem};\n\
             fn f(dk: &mlkem::MlKem768DecapsKey, ct: &[u8; 1088]) {\n\
             let _ = mlkem::acvp::decapsulate(dk, ct);\n\
             }\n",
            "mlkem",
        ),
        (
            "use fstp_crypto::{\n    composite::{self, verify},\n    mldsa,\n};\n",
            "mldsa",
        ),
    ] {
        assert!(
            names_crypto_module(code, module),
            "the I-75 scan misses `{module}` in:\n{code}"
        );
    }
}

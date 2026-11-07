//! The I-75 source scan of the M9 rules (`docs/handoff/m9-design.md`
//! section 3, lane C1): moduletto is always used in a hybrid with a
//! classical primitive. Each finding code is `i75-hybrid-only`.
//!
//! It reads the shipped sources of every workspace member, as
//! [`layering_m3::member_sources`] collects them, through the same lexer,
//! so comments and string contents never count and a raw identifier
//! counts as the plain one.
//!
//! - Outside `fstp-crypto`, no shipped source names `moduletto`, `mldsa`
//!   or `mlkem` as an identifier. A path, a `use` group, a rename and a
//!   macro argument all name it, so each is refused.
//! - Inside `fstp-crypto`, `moduletto` appears only in `mlkem.rs` and
//!   `mldsa.rs`. `mlkem` appears only there and in `hybrid_kem.rs`, and
//!   `mldsa` only in `mldsa.rs` and `composite.rs`. `lib.rs` may only
//!   declare the two modules with `pub mod`.
//!
//! The test-only `fstp-celltest` holds the differential tests and is
//! exempt, as in layering rule 9. deps-check itself holds the names as
//! rule data. Rule 8 of `layering_m3` already keeps the moduletto package
//! out of every other crate's graph. This scan closes the source side.

use crate::layering_m3::{SCANNER, SourceFile, Tok, tokens};
use crate::report::Finding;

/// The crate that holds the hybrids.
const CRYPTO: &str = "fstp-crypto";
/// The test-only crate that runs the differential tests.
const CELLTEST: &str = "fstp-celltest";

/// The Tier B crate and the two single-half modules. They are built with
/// `concat!`, so this file does not name them and the `fstp-crypto` source
/// scans, which read deps-check too, stay quiet.
const MODULETTO: &str = concat!("modu", "letto");
const ML_KEM: &str = concat!("ml", "kem");
const ML_DSA: &str = concat!("ml", "dsa");

/// Each single-half name, with the `fstp-crypto` files that may name it.
const RULES: [(&str, &[&str]); 3] = [
    (
        MODULETTO,
        &[concat!("src/ml", "kem.rs"), concat!("src/ml", "dsa.rs")],
    ),
    (ML_KEM, &[concat!("src/ml", "kem.rs"), "src/hybrid_kem.rs"]),
    (ML_DSA, &[concat!("src/ml", "dsa.rs"), "src/composite.rs"]),
];

/// The path of `rel` inside the `fstp-crypto` package, if it is one.
fn crypto_path(rel: &str) -> Option<&str> {
    rel.strip_prefix("crates/fstp-crypto/")
}

/// Whether token `i` of `toks` is the module name of `pub mod <name>;`.
fn module_declaration(toks: &[Tok<'_>], i: usize) -> bool {
    let at = |j: Option<usize>| j.and_then(|j| toks.get(j)).map(|t| t.s);
    at(i.checked_sub(2)) == Some("pub")
        && at(i.checked_sub(1)) == Some("mod")
        && at(i.checked_add(1)) == Some(";")
}

/// The I-75 findings over the shipped `sources`.
pub(crate) fn scan(sources: &[SourceFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in sources {
        let k = f.krate.as_str();
        if k == CELLTEST || k == SCANNER {
            continue;
        }
        let inner = if k == CRYPTO {
            crypto_path(&f.rel)
        } else {
            None
        };
        let toks = tokens(&f.text);
        for (i, t) in toks.iter().enumerate() {
            let Some((name, allowed)) = RULES.iter().find(|(n, _)| *n == t.s) else {
                continue;
            };
            let ok = match inner {
                Some(p) if allowed.contains(&p) => true,
                Some("src/lib.rs") => *name != MODULETTO && module_declaration(&toks, i),
                _ => false,
            };
            if !ok {
                let rule = if k == CRYPTO {
                    "inside fstp-crypto only the hybrid's own files may"
                } else {
                    "only fstp-crypto may, behind composite and hybrid_kem"
                };
                out.push(Finding::error(
                    "i75-hybrid-only",
                    format!(
                        "{k} names `{name}` in {}:{}; {rule} (I-75, M9 design section 3)",
                        f.rel, t.line
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::fs;
    use std::path::Path;

    use super::*;

    /// `s` with `@M`, `@K` and `@D` replaced by the names, so this file
    /// does not name them.
    fn names(s: &str) -> String {
        s.replace("@M", MODULETTO)
            .replace("@K", ML_KEM)
            .replace("@D", ML_DSA)
    }

    fn file(krate: &str, rel: &str, text: &str) -> SourceFile {
        SourceFile {
            krate: krate.to_string(),
            rel: names(rel),
            text: names(text),
        }
    }

    fn found(f: SourceFile) -> usize {
        scan(&[f]).len()
    }

    /// I-75 (M9 design section 3): a planted non-hybrid use fails the
    /// scan, in every form a shipped file could take.
    #[test]
    fn i75_scan_fails_on_planted_non_hybrid_use() {
        for (krate, rel, text) in [
            (
                "fstp-contract",
                "crates/fstp-contract/src/notice.rs",
                "fn f(sk: &[u8]) { fstp_crypto::@D::acvp::sign(sk, b\"m\", b\"\", &[0; 32]); }",
            ),
            (
                "fstp-cell",
                "crates/fstp-cell/src/k.rs",
                "use fstp_crypto::{hybrid_kem::{self, X}, @K};",
            ),
            (
                "fstp-cell",
                "crates/fstp-cell/src/k.rs",
                "use fstp_crypto::{@D as d};",
            ),
            (
                "fstp-cell",
                "crates/fstp-cell/src/k.rs",
                "fn f() { fc::r#@K::generate(); }",
            ),
            (
                "fstp-cell",
                "crates/fstp-cell/src/k.rs",
                "fn f() { m!(@D); }",
            ),
            (
                "fstp-tls",
                "crates/fstp-tls/src/p.rs",
                "use @M::kem::ml_kem_768;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/sig.rs",
                "use crate::@D;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/x25519.rs",
                "use @M::kem;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/composite.rs",
                "use @M::dsa;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/lib.rs",
                "pub use @K::acvp;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/lib.rs",
                "pub mod @M;",
            ),
        ] {
            assert!(found(file(krate, rel, text)) > 0, "{rel}: {text}");
        }
    }

    /// I-75: the hybrids, the module declarations, the test-only crate,
    /// comments, strings and longer identifiers pass.
    #[test]
    fn i75_scan_passes_the_hybrids_and_text() {
        for (krate, rel, text) in [
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/@D.rs",
                "use @M::dsa::ml_dsa_65;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/composite.rs",
                "use crate::@D::{self, X};",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/hybrid_kem.rs",
                "use crate::@K;",
            ),
            (
                "fstp-crypto",
                "crates/fstp-crypto/src/lib.rs",
                "pub mod @D;\npub mod @K;",
            ),
            (
                "fstp-celltest",
                "crates/fstp-celltest/src/r.rs",
                "fstp_crypto::@D::acvp::keygen(&s);",
            ),
            (
                "fstp-audit",
                "crates/fstp-audit/src/a.rs",
                "// @D, @M\nconst MLDSA_SIG_LEN: usize = 3309;\nconst S: &str = \"@K\";\nlet @K_len = 1;",
            ),
        ] {
            assert_eq!(found(file(krate, rel, text)), 0, "{rel}: {text}");
        }
    }

    /// The `.rs` files below `dir`, outside `tests`, `benches`, `examples`,
    /// `fuzz` and `target`.
    fn shipped(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(read) = fs::read_dir(dir) else {
            return;
        };
        for e in read.flatten() {
            let p = e.path();
            let name = e.file_name();
            if p.is_dir() {
                if !["tests", "benches", "examples", "fuzz", "target"]
                    .iter()
                    .any(|s| name == *s)
                {
                    shipped(&p, out);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// I-75: the repository's own crates pass the scan. Each crate
    /// directory under `crates/` stands for its package name.
    #[test]
    fn i75_repository_crates_pass_the_scan() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut sources = Vec::new();
        for e in fs::read_dir(root.join("crates")).unwrap().flatten() {
            let krate = e.file_name().to_string_lossy().into_owned();
            let mut files = Vec::new();
            shipped(&e.path(), &mut files);
            for p in files {
                let rel = p
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = String::from_utf8_lossy(&fs::read(&p).unwrap()).into_owned();
                sources.push(SourceFile {
                    krate: krate.clone(),
                    rel,
                    text,
                });
            }
        }
        assert!(sources.len() > 100, "{} files", sources.len());
        let found = scan(&sources);
        assert!(found.is_empty(), "{found:#?}");
    }
}

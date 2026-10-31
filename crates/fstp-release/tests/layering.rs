//! Layering of the release crates (I-38, I-19, design section 2.4 rules
//! 4 and 6).
//!
//! Rule 4: `fstp-release` and `fstp-release-svc` reach none of the crates
//! that decode tenant data, so no request they build or serve can carry
//! it (I-38). Rule 6 has its own test in `fstp-celltest`
//! (`i39_no_command_path_reaches_release_crate`). `tools/deps-check`
//! runs both rules too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The crates of design section 2.4 rule 4.
const TENANT_CRATES: [&str; 7] = [
    "fstp-domain",
    "fstp-engine",
    "fstp-findings",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-pgstore",
    "fstp-vault",
];

/// Every package `krate` reaches through normal and build edges.
fn reach(krate: &str) -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--offline",
            "-p",
            krate,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// I-38, I-19, design section 2.4 rule 4: neither release crate reaches a
/// crate that decodes tenant data, and neither reaches any `fstp-vault*`
/// crate.
#[test]
fn i38_release_crates_reach_no_tenant_data_crate() {
    for krate in ["fstp-release", "fstp-release-svc"] {
        let reached = reach(krate);
        assert!(
            reached.contains("fstp-crypto"),
            "the tree of {krate} was not read: {reached:?}"
        );
        let offenders: Vec<&String> = reached
            .iter()
            .filter(|p| TENANT_CRATES.contains(&p.as_str()) || p.starts_with("fstp-vault"))
            .collect();
        assert!(
            offenders.is_empty(),
            "I-38: {krate} reaches tenant data crates {offenders:?}"
        );
    }
}

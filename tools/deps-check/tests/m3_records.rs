//! Checks of the M3 W0 records in the real repository
//! (`docs/handoff/m3-design.md` sections 0.5, 2.1, 2.6, 15 and 19).
//!
//! These tests read files only. They check that each record the M3 gates
//! rely on exists and agrees with the ADR or design text it mirrors:
//!
//! - `deps/tier-b-confirmations.txt` against the ADR-001 Tier B table and
//!   its release gate table (I-74, ADR-001 A5);
//! - `deps/funds-allowed.txt`, empty in M3 (I-16);
//! - the workspace members against the new crates of design section 2.1;
//! - every fuzz project and target of design section 15, and its
//!   registration in `deps/fuzz-required.txt` (TH-26, H-05);
//! - the new crate stubs, which refuse with a typed `NotImplemented`
//!   error and never with a panicking macro;
//! - `docs/handoff/m3-base.md`, the M2 base commit record of design
//!   section 0.5.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The new crates of design section 2.1, in table order.
const NEW_CRATES: [&str; 22] = [
    "fstp-pki",
    "fstp-keys",
    "fstp-custody",
    "fstp-keyd",
    "fstp-audit",
    "fstp-obs",
    "fstp-pgstore",
    "fstp-vault-proto",
    "fstp-vault-core",
    "fstp-vault",
    "fstp-webauthn",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-cell",
    "fstp-cp-proto",
    "fstp-control",
    "fstp-witness",
    "fstp-edge",
    "fstp-release",
    "fstp-release-svc",
    "fstp-backup",
    "fstp-celltest",
];

/// Design section 15: each new parser-bearing crate and its fuzz targets.
/// `fstp-obs` has no parser. `fstp-crypto` is an M1 crate whose fuzz
/// project W1h owns, so it is checked separately below. deps-check also
/// owns `rust_tokens`, the target of its source-scan lexer.
const FUZZ_TARGETS: [(&str, &[&str]); 22] = [
    (
        "fstp-keys",
        &[
            "sealed_key_decode",
            "sealed_blob_decode",
            "erasure_plan_sequence",
        ],
    ),
    ("fstp-pki", &["cert_build_roundtrip"]),
    (
        "fstp-custody",
        &["okms_response_decode", "keyd_frame_decode"],
    ),
    ("fstp-keyd", &["keyd_request_decode", "custody_file_decode"]),
    (
        "fstp-audit",
        &[
            "chain_row_decode",
            "anchor_decode",
            "receipt_decode",
            "verify_mutations",
        ],
    ),
    ("fstp-pgstore", &["stored_entry_decode"]),
    (
        "fstp-vault-proto",
        &[
            "vault_request_decode",
            "vault_response_decode",
            "ticket_decode",
        ],
    ),
    // Design section 2.1 marks a fuzz project, section 15 names no target.
    // The stricter reading holds, pending Daniel (docs/handoff/m3-base.md).
    ("fstp-vault-core", &["fact_commit_sequence"]),
    ("fstp-vault", &["origin_write_decode", "fact_body_decode"]),
    (
        "fstp-webauthn",
        &[
            "cbor_decode",
            "cose_key_decode",
            "authenticator_data_decode",
            "client_data_decode",
            "attestation_object_decode",
            "assertion_verify",
            "registration_verify",
        ],
    ),
    (
        "fstp-auth",
        &[
            "auth_record_decode",
            "auth_command_decode",
            "session_cookie_decode",
            "token_decode",
        ],
    ),
    (
        "fstp-cell-core",
        &[
            "cell_record_decode",
            "cell_command_decode",
            "cell_decide_sequence",
            "driver_core_sequence",
        ],
    ),
    ("fstp-cell", &["command_request_decode"]),
    ("fstp-cp-proto", &["cell_to_cp_decode", "cp_to_cell_decode"]),
    (
        "fstp-control",
        &[
            "cp_api_decode",
            "pgagent_job_decode",
            "ddl_identifier_render",
            "install_config_decode",
        ],
    ),
    (
        "fstp-witness",
        &["witness_message_decode", "file_store_decode"],
    ),
    ("fstp-edge", &["client_hello_sni", "tunnel_header_decode"]),
    (
        "fstp-release",
        &[
            "licence_token_decode",
            "licence_file_import_decode",
            "key_transition_decode",
            "release_metadata_decode",
            "egress_response_decode",
        ],
    ),
    (
        "fstp-release-svc",
        &["refresh_request_decode", "update_query_decode"],
    ),
    (
        "fstp-backup",
        &["backup_container_decode", "s3_xml_decode", "wal_name_parse"],
    ),
    ("fstp-celltest", &["proc_maps_decode"]),
    (
        "deps-check",
        &[
            "npm_lock_decode",
            "tier_b_confirmations_decode",
            "rust_tokens",
        ],
    ),
];

/// The directory of a crate in this repository.
fn crate_dir(krate: &str) -> String {
    if krate == "deps-check" {
        "tools/deps-check".to_owned()
    } else {
        format!("crates/{krate}")
    }
}

/// The non-comment, non-blank lines of a policy file.
fn entries(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// The cells of the table rows that follow the heading `heading` in a
/// Markdown document, without the header and separator rows.
fn table_after(text: &str, heading: &str) -> Vec<Vec<String>> {
    let mut lines = text.lines().skip_while(|l| l.trim() != heading).skip(1);
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in lines.by_ref() {
        let t = line.trim();
        if t.starts_with('|') {
            in_table = true;
            let cells: Vec<String> = t
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect();
            rows.push(cells);
        } else if in_table || t.starts_with('#') {
            break;
        }
    }
    // Drop the header and the separator row.
    rows.into_iter().skip(2).collect()
}

/// The crate names of the ADR-001 Tier B table.
fn adr_001_tier_b_crates() -> BTreeSet<String> {
    let adr = read("docs/adr/ADR-001-crypto-allowlist.md");
    let rows = table_after(&adr, "### Tier B: unaudited, release-gated");
    assert!(!rows.is_empty(), "setup: no Tier B table in ADR-001");
    let mut out = BTreeSet::new();
    for row in rows {
        let cell = row.first().cloned().unwrap_or_default();
        let cell = cell.split(" (").next().unwrap_or_default();
        let cell = cell.strip_prefix("RustCrypto ").unwrap_or(cell);
        for name in cell.split(',') {
            out.insert(name.trim().to_owned());
        }
    }
    out
}

/// The confirmation rows of the ADR-001 release gate table, each as
/// crate, version, source hash, date and findings reference.
fn adr_001_confirmations() -> BTreeSet<Vec<String>> {
    let adr = read("docs/adr/ADR-001-crypto-allowlist.md");
    let rows = table_after(&adr, "## Release gate (I-74)");
    assert!(!rows.is_empty(), "setup: no release gate table in ADR-001");
    rows.into_iter()
        .filter(|r| r.first().is_some_and(|c| c != "(none yet)"))
        .map(|r| r.into_iter().take(5).collect())
        .collect()
}

/// I-74, ADR-001 A5: the Tier B markers in `deps/tier-b-confirmations.txt`
/// name exactly the crates of the ADR-001 Tier B table.
#[test]
fn i74_tier_b_markers_equal_the_adr_001_tier_b_table() {
    let expected = adr_001_tier_b_crates();
    assert_eq!(
        expected,
        ["moduletto", "der", "spki", "x509-cert", "cms"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "setup: the ADR-001 Tier B table changed"
    );
    let mirror = read("deps/tier-b-confirmations.txt");
    let markers: BTreeSet<String> = entries(&mirror)
        .into_iter()
        .filter_map(|l| l.strip_prefix("tier-b "))
        .map(|n| n.trim().to_owned())
        .collect();
    assert_eq!(markers, expected);
}

/// I-74, ADR-001 A5: the confirmation rows of the mirror equal the rows of
/// the ADR-001 release gate table. M3 records none.
#[test]
fn i74_tier_b_mirror_equals_the_adr_001_confirmation_rows() {
    let mirror = read("deps/tier-b-confirmations.txt");
    let rows: BTreeSet<Vec<String>> = entries(&mirror)
        .into_iter()
        .filter_map(|l| l.strip_prefix("confirmed "))
        .map(|l| {
            let mut fields: Vec<String> = l.split_whitespace().map(str::to_owned).collect();
            // The findings reference is the rest of the line.
            let rest = fields.split_off(fields.len().min(4)).join(" ");
            fields.push(rest);
            fields
        })
        .collect();
    assert_eq!(rows, adr_001_confirmations());
}

/// I-74, ADR-001 A5: every line of the mirror is a comment, a Tier B marker
/// or a confirmation row.
#[test]
fn i74_tier_b_mirror_has_only_markers_and_confirmations() {
    let mirror = read("deps/tier-b-confirmations.txt");
    for line in entries(&mirror) {
        assert!(
            line.starts_with("tier-b ") || line.starts_with("confirmed "),
            "unexpected line in deps/tier-b-confirmations.txt: {line}"
        );
    }
}

/// I-16, design section 14.4: `deps/funds-allowed.txt` exists and lists no
/// crate in M3. Payment adapters arrive in M5.
#[test]
fn i16_funds_allowed_is_empty_in_m3() {
    let text = read("deps/funds-allowed.txt");
    assert_eq!(entries(&text), Vec::<&str>::new());
}

/// The member paths of the workspace manifest.
fn workspace_members() -> BTreeSet<String> {
    let manifest = read("Cargo.toml");
    let start = manifest.find("members = [").unwrap();
    let rest = manifest.get(start..).unwrap_or_default();
    let end = rest.find(']').unwrap();
    rest.get(..end)
        .unwrap_or_default()
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// Design section 2.1: every new crate is a workspace member with its own
/// manifest and library root.
#[test]
fn w0_every_new_crate_is_a_workspace_member() {
    let members = workspace_members();
    for krate in NEW_CRATES {
        let dir = crate_dir(krate);
        assert!(members.contains(&dir), "{dir} is not a workspace member");
        let manifest = read(&format!("{dir}/Cargo.toml"));
        assert!(
            manifest.contains(&format!("name = \"{krate}\"")),
            "{dir}/Cargo.toml does not name {krate}"
        );
        assert!(
            repo_root().join(&dir).join("src/lib.rs").is_file(),
            "{dir} has no src/lib.rs"
        );
    }
}

/// Design section 2.1: `fstp-celltest` is test only and never published.
#[test]
fn w0_celltest_is_never_published() {
    let manifest = read("crates/fstp-celltest/Cargo.toml");
    assert!(
        manifest.lines().any(|l| l.trim() == "publish = false"),
        "{manifest}"
    );
}

/// Whether a cargo-fuzz manifest declares the binary `target` at
/// `fuzz_targets/<target>.rs`.
fn declares_target(manifest: &str, target: &str) -> bool {
    manifest.contains(&format!(
        "[[bin]]\nname = \"{target}\"\npath = \"fuzz_targets/{target}.rs\"\n"
    ))
}

/// TH-26, H-05, design section 15: each new parser-bearing crate owns a
/// cargo-fuzz project with every target the design lists, and
/// `deps/fuzz-required.txt` registers it.
#[test]
fn th26_every_m3_parser_crate_owns_its_section_15_fuzz_targets() {
    let required = read("deps/fuzz-required.txt");
    let required: BTreeSet<&str> = entries(&required).into_iter().collect();
    let mut missing = Vec::new();
    for (krate, targets) in FUZZ_TARGETS {
        if !required.contains(krate) {
            missing.push(format!("deps/fuzz-required.txt lacks {krate}"));
        }
        let dir = crate_dir(krate);
        let manifest =
            fs::read_to_string(repo_root().join(&dir).join("fuzz/Cargo.toml")).unwrap_or_default();
        if !repo_root().join(&dir).join("fuzz/Cargo.lock").is_file() {
            missing.push(format!("{dir}/fuzz has no Cargo.lock"));
        }
        for target in targets {
            if !declares_target(&manifest, target) {
                missing.push(format!("{dir}/fuzz/Cargo.toml lacks [[bin]] {target}"));
            }
            let file = repo_root()
                .join(&dir)
                .join(format!("fuzz/fuzz_targets/{target}.rs"));
            if !file.is_file() {
                missing.push(format!("{dir}/fuzz/fuzz_targets/{target}.rs is missing"));
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// TH-26, design section 15: the M3 fuzz targets of `fstp-crypto`. The
/// W1h test agent owns `crates/fstp-crypto/fuzz/**`, so this stays red
/// until that lane lands them.
#[test]
fn th26_fstp_crypto_owns_its_m3_fuzz_targets() {
    let required = read("deps/fuzz-required.txt");
    assert!(
        entries(&required).contains(&"fstp-crypto"),
        "deps/fuzz-required.txt lacks fstp-crypto"
    );
    let manifest = fs::read_to_string(repo_root().join("crates/fstp-crypto/fuzz/Cargo.toml"))
        .unwrap_or_default();
    for target in [
        "hybrid_ciphertext_decode",
        "public_key_decode",
        "composite_signature_decode",
    ] {
        assert!(
            declares_target(&manifest, target),
            "crates/fstp-crypto/fuzz lacks {target}"
        );
    }
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for item in read.flatten() {
        let p = item.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// The new crates whose W0 stubs have all landed, so no refusal is left
/// to name. Lane W2e replaced every stub of `fstp-pgstore` (lane F-STORE
/// records it). A crate listed here must hold no `NotImplemented` at all,
/// so a stub that is still in place cannot hide behind the list.
const STUBS_LANDED: [&str; 1] = ["fstp-pgstore"];

/// Lane W0 rule: the stubs refuse with a typed `NotImplemented` error. No
/// new crate's `src/` holds `todo!` or `unimplemented!`, and each one
/// defines or returns `NotImplemented`, unless all its stubs have landed
/// ([`STUBS_LANDED`]).
#[test]
fn w0_new_crate_stubs_refuse_without_panicking_macros() {
    let mut problems = Vec::new();
    let todo = ["todo", "!("].concat();
    let unimplemented = ["unimplemented", "!("].concat();
    for krate in NEW_CRATES {
        let dir = repo_root().join(crate_dir(krate)).join("src");
        let mut files = Vec::new();
        rust_files(&dir, &mut files);
        if files.is_empty() {
            problems.push(format!("{krate} has no source"));
            continue;
        }
        let mut refuses = false;
        for f in &files {
            let text = fs::read_to_string(f).unwrap_or_default();
            for bad in [&todo, &unimplemented] {
                if text.contains(bad.as_str()) {
                    problems.push(format!("{} holds {bad}", f.display()));
                }
            }
            refuses |= text.contains("NotImplemented");
        }
        let landed = STUBS_LANDED.contains(&krate);
        if landed && refuses {
            problems.push(format!(
                "{krate} is listed as landed but still holds NotImplemented"
            ));
        }
        if !landed && !refuses {
            problems.push(format!("{krate} has no NotImplemented refusal"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Design section 0.5 and lane W0: `docs/handoff/m3-base.md` records the
/// M2 base commit and every seam a stub holds in place of a dependency
/// that waits for Daniel's acceptance of its ADR.
#[test]
fn w0_m3_base_record_names_the_m2_base_and_the_seams() {
    let text = read("docs/handoff/m3-base.md");
    for needle in [
        "367b7be",
        "m2/w7-fix",
        "PR #4",
        "moduletto",
        "zeroize",
        "signal",
    ] {
        assert!(
            text.contains(needle),
            "docs/handoff/m3-base.md does not mention {needle}"
        );
    }
}

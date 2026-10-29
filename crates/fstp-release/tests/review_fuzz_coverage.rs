//! Review reproducers (lane W2j, robustness and test strength).
//!
//! Design section 15 asks the `fstp-release` fuzz targets to check "no
//! panic; signature checked before use". The project rule is that every
//! in-house parser gets a fuzz target. Two parsers of untrusted network
//! bytes are reached by no target:
//!
//! - The refresh response body (`"FSTPRR01" || flag || transition? ||
//!   token`) is split and applied by `licence::apply_refresh`. The
//!   `key_transition_decode` target calls `decode_key_transition`, which
//!   checks against the empty `SHIPPED_KEYS`. So no target reaches a
//!   transition past its signature check, or the refresh response at all.
//! - Signed release metadata is parsed by `metadata::verify_metadata`.
//!   The `release_metadata_decode` target calls only
//!   `decode_release_metadata`, which refuses every input without reading
//!   it. So the target exercises no parser.
//!
//! Each test scans the fuzz target sources and fails while no target
//! reaches the parser.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// The source of every fuzz target of this crate, by file name.
fn targets() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fuzz_targets directory") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push((name, std::fs::read_to_string(&path).expect("target source")));
        }
    }
    out
}

/// I-39, design sections 10.2 and 15: the refresh response body and a key
/// transition under a non-empty pinned set are fuzzed. Fails while no
/// target calls `apply_refresh` and no target drives a `KeySet`.
#[test]
fn review_i39_refresh_response_and_key_set_reach_a_fuzz_target() {
    let srcs = targets();
    let refresh = srcs.iter().any(|(_, s)| s.contains("apply_refresh"));
    let key_set = srcs.iter().any(|(_, s)| {
        s.contains("KeySet") && (s.contains("apply_transition") || s.contains("verify_transition"))
    });
    assert!(
        refresh && key_set,
        "I-39: no fuzz target reaches the refresh response parser (apply_refresh: {refresh}) \
         or a transition past the signature check of a non-empty key set (KeySet: {key_set})"
    );
}

/// TH-32, design section 15: the parser of signed release metadata is
/// fuzzed. Fails while no target calls `verify_metadata` or
/// `MetadataStore::accept_signed`.
#[test]
fn review_th_32_verify_metadata_reaches_a_fuzz_target() {
    let srcs = targets();
    let reached = srcs
        .iter()
        .any(|(_, s)| s.contains("verify_metadata") || s.contains("accept_signed"));
    assert!(
        reached,
        "TH-32: no fuzz target reaches metadata::verify_metadata; \
         release_metadata_decode fuzzes a function that reads no input"
    );
}

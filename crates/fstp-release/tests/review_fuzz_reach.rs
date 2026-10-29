//! Review reproducer (lane W2j, spec and security fidelity lens).
//!
//! Design section 15 asks the `fstp-release` fuzz targets to check that
//! the signature is checked before any field is used. The CLAUDE.md hard
//! rule gives every in-house parser a fuzz target. The live decoders of
//! signed bodies are `apply_refresh` (the refresh response body with its
//! optional transition), `KeySet::verify_transition` over a non-empty
//! pinned set, and `verify_metadata`. No fuzz target calls any of them.
//! `key_transition_decode` runs against the empty shipped set, and
//! `release_metadata_decode` runs against a function that refuses every
//! input. So no target ever reaches a field read behind a signature.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

/// The text of every fuzz target of this crate.
fn fuzz_sources() -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    let mut all = String::new();
    for entry in std::fs::read_dir(&dir).expect("fuzz target directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            all.push_str(&std::fs::read_to_string(&path).expect("fuzz target source"));
        }
    }
    all
}

/// I-39, design section 15: some fuzz target drives each live decoder of
/// a signed body, so a field read before the signature check would be
/// found by fuzzing.
#[test]
fn review_fuzz_targets_reach_the_live_signed_decoders() {
    let sources = fuzz_sources();
    let live = ["apply_refresh", "verify_transition", "verify_metadata"];
    let missing: Vec<&str> = live
        .iter()
        .copied()
        .filter(|name| !sources.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "no fuzz target of fstp-release calls {missing:?}"
    );
}

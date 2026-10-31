//! Fuzz target `asset_manifest_decode` of `fstp-web-assets` (TH-26, H-05, ADR-014, M4 design section 9).
//!
//! Design checks: the asset manifest.
//!
//! - No input panics, and a refusal formats.
//! - The decoder is deterministic.
//! - An accepted manifest is ASCII text with no backslash and no `..`, so
//!   no JSON escape and no parent segment reaches a path. This is the
//!   interim grammar of `crates/fstp-web-assets/tests/assets_common/mod.rs`.
//! - An accepted manifest names `"schema"`, `"entry"` and `"assets"`.
//!
//! The W0 stub refuses every input with `NotImplemented`, which the
//! checks on accepted manifests never see. They take effect once lane W4e
//! lands the decoder.

#![no_main]

use fstp_web_assets::decode_manifest;
use libfuzzer_sys::fuzz_target;

/// Whether `needle` occurs in `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fuzz_target!(|data: &[u8]| {
    let first = decode_manifest(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(
        first,
        decode_manifest(data),
        "the decoder is not deterministic"
    );
    if first.is_ok() {
        assert!(
            data.is_ascii(),
            "an accepted manifest holds non-ASCII bytes"
        );
        assert!(
            !data.contains(&b'\\'),
            "an accepted manifest holds a backslash"
        );
        assert!(!contains(data, b".."), "an accepted manifest holds `..`");
        for member in [&b"\"schema\""[..], b"\"entry\"", b"\"assets\""] {
            assert!(
                contains(data, member),
                "an accepted manifest lacks a member"
            );
        }
    }
});

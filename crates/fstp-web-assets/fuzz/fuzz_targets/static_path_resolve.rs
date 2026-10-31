//! Fuzz target `static_path_resolve` of `fstp-web-assets` (TH-26, H-05, ADR-014, M4 design section 9).
//!
//! Design checks: asset paths.
//!
//! - No input panics, and a refusal formats.
//! - The resolver is deterministic.
//! - A path resolves exactly when it is `/app/assets/`, 64 lowercase
//!   hexadecimal digits, then `.js` or `.css`. This is the interim reading
//!   of `crates/fstp-web-assets/tests/assets_common/mod.rs`.
//!
//! The W0 stub refuses every input with `NotImplemented`. The grammar
//! check skips that refusal, so the target runs on the stub and checks the
//! grammar once lane W4e lands the resolver.

#![no_main]

use fstp_web_assets::{AssetError, resolve_static_path};
use libfuzzer_sys::fuzz_target;

/// The prefix of every asset path.
const PREFIX: &[u8] = b"/app/assets/";

/// The asset path grammar, written apart from the resolver.
fn grammar(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((hash, ext)) = rest.split_at_checked(64) else {
        return false;
    };
    hash.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && (ext == b".js" || ext == b".css")
}

fuzz_target!(|data: &[u8]| {
    let first = resolve_static_path(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(
        first,
        resolve_static_path(data),
        "the resolver is not deterministic"
    );
    if matches!(first, Err(AssetError::NotImplemented(_))) {
        return;
    }
    assert_eq!(
        first.is_ok(),
        grammar(data),
        "resolution disagrees with the asset path grammar"
    );
});

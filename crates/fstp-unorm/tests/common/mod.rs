//! Shared helpers of the `fstp-unorm` tests.

#![allow(dead_code, reason = "each test file uses a part")]
#![allow(clippy::panic, reason = "test helpers")]

use std::path::{Path, PathBuf};

/// The repository root.
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The vendored Unicode Character Database files.
pub(crate) fn ucd_dir() -> PathBuf {
    repo_root().join(unorm_gen::UCD_DIR)
}

/// The string of a sequence of scalar values.
pub(crate) fn text(cps: &[u32]) -> String {
    cps.iter()
        .map(|&c| char::from_u32(c).unwrap_or_else(|| panic!("U+{c:04X} is no scalar")))
        .collect()
}

/// Every Unicode scalar value.
pub(crate) fn every_char() -> impl Iterator<Item = char> {
    (0..=0x10_FFFFu32).filter_map(char::from_u32)
}

//! Needles of root bytes for the I-80 scans of `fstp-celltest` only, as
//! the custody simulator's `--needles-out` gives them.
//!
//! The `test-needles` feature builds this module. Only the test crate
//! `fstp-celltest` enables it, and a build without debug assertions
//! refuses it, so no release artifact can hold it. With the feature,
//! every root `fstp-keyd` creates in this process is recorded here with
//! its key volume. A scan then looks for those bytes on the volume and
//! in everything the client received, and finds none (I-80).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Every root created in this process, with its key volume.
static ROOTS: Mutex<Vec<(PathBuf, [u8; 32])>> = Mutex::new(Vec::new());

/// Records the root `bytes` created on `volume`.
pub(crate) fn record(volume: &Path, bytes: &[u8; 32]) {
    ROOTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((volume.to_path_buf(), *bytes));
}

/// The root bytes created on `volume` in this process, in creation
/// order, destroyed roots included.
#[must_use]
pub fn root_needles(volume: &Path) -> Vec<[u8; 32]> {
    ROOTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(v, _)| v == volume)
        .map(|(_, b)| *b)
        .collect()
}

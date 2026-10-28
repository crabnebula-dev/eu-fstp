//! The reference vault commit protocol and query evaluation (NOTE 4, I-17, I-18). Lane W1c owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference answer for one input, encoded canonically.
pub fn answer(input: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    let _ = input;
    Err(NotImplemented::new(
        "fstp_celltest::reference::vault::answer",
    ))
}

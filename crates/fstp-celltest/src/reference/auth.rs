//! The reference login, step-up and recovery policy (I-77, I-78, I-79). Lane W1b owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference answer for one input, encoded canonically.
pub fn decide(input: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    let _ = input;
    Err(NotImplemented::new(
        "fstp_celltest::reference::auth::decide",
    ))
}

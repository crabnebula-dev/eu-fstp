//! The reference licence state (I-39). Lane W1g owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference answer for one input, encoded canonically.
pub fn state(input: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    let _ = input;
    Err(NotImplemented::new(
        "fstp_celltest::reference::licence::state",
    ))
}

//! The reference key hierarchy and erasure closure (I-80, I-81). Lane W1d owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference answer for one input, encoded canonically.
pub fn closure(input: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    let _ = input;
    Err(NotImplemented::new(
        "fstp_celltest::reference::keys::closure",
    ))
}

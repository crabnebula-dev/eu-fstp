//! The reference audit chain link function and verifier (I-24). Lane W1e owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference answer for one input, encoded canonically.
pub fn link(input: &[u8]) -> Result<Vec<u8>, NotImplemented> {
    let _ = input;
    Err(NotImplemented::new("fstp_celltest::reference::audit::link"))
}

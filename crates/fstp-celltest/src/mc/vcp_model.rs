//! M-VCP (design section 14.2). Lane W1c owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-VCP model.
#[derive(Debug)]
pub struct VcpModel {
    states: usize,
}

impl VcpModel {
    /// Builds the model.
    pub fn new() -> Result<VcpModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::vcp_model::VcpModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

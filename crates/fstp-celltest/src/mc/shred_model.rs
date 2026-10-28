//! M-SHRED (design section 14.2). Lane W1d owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-SHRED model.
#[derive(Debug)]
pub struct ShredModel {
    states: usize,
}

impl ShredModel {
    /// Builds the model.
    pub fn new() -> Result<ShredModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::shred_model::ShredModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

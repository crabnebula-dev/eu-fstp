//! M-LICENCE (design section 14.2). Lane W1g owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-LICENCE model.
#[derive(Debug)]
pub struct LicenceModel {
    states: usize,
}

impl LicenceModel {
    /// Builds the model.
    pub fn new() -> Result<LicenceModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::licence_model::LicenceModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

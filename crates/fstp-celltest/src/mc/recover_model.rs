//! M-RECOVER (design section 14.2). Lane W1b owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-RECOVER model.
#[derive(Debug)]
pub struct RecoverModel {
    states: usize,
}

impl RecoverModel {
    /// Builds the model.
    pub fn new() -> Result<RecoverModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::recover_model::RecoverModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

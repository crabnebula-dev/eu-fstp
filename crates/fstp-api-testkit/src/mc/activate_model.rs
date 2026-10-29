//! M-ACTIVATE (M4 design section 8.5). Lane W2a owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-ACTIVATE model.
#[derive(Debug)]
pub struct ActivateModel {
    states: usize,
}

impl ActivateModel {
    /// Builds the model.
    pub fn new() -> Result<ActivateModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_api_testkit::mc::activate_model::ActivateModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

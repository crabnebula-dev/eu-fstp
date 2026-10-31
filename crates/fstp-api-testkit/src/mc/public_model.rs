//! M-PUBLIC (M4 design section 8.5). Lane W2c owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-PUBLIC model.
#[derive(Debug)]
pub struct PublicModel {
    states: usize,
}

impl PublicModel {
    /// Builds the model.
    pub fn new() -> Result<PublicModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_api_testkit::mc::public_model::PublicModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

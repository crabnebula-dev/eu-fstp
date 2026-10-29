//! M-PARITY (M4 design section 8.5). Lane W3c owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-PARITY model.
#[derive(Debug)]
pub struct ParityModel {
    states: usize,
}

impl ParityModel {
    /// Builds the model.
    pub fn new() -> Result<ParityModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_api_testkit::mc::parity_model::ParityModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

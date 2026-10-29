//! M-IMPORT (M4 design section 8.5). Lane W2b owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-IMPORT model.
#[derive(Debug)]
pub struct ImportModel {
    states: usize,
}

impl ImportModel {
    /// Builds the model.
    pub fn new() -> Result<ImportModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_api_testkit::mc::import_model::ImportModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

//! M-PLACE (design section 14.2). Lane W1f owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-PLACE model.
#[derive(Debug)]
pub struct PlaceModel {
    states: usize,
}

impl PlaceModel {
    /// Builds the model.
    pub fn new() -> Result<PlaceModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::place_model::PlaceModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

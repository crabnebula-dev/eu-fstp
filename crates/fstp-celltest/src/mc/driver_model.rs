//! M-DRIVER (design section 14.2). Lane W1c owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-DRIVER model.
#[derive(Debug)]
pub struct DriverModel {
    states: usize,
}

impl DriverModel {
    /// Builds the model.
    pub fn new() -> Result<DriverModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::driver_model::DriverModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

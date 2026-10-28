//! M-AUTH (design section 14.2). Lane W1b owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-AUTH model.
#[derive(Debug)]
pub struct AuthModel {
    states: usize,
}

impl AuthModel {
    /// Builds the model.
    pub fn new() -> Result<AuthModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::auth_model::AuthModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

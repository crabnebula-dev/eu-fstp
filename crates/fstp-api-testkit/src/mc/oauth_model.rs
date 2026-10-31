//! M-OAUTH (M4 design section 8.5). Lane W1e owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-OAUTH model.
#[derive(Debug)]
pub struct OauthModel {
    states: usize,
}

impl OauthModel {
    /// Builds the model.
    pub fn new() -> Result<OauthModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_api_testkit::mc::oauth_model::OauthModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

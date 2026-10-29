//! M-BALLOT (M4 design section 8.5): 4 committee members and a chair, one
//! recused, one delegation and one round. Each counted ballot was cast by
//! its voter or its single delegate, recused members neither vote nor
//! count, and the outcome follows P-16 NOTE 8 (R-EV-09, change D5).
//!
//! Lane W1b (L-DOM) owns this file. The M4 W0 lane added it with its
//! `mod` line.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

/// The refusal of the W0 stub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotImplemented {
    /// The operation that refused.
    pub operation: &'static str,
}

/// The state count the model's first exhaustive run records. Zero stops
/// every run, so no model passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The M-BALLOT model.
#[derive(Debug)]
pub struct BallotModel {
    states: usize,
}

impl BallotModel {
    /// Builds the model.
    pub fn new() -> Result<BallotModel, NotImplemented> {
        Err(NotImplemented {
            operation: "fstp_domain_testkit::mc::ballot_model::BallotModel::new",
        })
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

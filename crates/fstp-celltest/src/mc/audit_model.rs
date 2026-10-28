//! M-AUDIT (design section 14.2). Lane W1e owns this file.
//!
//! Status: W0 stub. Building the model refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The M-AUDIT model.
#[derive(Debug)]
pub struct AuditModel {
    states: usize,
}

impl AuditModel {
    /// Builds the model.
    pub fn new() -> Result<AuditModel, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::mc::audit_model::AuditModel::new",
        ))
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }
}

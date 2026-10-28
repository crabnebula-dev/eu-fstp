//! The custody simulator behind `fstp-custody-sim`. It holds known root
//! bytes so the scanners can look for them (design section 14.3). Lane W1a.

use crate::NotImplemented;

/// The custody simulator.
#[derive(Debug)]
pub struct CustodySim {
    roots: usize,
}

impl CustodySim {
    /// A new simulator.
    pub fn new() -> Result<CustodySim, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::custody_sim::CustodySim::new",
        ))
    }

    /// The number of roots it holds.
    pub fn roots(&self) -> usize {
        self.roots
    }
}

/// Runs the simulator as a process until shutdown.
pub fn run() -> Result<(), NotImplemented> {
    Err(NotImplemented::new("fstp_celltest::custody_sim::run"))
}

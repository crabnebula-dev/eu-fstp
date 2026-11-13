//! The creator shell of a cell (M4 design section 3.2, lane F-CYCLE2).
//!
//! A creator command reads facts that only the shell holds
//! (`fstp_cell_core::creator`): the probes, the Q35 answers, the ports and
//! the funder profile. The route reads them through [`CreatorShell`] when
//! it admits the command, and hands them to the decision as route inputs.
//!
//! [`ProductionShell`] is the shell of a serving cell today:
//!
//! - No prober runs in the cell yet, so every probe is absent. The
//!   channel and sending domain checks then report a failure (Q5,
//!   interim, pending Daniel), and no programme activates.
//! - The vault has no Q35 query yet, so both answers are missing. The
//!   exclusion class check fails closed, and the proximity list check
//!   reports its warning.
//! - The cell has no pre-check provider and no score tools.
//! - The funder profile comes from the shipped profiles only (rule A9b).
//!   Their legal wording is pending (Q6), so the creator reports
//!   `LegalWordingPending` until Daniel approves it.
//!
//! So a production cell activates no programme until those parts exist.
//! A test world passes a shell of its own through
//! `crate::process::StartOptions`, and says so in its claims.

use fstp_cell_core::CellState;
use fstp_cell_core::creator::CreatorFacts;
use fstp_creator::{CreatorCommand, PortPresence, ProbeSet};
use fstp_guide::ProfileSource;

/// The facts a creator command reads from the cell's shell (module
/// documentation).
pub trait CreatorShell: Send + Sync + 'static {
    /// The shell facts of `cmd` on `state`.
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts;
}

/// The shell of a serving cell (module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionShell;

impl CreatorShell for ProductionShell {
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts {
        let profile = fstp_engine::compose::profile_ref(state.engine(), cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| fstp_guide::ShippedProfiles.profile(&name).ok());
        CreatorFacts {
            probes: ProbeSet::absent(),
            exclusion_classes_known: None,
            proximity_lists_declared: None,
            ports: PortPresence {
                precheck: false,
                score_tools: false,
            },
            profile,
        }
    }
}

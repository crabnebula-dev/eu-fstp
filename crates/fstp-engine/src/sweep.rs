//! The minimal deadline sweep (R-EV-07, M4 design section 3.4, change
//! D13).
//!
//! A pure function from engine state and `now` to the due system
//! commands: `ExpireStage2` at the P-07 deadline and `ReEnter` when a next
//! call opens. The cell runs it on its clock as `Actor::System`. M6's
//! timeline engine replaces it.
//!
//! Lane W2e (L-ENGINE) owns this file. The M4 W0 lane added it with its
//! `mod` line.
//!
//! Status: W0 stub. The design makes `due` total. The stub returns a
//! `Result`, so it never answers with a made-up empty list. It refuses
//! with [`SweepError::NotImplemented`].

use fstp_domain::time::Timestamp;

use crate::{Command, EngineState};

/// Why the sweep failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

/// The system commands due at `now`.
pub fn due(state: &EngineState, now: Timestamp) -> Result<Vec<Command>, SweepError> {
    let _ = (state, now);
    Err(SweepError::NotImplemented("fstp_engine::sweep::due"))
}

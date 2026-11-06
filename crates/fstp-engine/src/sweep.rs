//! The minimal deadline sweep (R-EV-07, M4 design section 3.4, change
//! D13).
//!
//! [`due`] is a pure function from engine state and `now` to the due
//! System commands of four kinds:
//!
//! - `ExpireStage2` for every proposal in STAGE2 whose P-07 window has
//!   elapsed without answers and without a "no questions" record
//!   (`state-machine.md` NOTE 4 and NOTE 5);
//! - `ReEnter` for every deferred proposal whose next published call has
//!   opened, into that call (NOTE 8).
//! - `StartExecution` for every GRANTED grant whose earliest milestone
//!   start has come (NOTE 11, M5 design section 4.2);
//! - `Complete` for every grant in execution whose milestones are all
//!   closed and whose payment requests are all terminal (NOTE 12).
//!
//! The cell is to run it on its clock and issue each command as
//! `Actor::System(SystemCause::Timeline)`. D13 makes it the only issuer of
//! these kinds in an M4 cell. That wiring and the matching narrowing of
//! the cell's timeline admission belong to the cell lane, not to this
//! crate. M6's timeline engine replaces the sweep.
//!
//! The sweep reads only the core part of the state (I-10). It takes its
//! commands from `fstp_domain::due`, so it issues nothing the domain
//! does not list as due at `now`. It keeps the four kinds above and drops
//! every other due kind, which cells issue elsewhere or not at all. A
//! proposal gets at most one `ReEnter`, the first the domain lists.
//!
//! Reading taken where the design is silent: the W0 signature returns a
//! `Result`, and other lanes code against it. The design makes the sweep
//! total, so [`due`] never returns an error. [`SweepError`] keeps the W0
//! variant so that code written against the stub still compiles.

use std::collections::BTreeSet;

use fstp_domain::time::Timestamp;

use crate::{Command, EngineState};

/// Why the sweep failed. The sweep is total (design section 3.4, D13), so
/// [`due`] returns no variant of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SweepError {
    /// Kept for the lanes that code against the W0 stub. [`due`] never
    /// returns it.
    NotImplemented(&'static str),
}

impl core::fmt::Display for SweepError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SweepError::NotImplemented(op) => write!(f, "{op} is not implemented"),
        }
    }
}

impl std::error::Error for SweepError {}

/// The `ExpireStage2`, `ReEnter`, `StartExecution` and `Complete` commands
/// due at `now`, in the order
/// `fstp_domain::due` lists them, each wrapped as a core engine command.
///
/// Every command is one the System may issue at `now`. The caller runs
/// each as `Actor::System(SystemCause::Timeline)` at `now`. A command the
/// state already reflects is no longer due, so a later sweep does not
/// issue it again.
pub fn due(state: &EngineState, now: Timestamp) -> Result<Vec<Command>, SweepError> {
    let mut reentered = BTreeSet::new();
    let mut out = Vec::new();
    for cmd in fstp_domain::due(&state.core, now) {
        let keep = match &cmd {
            fstp_domain::Command::ExpireStage2 { .. }
            | fstp_domain::Command::StartExecution { .. }
            | fstp_domain::Command::Complete { .. } => true,
            fstp_domain::Command::ReEnter { proposal, .. } => reentered.insert(*proposal),
            _ => false,
        };
        if keep {
            out.push(Command::Core(cmd));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D13: the empty state has nothing due at any instant.
    #[test]
    fn d13_genesis_has_nothing_due() {
        for now in [0, 1, i64::MAX] {
            assert_eq!(
                due(&EngineState::genesis(), Timestamp::from_micros(now)),
                Ok(Vec::new())
            );
        }
    }
}

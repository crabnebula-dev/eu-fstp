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
//! M6 (lane L6-TL): the timeline engine (`fstp-timeline`) derives one event
//! per command [`due`] lists, of the kind [`kind_of`] names, and fires the
//! command in the same ledger entry as its `EventFired` record. This
//! module stays the one list of the four kinds. The timeline crate sits
//! above this one (it reads the cell state, which holds the engine
//! state), so the shim runs that way round: the timeline is built over
//! [`due`], and [`due`] keeps its signature for the M5 callers.
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

/// The four kinds of the sweep. The M6 timeline engine gives each its own
/// event kind (M6 design section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SweepKind {
    /// `ExpireStage2` (NOTE 4 and NOTE 5).
    ExpireStage2,
    /// `ReEnter` (NOTE 8).
    ReEnter,
    /// `StartExecution` (NOTE 11).
    StartExecution,
    /// `Complete` (NOTE 12).
    Complete,
}

impl SweepKind {
    /// Every sweep kind.
    pub const ALL: [SweepKind; 4] = [
        SweepKind::ExpireStage2,
        SweepKind::ReEnter,
        SweepKind::StartExecution,
        SweepKind::Complete,
    ];
}

/// The sweep kind of a core command, or `None` for a command the sweep
/// does not issue.
pub fn kind_of(cmd: &fstp_domain::Command) -> Option<SweepKind> {
    match cmd {
        fstp_domain::Command::ExpireStage2 { .. } => Some(SweepKind::ExpireStage2),
        fstp_domain::Command::ReEnter { .. } => Some(SweepKind::ReEnter),
        fstp_domain::Command::StartExecution { .. } => Some(SweepKind::StartExecution),
        fstp_domain::Command::Complete { .. } => Some(SweepKind::Complete),
        _ => None,
    }
}

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
        let keep = match (&cmd, kind_of(&cmd)) {
            (fstp_domain::Command::ReEnter { proposal, .. }, _) => reentered.insert(*proposal),
            (_, kind) => kind.is_some(),
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

    /// D13, M6 design section 4: `kind_of` names exactly the four sweep
    /// kinds, each once, and no other command.
    #[test]
    fn d13_kind_of_names_the_four_sweep_kinds() {
        use fstp_domain::id::{BindingId, CallId, ProposalId};
        let p = ProposalId::from_raw(1);
        let cases = [
            (
                fstp_domain::Command::ExpireStage2 { proposal: p },
                Some(SweepKind::ExpireStage2),
            ),
            (
                fstp_domain::Command::ReEnter {
                    proposal: p,
                    call: CallId::from_raw(2),
                },
                Some(SweepKind::ReEnter),
            ),
            (
                fstp_domain::Command::StartExecution { proposal: p },
                Some(SweepKind::StartExecution),
            ),
            (
                fstp_domain::Command::Complete { proposal: p },
                Some(SweepKind::Complete),
            ),
            (
                fstp_domain::Command::EndScheduledRole {
                    binding: BindingId::from_raw(3),
                },
                None,
            ),
        ];
        for (cmd, want) in cases {
            assert_eq!(kind_of(&cmd), want);
        }
        assert_eq!(SweepKind::ALL.len(), 4);
    }

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

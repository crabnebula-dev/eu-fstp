//! Copy requests of a submission record (R-SB-04, TH-21, M6 design
//! reading 4 and section 6, lane L6-API).
//!
//! - `RequestCopy`, by the proposal's lead account, appends one
//!   `OutboxEnqueued(CopyRequested)`. The record holds the proposal id and
//!   the reference of the sealed address text, so ids only. Its entry time
//!   is the request time. The M6 timeline fires it as an immediate event.
//! - TH-21: at most [`COPIES_PER_DAY`] requests per proposal in any
//!   [`DAY_MICROS`] window. A further request is refused with R-SB-04.
//! - The lead is checked by account, as the calibration lane does, since
//!   the API checks the active binding first.
//!
//! The fold also keeps the first submission instant of each proposal, so
//! the copy email names when the proposal was submitted.

use std::collections::BTreeMap;

use crate::command::{Command, Ctx};
use crate::id::ProposalId;
use crate::record::{OutboxEvent, Record, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::rules::StateTag;
use crate::state::State;
use crate::time::Timestamp;

/// The most copies of one proposal in one day (TH-21, M6 design reading 4).
pub const COPIES_PER_DAY: usize = 3;

/// One day, microseconds.
pub const DAY_MICROS: i64 = 86_400_000_000;

/// The copy part of the proposal store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Copies {
    /// The latest request instants of each proposal, oldest first, at most
    /// [`COPIES_PER_DAY`] of them.
    recent: BTreeMap<ProposalId, Vec<Timestamp>>,
    /// The first submission instant of each proposal.
    submitted: BTreeMap<ProposalId, Timestamp>,
}

impl Copies {
    /// No request and no submission.
    pub(crate) const fn genesis() -> Copies {
        Copies {
            recent: BTreeMap::new(),
            submitted: BTreeMap::new(),
        }
    }

    /// Whether `proposal` may have one more copy at `now`: fewer than
    /// [`COPIES_PER_DAY`] requests after `now` minus one day (TH-21).
    fn allowed(&self, proposal: ProposalId, now: Timestamp) -> bool {
        let since = now.micros().saturating_sub(DAY_MICROS);
        self.recent
            .get(&proposal)
            .map_or(0, |v| v.iter().filter(|t| t.micros() > since).count())
            < COPIES_PER_DAY
    }
}

/// Whether `cmd` is decided here.
pub(crate) const fn is_copy_command(cmd: &Command) -> bool {
    matches!(cmd, Command::RequestCopy { .. })
}

/// Decides `RequestCopy`.
pub(crate) fn decide(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let Command::RequestCopy { proposal, address } = cmd else {
        return Err(super::life::wrong_state());
    };
    let actor = crate::policy::actor_account(ctx)?;
    let d = super::draft::draft(state, *proposal).ok_or_else(super::life::unknown)?;
    if d.lead != actor {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    if !state.proposals.copies.allowed(*proposal, ctx.now) {
        return Err(Refusal::new(RuleRef::Rsb04, RefusalReason::GuardFailed));
    }
    Ok(vec![Record::OutboxEnqueued(OutboxEvent::CopyRequested {
        proposal: *proposal,
        address: *address,
    })])
}

/// Keeps the instant of a copy request folded at `at`.
pub(crate) fn on_outbox(state: &mut State, at: Timestamp, record: &Record) {
    if let Record::OutboxEnqueued(OutboxEvent::CopyRequested { proposal, .. }) = record {
        let v = state.proposals.copies.recent.entry(*proposal).or_default();
        v.push(at);
        if v.len() > COPIES_PER_DAY {
            v.remove(0);
        }
    }
}

/// Keeps the first submission instant of a proposal.
pub(crate) fn on_transition(state: &mut State, t: &Transitioned, at: Timestamp) {
    if t.from == StateTag::Draft && t.to == StateTag::Submitted {
        state
            .proposals
            .copies
            .submitted
            .entry(t.proposal)
            .or_insert(at);
    }
}

/// When `proposal` was first submitted, once it was (R-SB-04).
pub fn submitted_at(state: &State, proposal: ProposalId) -> Option<Timestamp> {
    state.proposals.copies.submitted.get(&proposal).copied()
}

/// Whether `proposal` may have one more copy at `now` (TH-21). The API
/// asks before it stores the address, so a limited request stores no
/// text. `RequestCopy` checks it again.
pub fn copy_allowed(state: &State, proposal: ProposalId, now: Timestamp) -> bool {
    state.proposals.copies.allowed(proposal, now)
}

//! Read-only accessors that the M3 cell needs and `State` lacks (M3
//! design section 0.5). Lane W2c owns this file, and Daniel reviews it as
//! an M2 crate change.
//!
//! - [`proposal_minor_flagged`] gives the minor flag of a proposal for
//!   the public filter (I-42), failing closed.
//! - [`proposal_state`] gives the state of a proposal. The release rule
//!   of design section 6.5 issues a release ticket only for a proposal in
//!   NEGOTIATION or later (I-17).
//! - [`plan_version`] gives one recorded plan version of a proposal, so
//!   the team reads back the plan it recorded (R-SB-01, lane
//!   m4/author-reads).
//!
//! Each accessor reads the projection and changes nothing. No record and
//! no rule changes.

use crate::id::ProposalId;
use crate::rules::StateTag;
use crate::state::State;

/// The state of `proposal`, or `None` for an unknown proposal.
pub fn proposal_state(state: &State, proposal: ProposalId) -> Option<StateTag> {
    crate::proposal::intake::proposal_state(state, proposal)
}

/// Whether `proposal` is minor-flagged (R-ID-04, state-machine NOTE 14),
/// for the public filter of I-42, which never shows a minor-flagged
/// proposal. It fails closed: it is true for an unknown proposal and
/// before the IRC_REVIEW to NEGOTIATION gate has derived the flag, so the
/// filter hides such a proposal (I-42).
pub fn proposal_minor_flagged(state: &State, proposal: ProposalId) -> bool {
    crate::proposal::draft::minor_flagged(state, proposal)
}

/// The plan an amount determination of `proposal` starts from, with its
/// total (R-NG-03, I-13): the agreed plan of the current determination,
/// else the effective plan (I-09). `None` before submission. The total
/// is `None` when the plan sum fails (ADR-006). M5 reads follow-up.
pub fn determination_plan(
    state: &State,
    proposal: ProposalId,
) -> Option<(crate::id::PlanVersionId, Option<fstp_money::NonNegAmount>)> {
    let plan = state
        .money()
        .determined(proposal)
        .map(|(p, _)| p)
        .or_else(|| crate::proposal::intake::effective_plan(state, proposal))?;
    Some((plan, crate::grant::plan_total(state, plan)))
}

/// One recorded plan version, read-only (lane m4/author-reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanVersionView<'a> {
    /// Where it comes from.
    pub origin: crate::proposal::PlanOrigin,
    /// Its tasks with their milestones.
    pub tasks: &'a [crate::proposal::Task],
    /// The digest of the plan text held outside the domain.
    pub content: crate::id::ContentDigest,
    /// The stored work plan text whose digest is `content` (ADR-007), or
    /// `None` when the plan names none (Daniel, 2026-11-16).
    pub text: Option<crate::id::TextRef>,
    /// The total of its milestone amounts, or `None` when the sum fails
    /// (ADR-006).
    pub total: Option<fstp_money::NonNegAmount>,
}

/// The plan version `plan` of `proposal`, or `None` for an unknown plan or
/// a plan of another proposal (R-SB-01). It reads the projection only.
pub fn plan_version(
    state: &State,
    proposal: ProposalId,
    plan: crate::id::PlanVersionId,
) -> Option<PlanVersionView<'_>> {
    let p = crate::proposal::intake::plan(state, plan).filter(|p| p.proposal == proposal)?;
    Some(PlanVersionView {
        origin: p.origin,
        tasks: &p.tasks,
        content: p.content,
        text: p.text,
        total: crate::proposal::intake::plan_total(p),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-42: the minor flag fails closed, so a proposal the state does
    /// not know reads as minor-flagged and stays hidden from the public
    /// view.
    #[test]
    fn i42_unknown_proposal_reads_as_minor_flagged() {
        let state = State::genesis();
        assert!(proposal_minor_flagged(&state, ProposalId::from_raw(1)));
    }

    /// R-SB-01 (lane m4/author-reads): a plan the state does not know reads
    /// as none, never as an empty plan.
    #[test]
    fn r_sb_01_unknown_plan_reads_as_none() {
        let state = State::genesis();
        let plan = crate::id::PlanVersionId::from_raw(70);
        assert_eq!(plan_version(&state, ProposalId::from_raw(1), plan), None);
    }
}

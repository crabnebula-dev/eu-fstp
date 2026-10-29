//! Read-only accessors that the M3 cell needs and `State` lacks (M3
//! design section 0.5). Lane W2c owns this file, and Daniel reviews it as
//! an M2 crate change.
//!
//! - [`proposal_state`] gives the state of a proposal. The release rule
//!   of design section 6.5 issues a release ticket only for a proposal in
//!   NEGOTIATION or later (I-17).
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

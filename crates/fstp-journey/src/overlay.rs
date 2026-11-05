//! The programme overlay (`SPEC/12-journey-ui.md` section 5.5, R-JV-07).
//!
//! The overlay is what the route map shows that depends on policy. It is
//! computed from the policy version a call froze, never edited by hand.
//! For a deferred proposal the caller passes the original call's frozen
//! version (NOTE 8). [`compute`] is a pure function of its inputs.
//!
//! I-97: the overlay never carries the text of a policy value. A
//! parameter whose value M2 keeps opaque appears in [`Overlay::wording`]
//! by its id only, so the interface picks the wording through the
//! parameter, never through text copied from a ledger record.
//!
//! The P-20 payment wording is a tenant setting, so the caller passes it
//! in [`OverlayInputs::tenant_params`] when it is set.

use std::collections::BTreeSet;

use fstp_domain::id::PolicyVersionId;
use fstp_domain::policy::{McpBindingActions, PolicyVersion, ReviewerAnonymity};
use fstp_domain::rules::ParamId;
use fstp_domain::time::Days;

/// The parameters of section 5.5 whose value M2 keeps opaque. Each shows
/// as a wording choice.
pub const WORDING_PARAMS: [ParamId; 7] = [
    ParamId::P08,
    ParamId::P20,
    ParamId::P50,
    ParamId::P51,
    ParamId::P60,
    ParamId::P65,
    ParamId::P66,
];

/// Where an IRC concern leads (NOTE 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrcConcern {
    /// A later call is published, so the proposal is deferred.
    Deferred,
    /// No later call is published, so the proposal is declined.
    Declined,
}

/// The facts besides the policy version that the overlay reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct OverlayInputs {
    /// Whether a later call of the programme is published (NOTE 7).
    pub later_call_published: bool,
    /// The tenant-level parameters that are set, such as P-20.
    pub tenant_params: BTreeSet<ParamId>,
}

/// The overlay of section 5.5.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Overlay {
    /// The policy version it was computed from.
    pub policy: PolicyVersionId,
    /// P-07: the stage 2 window length.
    pub stage2_window: Days,
    /// P-11: the reviewer anonymity wording.
    pub anonymity: ReviewerAnonymity,
    /// NOTE 7: where an IRC concern leads.
    pub irc_concern: IrcConcern,
    /// P-77: whether agent actions are drafted or completed.
    pub agent_actions: McpBindingActions,
    /// The [`WORDING_PARAMS`] that are set, by id only.
    pub wording: BTreeSet<ParamId>,
}

/// The overlay of `version` (R-JV-07): each output from its section 5.5
/// source and nothing else. A wording parameter counts as set when the
/// frozen or live values of the version hold it, or the tenant sets it.
/// Only its id is carried, never its value (I-97).
pub fn compute(version: &PolicyVersion, inputs: &OverlayInputs) -> Overlay {
    let irc_concern = if inputs.later_call_published {
        IrcConcern::Deferred
    } else {
        IrcConcern::Declined
    };
    let wording = WORDING_PARAMS
        .into_iter()
        .filter(|p| {
            version.frozen.opaque.contains_key(p)
                || version.live.opaque.contains_key(p)
                || inputs.tenant_params.contains(p)
        })
        .collect();
    Overlay {
        policy: version.id,
        stage2_window: version.frozen.p07,
        anonymity: version.frozen.p11,
        irc_concern,
        agent_actions: version.frozen.p77,
        wording,
    }
}

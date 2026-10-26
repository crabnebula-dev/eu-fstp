//! The M-EXCL model for fstp-mc and its I-04 properties (design sections 6.2 and 6.3).
//!
//! Two accounts and three classes, shaped like the corpus variant
//! "Excluded affiliation" (`SPEC/07-test-plan/synthetic-corpus.md`):
//!
//! - x has a pending exclusion in class K1, which the vault reveals only
//!   when it verifies x, as at negotiation. A new affiliation may also put
//!   x in class K3.
//! - y is in class K2, which is not in P-13 until the one P-13 edit adds it.
//! - P-13 starts as {K1, K3}. One call is published by the setup.
//!
//! Each account may draft once and verify once. Each lead may add the other
//! account to its proposal once, as team member or as guardian. Every vault
//! change runs with its reaction in the same step (design 6.1).
//!
//! The NEGOTIATION entry of the test plan row needs the lifecycle (lane
//! L-LIFE, W4). Here verification is the vault event that reveals the fact.

use std::collections::BTreeMap;

use fstp_domain::id::{AccountId, BindingId, PolicyVersionId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_mc::{Model, Property};

use crate::r#gen::roster::{
    Backend, K1, K2, K3, P1, SodSetup, SodWorld, T0, add_member, add_staff, call, draft,
    edit_policy,
};
use crate::mc::sod_model::{
    SodMcState, inject, injected_grant, judged, two_way, unjudged, vault_step,
};
use crate::reference::sod::{
    RefGroup, Verdict, check_i04, excluded_under, expected_voids, new_bindings, verdict,
};
use crate::vault::{GroundTruth, IdentityTag, PendingFact};

/// Account x: excluded in K1 once verified, or in K3 after a new affiliation.
pub const X: AccountId = AccountId::from_raw(201);
/// Account y: excluded in K2 from the start.
pub const Y: AccountId = AccountId::from_raw(202);
/// The identity of x.
pub const ID_X: IdentityTag = IdentityTag::new(2001);
/// The identity of y.
pub const ID_Y: IdentityTag = IdentityTag::new(2002);

/// The vault of M-EXCL: staff, x unverified with a pending exclusion in
/// K1, and y unverified and excluded in K2.
pub fn excl_truth() -> GroundTruth {
    let mut truth = GroundTruth::new();
    add_staff(&mut truth);
    truth.set_identity(X, ID_X);
    truth.add_pending(
        X,
        PendingFact::Excluded {
            identity: ID_X,
            class: K1,
        },
    );
    truth.set_identity(Y, ID_Y);
    truth.exclude(ID_Y, K2);
    truth
}

/// The setup of M-EXCL: P-13 {K1, K3} and call 1 published.
pub fn excl_setup() -> SodSetup {
    let mut s = SodSetup::one(1, &[1]);
    s.p13 = [K1, K3].into_iter().collect();
    s.published = vec![call(1)];
    s
}

/// The state count of M-EXCL, measured on the production backend in step
/// W6. The reference backend stores the same count.
pub const M_EXCL_STATES: usize = 470;

/// An M-EXCL action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExclAction {
    /// `CreateDraft` by the account in call 1, flagged as a minor's.
    Draft(AccountId),
    /// The lead adds the other account as team member, or as guardian.
    Add {
        /// The lead.
        lead: AccountId,
        /// Guardian rather than team member.
        guardian: bool,
    },
    /// The vault verifies the account, revealing its pending facts.
    Verify(AccountId),
    /// The P-13 edit that adds K2.
    AddK2,
    /// The vault reports a new affiliation that puts x in K3.
    AffiliateX,
}

/// The other account of M-EXCL.
const fn other(a: AccountId) -> AccountId {
    if a.raw() == X.raw() { Y } else { X }
}

/// The proposal and Applicant binding id of `lead`'s draft.
fn draft_id(lead: AccountId) -> u128 {
    lead.raw().saturating_mul(10)
}

/// The binding id of the member `lead` adds.
fn member_id(lead: AccountId) -> u128 {
    lead.raw().saturating_mul(10).saturating_add(1)
}

/// The M-EXCL model (design 6.3).
pub struct ExclModel {
    /// The start state.
    pub start: SodMcState,
    /// The first policy version, the head the one edit is based on.
    pub head: fstp_domain::policy::PolicyVersion,
}

impl ExclModel {
    /// The model with its start state built from genesis.
    pub fn new(backend: Backend) -> Result<ExclModel, String> {
        let setup = excl_setup();
        let world = SodWorld::from_setup(backend, excl_truth(), &setup)?;
        Ok(ExclModel {
            start: SodMcState::new(world),
            head: setup.version(P1)?,
        })
    }
}

/// Whether K2 is in the head's P-13.
fn k2_added(s: &SodMcState) -> bool {
    s.view().head(P1).is_some_and(|h| h.p13.contains(&K2))
}

impl Model for ExclModel {
    type State = SodMcState;
    type Action = ExclAction;

    fn init(&self) -> Vec<SodMcState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &SodMcState, actions: &mut Vec<ExclAction>) {
        for a in [X, Y] {
            actions.push(ExclAction::Draft(a));
            actions.push(ExclAction::Add {
                lead: a,
                guardian: false,
            });
            actions.push(ExclAction::Add {
                lead: a,
                guardian: true,
            });
            if !s.truth().is_verified(a) {
                actions.push(ExclAction::Verify(a));
            }
        }
        if !k2_added(s) {
            actions.push(ExclAction::AddK2);
        }
        if !s.truth().is_excluded(ID_X, K3) {
            actions.push(ExclAction::AffiliateX);
        }
    }

    fn step(&self, s: &SodMcState, a: &ExclAction) -> Option<SodMcState> {
        if s.divergence.is_some() {
            return None;
        }
        match *a {
            ExclAction::Draft(lead) => {
                let id = draft_id(lead);
                if s.view().proposals.contains_key(&ProposalId::from_raw(id)) {
                    return None;
                }
                judged(
                    s,
                    &draft(
                        lead,
                        ProposalId::from_raw(id),
                        call(1),
                        BindingId::from_raw(id),
                        true,
                    ),
                )
            }
            ExclAction::Add { lead, guardian } => {
                let proposal = ProposalId::from_raw(draft_id(lead));
                let binding = BindingId::from_raw(member_id(lead));
                if !s.view().proposals.contains_key(&proposal)
                    || s.view().bindings.contains_key(&binding)
                {
                    return None;
                }
                judged(
                    s,
                    &add_member(lead, proposal, other(lead), binding, guardian),
                )
            }
            ExclAction::Verify(account) => {
                if s.truth().is_verified(account) {
                    return None;
                }
                vault_step(s, |t| t.verify(account))
            }
            ExclAction::AddK2 => {
                if k2_added(s) {
                    return None;
                }
                let step = edit_policy(&self.head, PolicyVersionId::from_raw(50), |v| {
                    v.live.p13.0.insert(K2);
                });
                let fstp_domain::command::Command::EditPolicy { version, .. } = &step.cmd else {
                    return None;
                };
                let version = version.clone();
                unjudged(s, &step, |before| {
                    let mut after = before.view().clone();
                    let recorded = Record::PolicyVersionRecorded {
                        version,
                        author: crate::r#gen::roster::STAFF_PM,
                    };
                    if after.fold(&recorded).is_err() {
                        return BTreeMap::new();
                    }
                    expected_voids(&after, before.truth())
                })
            }
            ExclAction::AffiliateX => {
                if s.truth().is_excluded(ID_X, K3) {
                    return None;
                }
                vault_step(s, |t| t.exclude(ID_X, K3))
            }
        }
    }

    fn is_terminal(&self, s: &SodMcState) -> bool {
        s.divergence.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// `always("I-04")` over the reference view and the vault's effective facts.
pub fn always_i04<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("I-04", |s| check_i04(s.view(), s.truth()))
}

/// `transition("SoD-06")`: no step creates a Receiving binding for an
/// account in an excluded class of its call's effective P-13 before the step.
pub fn transition_sod06<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("SoD-06", |before, _, after| {
        for b in new_bindings(before.view(), after.view()) {
            let Some(c) = b.call else { continue };
            if b.group == RefGroup::Receiving
                && excluded_under(before.truth(), b.account, &before.view().effective_p13(c))
            {
                return Err(format!(
                    "SoD-06: {:?} {:?} granted to an account in an excluded class",
                    b.role, b.binding
                ));
            }
        }
        Ok(())
    })
}

/// Witness: the reference refuses y's draft at binding under SoD-06, after
/// the P-13 edit made y's class excluded.
pub fn blocked_at_binding(s: &SodMcState) -> bool {
    let id = draft_id(Y);
    let step = draft(
        Y,
        ProposalId::from_raw(id),
        call(1),
        BindingId::from_raw(id),
        true,
    );
    s.view().bindings_of(Y, P1).next().is_none()
        && verdict(s.view(), s.truth(), &step.ask(T0)) == Verdict::Refuse("SoD-06".to_owned())
}

/// Whether a binding of `account` in `role` was voided under I-04.
fn voided_i04(s: &SodMcState, account: AccountId, role: Role) -> bool {
    s.view()
        .bindings
        .values()
        .any(|b| b.account == account && b.role == role && b.voided == Some(RuleRef::I04))
}

/// Witness: x's class is revealed at verification and x's Applicant binding
/// is voided in the same step.
pub fn revealed_and_voided(s: &SodMcState) -> bool {
    s.truth().is_verified(X)
        && !s.truth().is_excluded(ID_X, K3)
        && voided_i04(s, X, Role::Applicant)
}

/// Witness: the P-13 edit voids y's Applicant binding in the same step.
pub fn voided_at_p13_edit(s: &SodMcState) -> bool {
    k2_added(s) && voided_i04(s, Y, Role::Applicant)
}

/// Witness: a new affiliation voids unverified x's Applicant binding.
pub fn voided_at_new_affiliation(s: &SodMcState) -> bool {
    !s.truth().is_verified(X) && voided_i04(s, X, Role::Applicant)
}

/// Witness: a team member or guardian is voided under I-04.
pub fn member_voided(s: &SodMcState) -> bool {
    [X, Y]
        .into_iter()
        .any(|a| voided_i04(s, a, Role::ApplicantTeamMember) || voided_i04(s, a, Role::Guardian))
}

/// The M-EXCL properties with their witnesses.
pub fn excl_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i04::<M>(),
        transition_sod06::<M>(),
        Property::<M>::reachable(
            "SoD-06 witness: an excluded account is blocked at binding",
            blocked_at_binding,
        ),
        Property::<M>::reachable(
            "I-04 witness: revealed at verification and voided in the same step",
            revealed_and_voided,
        ),
        Property::<M>::reachable("I-04 witness: voided at the P-13 edit", voided_at_p13_edit),
        Property::<M>::reachable(
            "I-04 witness: voided at a new affiliation",
            voided_at_new_affiliation,
        ),
        Property::<M>::reachable(
            "I-04 witness: a team member or guardian is voided",
            member_voided,
        ),
    ]
}

/// The fault of `i04_teeth_excluded_receiving_is_caught`: a broken engine
/// adds y to x's proposal as team member while y is in an excluded class
/// of the call.
pub fn fault_excluded_member(s: &SodMcState) -> Option<SodMcState> {
    let v = s.view();
    let proposal = ProposalId::from_raw(draft_id(X));
    let p = v.proposals.get(&proposal)?;
    if !excluded_under(s.truth(), Y, &v.effective_p13(p.call)) {
        return None;
    }
    let binding = BindingId::from_raw(9_004);
    if v.bindings.contains_key(&binding) {
        return None;
    }
    inject(
        s,
        &[injected_grant(
            binding,
            Y,
            P1,
            Role::ApplicantTeamMember,
            Some((proposal, p.call)),
        )],
    )
}

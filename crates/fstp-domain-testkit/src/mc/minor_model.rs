//! M-MINOR: the IRC_REVIEW to NEGOTIATION gate over the vault facts that derive the minor flag (R-ID-04, I-18).
//!
//! Lane dom of M3 (Q13 A, decided 2026-10-28). `SPEC/02-domain/state-machine.md`
//! NOTE 14: the gate admits a proposal only when its lead has an effective
//! verified over-18 attestation at the deadline, or the proposal has a
//! verified guardian consent record. Every other proposal is minor-flagged
//! and stays in IRC_REVIEW until its consent is effective. The flag never
//! comes from the actor (`01-requirements/functional.md` R-ID-04).
//!
//! - The start is PR1 of lead L1 in IRC_REVIEW, built from genesis by
//!   production commands, with IRC and IRC2 assigned and P-15 = 2. The
//!   vault holds neither fact about L1 or PR1, whatever the actor's
//!   `CreateDraft` field said. Each instance fixes that field.
//! - The actions are the two validations, an over-18 attestation that
//!   shows L1 18 or older before the deadline or only after it, and a
//!   guardian consent. Each vault change happens at most once, and the
//!   reaction to it runs in the same step. The model stops once PR1 leaves
//!   IRC_REVIEW.
//! - Every step is compared with the references in both directions, as in
//!   the life models.
//!
//! The properties read the reference view and the vault facts only. The
//! gate property is a safety check of NOTE 14. The witnesses show both
//! admission paths, and a proposal that stays minor-flagged with every
//! validation recorded, so the model is not vacuous.
//!
//! The deadline is that of the call PR1 was submitted to (ADR-008, "Which
//! deadline", interim). The model leaves out the guard into GRANTED,
//! whose second derivation is not decided.

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Vote;
use fstp_domain::id::AccountId;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_mc::{Model, Property};

use crate::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use crate::r#gen::roster::{
    Backend, CALL_DEADLINE, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM, call,
};
use crate::mc::life_model::{
    IRC2, LifeSetup, LifeWorld, Start, assign_declared, ballots, cut_off, cut_off_decision,
    irc_review, life_judges,
};

/// The state count of M-MINOR with the actor's field clear, measured on
/// production with the gate of NOTE 14 in lane dom of M3 (38, equal to
/// the reference count). The tripwire bounds a run at twice this count.
pub const M_MINOR_FIELD_CLEAR_STATES: usize = 38;
/// The reference twin of [`M_MINOR_FIELD_CLEAR_STATES`].
pub const M_MINOR_FIELD_CLEAR_REFERENCE_STATES: usize = 38;
/// The state count of M-MINOR with the actor's field set, measured on
/// production with the gate of NOTE 14 in lane dom of M3 (38, equal to
/// the reference count).
pub const M_MINOR_FIELD_SET_STATES: usize = 38;
/// The reference twin of [`M_MINOR_FIELD_SET_STATES`].
pub const M_MINOR_FIELD_SET_REFERENCE_STATES: usize = 38;

/// One action of M-MINOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MinorAction {
    /// The IRC member validates PR1.
    Validate(AccountId),
    /// The vault records an effective verified over-18 attestation of L1.
    /// It shows L1 18 or older before the deadline when the bit is set,
    /// and only after the deadline otherwise.
    Attest(bool),
    /// The vault records a verified guardian consent for PR1.
    Consent,
}

/// One M-MINOR state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MinorState {
    /// Production, the vault and the reference views.
    pub world: LifeWorld,
    /// The attestation recorded, by its on-time bit, if any.
    pub attested: Option<bool>,
    /// Whether the consent is recorded.
    pub consented: bool,
    /// Set when production and the references disagree. The state is terminal.
    pub divergence: Option<String>,
}

impl MinorState {
    /// The reference state of PR1.
    pub fn state(&self) -> Option<StateTag> {
        self.world.life.state_of(PR1)
    }

    /// Whether the vault holds an effective verified over-18 attestation of
    /// L1 at the deadline of call 1 (overview NOTE 7).
    pub fn adult(&self) -> bool {
        self.world.rev.sod.truth.is_adult_at(L1, CALL_DEADLINE)
    }

    /// Whether the vault holds a verified guardian consent for PR1 (I-18).
    pub fn consent(&self) -> bool {
        self.world.rev.sod.truth.has_consent(PR1)
    }

    /// Whether every IRC assignment of PR1 has a recorded validation.
    pub fn all_validated(&self) -> bool {
        self.world
            .life
            .proposals
            .get(&PR1)
            .is_some_and(|p| p.irc.len() >= 2 && p.irc.values().all(|ok| *ok))
    }
}

/// M-MINOR over one value of the actor's `CreateDraft` field.
pub struct MinorModel {
    /// The start state.
    pub start: MinorState,
}

/// The setup underneath: PR1 of L1 in RANKED on its original plan, with
/// reviewers R1 and R2, P-03 = 2 and P-15 = 2. `field` is the actor's
/// `CreateDraft` field.
pub fn minor_setup(field: bool) -> LifeSetup {
    LifeSetup {
        scale_max: 2,
        weights: vec![1, 1],
        p02_bp: 5_000,
        p03: 2,
        p07_days: 28,
        p15: 2,
        judges: life_judges(),
        proposals: vec![(L1, PR1, field)],
        reviewers: vec![R1, R2],
        start_scores: vec![vec![2, 2], vec![2, 2]],
        revision_scores: Vec::new(),
        start: Start::Ranked { revised: false },
    }
}

impl MinorModel {
    /// The model with the actor's field `field` over `backend`, its start
    /// built from genesis.
    pub fn new(field: bool, backend: Backend) -> Result<MinorModel, String> {
        let setup = minor_setup(field);
        let mut truth = setup.truth();
        truth.withdraw_attestation(L1);
        let mut w = setup.world(backend, truth)?;
        w = w.must(&cut_off(
            R1,
            cut_off_decision(1),
            call(1),
            vec![PR1],
            1,
            false,
            ballots(&[R1, R2, R3], Vote::For),
        ))?;
        for i in [IRC, IRC2] {
            for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
                w = w.must(&st)?;
            }
        }
        if w.life.state_of(PR1) != Some(StateTag::IrcReview) {
            return Err(format!(
                "M-MINOR start: PR1 is in {:?}, not IRC_REVIEW",
                w.life.state_of(PR1)
            ));
        }
        Ok(MinorModel {
            start: MinorState {
                world: w,
                attested: None,
                consented: false,
                divergence: None,
            },
        })
    }
}

fn diverged(s: &MinorState, why: String) -> MinorState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

impl Model for MinorModel {
    type State = MinorState;
    type Action = MinorAction;

    fn init(&self) -> Vec<MinorState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &MinorState, actions: &mut Vec<MinorAction>) {
        if self.is_terminal(s) {
            return;
        }
        actions.push(MinorAction::Validate(IRC));
        actions.push(MinorAction::Validate(IRC2));
        if s.attested.is_none() {
            actions.push(MinorAction::Attest(true));
            actions.push(MinorAction::Attest(false));
        }
        if !s.consented {
            actions.push(MinorAction::Consent);
        }
    }

    fn step(&self, s: &MinorState, action: &MinorAction) -> Option<MinorState> {
        if s.divergence.is_some() {
            return None;
        }
        let mut next = s.clone();
        match action {
            MinorAction::Validate(i) => {
                let a = s
                    .world
                    .assignment(*i, PR1, Stage::Two, AssignmentKind::Irc)?;
                match s.world.step(&irc_review(*i, a, true)) {
                    Ok(Some((w, _))) => next.world = w,
                    Ok(None) => return None,
                    Err(e) => return Some(diverged(s, format!("{action:?}: {e}"))),
                }
            }
            MinorAction::Attest(on_time) => {
                let from = if *on_time {
                    LEAD_ADULT_FROM
                } else {
                    LEAD_ADULT_AFTER_DEADLINE
                };
                next.world.rev.sod.truth.attest_adult(L1, from);
                next.attested = Some(*on_time);
                if let Err(e) = next.world.sync() {
                    next.divergence = Some(e);
                }
            }
            MinorAction::Consent => {
                next.world.rev.sod.truth.consent(PR1);
                next.consented = true;
                if let Err(e) = next.world.sync() {
                    next.divergence = Some(e);
                }
            }
        }
        Some(next)
    }

    fn is_terminal(&self, s: &MinorState) -> bool {
        s.divergence.is_some() || s.state() != Some(StateTag::IrcReview)
    }
}

/// always("two-way"): production and the references agreed on every step.
pub fn agree(s: &MinorState) -> Result<(), String> {
    match &s.divergence {
        Some(d) => Err(format!("two-way: {d}")),
        None => Ok(()),
    }
}

/// transition("NOTE 14"): PR1 enters NEGOTIATION from IRC_REVIEW only when
/// L1 has an effective verified over-18 attestation at the deadline, or
/// PR1 has a verified guardian consent (R-ID-04, I-18, R-NG-02).
pub fn gate_admits_only_on_the_vault(
    before: &MinorState,
    _: &MinorAction,
    after: &MinorState,
) -> Result<(), String> {
    let entered =
        before.state() == Some(StateTag::IrcReview) && after.state() == Some(StateTag::Negotiation);
    if entered && !(before.adult() || before.consent()) {
        return Err(format!(
            "NOTE 14: PR1 entered NEGOTIATION with no over-18 attestation at the \
             deadline and no guardian consent (attested {:?}, consented {})",
            before.attested, before.consented
        ));
    }
    Ok(())
}

/// Whether PR1 entered NEGOTIATION on L1's attestation alone.
pub fn entered_on_attestation(s: &MinorState) -> bool {
    s.state() == Some(StateTag::Negotiation) && s.adult() && !s.consent()
}

/// Whether PR1 entered NEGOTIATION on its guardian consent alone.
pub fn entered_on_consent(s: &MinorState) -> bool {
    s.state() == Some(StateTag::Negotiation) && s.consent() && !s.adult()
}

/// Whether PR1 stays minor-flagged in IRC_REVIEW with every validation
/// recorded and neither fact in the vault.
pub fn waits_minor_flagged(s: &MinorState) -> bool {
    s.state() == Some(StateTag::IrcReview) && s.all_validated() && !s.adult() && !s.consent()
}

/// Whether PR1 stays minor-flagged in IRC_REVIEW with every validation
/// recorded although L1 is attested 18 or older after the deadline.
pub fn waits_after_late_attestation(s: &MinorState) -> bool {
    s.state() == Some(StateTag::IrcReview)
        && s.all_validated()
        && s.attested == Some(false)
        && !s.consent()
}

/// The M-MINOR properties: two-way, the NOTE 14 gate, and a witness of each
/// admission path and of each way to stay minor-flagged.
pub fn minor_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = MinorState, Action = MinorAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::transition_with("NOTE 14", gate_admits_only_on_the_vault),
        Property::reachable(
            "R-ID-04 witness: NEGOTIATION through the over-18 attestation",
            entered_on_attestation,
        ),
        Property::reachable(
            "I-18 witness: NEGOTIATION through the guardian consent",
            entered_on_consent,
        ),
        Property::reachable(
            "I-18 witness: every IRC member validated and PR1 stays minor-flagged",
            waits_minor_flagged,
        ),
        Property::reachable(
            "R-ID-04 witness: an attestation after the deadline leaves PR1 minor-flagged",
            waits_after_late_attestation,
        ),
    ]
}

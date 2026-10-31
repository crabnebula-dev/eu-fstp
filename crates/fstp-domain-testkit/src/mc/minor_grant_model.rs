//! M-MINOR-GRANT: the guard into GRANTED derives the minor flag again over changing vault facts (R-ID-04, I-18, state-machine NOTE 14).
//!
//! Lane dom2 of M3 (decided 2026-10-29). `SPEC/02-domain/state-machine.md`
//! NOTE 14: the guard into GRANTED derives the flag again in the same way
//! as the negotiation gate, so a proposal that is minor-flagged there needs
//! a verified guardian consent before GRANTED. A conflict between an adult
//! attestation and an under-18 verification at the deadline is resolved
//! by a manual identity check before either gate admits. The vault gives
//! no answer until then, so the guard fails closed (overview NOTE 2).
//!
//! - There are two starts, each PC of lead LC in NEGOTIATION, built from
//!   genesis by production commands. In one the negotiation gate admitted
//!   PC on an effective verified over-18 attestation with no guardian
//!   consent. In the other it admitted PC on a verified guardian consent,
//!   with no attestation. The actor's `CreateDraft` field is set. R1 has
//!   determined the amount, the lead has accepted and the programme
//!   manager has approved. Only the contract fact is missing, so it
//!   completes the grant facts.
//! - The actions are the contract fact and the programme manager's
//!   `DeclineNegotiation`, each sent again after a refusal, and six vault
//!   changes, each at most once: an attestation is recorded where none is
//!   effective; the attestation is withdrawn; a verification shows LC
//!   under 18 at the deadline, which conflicts with an attestation; a
//!   guardian consent is recorded; the consent is withdrawn; and, while the
//!   conflict holds, a manual check resolves it either way. The reaction to
//!   each change runs in the same step. The model stops once PC leaves
//!   NEGOTIATION.
//! - Every step is compared with the references in both directions, as in
//!   the money models.
//!
//! The properties read the vault facts only. The transition properties
//! are the safety checks of NOTE 14 at GRANTED and of NOTE 9 at DECLINED.
//! A decline needs a missing consent, the only NOTE 9 ground the model can
//! make hold. The always property checks the converse: a decline is never
//! refused while consent is missing, so no proposal is stuck. The
//! witnesses show each way to GRANTED, the decline and the refusal under
//! the conflict, so the model is not vacuous.

use fstp_mc::{Model, Property};

use crate::r#gen::minor::money_setup;
use crate::r#gen::money::{
    LC, MoneyStory, MoneyWorld, PC, accept_grant, approve_grant, contract_effective,
    decline_negotiation,
};
use crate::r#gen::roster::{
    Backend, CALL_DEADLINE, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM, STAFF_PM,
};
use crate::vault::AgeCheck;
use fstp_domain::command::Actor;
use fstp_domain::rules::StateTag;

/// The state count of M-MINOR-GRANT on the references, measured in lane
/// dom2 fix round 1 of M3 with the second start, the attestation, the
/// consent withdrawal and the decline (490 states, 576 transitions). It was
/// 74 with one start. The production count is [`M_MINOR_GRANT_STATES`].
/// The tripwire bounds a run at twice the count.
pub const M_MINOR_GRANT_REFERENCE_STATES: usize = 490;

/// The state count of M-MINOR-GRANT on production, measured in lane dom2
/// fix round 1 of M3 once the decline derived the flag again (490 states,
/// 576 transitions). It equals the reference count. It was 74 with one
/// start.
pub const M_MINOR_GRANT_STATES: usize = 490;

/// How the negotiation gate admitted PC at a start of M-MINOR-GRANT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GateStart {
    /// On LC's effective verified over-18 attestation, with no consent.
    Attested,
    /// On PC's verified guardian consent, with no attestation.
    Consented,
}

/// One action of M-MINOR-GRANT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrantAction {
    /// The contract port reports the contract EFFECTIVE: the fact that
    /// completes the grant facts.
    Contract,
    /// The programme manager's `DeclineNegotiation` (NOTE 9).
    Decline,
    /// The vault records an effective over-18 attestation of LC where none
    /// is effective.
    Attest,
    /// The vault withdraws LC's over-18 attestation.
    Withdraw,
    /// The vault records a verification that shows LC under 18 at the
    /// deadline of call 1.
    Override,
    /// The vault records a verified guardian consent for PC.
    Consent,
    /// The vault withdraws PC's guardian consent.
    WithdrawConsent,
    /// A manual identity check resolves the age conflict of LC (G9).
    Check(AgeCheck),
}

/// One M-MINOR-GRANT state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantState {
    /// Production, the vault and the reference views.
    pub world: MoneyWorld,
    /// How the gate admitted PC.
    pub start: GateStart,
    /// Whether an attestation was recorded in NEGOTIATION.
    pub attested: bool,
    /// Whether the attestation was withdrawn.
    pub withdrawn: bool,
    /// Whether the consent was withdrawn.
    pub consent_withdrawn: bool,
    /// Set when `DeclineNegotiation` was refused while the vault showed LC
    /// not 18 or older and held no consent, so PC could neither reach
    /// GRANTED nor be declined (NOTE 9). The state is terminal.
    pub stuck: bool,
    /// Whether the under-18 verification was recorded.
    pub overridden: bool,
    /// Whether the consent was recorded.
    pub consented: bool,
    /// The manual check recorded, if any.
    pub checked: Option<AgeCheck>,
    /// Whether the contract fact was refused during the conflict while the
    /// vault held a consent.
    pub refused_in_conflict_with_consent: bool,
    /// Set when production and the references disagree. The state is terminal.
    pub divergence: Option<String>,
}

impl GrantState {
    /// The reference state of PC.
    pub fn state(&self) -> Option<StateTag> {
        self.world.state(PC)
    }

    /// The vault's answer about LC's attestation at the deadline of call 1,
    /// in which PC passed IRC review. `None` during the conflict.
    pub fn adult_answer(&self) -> Option<bool> {
        self.world.truth().adult_answer(LC, CALL_DEADLINE)
    }

    /// Whether the vault holds the age conflict of LC at the deadline.
    pub fn conflict(&self) -> bool {
        self.world.truth().age_conflict_at(LC, CALL_DEADLINE)
    }

    /// Whether the vault holds a verified guardian consent for PC.
    pub fn consent(&self) -> bool {
        self.world.truth().has_consent(PC)
    }

    /// Whether the guard into GRANTED finds the consent missing: the vault
    /// answers that LC is not 18 or older, and PC has no consent (NOTE 14).
    pub fn consent_missing(&self) -> bool {
        self.adult_answer() == Some(false) && !self.consent()
    }
}

/// M-MINOR-GRANT over one backend.
pub struct MinorGrantModel {
    /// The start states, one per [`GateStart`].
    pub starts: Vec<GrantState>,
}

/// The start of M-MINOR-GRANT over `backend` where the gate admitted PC
/// as `start` says.
fn start_state(backend: Backend, start: GateStart) -> Result<GrantState, String> {
    let mut s = MoneyStory::with(&money_setup(true), backend, |t| {
        t.withdraw_attestation(LC);
        match start {
            GateStart::Attested => t.attest_adult(LC, LEAD_ADULT_FROM),
            GateStart::Consented => t.consent(PC),
        }
    })?;
    if s.state(PC) != Some(StateTag::Negotiation) {
        return Err(format!(
            "M-MINOR-GRANT start {start:?}: PC is in {:?}, not NEGOTIATION",
            s.state(PC)
        ));
    }
    s.determine(PC, 1, &[])?;
    s.run(&accept_grant(LC, PC))?;
    s.run(&approve_grant(STAFF_PM, PC))?;
    Ok(GrantState {
        world: s.world,
        start,
        attested: false,
        withdrawn: false,
        consent_withdrawn: false,
        stuck: false,
        overridden: false,
        consented: start == GateStart::Consented,
        checked: None,
        refused_in_conflict_with_consent: false,
        divergence: None,
    })
}

impl MinorGrantModel {
    /// The model over `backend`, its starts built from genesis.
    pub fn new(backend: Backend) -> Result<MinorGrantModel, String> {
        Ok(MinorGrantModel {
            starts: vec![
                start_state(backend, GateStart::Attested)?,
                start_state(backend, GateStart::Consented)?,
            ],
        })
    }
}

impl Model for MinorGrantModel {
    type State = GrantState;
    type Action = GrantAction;

    fn init(&self) -> Vec<GrantState> {
        self.starts.clone()
    }

    fn actions(&self, s: &GrantState, actions: &mut Vec<GrantAction>) {
        if self.is_terminal(s) {
            return;
        }
        actions.push(GrantAction::Contract);
        actions.push(GrantAction::Decline);
        let attestation = s.world.truth().is_adult_at(LC, CALL_DEADLINE);
        if !s.attested && !attestation {
            actions.push(GrantAction::Attest);
        }
        if !s.withdrawn && attestation {
            actions.push(GrantAction::Withdraw);
        }
        if !s.consent_withdrawn && s.consent() {
            actions.push(GrantAction::WithdrawConsent);
        }
        if !s.overridden {
            actions.push(GrantAction::Override);
        }
        if !s.consented {
            actions.push(GrantAction::Consent);
        }
        if s.checked.is_none() && s.conflict() {
            actions.push(GrantAction::Check(AgeCheck::Adult));
            actions.push(GrantAction::Check(AgeCheck::Minor));
        }
    }

    fn step(&self, s: &GrantState, action: &GrantAction) -> Option<GrantState> {
        if s.divergence.is_some() {
            return None;
        }
        let mut next = s.clone();
        let changed = match action {
            GrantAction::Contract => {
                match s.world.step(&contract_effective(PC)) {
                    Ok(Some((w, _))) => next.world = w,
                    Ok(None) if s.conflict() && s.consent() => {
                        next.refused_in_conflict_with_consent = true;
                    }
                    Ok(None) => return None,
                    Err(e) => next.divergence = Some(format!("{action:?}: {e}")),
                }
                return Some(next);
            }
            GrantAction::Decline => {
                match s
                    .world
                    .step(&decline_negotiation(Actor::Account(STAFF_PM), PC))
                {
                    Ok(Some((w, _))) => next.world = w,
                    Ok(None) if s.consent_missing() => next.stuck = true,
                    Ok(None) => return None,
                    Err(e) => next.divergence = Some(format!("{action:?}: {e}")),
                }
                return Some(next);
            }
            GrantAction::Attest => {
                next.attested = true;
                next.world.vault(|t| t.attest_adult(LC, LEAD_ADULT_FROM))
            }
            GrantAction::WithdrawConsent => {
                next.consent_withdrawn = true;
                next.world.vault(|t| t.withdraw_consent(PC))
            }
            GrantAction::Withdraw => {
                next.withdrawn = true;
                next.world.vault(|t| t.withdraw_attestation(LC))
            }
            GrantAction::Override => {
                next.overridden = true;
                next.world
                    .vault(|t| t.verify_under_18(LC, LEAD_ADULT_AFTER_DEADLINE))
            }
            GrantAction::Consent => {
                next.consented = true;
                next.world.vault(|t| t.consent(PC))
            }
            GrantAction::Check(outcome) => {
                next.checked = Some(*outcome);
                next.world.vault(|t| t.resolve_age_conflict(LC, *outcome))
            }
        };
        if let Err(e) = changed {
            next.divergence = Some(format!("{action:?}: {e}"));
        }
        Some(next)
    }

    fn is_terminal(&self, s: &GrantState) -> bool {
        s.divergence.is_some() || s.stuck || s.state() != Some(StateTag::Negotiation)
    }
}

/// always("two-way"): production and the references agreed on every step.
pub fn agree(s: &GrantState) -> Result<(), String> {
    match &s.divergence {
        Some(d) => Err(format!("two-way: {d}")),
        None => Ok(()),
    }
}

/// transition("NOTE 14 at GRANTED"): PC enters GRANTED from NEGOTIATION
/// only when the vault answers about LC's attestation at the deadline, and
/// either the answer is yes or PC has a verified guardian consent (R-ID-04,
/// I-18, overview NOTE 2).
pub fn granted_only_on_the_vault(
    before: &GrantState,
    _: &GrantAction,
    after: &GrantState,
) -> Result<(), String> {
    let entered =
        before.state() == Some(StateTag::Negotiation) && after.state() == Some(StateTag::Granted);
    if !entered {
        return Ok(());
    }
    match before.adult_answer() {
        None => Err(
            "NOTE 14, overview NOTE 2: PC entered GRANTED while the vault gave no \
             answer about LC's attestation (an unresolved age conflict)"
                .to_owned(),
        ),
        Some(adult) if !adult && !before.consent() => Err(format!(
            "NOTE 14, I-18: PC entered GRANTED minor-flagged without a guardian \
             consent (withdrawn {}, overridden {}, checked {:?})",
            before.withdrawn, before.overridden, before.checked
        )),
        Some(_) => Ok(()),
    }
}

/// transition("NOTE 9 at DECLINED"): PC enters DECLINED from NEGOTIATION
/// only when the guard into GRANTED finds the consent missing, the one
/// NOTE 9 ground this model can make hold (I-18, NOTE 14).
pub fn declined_only_when_consent_missing(
    before: &GrantState,
    _: &GrantAction,
    after: &GrantState,
) -> Result<(), String> {
    let entered =
        before.state() == Some(StateTag::Negotiation) && after.state() == Some(StateTag::Declined);
    if entered && !before.consent_missing() {
        return Err(format!(
            "NOTE 9, NOTE 14: PC was declined though GRANTED was reachable \
             (adult answer {:?}, consent {}, start {:?})",
            before.adult_answer(),
            before.consent(),
            before.start
        ));
    }
    Ok(())
}

/// always("NOTE 9 no dead end"): `DeclineNegotiation` is never refused
/// while the guard into GRANTED finds the consent missing.
pub fn never_stuck(s: &GrantState) -> Result<(), String> {
    if s.stuck {
        return Err(format!(
            "NOTE 9, NOTE 14: PC could neither reach GRANTED nor be declined \
             (start {:?}, withdrawn {}, consent withdrawn {})",
            s.start, s.withdrawn, s.consent_withdrawn
        ));
    }
    Ok(())
}

/// Whether PC was granted on an attestation recorded in NEGOTIATION, with
/// no consent, after the gate admitted it on its consent.
pub fn granted_on_attestation_in_negotiation(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Granted)
        && s.start == GateStart::Consented
        && s.attested
        && !s.consent()
}

/// Whether PC was declined for a missing consent after the gate admitted
/// it on the attestation.
pub fn declined_after_attestation_loss(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Declined) && s.start == GateStart::Attested && s.withdrawn
}

/// Whether PC was granted on LC's attestation alone, with no consent.
pub fn granted_on_attestation(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Granted) && s.adult_answer() == Some(true) && !s.consent()
}

/// Whether PC was granted on its consent after the attestation was lost.
pub fn granted_on_consent_after_loss(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Granted) && s.withdrawn && s.consent()
}

/// Whether the completing fact was refused during the conflict while the
/// vault held a consent, so the consent did not excuse the missing answer.
pub fn refused_in_conflict(s: &GrantState) -> bool {
    s.refused_in_conflict_with_consent && s.state() == Some(StateTag::Negotiation)
}

/// Whether PC was granted without a consent after a manual check found LC adult.
pub fn granted_after_adult_check(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Granted) && s.checked == Some(AgeCheck::Adult) && !s.consent()
}

/// Whether PC was granted on its consent after a manual check found LC a minor.
pub fn granted_after_minor_check(s: &GrantState) -> bool {
    s.state() == Some(StateTag::Granted) && s.checked == Some(AgeCheck::Minor) && s.consent()
}

/// The M-MINOR-GRANT properties: two-way, NOTE 14 at GRANTED, and a
/// witness of each way to GRANTED and of the refusal under the conflict.
pub fn minor_grant_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = GrantState, Action = GrantAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::transition_with("NOTE 14 at GRANTED", granted_only_on_the_vault),
        Property::transition_with("NOTE 9 at DECLINED", declined_only_when_consent_missing),
        Property::always_with("NOTE 9 no dead end", never_stuck),
        Property::reachable(
            "R-ID-04 witness: GRANTED on an attestation recorded in NEGOTIATION, no consent",
            granted_on_attestation_in_negotiation,
        ),
        Property::reachable(
            "NOTE 9 witness: DECLINED for a missing consent after the attestation was lost",
            declined_after_attestation_loss,
        ),
        Property::reachable(
            "R-ID-04 witness: GRANTED on the attestation alone",
            granted_on_attestation,
        ),
        Property::reachable(
            "I-18 witness: GRANTED on a consent after the attestation was withdrawn",
            granted_on_consent_after_loss,
        ),
        Property::reachable(
            "NOTE 14 witness: the conflict refuses the completing fact despite a consent",
            refused_in_conflict,
        ),
        Property::reachable(
            "G9 witness: GRANTED without a consent after a check found LC adult",
            granted_after_adult_check,
        ),
        Property::reachable(
            "I-18 witness: GRANTED on a consent after a check found LC a minor",
            granted_after_minor_check,
        ),
    ]
}

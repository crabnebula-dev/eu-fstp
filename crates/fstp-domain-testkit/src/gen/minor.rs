//! Generators for the minor flag stories of state-machine NOTE 14 (R-ID-04, I-18, decided 2026-10-29).
//!
//! Daniel answered three readings of ADR-008 "Minor flag details" on
//! 2026-10-29. The guard into GRANTED derives the flag again. The deadline
//! is that of the call in which the proposal passes IRC review, which for
//! a re-entered proposal is the later call (NOTE 8). A conflict between an
//! adult attestation and an under-18 verification waits for a manual
//! identity check, and the vault gives no answer until then.
//!
//! - [`money_setup`] is the money setup of PC alone, with the actor's
//!   `CreateDraft` field chosen by the test.
//! - [`reentered_money_world`] takes PC of lead LC from genesis through a
//!   concern in IRC_REVIEW of call 1, a deferral and a re-entry into call
//!   2, whose deadline is [`LATER_DEADLINE`]. IRC and IRC2 then validate
//!   PC in call 2.
//! - [`ask_production`] gives the production questions of a step with the
//!   answers the vault gives. A query the vault does not answer stays out
//!   of the answers, so the command fails closed (overview NOTE 2).
//!
//! Every id and instant is synthetic. No real personal data is used.

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, Ctx, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::id::{CommandId, DecisionId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::Refusal;
use fstp_domain::rules::StateTag;
use fstp_domain::time::{Timestamp, ZoneName};

use crate::r#gen::money::{LC, MoneySetup, MoneyWorld, PC, T_EVAL};
use crate::r#gen::policy::{eur, text};
use crate::r#gen::review::{IRC, R1, R2, R3, plan_of, submit};
use crate::r#gen::roster::{
    Backend, CALL_OPENS, Flags, STAFF_DRAFTER, STAFF_PM, Step, call, publish,
};
use crate::mc::life_model::{
    IRC2, assign_declared, assignment_of, ballots, cut_off, cut_off_decision, decline, irc_review,
    reenter,
};
use crate::vault::GroundTruth;

/// The deadline of call 2 in the re-entry stories. It is later than
/// [`crate::r#gen::roster::CALL_DEADLINE`], the deadline of call 1, and
/// later than [`crate::r#gen::roster::LEAD_ADULT_AFTER_DEADLINE`].
pub const LATER_DEADLINE: Timestamp = Timestamp::from_micros(5_000_000_000_000);

/// The instant from which a lead who turns 18 after [`LATER_DEADLINE`] is
/// shown 18 or older: one microsecond after it (R-ID-04).
pub const LEAD_ADULT_AFTER_LATER_DEADLINE: Timestamp = Timestamp::from_micros(5_000_000_000_001);

/// The command id of every step [`ask_production`] builds a context for.
/// The pure functions never read it.
const STORY_COMMAND: CommandId = CommandId::from_bytes(*b"story:minor:flag");

/// The money setup of PC alone, with the actor's `CreateDraft` field
/// `field` (R-ID-04: no guard may read it).
pub fn money_setup(field: bool) -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    if let Some(d) = s.drafts.first_mut() {
        d.minor = field;
    }
    s
}

/// The world of [`money_setup`] with the actor's field clear, over its
/// vault after `change`, with PC re-entered into call 2 and validated
/// there by IRC and IRC2.
///
/// The steps from genesis: call 2 gets [`LATER_DEADLINE`] and is approved
/// again; PC is submitted, ranked and cut off into IRC_REVIEW of call 1;
/// IRC raises a concern; call 2 is published, so the System defers PC
/// (NOTE 7); PC re-enters IRC_REVIEW in call 2 (NOTE 8); IRC and IRC2 are
/// assigned in call 2 and both validate. Whether the last validation
/// takes PC into NEGOTIATION is the vault's answer at the gate (NOTE 14).
/// Every step is compared with the references in both directions.
pub fn reentered_money_world(
    backend: Backend,
    change: impl FnOnce(&mut GroundTruth),
) -> Result<MoneyWorld, String> {
    let setup = money_setup(false);
    let mut truth = setup.truth();
    change(&mut truth);
    let mut w = MoneyWorld::new(backend, truth);
    for s in setup.draft_steps()? {
        w = w.must(&s)?;
    }
    let zone =
        ZoneName::new("Europe/Brussels").ok_or("zone: Europe/Brussels is not a zone name")?;
    let budget = eur(100_000_000)?;
    w = w.must(&Step::by(
        STAFF_DRAFTER,
        Flags::NONE,
        Command::EditCall {
            call: call(2),
            opens: CALL_OPENS,
            deadline: LATER_DEADLINE,
            deadline_zone: zone,
            budget,
            text: text(10_002),
        },
    ))?;
    w = w.must(&Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::ApproveCallPublication {
            call: call(2),
            decision: DecisionId::from_raw(9_702),
        },
    ))?;
    w = w.must(&submit(LC, PC, plan_of(PC), false))?;
    w.set_now(T_EVAL);
    w = w.ranked(PC, &setup.reviewers)?;
    w = w.must(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PC],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))?;
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PC, call(1), AssignmentKind::Irc) {
            w = w.must(&st)?;
        }
    }
    w = w.must(&irc_review(
        IRC,
        assignment_of(IRC, PC, call(1), AssignmentKind::Irc),
        false,
    ))?;
    w = w.must(&publish(call(2)))?;
    w = w.must(&decline(Actor::System(SystemCause::Timeline), PC))?;
    if w.state(PC) != Some(StateTag::Deferred) {
        return Err(format!("NOTE 7: PC is in {:?}, not DEFERRED", w.state(PC)));
    }
    w = w.must(&reenter(PC, call(2)))?;
    if w.state(PC) != Some(StateTag::IrcReview) {
        return Err(format!(
            "NOTE 8: PC is in {:?} after its re-entry, not IRC_REVIEW",
            w.state(PC)
        ));
    }
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PC, call(2), AssignmentKind::Irc) {
            w = w.must(&st)?;
        }
    }
    for i in [IRC, IRC2] {
        let step = irc_review(i, assignment_of(i, PC, call(2), AssignmentKind::Irc), true);
        w = match w.step(&step)? {
            Some((next, _)) => next,
            None => {
                return Err(format!(
                    "{i:?} validates PC in call 2: refused by production and the references"
                ));
            }
        };
    }
    Ok(w)
}

/// The production questions of `step` in `w` now, with the answers the
/// vault gives. A query the vault does not answer, such as the over-18
/// query during an unresolved age conflict, stays out of the answers
/// (state-machine NOTE 14).
pub fn ask_production(w: &MoneyWorld, step: &Step) -> Result<(Ctx, Answers), Refusal> {
    let state = &w.life.rev.sod.state;
    let ctx = step.ctx(w.now(), STORY_COMMAND);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
        if w.truth().answers(&q) {
            let a = w.life.rev.answer(&q);
            answers.insert(q, a);
        }
    }
    Ok((ctx, answers))
}

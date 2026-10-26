//! The M-LIFECYCLE model for fstp-mc and its conformance properties (design sections 6.3 and 6.4).
//!
//! Owned by lane L-LIFE (docs/handoff/m2-design.md section 10).
//!
//! M-LIFECYCLE is [`LifeModel`] over one proposal from DRAFT, built from
//! genesis, with two calls, a havoc vault that may flip one conflict bit,
//! and coarse scores: every criterion at 0 or every criterion at the scale
//! maximum. It offers one action of each kind the lifecycle has up to
//! NEGOTIATION. Intake: submission, assignment, knock-out and admission.
//! Stage 1: scores and the close. Stage 2: questions, answers, the clock,
//! expiry, publication of the next call and re-entry. Later: the cut-off,
//! IRC assignment and review, the decline and withdrawal.
//!
//! The rows from NEGOTIATION onwards (GRANTED, IN_EXECUTION, COMPLETED,
//! TERMINATED and NEGOTIATION to DECLINED) belong to lane L-MONEY. They
//! join this model with that lane.
//!
//! The properties are conformance checks, not exit criteria (design 6.4).
//! Terminal states have no exits, and every state up to NEGOTIATION is
//! reachable. INELIGIBLE has no successor and no further review (R-EV-01).
//! A stage 2 deferral needs no future call (R-EV-07). An IRC concern goes
//! to the applicant and defers or declines (R-IR-02).

use fstp_domain::rules::StateTag;
use fstp_mc::{Model, Property};

use crate::r#gen::review::{L1, PR1, R1, R2};
use crate::r#gen::roster::call;
use crate::mc::life_model::{
    LifeAction, LifeConfig, LifeSetup, LifeState, Phases, Start, agree, in_state, life_judges,
};

/// The measured state count of M-LIFECYCLE, on the references.
pub const M_LIFECYCLE_STATES: usize = 4_476;

/// The states this model reaches, every state up to NEGOTIATION. GRANTED,
/// IN_EXECUTION, COMPLETED and TERMINATED come with lane L-MONEY.
pub const REACHED_STATES: [StateTag; 12] = [
    StateTag::Draft,
    StateTag::Submitted,
    StateTag::Ineligible,
    StateTag::Stage1,
    StateTag::NotSelected,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Declined,
    StateTag::Negotiation,
    StateTag::Withdrawn,
];

/// The M-LIFECYCLE instance: PR1 in DRAFT, reviewers R1 and R2, P-03 = 2,
/// P-15 = 2, weights (1, 1) on a scale of 0 to 2 at P-02 50.00, and a
/// havoc bit for R1.
pub fn lifecycle_config() -> LifeConfig {
    LifeConfig {
        setup: LifeSetup {
            scale_max: 2,
            weights: vec![1, 1],
            p02_bp: 5_000,
            p03: 2,
            p07_days: 28,
            p15: 2,
            judges: life_judges(),
            proposals: vec![(L1, PR1, false)],
            reviewers: vec![R1, R2],
            start_scores: Vec::new(),
            revision_scores: Vec::new(),
            start: Start::Draft,
        },
        reviewers: vec![R1, R2],
        vectors: vec![vec![0, 0], vec![2, 2]],
        vectors2: Vec::new(),
        corrections: 0,
        conflicts: Vec::new(),
        havoc: vec![R1],
        revisions: 0,
        phases: Phases {
            intake: true,
            stage1: true,
            stage2: true,
            revisions: false,
            deferral: true,
            after: true,
            withdraw: true,
        },
    }
}

/// Whether call 2, the call after PR1's, is published.
pub fn next_call_published(s: &LifeState) -> bool {
    s.world.life.seq_of(call(2)).is_some()
}

/// transition("terminal"): a proposal in a terminal state stays in it
/// (NOTE 10: terminal states have no exits).
pub fn terminal_stays(before: &LifeState, after: &LifeState) -> Result<(), String> {
    match before.state() {
        Some(s) if s.is_terminal() && after.state() != Some(s) => Err(format!(
            "terminal: PR1 left the terminal state {} for {:?}",
            s.spec_name(),
            after.state()
        )),
        _ => Ok(()),
    }
}

/// transition("R-EV-01"): an INELIGIBLE proposal gets no successor state,
/// no assignment, no score and no review record.
pub fn ineligible_has_no_successor(before: &LifeState, after: &LifeState) -> Result<(), String> {
    if before.state() != Some(StateTag::Ineligible) {
        return Ok(());
    }
    let b = &before.world.life;
    let a = &after.world.life;
    if after.state() != Some(StateTag::Ineligible) {
        return Err(format!(
            "R-EV-01: INELIGIBLE PR1 moved to {:?}",
            after.state()
        ));
    }
    let count = |v: &crate::reference::lifecycle::LifeView| {
        v.assignments.values().filter(|x| x.proposal == PR1).count()
    };
    if count(a) != count(b) || a.scores != b.scores {
        return Err("R-EV-01: INELIGIBLE PR1 received a further assignment or score".to_owned());
    }
    Ok(())
}

/// transition("R-EV-07"): STAGE2 to DEFERRED happens only once P-07 has
/// elapsed without answers, whether or not a future call exists.
pub fn deferral_after_window(before: &LifeState, after: &LifeState) -> Result<(), String> {
    if !(before.state() == Some(StateTag::Stage2) && after.state() == Some(StateTag::Deferred)) {
        return Ok(());
    }
    let life = &before.world.life;
    let end = life.window_end(PR1);
    let answered = life
        .proposals
        .get(&PR1)
        .and_then(|p| p.round.as_ref())
        .is_some_and(|r| r.answered);
    if end.is_some_and(|e| before.world.now() >= e) && !answered {
        Ok(())
    } else {
        Err(format!(
            "R-EV-07: STAGE2 to DEFERRED at {:?} with the window closing at {end:?}, answered {answered}",
            before.world.now()
        ))
    }
}

/// Whether PR1 is DEFERRED from STAGE2 while no later call is published (R-EV-07, NOTE 5).
pub fn deferred_without_future_call(s: &LifeState) -> bool {
    in_state(s, StateTag::Deferred)
        && !next_call_published(s)
        && s.world.life.proposals.get(&PR1).is_some_and(|p| {
            p.deferral
                .is_some_and(|(_, left)| left == fstp_domain::proposal::ReentryStage::Stage2)
        })
}

/// transition("R-IR-02"): an IRC concern is enqueued for the applicant,
/// and defers the proposal exactly when a later call is published. A
/// decline from IRC_REVIEW follows a concern with no later call (NOTE 7).
pub fn concern_defers_or_declines(
    before: &LifeState,
    action: &LifeAction,
    after: &LifeState,
) -> Result<(), String> {
    if before.state() != Some(StateTag::IrcReview) {
        return Ok(());
    }
    let b = &before.world.life;
    let a = &after.world.life;
    let current = b.proposals.get(&PR1).map(|p| p.current_call);
    let later = current.is_some_and(|c| b.later_call_published(c));
    if let LifeAction::Irc(_, false) = action {
        let sent = a.concern_outbox.iter().any(|(p, _)| *p == PR1);
        let deferred = after.state() == Some(StateTag::Deferred);
        let stays = after.state() == Some(StateTag::IrcReview);
        if !sent {
            return Err("R-IR-02: the concern was not enqueued for the applicant".to_owned());
        }
        if (later && !deferred) || (!later && !stays) {
            return Err(format!(
                "R-IR-02: a concern with a later call published {later} led to {:?}",
                after.state()
            ));
        }
    }
    if after.state() == Some(StateTag::Declined) {
        let concern = b.proposals.get(&PR1).is_some_and(|p| p.concern.is_some());
        if !concern || later {
            return Err(format!(
                "R-IR-02: IRC_REVIEW to DECLINED with a concern {concern} and a later call {later}"
            ));
        }
    }
    Ok(())
}

/// Whether PR1 was deferred by an IRC concern.
pub fn deferred_by_concern(s: &LifeState) -> bool {
    s.world.life.proposals.get(&PR1).is_some_and(|p| {
        p.state == StateTag::Deferred
            && p.deferral
                .is_some_and(|(_, left)| left == fstp_domain::proposal::ReentryStage::IrcReview)
    })
}

/// Whether PR1 was declined after an IRC concern.
pub fn declined_after_concern(s: &LifeState) -> bool {
    s.world
        .life
        .proposals
        .get(&PR1)
        .is_some_and(|p| p.state == StateTag::Declined && p.concern.is_some())
}

/// The terminal-set properties: two-way, no exit from a terminal state,
/// and a witness of each terminal state up to NEGOTIATION.
pub fn terminal_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    let mut out = vec![
        Property::always_with("two-way", agree),
        Property::transition_with(
            "terminal",
            |b: &LifeState, _: &LifeAction, a: &LifeState| terminal_stays(b, a),
        ),
    ];
    for s in REACHED_STATES.into_iter().filter(|s| s.is_terminal()) {
        out.push(Property::reachable(
            format!("terminal witness: {}", s.spec_name()),
            move |x: &LifeState| in_state(x, s),
        ));
    }
    out
}

/// The reachability properties: two-way, no decision row recorded by the
/// System (R-LA-03, NOTE 13), and a witness of every state up to NEGOTIATION.
pub fn reachability_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    let mut out = vec![
        Property::always_with("two-way", agree),
        Property::always_with("R-LA-03", |s: &LifeState| {
            crate::reference::lifecycle::check_recorded_by_human(&s.world.life)
        }),
    ];
    for s in REACHED_STATES {
        out.push(Property::reachable(
            format!("lifecycle witness: {}", s.spec_name()),
            move |x: &LifeState| in_state(x, s),
        ));
    }
    out
}

/// The R-EV-01 properties: two-way, no successor of INELIGIBLE, and the witness.
pub fn r_ev_01_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::transition_with("R-EV-01", |b: &LifeState, _: &LifeAction, a: &LifeState| {
            ineligible_has_no_successor(b, a)
        }),
        Property::reachable("R-EV-01 witness: INELIGIBLE", |s: &LifeState| {
            in_state(s, StateTag::Ineligible)
        }),
    ]
}

/// The R-EV-07 properties: two-way, the deferral guard, and the witness of
/// a deferral from STAGE2 with no future call.
pub fn r_ev_07_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::transition_with("R-EV-07", |b: &LifeState, _: &LifeAction, a: &LifeState| {
            deferral_after_window(b, a)
        }),
        Property::reachable(
            "R-EV-07 witness: DEFERRED from STAGE2 with no future call",
            deferred_without_future_call,
        ),
        Property::reachable("R-EV-07 witness: re-entry into STAGE2", |s: &LifeState| {
            s.world
                .life
                .proposals
                .get(&PR1)
                .is_some_and(|p| p.state == StateTag::Stage2 && p.current_call != p.created_call)
        }),
    ]
}

/// The R-IR-02 properties: two-way, the concern rule, and the witnesses of
/// a concern that defers and one that leads to DECLINED.
pub fn r_ir_02_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState, Action = LifeAction> + 'a,
{
    vec![
        Property::always_with("two-way", agree),
        Property::transition_with("R-IR-02", concern_defers_or_declines),
        Property::reachable("R-IR-02 witness: a concern defers", deferred_by_concern),
        Property::reachable(
            "R-IR-02 witness: a concern without a future call declines",
            declined_after_concern,
        ),
    ]
}

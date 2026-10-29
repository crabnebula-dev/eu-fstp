//! M-CONFORMANCE: the whole proposal lifecycle in one model, and the deadlock diagnostic (design sections 6.3 and 6.4).
//!
//! Owned by lane W6 twin (docs/handoff/m2-design.md section 10, step W6).
//!
//! M-CONFORMANCE runs one proposal, PC of lead LC, from DRAFT, built from
//! genesis by production commands, through every row of
//! `SPEC/02-domain/state-machine.md`. The lead is a minor with a verified
//! guardian consent, which the vault may withdraw in NEGOTIATION. The
//! plan has two milestones of 2.00 EUR. Two calls exist, call 2 is
//! published by an action, and scores are coarse: every criterion at the
//! scale maximum, or every criterion at 0.
//!
//! Each action is one command, or a short composite of the commands one
//! actor group records together, such as both reviewers' stage 1 scores
//! with the close. Every command runs through
//! [`crate::r#gen::money::MoneyWorld::step`], which compares production with the
//! references in both directions. From NEGOTIATION on, the actions are
//! those of the money models, run by [`crate::mc::money_model::run_action`].
//!
//! The properties are conformance checks, not exit criteria (design 6.4).
//! [`conformance_properties`]: every one of the sixteen states is
//! reachable, a terminal state is never left, and every reachable state
//! has an enabled action. [`r_la_03_properties`]: no decision row is
//! recorded with the System as actor, over every row (R-LA-03, NOTE 13). [`stalls`] is the diagnostic of
//! design 6.4: on the variant without withdrawal it lists the states from
//! which no action ever moves the proposal on.

use std::collections::BTreeMap;

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, CallId};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_mc::{Config, Model, Property, explore};

use crate::clock::ReducedClock;
use crate::r#gen::money::{LC, MoneyDraft, MoneySetup, PC, milestone_n};
use crate::r#gen::review::{COORDINATOR, IRC, R1, R2, R3, declare, plan_of, submit, withdraw};
use crate::r#gen::roster::{Backend, STAFF_PM, Step, call, publish};
use crate::mc::life_model::{
    IRC2, T_EVAL, admit, ask, assign_declared, assignment_of, ballots, close, cut_off,
    cut_off_decision, decline, expire, irc_review, knock_out, no_questions, reenter, score,
};
use crate::mc::money_model::{Fact, McAction, McState, run_action};

/// The measured state count of M-CONFORMANCE with withdrawal, on production.
/// Measured in close-out round 2, up from 19,929. A new amount now clears
/// the contract fact of the old one (Q-W7-4), so the contract fact is given
/// again after a new determination.
pub const M_CONFORMANCE_STATES: usize = 21_711;

/// The measured state count of M-CONFORMANCE without withdrawal, on production.
/// Measured in close-out round 2, up from 14,470, for the reason above.
pub const M_CONFORMANCE_NO_WITHDRAW_STATES: usize = 15_658;

/// One action of M-CONFORMANCE on PC.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConfAction {
    /// The lead submits before the deadline, and the evaluation starts.
    Submit,
    /// The coordinator's declaration and a failed knock-out check.
    Ineligible,
    /// R1 and R2 assigned and declared, the coordinator's declaration, a
    /// passed knock-out check and the admission.
    Admit,
    /// R1 and R2 score every criterion at the maximum or at 0, and the
    /// coordinator records the close.
    Stage1(bool),
    /// R1 and R2 record "no questions".
    NoQuestions,
    /// R1 asks a stage 2 question.
    Ask,
    /// The reduced clock moves to the next instant up to the window end.
    Tick,
    /// The System's `ExpireStage2`.
    Expire,
    /// The programme manager publishes call 2.
    Publish2,
    /// The System's `ReEnter` into call 2.
    ReEnter,
    /// R1 and R2 assigned and declared in the current call after re-entry.
    Assign2,
    /// The cut-off of the current call, nominating PC or not.
    CutOff(bool),
    /// IRC and IRC2 assigned and declared in the current call.
    AssignIrc,
    /// IRC and IRC2 validate.
    Validate,
    /// An IRC member raises a concern.
    Concern(AccountId),
    /// The programme manager records IRC_REVIEW to DECLINED.
    DeclineConcern,
    /// The System records `DeclineAfterConcern` as `due` emits it, which
    /// takes IRC_REVIEW to DEFERRED once a later call is published (NOTE 7).
    DeferConcern,
    /// An action of the money models, from NEGOTIATION on.
    Money(McAction),
    /// The lead withdraws.
    Withdraw,
}

/// One state of M-CONFORMANCE: the money model state, whose world holds
/// production, the vault and every reference view.
pub type ConfState = McState;

/// M-CONFORMANCE.
pub struct ConformanceModel {
    /// Whether the lead may withdraw. The diagnostic variant drops it.
    pub withdraw: bool,
    /// The start state, built from genesis.
    pub start: ConfState,
}

/// The setup: PC of lead LC, a minor with a verified guardian consent,
/// with two milestones of 2.00 EUR, in DRAFT in call 1.
pub fn conformance_setup() -> MoneySetup {
    let mut setup = MoneySetup::sybil([400, 400, 400]);
    setup.drafts = vec![MoneyDraft {
        lead: LC,
        proposal: PC,
        minor: true,
        milestones: vec![
            (milestone_n(PC, 0), 200, crate::r#gen::roster::T0),
            (milestone_n(PC, 1), 200, crate::r#gen::roster::T0),
        ],
        negotiate: false,
    }];
    setup.shared = Vec::new();
    setup.consents = vec![PC];
    setup
}

/// The reference state of PC.
pub fn state_of(s: &ConfState) -> Option<StateTag> {
    s.world.state(PC)
}

fn current_call(s: &ConfState) -> Option<CallId> {
    s.world.life.life.proposals.get(&PC).map(|p| p.current_call)
}

fn created_call(s: &ConfState) -> Option<CallId> {
    s.world.life.life.proposals.get(&PC).map(|p| p.created_call)
}

fn call2_published(s: &ConfState) -> bool {
    s.world.life.life.seq_of(call(2)).is_some()
}

fn diverged(s: &ConfState, why: String) -> ConfState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

impl ConformanceModel {
    /// The model over production, with or without withdrawal, its start
    /// built from genesis.
    pub fn new(withdraw: bool) -> Result<ConformanceModel, String> {
        let setup = conformance_setup();
        let mut world = crate::r#gen::money::MoneyWorld::new(Backend::Production, setup.truth());
        for s in setup.draft_steps()? {
            world = world.must(&s)?;
        }
        Ok(ConformanceModel {
            withdraw,
            start: McState {
                world,
                edited: false,
                cap_blocked: false,
                grant_blocked: false,
                superseded: false,
                contract_cleared: false,
                deliverables: 0,
                divergence: None,
            },
        })
    }

    /// The commands of a lifecycle action in `s`, or `None` where it does not apply.
    fn steps(&self, s: &ConfState, action: &ConfAction) -> Option<Vec<Step>> {
        let current = current_call(s)?;
        let reviewer = |r: AccountId| assignment_of(r, PC, current, AssignmentKind::Reviewer);
        let irc = |i: AccountId| assignment_of(i, PC, current, AssignmentKind::Irc);
        let stage1_key = |r: AccountId| ScoreKey {
            assignment: assignment_of(r, PC, call(1), AssignmentKind::Reviewer),
            stage: Stage::One,
            plan: plan_of(PC),
        };
        Some(match action {
            ConfAction::Submit => vec![submit(LC, PC, plan_of(PC), false)],
            ConfAction::Ineligible => vec![
                declare(
                    COORDINATOR,
                    fstp_domain::command::DeclarationSubject::Proposal(PC),
                    false,
                    false,
                ),
                knock_out(PC, false),
            ],
            ConfAction::Admit => {
                let mut out = assign_declared(R1, PC, current, AssignmentKind::Reviewer);
                out.extend(assign_declared(R2, PC, current, AssignmentKind::Reviewer));
                out.push(declare(
                    COORDINATOR,
                    fstp_domain::command::DeclarationSubject::Proposal(PC),
                    false,
                    false,
                ));
                out.push(knock_out(PC, true));
                out.push(admit(PC));
                out
            }
            ConfAction::Stage1(high) => {
                let v: &[u8] = if *high { &[2, 2] } else { &[0, 0] };
                vec![
                    score(R1, stage1_key(R1), v),
                    score(R2, stage1_key(R2), v),
                    close(Actor::Account(COORDINATOR), PC),
                ]
            }
            ConfAction::NoQuestions => vec![
                no_questions(R1, PC, reviewer(R1)),
                no_questions(R2, PC, reviewer(R2)),
            ],
            ConfAction::Ask => vec![ask(R1, PC, reviewer(R1))],
            ConfAction::Expire => vec![expire(PC)],
            ConfAction::Publish2 => vec![publish(call(2))],
            ConfAction::ReEnter => vec![reenter(PC, call(2))],
            ConfAction::Assign2 => {
                let mut out = assign_declared(R1, PC, current, AssignmentKind::Reviewer);
                out.extend(assign_declared(R2, PC, current, AssignmentKind::Reviewer));
                out
            }
            ConfAction::CutOff(nominate) => vec![cut_off(
                R1,
                cut_off_decision(current.raw()),
                current,
                vec![PC],
                u32::from(*nominate),
                false,
                ballots(&[R1, R2, R3], Vote::For),
            )],
            ConfAction::AssignIrc => {
                let mut out = assign_declared(IRC, PC, current, AssignmentKind::Irc);
                out.extend(assign_declared(IRC2, PC, current, AssignmentKind::Irc));
                out
            }
            ConfAction::Validate => vec![
                irc_review(IRC, irc(IRC), true),
                irc_review(IRC2, irc(IRC2), true),
            ],
            ConfAction::Concern(i) => vec![irc_review(*i, irc(*i), false)],
            ConfAction::DeclineConcern => vec![decline(Actor::Account(STAFF_PM), PC)],
            ConfAction::DeferConcern => vec![decline(Actor::System(SystemCause::Timeline), PC)],
            ConfAction::Withdraw => vec![withdraw(LC, PC)],
            ConfAction::Tick | ConfAction::Money(_) => return None,
        })
    }

    fn tick(&self, s: &ConfState) -> Option<ConfState> {
        let end = s.world.life.life.window_end(PC)?;
        let now = s.world.now();
        let t = ReducedClock::new([end])
            .instants()
            .iter()
            .copied()
            .filter(|t| *t > now && *t <= end)
            .min()?;
        let mut next = s.clone();
        next.world.set_now(t);
        Some(next)
    }
}

impl Model for ConformanceModel {
    type State = ConfState;
    type Action = ConfAction;

    fn init(&self) -> Vec<ConfState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &ConfState, actions: &mut Vec<ConfAction>) {
        if s.divergence.is_some() {
            return;
        }
        let Some(state) = state_of(s) else {
            return;
        };
        let reentered = current_call(s) != created_call(s);
        let publishable = !call2_published(s);
        match state {
            StateTag::Draft => actions.push(ConfAction::Submit),
            StateTag::Submitted => {
                actions.push(ConfAction::Ineligible);
                actions.push(ConfAction::Admit);
            }
            StateTag::Stage1 => {
                actions.push(ConfAction::Stage1(true));
                actions.push(ConfAction::Stage1(false));
            }
            StateTag::Stage2 => {
                if reentered {
                    actions.push(ConfAction::Assign2);
                }
                actions.push(ConfAction::NoQuestions);
                actions.push(ConfAction::Ask);
                actions.push(ConfAction::Tick);
                actions.push(ConfAction::Expire);
            }
            StateTag::Ranked => {
                actions.push(ConfAction::CutOff(true));
                actions.push(ConfAction::CutOff(false));
            }
            StateTag::IrcReview => {
                actions.push(ConfAction::AssignIrc);
                actions.push(ConfAction::Validate);
                actions.push(ConfAction::Concern(IRC));
                actions.push(ConfAction::Concern(IRC2));
                actions.push(ConfAction::DeclineConcern);
                actions.push(ConfAction::DeferConcern);
            }
            StateTag::Deferred => actions.push(ConfAction::ReEnter),
            StateTag::Negotiation => {
                // The amount is never locked (NOTE 9, decided 2026-10-28),
                // so a new determination stays open after acceptance and
                // approval. A new amount clears both, so unbounded it would
                // cycle with fresh decision ids. After acceptance or
                // approval it is drawn while fewer than two exist, as in
                // M-MONEY. Before, it is drawn as it always was.
                let given = s
                    .world
                    .money
                    .proposals
                    .get(&PC)
                    .is_some_and(|q| q.accepted.is_some() || q.approved.is_some());
                if !given || crate::mc::money_model::determinations(&s.world, PC) < 2 {
                    actions.push(ConfAction::Money(McAction::Determine(PC, 0)));
                }
                actions.push(ConfAction::Money(McAction::Grant(PC, Fact::Contract)));
                actions.push(ConfAction::Money(McAction::Grant(PC, Fact::Approve)));
                actions.push(ConfAction::Money(McAction::Decline(PC)));
                if s.world.truth().has_consent(PC) {
                    actions.push(ConfAction::Money(McAction::WithdrawConsent(PC)));
                }
            }
            StateTag::Granted => {
                actions.push(ConfAction::Money(McAction::Start(PC)));
                actions.push(ConfAction::Money(McAction::Terminate(PC)));
            }
            StateTag::InExecution => {
                actions.push(ConfAction::Money(McAction::Terminate(PC)));
                actions.push(ConfAction::Money(McAction::CloseMilestones(PC)));
                actions.push(ConfAction::Money(McAction::Complete(PC)));
            }
            _ => {}
        }
        if publishable
            && matches!(
                state,
                StateTag::Stage2 | StateTag::Ranked | StateTag::IrcReview | StateTag::Deferred
            )
        {
            actions.push(ConfAction::Publish2);
        }
        if self.withdraw && state.is_withdrawable() {
            actions.push(ConfAction::Withdraw);
        }
    }

    fn step(&self, s: &ConfState, action: &ConfAction) -> Option<ConfState> {
        if s.divergence.is_some() {
            return None;
        }
        match action {
            ConfAction::Tick => return self.tick(s),
            ConfAction::Money(a) => return run_action(s, a),
            _ => {}
        }
        let steps = self.steps(s, action)?;
        let mut w = s.world.clone();
        for (i, st) in steps.iter().enumerate() {
            match w.step(st) {
                Ok(Some((nw, _))) => w = nw,
                Ok(None) if i == 0 => return None,
                Ok(None) => break,
                Err(e) => return Some(diverged(s, format!("{action:?}: {e}"))),
            }
        }
        let mut next = s.clone();
        next.world = w;
        if *action == ConfAction::Submit {
            next.world.set_now(T_EVAL);
        }
        Some(next)
    }

    fn is_terminal(&self, s: &ConfState) -> bool {
        s.divergence.is_some() || state_of(s).is_some_and(StateTag::is_terminal)
    }
}

/// Whether `s` holds PC in `state`.
pub fn in_state(s: &ConfState, state: StateTag) -> bool {
    state_of(s) == Some(state)
}

/// transition("terminal"): a proposal in a terminal state stays in it (NOTE 10).
pub fn terminal_stays(before: &ConfState, after: &ConfState) -> Result<(), String> {
    match state_of(before) {
        Some(s) if s.is_terminal() && state_of(after) != Some(s) => Err(format!(
            "terminal: PC left the terminal state {} for {:?}",
            s.spec_name(),
            state_of(after)
        )),
        _ => Ok(()),
    }
}

/// The conformance properties: two-way agreement, terminal states without
/// exits, no deadlock, and a witness of each of the sixteen states of
/// `SPEC/02-domain/state-machine.md`.
pub fn conformance_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ConfState, Action = ConfAction> + 'a,
{
    let mut out = vec![
        Property::always_with("two-way", |s: &ConfState| match &s.divergence {
            Some(why) => Err(why.clone()),
            None => Ok(()),
        }),
        Property::transition_with(
            "terminal",
            |b: &ConfState, _: &ConfAction, a: &ConfState| terminal_stays(b, a),
        ),
        Property::deadlock_free("deadlock"),
    ];
    for s in StateTag::ALL {
        out.push(Property::reachable(
            format!("lifecycle witness: {}", s.spec_name()),
            move |x: &ConfState| in_state(x, s),
        ));
    }
    out
}

/// The R-LA-03 properties over the whole lifecycle: two-way agreement, no
/// decision row recorded with the System as actor (NOTE 13), and the
/// witnesses of GRANTED and COMPLETED, so the rows after NEGOTIATION are
/// covered.
pub fn r_la_03_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ConfState, Action = ConfAction> + 'a,
{
    vec![
        Property::always_with("two-way", |s: &ConfState| match &s.divergence {
            Some(why) => Err(why.clone()),
            None => Ok(()),
        }),
        Property::always_with("R-LA-03", |s: &ConfState| {
            crate::reference::lifecycle::check_recorded_by_human(&s.world.life.life)
        }),
        Property::reachable("R-LA-03 witness: GRANTED", |s: &ConfState| {
            in_state(s, StateTag::Granted)
        }),
        Property::reachable("R-LA-03 witness: COMPLETED", |s: &ConfState| {
            in_state(s, StateTag::Completed)
        }),
    ]
}

/// The stalls the diagnostic finds: per proposal state, the number of
/// stalled states and a shortest action sequence to one of them.
pub type Stalls = BTreeMap<StateTag, (usize, Vec<ConfAction>)>;

/// The diagnostic of design 6.4 on `model`: every reachable state with a
/// non-terminal proposal from which no sequence of actions changes the
/// proposal's state. Each entry counts such states per proposal state,
/// with the shortest action sequence to one of them, beside the number of
/// states explored.
pub fn stalls(model: &ConformanceModel, measured: usize) -> Result<(usize, Stalls), String> {
    let config = Config::default()
        .with_stop_when_decided(false)
        .with_max_depth(usize::MAX)
        .with_max_states(measured.saturating_mul(2));
    let space = explore(model, &config);
    if !space.exhaustive {
        return Err(format!(
            "the diagnostic run is not exhaustive under {} states",
            config.max_states
        ));
    }
    let n = space.len();
    let tags: Vec<Option<StateTag>> = (0..n).map(|i| space.state(i).and_then(state_of)).collect();
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, out) in succ.iter_mut().enumerate() {
        let Some(s) = space.state(i) else { continue };
        let mut acts = Vec::new();
        model.actions(s, &mut acts);
        for a in &acts {
            if let Some(next) = model.step(s, a)
                && let Some(j) = space.find(&model.canonicalize(&next))
            {
                out.push(j);
            }
        }
    }
    // A state moves when a successor has another proposal state, or when a
    // successor with the same proposal state moves. Iterate to the fixpoint.
    let mut moves: Vec<bool> = (0..n)
        .map(|i| {
            succ.get(i)
                .is_some_and(|ss| ss.iter().any(|j| tags.get(*j) != tags.get(i)))
        })
        .collect();
    loop {
        let mut changed = false;
        for i in 0..n {
            if moves.get(i).copied().unwrap_or(true) {
                continue;
            }
            let reach = succ
                .get(i)
                .is_some_and(|ss| ss.iter().any(|j| moves.get(*j).copied().unwrap_or(false)));
            if reach && let Some(m) = moves.get_mut(i) {
                *m = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut out: Stalls = BTreeMap::new();
    for i in 0..n {
        let Some(Some(tag)) = tags.get(i).copied() else {
            continue;
        };
        if tag.is_terminal() || moves.get(i).copied().unwrap_or(true) {
            continue;
        }
        let entry = out.entry(tag).or_insert_with(|| {
            let path = space
                .trace_to(i)
                .map(|t| t.steps.iter().map(|s| s.action.clone()).collect())
                .unwrap_or_default();
            (0, path)
        });
        entry.0 = entry.0.saturating_add(1);
    }
    Ok((n, out))
}

//! Every lane has landed: a walk from genesis reaches every command kind on a state where it is legal, and production accepts each one (step W5 integration, design section 10).
//!
//! The walk runs one money world from genesis by production commands. It
//! drives seven proposals along every row of the state machine, the
//! payment chain, both amendment routes, a negotiated plan with a
//! deduction, policy and call edits, and a vault merge that suspends a
//! binding until it is reinstated. Before each step it asks production for
//! its typed outcome without committing, and fails on any refusal, naming
//! it when it is a not-implemented one. Then the step runs through
//! `MoneyWorld::step`, which compares it with every reference in both
//! directions. At the end every `CommandKind` was accepted at least once.
//!
//! The `_on_the_reference` twin runs the same walk on the references alone,
//! which checks that each step is legal by the spec readings.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, CommandKind, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AmendmentId, BindingId, ContractId, DecisionId, DeliverableId, LineId,
    PlanVersionId, PolicyVersionId, ProposalId, RequestId,
};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, LB, LC, MoneyDraft, MoneySetup, MoneyWorld, PA, PB, PC, REL, accept_grant,
    accept_line, activate_amendment, amendment_assignment, amount_decision, approve_grant,
    approve_payment, assign_amendment_declared, close_milestone, close_request, complete,
    confirm_paid, contract_effective, decline_negotiation, determine, edit_p05, milestone_n,
    money_plan, propose_amendment, record_deliverable, release_payment, request_changes,
    request_payment, route_amendment, start_execution, terminate, withdraw_request,
};
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, R1, R2, R3, declare, plan_of, read, submit, tag, unassign, withdraw,
};
use fstp_domain_testkit::r#gen::roster::{
    Backend, Flags, STAFF_DRAFTER, STAFF_PM, Step, T0, add_member, call, end, publish, reinstate,
};
use fstp_domain_testkit::mc::life_model::{
    IRC2, T_EVAL, admit, answer, ask, assign_declared, assignment_of, ballots, close, correct,
    cut_off, cut_off_decision, decline, expire, irc_review, knock_out, no_questions, rank, reenter,
    revision_milestone, revision_of, revision_plan, score, submit_revision,
};
use fstp_domain_testkit::vault::IdentityTag;

#[path = "i37_support/mod.rs"]
mod i37_support;

/// The lead of the proposal that is declined in NEGOTIATION.
const LD: AccountId = AccountId::from_raw(404);
/// The lead of the proposal with stage 2 questions and a revision.
const LE: AccountId = AccountId::from_raw(405);
/// The lead of the proposal deferred from STAGE2.
const LF: AccountId = AccountId::from_raw(406);
/// The lead of the proposal declined after an IRC concern.
const LG: AccountId = AccountId::from_raw(407);
/// The lead of the minor's proposal, which stays in DRAFT.
const LH: AccountId = AccountId::from_raw(408);
/// The guardian added to the minor's proposal.
const GUARDIAN: AccountId = AccountId::from_raw(409);
/// The team member added to PE.
const MEMBER: AccountId = AccountId::from_raw(410);

const PD: ProposalId = ProposalId::from_raw(14);
const PE: ProposalId = ProposalId::from_raw(15);
const PF: ProposalId = ProposalId::from_raw(16);
const PG: ProposalId = ProposalId::from_raw(17);
const PH: ProposalId = ProposalId::from_raw(18);

/// Call 2's deadline after its edit: after every command of the walk.
const FAR: Timestamp = Timestamp::from_micros(9_000_000_000_000_000);

/// Whether `r` is a not-implemented refusal. It reads the debug names, so
/// it compiles whether or not the `NotImplemented` variants stay.
fn is_not_implemented(r: &Refusal) -> bool {
    format!("{:?}", r.rule) == "NotImplemented" || format!("{:?}", r.reason) == "NotImplemented"
}

struct Walk {
    w: MoneyWorld,
    seen: BTreeSet<CommandKind>,
}

impl Walk {
    /// Runs `step`, which must be legal: production's typed outcome is
    /// checked first, then the two-way step.
    fn go(&mut self, step: &Step) -> Vec<Record> {
        let kind = step.cmd.kind();
        if let Some(Err(r)) = self.w.life.rev.production_outcome(step) {
            if is_not_implemented(&r) {
                panic!("{kind:?} reached a not-implemented refusal: {:?}", step.cmd);
            }
            panic!(
                "production refuses a legal {kind:?} with {r}: {:?}",
                step.cmd
            );
        }
        match self.w.step(step) {
            Ok(Some((w, records))) => {
                self.w = w;
                self.seen.insert(kind);
                // The synthetic checks runner of the money world records
                // `RecordChecks` after each request, through production (I-32).
                if records
                    .iter()
                    .any(|r| matches!(r, Record::ChecksRecorded { .. }))
                {
                    self.seen.insert(CommandKind::RecordChecks);
                }
                records
            }
            Ok(None) => panic!(
                "{kind:?} was refused by production and the references: {:?} by {:?}",
                step.cmd, step.actor
            ),
            Err(e) => panic!("{kind:?}: {e}"),
        }
    }

    fn all(&mut self, steps: Vec<Step>) {
        for s in steps {
            self.go(&s);
        }
    }

    /// Changes the vault, checks production's `VaultChanged` outcome, and
    /// processes the change. Returns the reaction's records.
    fn vault(
        &mut self,
        change: impl FnOnce(&mut fstp_domain_testkit::vault::GroundTruth),
    ) -> Vec<Record> {
        change(&mut self.w.life.rev.sod.truth);
        let step = self.w.life.rev.vault_step();
        if let Some(Err(r)) = self.w.life.rev.production_outcome(&step) {
            panic!("production refuses the vault reaction with {r}");
        }
        let records = self
            .w
            .sync()
            .unwrap_or_else(|e| panic!("vault reaction: {e}"));
        if records
            .iter()
            .any(|r| matches!(r, Record::VaultEpochProcessed { .. }))
        {
            self.seen.insert(CommandKind::VaultChanged);
        }
        records
    }

    fn state(&self, p: ProposalId) -> Option<StateTag> {
        self.w.state(p)
    }
}

fn draft(lead: AccountId, proposal: ProposalId, cents: i64, minor: bool) -> MoneyDraft {
    MoneyDraft {
        lead,
        proposal,
        minor,
        milestones: vec![(milestone_n(proposal, 0), cents, T0)],
        negotiate: false,
    }
}

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([300, 300, 300]);
    s.p05 = 1_000;
    s.drafts = vec![
        draft(LA, PA, 300, false),
        draft(LB, PB, 300, false),
        draft(LC, PC, 300, false),
        draft(LD, PD, 100, false),
        draft(LE, PE, 300, false),
        draft(LF, PF, 300, false),
        draft(LG, PG, 300, false),
        draft(LH, PH, 300, true),
    ];
    s.staff = vec![
        (FINREL, Role::FinanceApprover),
        (REL, Role::PaymentReleaser),
    ];
    s
}

fn key(reviewer: AccountId, proposal: ProposalId, stage: Stage, plan: PlanVersionId) -> ScoreKey {
    ScoreKey {
        assignment: assignment_of(reviewer, proposal, call(1), AssignmentKind::Reviewer),
        stage,
        plan,
    }
}

fn reviewer_of(r: AccountId, p: ProposalId) -> fstp_domain::id::AssignmentId {
    assignment_of(r, p, call(1), AssignmentKind::Reviewer)
}

fn irc_of(m: AccountId, p: ProposalId) -> fstp_domain::id::AssignmentId {
    assignment_of(m, p, call(1), AssignmentKind::Irc)
}

/// Assigns R1 and R2, declares the coordinator clear, passes the
/// knock-out check and admits `p` to STAGE1.
fn to_stage1(walk: &mut Walk, p: ProposalId, extra: &[AccountId]) {
    for r in [R1, R2].iter().chain(extra) {
        walk.all(assign_declared(*r, p, call(1), AssignmentKind::Reviewer));
    }
    walk.go(&declare(
        COORDINATOR,
        DeclarationSubject::Proposal(p),
        false,
        false,
    ));
    walk.go(&knock_out(p, true));
    walk.go(&admit(p));
}

/// Stage 1 scores of R1 and R2 on the submitted plan, then the close.
fn to_stage2(walk: &mut Walk, p: ProposalId) {
    for r in [R1, R2] {
        walk.go(&score(r, key(r, p, Stage::One, plan_of(p)), &[2, 2]));
    }
    walk.go(&close(Actor::Account(COORDINATOR), p));
    assert_eq!(
        walk.state(p),
        Some(StateTag::Stage2),
        "{p:?} passed stage 1"
    );
}

fn to_ranked(walk: &mut Walk, p: ProposalId) {
    to_stage1(walk, p, &[]);
    to_stage2(walk, p);
    for r in [R1, R2] {
        walk.go(&no_questions(r, p, reviewer_of(r, p)));
    }
    assert_eq!(walk.state(p), Some(StateTag::Ranked), "{p:?} ranked");
}

fn irc_assigned(walk: &mut Walk, p: ProposalId) {
    for m in [IRC, IRC2] {
        walk.all(assign_declared(m, p, call(1), AssignmentKind::Irc));
    }
}

fn granted(walk: &mut Walk, lead: AccountId, p: ProposalId) {
    walk.go(&determine(R1, p, amount_decision(p, 1), plan_of(p), &[]).unwrap());
    walk.go(&accept_grant(lead, p));
    walk.go(&approve_grant(STAFF_PM, p));
    walk.go(&contract_effective(p));
    assert_eq!(walk.state(p), Some(StateTag::Granted), "{p:?} granted");
}

fn amendment_plan(
    lead: AccountId,
    p: ProposalId,
    plan: PlanVersionId,
    sup: PlanVersionId,
    n: u128,
    cents: i64,
) -> Step {
    money_plan(
        lead,
        p,
        plan,
        PlanOrigin::Amendment,
        Some(sup),
        &[(milestone_n(p, 40u128.saturating_add(n)), cents, T0)],
    )
    .unwrap()
}

fn edit_call_2() -> Step {
    Step::by(
        STAFF_DRAFTER,
        Flags::NONE,
        Command::EditCall {
            call: call(2),
            opens: Timestamp::from_micros(0),
            deadline: FAR,
            deadline_zone: fstp_domain::time::ZoneName::new("Europe/Brussels").unwrap(),
            budget: fstp_domain_testkit::r#gen::money::nonneg(100_000_000).unwrap(),
            text: text(10_102),
        },
    )
}

fn approve_call_2() -> Step {
    Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::ApproveCallPublication {
            call: call(2),
            decision: DecisionId::from_raw(9_902),
        },
    )
}

fn walk(backend: Backend) {
    let setup = setup();
    let mut truth = setup.truth();
    for a in [GUARDIAN, MEMBER] {
        truth.set_identity(a, tag(a));
        truth.verify(a);
    }
    let mut walk = Walk {
        w: MoneyWorld::new(backend, truth),
        seen: BTreeSet::new(),
    };

    // Genesis to every proposal in DRAFT, then the drafts' teams.
    for s in setup.draft_steps().unwrap() {
        walk.go(&s);
    }
    walk.go(&add_member(
        LE,
        PE,
        MEMBER,
        BindingId::from_raw(9_410),
        false,
    ));
    walk.go(&add_member(
        LH,
        PH,
        GUARDIAN,
        BindingId::from_raw(9_409),
        true,
    ));
    for p in [PA, PB, PC, PD, PE, PF, PG] {
        let lead = walk.w.money.proposals.get(&p).unwrap().lead;
        walk.go(&submit(lead, p, plan_of(p), false));
    }
    // R-SB-04, TH-21: the lead asks for a copy of the submission record.
    // The money references hold no copy model, so the reference twin
    // skips it, as it skips the calibration consent commands.
    // `r_sb_04_th21_copy_request` pins the copy rules themselves.
    if backend == Backend::Production {
        walk.go(&Step::by(
            LA,
            Flags::NONE,
            Command::RequestCopy {
                proposal: PA,
                address: text(10_100),
            },
        ));
    } else {
        walk.seen.insert(CommandKind::RequestCopy);
    }
    let head = walk.w.head.as_deref().unwrap().clone();
    walk.go(&edit_p05(&head, PolicyVersionId::from_raw(9_001), 1_200).unwrap());
    walk.w.set_now(T_EVAL);

    // Stage 1 and stage 2 for every evaluated proposal.
    for p in [PA, PB, PC, PD, PG] {
        to_ranked(&mut walk, p);
    }
    to_stage1(&mut walk, PE, &[R3]);
    walk.go(&unassign(COORDINATOR, reviewer_of(R3, PE)));
    walk.go(&read(R1, PE));
    walk.go(&fstp_domain_testkit::r#gen::roster::Step::by(
        R1,
        Flags::NONE,
        Command::RecordRankingSummary {
            proposal: PE,
            assignment: reviewer_of(R1, PE),
            title: text(10_201),
            neutral_summary: text(10_202),
            rationale: text(10_203),
        },
    ));
    walk.go(&score(R1, key(R1, PE, Stage::One, plan_of(PE)), &[2, 2]));
    walk.go(&correct(R1, key(R1, PE, Stage::One, plan_of(PE)), &[2, 1]));
    walk.go(&score(R2, key(R2, PE, Stage::One, plan_of(PE)), &[2, 2]));
    walk.go(&close(Actor::Account(COORDINATOR), PE));
    walk.go(&ask(R1, PE, reviewer_of(R1, PE)));
    walk.go(&answer(LE, PE));
    let rev = revision_of(PE, 1);
    walk.go(&revision_plan(LE, PE, rev, Some(plan_of(PE)), revision_milestone(PE, 1)).unwrap());
    walk.go(&submit_revision(LE, PE, rev));
    for r in [R1, R2] {
        walk.go(&score(r, key(r, PE, Stage::Two, rev), &[2, 2]));
    }
    walk.go(&rank(R1, PE));
    assert_eq!(walk.state(PE), Some(StateTag::Ranked));
    to_stage1(&mut walk, PF, &[]);
    to_stage2(&mut walk, PF);
    walk.go(&ask(R1, PF, reviewer_of(R1, PF)));

    // The cut-off and the IRC reviews.
    walk.all(cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PA, PB, PC, PD, PE, PG],
        6,
        false,
        // M4 change D5: R3 delegates its vote to R2, so the walk reaches
        // `DelegateVote` too.
        {
            let mut b = ballots(&[R1, R2], Vote::For);
            b.push(fstp_domain::decision::Ballot {
                voter: R2,
                vote: Vote::For,
                delegated_by: Some(R3),
            });
            b
        },
    ));
    for p in [PA, PB, PC, PD, PG] {
        irc_assigned(&mut walk, p);
    }
    for p in [PA, PB, PC, PD] {
        for m in [IRC, IRC2] {
            walk.go(&irc_review(m, irc_of(m, p), true));
        }
        assert_eq!(
            walk.state(p),
            Some(StateTag::Negotiation),
            "{p:?} negotiates"
        );
    }
    walk.go(&irc_review(IRC, irc_of(IRC, PG), false));
    assert_eq!(
        walk.state(PG),
        Some(StateTag::IrcReview),
        "no later call exists"
    );
    walk.go(&decline(Actor::Account(STAFF_PM), PG));
    assert_eq!(walk.state(PG), Some(StateTag::Declined));

    // Negotiation: a decline, and a deduction with its negotiated plan, then a withdrawal.
    walk.go(&decline_negotiation(Actor::Account(STAFF_PM), PD));
    assert_eq!(walk.state(PD), Some(StateTag::Declined));
    let negotiated = PlanVersionId::from_raw(4_913);
    walk.go(&money_plan(
        LC,
        PC,
        negotiated,
        PlanOrigin::Negotiated,
        Some(plan_of(PC)),
        &[(milestone_n(PC, 50), 200, T0)],
    )
    .unwrap());
    walk.go(&determine(R1, PC, amount_decision(PC, 1), negotiated, &[100]).unwrap());
    walk.go(&withdraw(LC, PC));
    assert_eq!(walk.state(PC), Some(StateTag::Withdrawn));

    // PA: grant, execution, the payment chain, a deliverable, closure.
    granted(&mut walk, LA, PA);
    walk.go(&start_execution(PA));
    let m0 = milestone_n(PA, 0);
    let (r1, r2, r3) = (
        RequestId::from_raw(36_001),
        RequestId::from_raw(36_002),
        RequestId::from_raw(36_003),
    );
    walk.go(&request_payment(LA, r1, PA, &[(LineId::from_raw(136_001), m0, 100)]).unwrap());
    walk.go(&request_changes(R1, r1));
    walk.go(&close_request(STAFF_PM, r1).unwrap());
    walk.go(&request_payment(LA, r2, PA, &[(LineId::from_raw(136_002), m0, 100)]).unwrap());
    walk.go(&withdraw_request(LA, r2));
    let l3 = LineId::from_raw(136_003);
    walk.go(&request_payment(LA, r3, PA, &[(l3, m0, 300)]).unwrap());
    walk.go(&accept_line(R1, r3, l3, 300, false).unwrap());
    walk.go(&approve_payment(FINREL, r3));
    walk.go(&release_payment(REL, r3));
    walk.go(&confirm_paid(r3));
    walk.go(&record_deliverable(
        PA,
        DeliverableId::from_raw(46_001),
        m0,
        "MIT",
        true,
    ));
    walk.go(&close_milestone(STAFF_PM, PA, m0).unwrap());
    walk.go(&complete(PA));
    assert_eq!(walk.state(PA), Some(StateTag::Completed));

    // PB: grant, an exempt amendment, an IRC-routed one, termination.
    granted(&mut walk, LB, PB);
    let (p1, p2) = (
        PlanVersionId::from_raw(4_921),
        PlanVersionId::from_raw(4_922),
    );
    let (a1, a2) = (AmendmentId::from_raw(921), AmendmentId::from_raw(922));
    walk.go(&amendment_plan(LB, PB, p1, plan_of(PB), 1, 200));
    walk.go(&propose_amendment(LB, a1, PB, p1));
    walk.go(&route_amendment(STAFF_PM, a1, AmendmentRoute::Exempt));
    walk.go(&activate_amendment(a1, ContractId::from_raw(56_921)));
    walk.go(&amendment_plan(LB, PB, p2, p1, 2, 250));
    walk.go(&propose_amendment(LB, a2, PB, p2));
    walk.go(&route_amendment(STAFF_PM, a2, AmendmentRoute::Irc));
    for m in [IRC, IRC2] {
        walk.all(assign_amendment_declared(m, PB, a2));
    }
    for m in [IRC, IRC2] {
        walk.go(&irc_review(m, amendment_assignment(m, a2), true));
    }
    walk.go(&activate_amendment(a2, ContractId::from_raw(56_922)));
    assert_eq!(walk.state(PB), Some(StateTag::Granted), "Q18");
    walk.go(&terminate(STAFF_PM, PB));
    assert_eq!(walk.state(PB), Some(StateTag::Terminated));

    // PF: call 2 is edited, approved and published, then PF's window
    // elapses and it re-enters call 2.
    walk.go(&edit_call_2());
    walk.go(&approve_call_2());
    walk.go(&publish(call(2)));
    let end_of_window = walk.w.life.life.window_end(PF).unwrap();
    walk.w.set_now(end_of_window);
    walk.go(&expire(PF));
    assert_eq!(walk.state(PF), Some(StateTag::Deferred));
    walk.go(&reenter(PF, call(2)));
    assert_eq!(walk.state(PF), Some(StateTag::Stage2));

    // A vault merge suspends IRC2's Judging binding (I-06). Once the
    // identity splits again, the tenant admin reinstates it. R3's
    // committee binding ends.
    // The references alone synthesize no I-06 suspension in a reaction
    // (`ReviewWorld::reference_reaction`), so the twin skips the
    // reinstatement.
    let merged = walk.vault(|t| t.set_identity(IRC2, IdentityTag::new(904)));
    let suspended = merged.iter().find_map(|r| match r {
        Record::BindingSuspended(b) => Some(b.binding),
        _ => None,
    });
    walk.vault(|t| t.set_identity(IRC2, tag(IRC2)));
    match (backend, suspended) {
        (Backend::Production, Some(b)) => {
            walk.go(&reinstate(b));
        }
        (Backend::Production, None) => {
            panic!("I-06: the merge suspended no binding: {merged:?}")
        }
        (Backend::Reference, _) => {
            walk.seen.insert(CommandKind::ReinstateBinding);
        }
    }
    let now = walk.w.now();
    walk.go(&end(
        fstp_domain_testkit::r#gen::review::judge_binding(3),
        now,
    ));
    scheduled_end(&mut walk, backend);
    calibration_consent(&mut walk, backend);
    public_choice(&mut walk, backend);

    walk.w
        .invariants()
        .unwrap_or_else(|e| panic!("the walk broke an invariant: {e}"));
    let missing: Vec<CommandKind> = CommandKind::ALL
        .iter()
        .copied()
        .filter(|k| !walk.seen.contains(k))
        .collect();
    assert!(
        missing.is_empty(),
        "the walk accepted no command of {missing:?}"
    );
}

/// The calibration consent commands of lane L12-I37 (I-37, R-LA-09,
/// R-LA-10). No production command writes the outcome notice record yet
/// (M6), so they run in the I-37 consent world, which appends the notice
/// itself and runs each command through production `decide`. The money
/// references hold no consent model, so the reference twin skips them.
fn calibration_consent(walk: &mut Walk, backend: Backend) {
    use fstp_domain_testkit::r#gen::review::PR1;
    let kinds = [
        CommandKind::RequestCalibrationConsent,
        CommandKind::GiveCalibrationConsent,
        CommandKind::RevokeCalibrationConsent,
    ];
    if backend == Backend::Reference {
        walk.seen.extend(kinds);
        return;
    }
    let mut w = i37_support::ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    w.notice(PR1).unwrap_or_else(|e| panic!("{e}"));
    let outcomes = [
        w.request(PR1).unwrap_or_else(|e| panic!("{e}")),
        w.give(PR1).unwrap_or_else(|e| panic!("{e}")),
        w.revoke(PR1).unwrap_or_else(|e| panic!("{e}")),
    ];
    for (kind, outcome) in kinds.into_iter().zip(outcomes) {
        match outcome {
            Ok(_) => {
                walk.seen.insert(kind);
            }
            Err(r) if is_not_implemented(&r) => {
                panic!("{kind:?} reached a not-implemented refusal")
            }
            Err(r) => panic!("production refuses a legal {kind:?} with {r}"),
        }
    }
}

/// The public choice commands of M9 lane P1 (R-PB-02, I-43). The money
/// references model no choice, so they run through production `decide`
/// on a copy of the walk's core state, where PA is COMPLETED. The
/// reference twin skips them.
fn public_choice(walk: &mut Walk, backend: Backend) {
    use fstp_domain::publicity::{PublicLevel, PublicPhase};
    use fstp_domain_testkit::publicity::{ChoiceDriver, set_choice};
    let kinds = [
        CommandKind::SetPublicChoice,
        CommandKind::WithdrawPublicChoice,
    ];
    if backend == Backend::Reference {
        walk.seen.extend(kinds);
        return;
    }
    assert_eq!(walk.state(PA), Some(StateTag::Completed), "PA completed");
    let mut d = ChoiceDriver::new(&walk.w.life.rev.sod.state, walk.w.now());
    let cmds = [
        set_choice(
            PA,
            PublicPhase::Finished,
            PublicLevel::Full,
            BTreeSet::new(),
        ),
        Command::WithdrawPublicChoice {
            proposal: PA,
            phase: PublicPhase::Finished,
        },
    ];
    for (kind, cmd) in kinds.into_iter().zip(cmds) {
        match d.exec(LA, &cmd).unwrap_or_else(|e| panic!("{e}")) {
            Ok(_) => {
                walk.seen.insert(kind);
            }
            Err(r) if is_not_implemented(&r) => {
                panic!("{kind:?} reached a not-implemented refusal")
            }
            Err(r) => panic!("production refuses a legal {kind:?} with {r}"),
        }
    }
}

/// `EndScheduledRole` (Cooling-off NOTE, decided 2026-10-25). The money
/// world's review references treat every `EndRole` as an end at once, so
/// the scheduled end runs in a roles world, which compares each step with
/// the roles reference. c is granted programme manager, its end is
/// scheduled one second later, and at that instant the System records the
/// end that `due` lists. On the references alone, the roles reference
/// records that end.
fn scheduled_end(walk: &mut Walk, backend: Backend) {
    use fstp_domain_testkit::r#gen::roster::{C, P1, SodSetup, SodWorld, grant, sod_truth};
    use fstp_domain_testkit::reference::sod::check_due_ends;
    let pm = BindingId::from_raw(301);
    let mut setup = SodSetup::one(1, &[1]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(backend, sod_truth(), &setup)
        .unwrap_or_else(|e| panic!("roles world: {e}"));
    w.now = T0;
    let later = Timestamp::from_micros(T0.micros().saturating_add(1_000_000));
    for step in [grant(pm, C, P1, Role::ProgrammeManager, T0), end(pm, later)] {
        w.exec(&step, fstp_domain_testkit::r#gen::roster::Facts::Effective)
            .unwrap_or_else(|e| panic!("roles world: {e}"))
            .unwrap_or_else(|r| panic!("{:?} refused: {r}", step.cmd));
    }
    let before = w.view.clone();
    let records = w
        .arrive(later)
        .unwrap_or_else(|e| panic!("roles world: {e}"))
        .unwrap_or_else(|r| panic!("the scheduled end due at {later:?} was refused: {r}"));
    check_due_ends(&before, later, &records).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::BindingEnded(e) if e.binding == pm)),
        "the System ends c's binding at the instant: {records:?}"
    );
    if backend == Backend::Production {
        assert_eq!(
            fstp_domain::due(&w.state, later),
            Vec::<Command>::new(),
            "nothing is due once the end is recorded"
        );
    }
    walk.seen.insert(CommandKind::EndScheduledRole);
}

/// Every lane has landed: every command kind is accepted on a legal state
/// reached from genesis, and none reaches a not-implemented refusal.
#[test]
fn interface_no_command_kind_reaches_not_implemented() {
    walk(Backend::Production);
}

/// The walk is legal by the references alone.
#[test]
fn interface_no_command_kind_reaches_not_implemented_on_the_reference() {
    walk(Backend::Reference);
}

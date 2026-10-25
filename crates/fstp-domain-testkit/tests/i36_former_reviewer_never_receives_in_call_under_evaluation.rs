//! I-36: a former reviewer never takes a Receiving role in a call where the reviewed proposal is under evaluation (design 2.7 and 6.2).
//!
//! The test plan row: generated deferral chains never allow a former
//! reviewer to apply to a call holding a proposal they reviewed. A
//! DEFERRED proposal is under evaluation in the next call (Q12), and the
//! bar holds whatever P-12 says. This scenario runs production commands
//! from genesis with P-12 = 0, so SoD-05 alone would let the former
//! reviewer apply to the next call. Reaching DEFERRED needs the stage 1
//! and stage 2 commands of lane L-LIFE, so this test stays red until that
//! lane lands, even once lane L-REV contributes the I-36 refusal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject, KnockOutResult, SystemCause};
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, DecisionId, KnockOutCriterionId, ProposalId,
};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, ScoreVector, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L1, PR1, R1, R2, R3, ReviewSetup, after, assign, declare, handle,
    judge_binding, machine_judges, plan_of, read, review_truth, run_records, scenario_from,
    withdraw,
};
use fstp_domain_testkit::r#gen::roster::{
    CALL_DEADLINE, Flags, SodSetup, Step, add_member, call, draft, end, publish,
};
use fstp_domain_testkit::scenario::Scenario;

/// The deadline of the second call, after the first call's evaluation.
const SECOND_DEADLINE: Timestamp = Timestamp::from_micros(40_000_000_000_000);
/// Sixty days in microseconds, beyond the 28 days of P-07.
const SIXTY_DAYS: i64 = 5_184_000_000_000;

fn setup() -> ReviewSetup {
    let mut base = SodSetup::one(0, &[1, 2]);
    base.published = vec![call(1)];
    ReviewSetup {
        base,
        p38: std::collections::BTreeMap::new(),
        p10: fstp_domain::policy::ReadAccess::AssignedReviewersOnly,
        judges: machine_judges(),
        drafts: vec![DraftSpec {
            lead: L1,
            proposal: PR1,
            call: call(1),
            team: Vec::new(),
            minor: false,
            submit: true,
        }],
    }
}

fn ok(s: &mut Scenario, step: &Step, now: Timestamp) -> Vec<Record> {
    run_records(s, step, now)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|r| panic!("{:?} refused: {r}", step.cmd.kind()))
}

fn by(actor: AccountId, cmd: Command) -> Step {
    Step::by(actor, Flags::NONE, cmd)
}

/// Runs the first call's evaluation of PR1 by R1 and R3 until PR1 is
/// DEFERRED, and returns the instant after it.
fn defer_pr1(s: &mut Scenario) -> Timestamp {
    let t = after(CALL_DEADLINE, 1_000_000);
    let reviewers = [(R1, 9_001u128), (R3, 9_002u128)];
    for (who, n) in reviewers {
        let id = AssignmentId::from_raw(n);
        ok(
            s,
            &assign(
                COORDINATOR,
                id,
                PR1,
                who,
                AssignmentKind::Reviewer,
                Some(handle(n)),
            ),
            t,
        );
        ok(
            s,
            &declare(who, DeclarationSubject::Assignment(id), false, false),
            t,
        );
    }
    ok(
        s,
        &declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false),
        t,
    );
    ok(s, &read(COORDINATOR, PR1), t);
    let outcomes = (1u128..=3)
        .map(|c| KnockOutResult {
            criterion: KnockOutCriterionId::from_raw(c),
            passed: true,
        })
        .collect();
    ok(
        s,
        &by(
            COORDINATOR,
            Command::RecordKnockOut {
                decision: DecisionId::from_raw(9_100),
                proposal: PR1,
                outcomes,
                reason: None,
            },
        ),
        t,
    );
    ok(
        s,
        &by(
            COORDINATOR,
            Command::AdmitToStage1 {
                decision: DecisionId::from_raw(9_101),
                proposal: PR1,
            },
        ),
        t,
    );
    for (who, n) in reviewers {
        ok(s, &read(who, PR1), t);
        ok(
            s,
            &by(
                who,
                Command::RecordScore {
                    key: ScoreKey {
                        assignment: AssignmentId::from_raw(n),
                        stage: Stage::One,
                        plan: plan_of(PR1),
                    },
                    values: ScoreVector(vec![4, 4, 4]),
                },
            ),
            t,
        );
    }
    ok(
        s,
        &by(COORDINATOR, Command::CloseStage1 { proposal: PR1 }),
        t,
    );
    let expire = after(t, SIXTY_DAYS);
    let deferred = ok(
        s,
        &Step {
            actor: Actor::System(SystemCause::Timeline),
            flags: Flags::NONE,
            cmd: Command::ExpireStage2 { proposal: PR1 },
        },
        expire,
    );
    assert!(
        deferred.iter().any(|r| matches!(
            r,
            Record::Transitioned(x) if x.proposal == PR1 && x.to == StateTag::Deferred
        )),
        "PR1 is DEFERRED after P-07: {deferred:?}"
    );
    expire
}

/// I-36, Q12: once PR1 is DEFERRED and the next call is published, R1,
/// who reviewed PR1, is refused a draft and a team role in that call under
/// I-36, with P-12 = 0. R2, a committee member who never reviewed PR1, is
/// not. After PR1 is withdrawn it is terminal. It is the only proposal R1
/// reviewed, so every proposal R1 reviewed is decided, and R1 may apply
/// (decided 2026-10-25).
#[test]
fn i36_former_reviewer_never_receives_in_call_under_evaluation() {
    let mut s = scenario_with_second_deadline(&setup());
    let t = defer_pr1(&mut s);
    ok(&mut s, &end(judge_binding(1), t), t);
    ok(&mut s, &end(judge_binding(2), t), t);
    ok(&mut s, &publish(call(2)), t);
    let barred = run_records(
        &mut s,
        &draft(
            R1,
            ProposalId::from_raw(9_201),
            call(2),
            BindingId::from_raw(9_201),
            false,
        ),
        t,
    )
    .unwrap();
    match barred {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "R1's draft is refused under I-36"),
        Ok(records) => panic!("I-36: the former reviewer drafted in the next call: {records:?}"),
    }
    ok(
        &mut s,
        &draft(
            R2,
            ProposalId::from_raw(9_202),
            call(2),
            BindingId::from_raw(9_202),
            false,
        ),
        t,
    );
    let team = run_records(
        &mut s,
        &add_member(
            R2,
            ProposalId::from_raw(9_202),
            R1,
            BindingId::from_raw(9_203),
            false,
        ),
        t,
    )
    .unwrap();
    match team {
        Err(r) => assert_eq!(r.rule, RuleRef::I36, "R1's team role is refused under I-36"),
        Ok(records) => {
            panic!("I-36: the former reviewer joined a team in the next call: {records:?}")
        }
    }
    ok(&mut s, &withdraw(L1, PR1), t);
    ok(
        &mut s,
        &draft(
            R1,
            ProposalId::from_raw(9_204),
            call(2),
            BindingId::from_raw(9_204),
            false,
        ),
        t,
    );
}

/// The scenario of `setup`, with the second call's deadline moved to
/// [`SECOND_DEADLINE`] before it is drafted.
fn scenario_with_second_deadline(setup: &ReviewSetup) -> Scenario {
    let mut s = Scenario::new(review_truth(setup.accounts())).unwrap();
    for mut step in setup.steps().unwrap() {
        if let Command::DraftCall {
            call: c, deadline, ..
        } = &mut step.cmd
            && *c == call(2)
        {
            *deadline = SECOND_DEADLINE;
        }
        ok(&mut s, &step, fstp_domain_testkit::r#gen::roster::T0);
    }
    s
}

/// Keeps the setup helper honest: the default setup runs from genesis.
#[test]
fn i36_setup_reaches_a_submitted_proposal() {
    let s = scenario_from(&setup(), review_truth(setup().accounts()));
    if let Err(e) = s {
        panic!("I-36 setup from genesis: {e}");
    }
}

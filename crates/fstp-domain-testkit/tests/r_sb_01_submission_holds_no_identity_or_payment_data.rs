//! R-SB-01 by type, and the intake guards of the DRAFT to SUBMITTED row (design 2.8 and 3.2).
//!
//! R-SB-01 AC: no submission form contains identity document, date of
//! birth or payment fields. The domain holds amounts, structure and a
//! digest of the plan text, which lives outside. The type tests destructure
//! every submission command, plan type and record without `..`, so a new
//! field breaks them until it is reviewed here. The scenario tests run
//! production commands from genesis through the reference driver.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{ContentDigest, MilestoneId, PlanVersionId};
use fstp_domain::proposal::{EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, Task};
use fstp_domain::record::{PlanVersionRecorded, Record};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    L1, L4, MEMBER, PR1, PR4, after, machine_accounts, machine_setup, plan_of, record_plan,
    review_truth, run_records, scenario_from, submit, tasks,
};
use fstp_domain_testkit::r#gen::roster::{CALL_DEADLINE, Flags, Step, T0};
use fstp_domain_testkit::scenario::Scenario;

const FORBIDDEN: [&str; 12] = [
    "birth",
    "dob",
    "passport",
    "identity_document",
    "id_document",
    "national",
    "iban",
    "bic",
    "bank",
    "payment",
    "card",
    "account_number",
];

fn assert_clean(what: &str, debug: &str) {
    let lower = debug.to_lowercase();
    for word in FORBIDDEN {
        assert!(
            !lower.contains(word),
            "R-SB-01: {what} names `{word}`: {debug}"
        );
    }
}

/// R-SB-01: `Submit`, `RecordPlanVersion`, `CreateDraft` and their plan
/// types and records hold only the fields listed here, and none of them is
/// an identity document, a date of birth or a payment field.
#[test]
fn r_sb_01_submission_types_hold_no_identity_or_payment_fields() {
    let step = submit(L4, PR4, plan_of(PR4), true);
    let Command::Submit {
        proposal: _,
        plan: _,
        ethics: EthicsDeclaration {
            issues_declared: _,
            text: _,
        },
        notice: NoticeVersion(_),
    } = &step.cmd
    else {
        panic!("not a Submit");
    };
    assert_clean("Submit", &format!("{:?}", step.cmd));
    let plan = record_plan(L4, plan_of(PR4), PR4, &[MilestoneId::from_raw(1)]).unwrap();
    let Command::RecordPlanVersion {
        plan: _,
        proposal: _,
        origin: _,
        supersedes: _,
        tasks: plan_tasks,
        content: _,
    } = &plan.cmd
    else {
        panic!("not a RecordPlanVersion");
    };
    for Task { milestones } in plan_tasks {
        for Milestone {
            id: _,
            amount: _,
            start: _,
            due: _,
            activity: _,
            deliverables: _,
        } in milestones
        {}
    }
    assert_clean("RecordPlanVersion", &format!("{:?}", plan.cmd));
    let draft = Command::CreateDraft {
        proposal: PR4,
        call: fstp_domain::id::CallId::from_raw(1),
        binding: fstp_domain::id::BindingId::from_raw(1),
        minor: false,
    };
    let Command::CreateDraft {
        proposal: _,
        call: _,
        binding: _,
        minor: _,
    } = &draft
    else {
        panic!("not a CreateDraft");
    };
    assert_clean("CreateDraft", &format!("{draft:?}"));
    let records = [
        Record::Submitted {
            proposal: PR4,
            plan: plan_of(PR4),
            ethics: EthicsDeclaration {
                issues_declared: false,
                text: fstp_domain_testkit::r#gen::policy::text(1),
            },
            notice: NoticeVersion(1),
        },
        Record::PlanVersionRecorded(PlanVersionRecorded {
            plan: plan_of(PR4),
            proposal: PR4,
            origin: PlanOrigin::Submitted,
            supersedes: None,
            tasks: tasks(&[MilestoneId::from_raw(1)]).unwrap(),
            content: ContentDigest::from_bytes([0; 32]),
        }),
        Record::ProposalCreated {
            proposal: PR4,
            call: fstp_domain::id::CallId::from_raw(1),
            lead: L4,
            minor: false,
        },
    ];
    for r in &records {
        match r {
            Record::Submitted {
                proposal: _,
                plan: _,
                ethics: _,
                notice: _,
            }
            | Record::PlanVersionRecorded(PlanVersionRecorded {
                plan: _,
                proposal: _,
                origin: _,
                supersedes: _,
                tasks: _,
                content: _,
            })
            | Record::ProposalCreated {
                proposal: _,
                call: _,
                lead: _,
                minor: _,
            } => assert_clean("intake record", &format!("{r:?}")),
            _ => panic!("unexpected record"),
        }
    }
}

fn start() -> Scenario {
    scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"))
}

/// R-SB-01: submitting asks the identity vault nothing, so no identity
/// data is needed before negotiation.
#[test]
fn r_sb_01_submit_asks_the_vault_nothing() {
    let s = start();
    let step = submit(L4, PR4, plan_of(PR4), false);
    let ctx = step.ctx(T0, fstp_domain::id::CommandId::from_bytes([7; 16]));
    let queries = fstp_domain::queries(&s.state().core, &step.cmd, &ctx)
        .unwrap_or_else(|r| panic!("Submit queries refused: {r}"));
    assert!(queries.is_empty(), "Submit asks the vault {queries:?}");
}

/// DRAFT to SUBMITTED: the lead submits a complete plan of the proposal
/// while the call is open. The batch records the submission and the
/// transition (R-SB-05, R-NG-06).
#[test]
fn r_sb_01_lead_submits_a_complete_plan() {
    let mut s = start();
    let records = run_records(&mut s, &submit(L4, PR4, plan_of(PR4), false), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("Submit refused: {r}"));
    assert!(records.iter().any(|r| matches!(
        r,
        Record::Transitioned(t)
            if t.proposal == PR4
                && t.from == StateTag::Draft
                && t.to == StateTag::Submitted
                && t.row == Row::DraftToSubmitted
                && t.actor == Actor::Account(L4)
    )));
    assert!(records.iter().any(|r| matches!(
        r,
        Record::Submitted { proposal, plan, .. } if *proposal == PR4 && *plan == plan_of(PR4)
    )));
    assert!(
        run_records(&mut s, &submit(L4, PR4, plan_of(PR4), false), T0)
            .unwrap()
            .is_err(),
        "a second Submit is refused: the proposal is no longer in DRAFT"
    );
}

/// R-SB-01, DRAFT to SUBMITTED row, actor: only the lead submits. A team member, the
/// lead of another proposal and an unbound account are refused.
#[test]
fn r_sb_01_submit_is_the_leads_only() {
    let mut s = start();
    for actor in [MEMBER, L1, fstp_domain_testkit::r#gen::review::STRANGER] {
        let mut step = submit(L4, PR4, plan_of(PR4), false);
        step.actor = Actor::Account(actor);
        assert!(
            run_records(&mut s, &step, T0).unwrap().is_err(),
            "{actor:?} submitted the proposal of L4"
        );
    }
}

/// R-SB-01, DRAFT to SUBMITTED row, call open: a submission at or after the
/// deadline is refused.
#[test]
fn r_sb_01_submit_needs_the_call_open() {
    let mut s = start();
    let late = run_records(&mut s, &submit(L4, PR4, plan_of(PR4), false), CALL_DEADLINE).unwrap();
    assert!(
        late.is_err(),
        "a submission at the deadline was accepted: {late:?}"
    );
    let later = run_records(
        &mut s,
        &submit(L4, PR4, plan_of(PR4), false),
        after(CALL_DEADLINE, 1),
    )
    .unwrap();
    assert!(
        later.is_err(),
        "a submission after the deadline was accepted: {later:?}"
    );
}

/// R-SB-01, DRAFT to SUBMITTED row, required fields: the plan must exist, belong to the
/// proposal, have origin "submitted" and hold at least one task with a
/// milestone. A plan without tasks is refused at recording or at `Submit`.
#[test]
fn r_sb_01_submit_needs_a_complete_plan_of_the_proposal() {
    let mut s = start();
    let unknown = submit(L4, PR4, PlanVersionId::from_raw(77_777), false);
    assert!(
        run_records(&mut s, &unknown, T0).unwrap().is_err(),
        "unknown plan"
    );
    let foreign = submit(L4, PR4, plan_of(PR1), false);
    assert!(
        run_records(&mut s, &foreign, T0).unwrap().is_err(),
        "plan of another proposal"
    );
    let empty = Step::by(
        L4,
        Flags::NONE,
        Command::RecordPlanVersion {
            plan: PlanVersionId::from_raw(77_778),
            proposal: PR4,
            origin: PlanOrigin::Submitted,
            supersedes: None,
            tasks: Vec::new(),
            content: ContentDigest::from_bytes([1; 32]),
        },
    );
    if run_records(&mut s, &empty, T0).unwrap().is_ok() {
        let step = submit(L4, PR4, PlanVersionId::from_raw(77_778), false);
        assert!(
            run_records(&mut s, &step, T0).unwrap().is_err(),
            "a plan without tasks was submitted"
        );
    }
}

/// R-SB-01 plan shape, `RecordPlanVersion`: the lead records a submitted plan in DRAFT with
/// fresh ids. A reused plan id, a reused milestone id, a superseded plan
/// of another proposal and a team member as actor are refused. The plans
/// of a proposal form one chain: a plan that supersedes nothing while a
/// live plan exists is refused, and so is a second successor of one plan.
#[test]
fn r_sb_01_record_plan_version_is_the_leads_in_draft_with_fresh_ids() {
    let mut s = start();
    let mut fork = record_plan(
        L4,
        PlanVersionId::from_raw(80_006),
        PR4,
        &[MilestoneId::from_raw(80_106)],
    )
    .unwrap();
    assert!(
        run_records(&mut s, &fork, T0).unwrap().is_err(),
        "a second live plan beside the setup plan of PR4"
    );
    let fresh = superseding(
        record_plan(
            L4,
            PlanVersionId::from_raw(80_001),
            PR4,
            &[MilestoneId::from_raw(80_101)],
        )
        .unwrap(),
        plan_of(PR4),
    );
    let records = run_records(&mut s, &fresh, T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("RecordPlanVersion refused: {r}"));
    assert!(records.iter().any(|r| matches!(
        r,
        Record::PlanVersionRecorded(p) if p.plan == PlanVersionId::from_raw(80_001) && p.proposal == PR4
    )));
    fork = superseding(fork, plan_of(PR4));
    assert!(
        run_records(&mut s, &fork, T0).unwrap().is_err(),
        "a second successor of the superseded setup plan"
    );
    let reused = record_plan(
        L4,
        PlanVersionId::from_raw(80_001),
        PR4,
        &[MilestoneId::from_raw(80_102)],
    )
    .unwrap();
    assert!(
        run_records(&mut s, &reused, T0).unwrap().is_err(),
        "plan id reused"
    );
    let milestone_reused = record_plan(
        L4,
        PlanVersionId::from_raw(80_002),
        PR4,
        &[MilestoneId::from_raw(80_101)],
    )
    .unwrap();
    assert!(
        run_records(&mut s, &milestone_reused, T0).unwrap().is_err(),
        "milestone id reused"
    );
    let mut foreign = record_plan(
        L4,
        PlanVersionId::from_raw(80_003),
        PR4,
        &[MilestoneId::from_raw(80_103)],
    )
    .unwrap();
    if let Command::RecordPlanVersion { supersedes, .. } = &mut foreign.cmd {
        *supersedes = Some(plan_of(PR1));
    }
    assert!(
        run_records(&mut s, &foreign, T0).unwrap().is_err(),
        "supersedes another proposal's plan"
    );
    let mut by_member = record_plan(
        L4,
        PlanVersionId::from_raw(80_004),
        PR1,
        &[MilestoneId::from_raw(80_104)],
    )
    .unwrap();
    by_member.actor = Actor::Account(MEMBER);
    assert!(
        run_records(&mut s, &by_member, T0).unwrap().is_err(),
        "a team member recorded a plan"
    );
    let submitted = record_plan(
        L1,
        PlanVersionId::from_raw(80_005),
        PR1,
        &[MilestoneId::from_raw(80_105)],
    )
    .unwrap();
    assert!(
        run_records(&mut s, &submitted, T0).unwrap().is_err(),
        "a submitted plan recorded outside DRAFT"
    );
}

/// `step` with `supersedes` set to `plan`.
fn superseding(mut step: Step, plan: PlanVersionId) -> Step {
    if let Command::RecordPlanVersion { supersedes, .. } = &mut step.cmd {
        *supersedes = Some(plan);
    }
    step
}

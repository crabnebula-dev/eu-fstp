//! I-66 and I-67 seams in the core: programmes start as drafts, and nothing but policy edits and programme manager grants runs on a draft (M4 design section 3.4, D1 and D3).
//!
//! Interim readings, pending Daniel (M4 design section 15.0, Q3 A):
//! `CreateProgramme` creates a programme in `Draft` status, and a core
//! `ActivateProgramme` by a second tenant admin makes it `Active` (D1,
//! D2). On a draft, `GrantRole` admits only `ProgrammeManager`, policy
//! edits run, and `DraftCall` is refused (D3). Test-author choice: the
//! draft gate refuses with `RuleRef::I66` and `RefusalReason::WrongState`,
//! because the programme has not passed the activation that I-66 gates.
//!
//! Every story runs production commands from genesis through the
//! reference driver over the synthetic vault.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::Command;
use fstp_domain::id::{BindingId, DecisionId, PolicyVersionId, ProgrammeId};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::ZoneName;
use fstp_domain_testkit::activation::{ADMIN_3, activation_step, activation_truth, draft_scenario};
use fstp_domain_testkit::r#gen::policy::{Edit, apply_edit, eur, next_version, text};
use fstp_domain_testkit::r#gen::review::{R1, R2, R3, run_records};
use fstp_domain_testkit::r#gen::roster::{
    CALL_DEADLINE, CALL_OPENS, Flags, P1, STAFF_DRAFTER, STAFF_PM, Step, T0, call, grant,
};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::IdentityTag;

/// The refusal of the draft gate (D3, test-author choice).
fn draft_gate() -> Refusal {
    Refusal::new(RuleRef::I66, RefusalReason::WrongState)
}

/// The vault of these stories: [`activation_truth`] and R1, R2 and R3,
/// each verified with its own identity.
fn truth() -> fstp_domain_testkit::vault::GroundTruth {
    let mut t = activation_truth();
    for (a, n) in [(R1, 9_211), (R2, 9_212), (R3, 9_213)] {
        t.set_identity(a, IdentityTag::new(n));
        t.verify(a);
    }
    t
}

fn draft() -> Scenario {
    draft_scenario(truth(), P1).unwrap_or_else(|e| panic!("{e}"))
}

fn run(s: &mut Scenario, step: &Step) -> Result<Vec<fstp_domain::record::Record>, Refusal> {
    run_records(s, step, T0).unwrap_or_else(|e| panic!("harness: {e}"))
}

fn status(s: &Scenario, p: ProgrammeId) -> Option<ProgrammeStatus> {
    programme_status(&s.state().core, p)
}

fn draft_call(n: u128) -> Step {
    Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::DraftCall {
            call: call(n),
            programme: P1,
            opens: CALL_OPENS,
            deadline: CALL_DEADLINE,
            deadline_zone: ZoneName::new("Europe/Brussels").unwrap(),
            budget: eur(100_000_000).unwrap(),
            text: text(n.saturating_add(10_000)),
        },
    )
}

/// D1, I-66: `CreateProgramme` creates a programme in `Draft` status, and
/// an unknown programme has no status.
#[test]
fn d1_create_programme_creates_a_draft() {
    let s = draft();
    assert_eq!(status(&s, P1), Some(ProgrammeStatus::Draft));
    assert_eq!(status(&s, ProgrammeId::from_raw(99)), None);
}

/// D3: on a draft, a programme manager grant is accepted, so builders can
/// hold the binding that I-65 names. Every other Drafting, Judging and
/// Operations grant is refused by the draft gate, whatever its role.
#[test]
fn d3_draft_admits_programme_manager_grants_only() {
    let mut s = draft();
    let pm = run(
        &mut s,
        &grant(
            BindingId::from_raw(11),
            STAFF_PM,
            P1,
            Role::ProgrammeManager,
            T0,
        ),
    );
    assert!(
        pm.is_ok(),
        "D3: a programme manager grant on a draft: {pm:?}"
    );
    let others = [
        (STAFF_DRAFTER, Role::CallDrafter),
        (R1, Role::FstpCoordinator),
        (R2, Role::CommitteeMember),
        (R3, Role::CommitteeChair),
        (R1, Role::IrcMember),
        (R2, Role::FinanceApprover),
        (R3, Role::PaymentReleaser),
        (R1, Role::ContractSignatory),
        (R2, Role::Auditor),
    ];
    for (i, (account, role)) in (20u128..).zip(others) {
        let r = run(
            &mut s,
            &grant(BindingId::from_raw(i), account, P1, role, T0),
        );
        assert_eq!(r, Err(draft_gate()), "D3: a {role:?} grant on a draft");
    }
}

/// D3: no call is drafted in a draft programme, even by its programme
/// manager.
#[test]
fn d3_draft_refuses_draft_call() {
    let mut s = draft();
    run(
        &mut s,
        &grant(
            BindingId::from_raw(11),
            STAFF_PM,
            P1,
            Role::ProgrammeManager,
            T0,
        ),
    )
    .unwrap();
    assert_eq!(run(&mut s, &draft_call(1)), Err(draft_gate()));
}

/// D3, R-PC-03: policy edits run on a draft, by its programme manager, so
/// builders set P-01 and P-09 and stay their last authors.
#[test]
fn d3_policy_edits_run_on_a_draft() {
    let mut s = draft();
    run(
        &mut s,
        &grant(
            BindingId::from_raw(11),
            STAFF_PM,
            P1,
            Role::ProgrammeManager,
            T0,
        ),
    )
    .unwrap();
    let head = fstp_domain::policy::head(&s.state().core, P1)
        .unwrap()
        .clone();
    let mut v = next_version(&head, PolicyVersionId::from_raw(2));
    apply_edit(&mut v, Edit::P02(6_000));
    let edit = Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::EditPolicy {
            base: head.id,
            version: Box::new(v),
        },
    );
    let r = run(&mut s, &edit);
    assert!(r.is_ok(), "D3: a policy edit on a draft: {r:?}");
    assert_eq!(
        fstp_domain::policy::head(&s.state().core, P1).map(|h| h.id),
        Some(PolicyVersionId::from_raw(2))
    );
    assert_eq!(
        status(&s, P1),
        Some(ProgrammeStatus::Draft),
        "an edit activates nothing"
    );
}

/// D1, D2: an activation by a second tenant admin makes the programme
/// active once. Then grants of every role and calls run. A second
/// activation, by another admin who built nothing and with a fresh
/// decision id, is refused for the programme's state.
#[test]
fn d1_activation_makes_the_programme_active_once() {
    let mut s = draft();
    let r = run(&mut s, &activation_step(P1));
    assert!(r.is_ok(), "D2: the second tenant admin activates: {r:?}");
    assert_eq!(status(&s, P1), Some(ProgrammeStatus::Active));
    let again = Step::by(
        ADMIN_3,
        Flags::ADMIN,
        Command::ActivateProgramme {
            programme: P1,
            decision: DecisionId::from_raw(77_999),
            report: ReportDigest::from_bytes([1; 32]),
            revision: 2,
            creator_builders: BTreeSet::new(),
        },
    );
    let refused = run(&mut s, &again);
    assert!(
        matches!(refused, Err(r) if r.reason == RefusalReason::WrongState),
        "D1: an active programme is not activated again: {refused:?}"
    );
    run(
        &mut s,
        &grant(
            BindingId::from_raw(11),
            STAFF_PM,
            P1,
            Role::ProgrammeManager,
            T0,
        ),
    )
    .unwrap();
    let drafter = run(
        &mut s,
        &grant(
            BindingId::from_raw(12),
            STAFF_DRAFTER,
            P1,
            Role::CallDrafter,
            T0,
        ),
    );
    assert!(
        drafter.is_ok(),
        "D3: grants of every role run once active: {drafter:?}"
    );
    let call_drafted = run(&mut s, &draft_call(1));
    assert!(
        call_drafted.is_ok(),
        "D3: calls run once active: {call_drafted:?}"
    );
}

//! I-67 in the core: the core `ActivateProgramme` guard refuses every builder and every account that shares a verified identity with one (M4 design section 3.4, D2).
//!
//! I-67: activating a programme needs approval by a second person who did
//! not build it. The creator checks the approver first. The core checks
//! it again as defence in depth, so a broken creator cannot activate
//! through a builder. Interim readings, pending Daniel (M4 design sections
//! 12.3 and 15.0):
//!
//! - Q1 A: the approver is a tenant admin outside the builder set. In the
//!   core the builders are the opener, every policy author while the
//!   programme is a draft, and every grantor of a binding on the draft.
//!   The creator adds its own builders through `creator_builders`.
//! - Q2 B: the guard asks `SameIdentityAsAny(approver, builders)` and
//!   refuses when it holds, so a second account of a builder cannot
//!   approve.
//! - Test-author choice: a builder's approval is refused with
//!   `RuleRef::I67` and `RefusalReason::GuardFailed`, and a shared
//!   identity with `RuleRef::I67` and `RefusalReason::VaultRefused`, as
//!   the SoD-09 grant guard names its refusals.
//!
//! Every story runs production commands from genesis through the
//! reference driver over the synthetic vault. The builder set is computed
//! by `activation::reference_builders` from the raw records, never from a
//! production structure.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Command, Via};
use fstp_domain::id::{AccountId, BindingId, DecisionId, PolicyVersionId, ProgrammeId};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::record::{Record, RulesVersion};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain_testkit::activation::{
    ADMIN_3, APPROVER, SYBIL_OF_ADMIN, activate_with, activation_decision, activation_truth,
    draft_scenario, forge_programme_activated, reference_builders, setup_activation_record,
};
use fstp_domain_testkit::r#gen::policy::{Edit, apply_edit, next_version};
use fstp_domain_testkit::r#gen::review::{records_of, run_records};
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, Flags, P1, STAFF_DRAFTER, STAFF_PM, Step, T0, grant,
};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::ExecError;

/// A builder's approval (test-author choice).
fn builder_refused() -> Refusal {
    Refusal::new(RuleRef::I67, RefusalReason::GuardFailed)
}

/// An approval by an account that shares a verified identity with a builder.
fn identity_refused() -> Refusal {
    Refusal::new(RuleRef::I67, RefusalReason::VaultRefused)
}

/// The draft P1 created by ADMIN, with STAFF_PM bound as programme manager
/// by ADMIN and a policy edit by STAFF_PM. Its core builders are ADMIN
/// and STAFF_PM.
fn built() -> Scenario {
    let mut s = draft_scenario(activation_truth(), P1).unwrap_or_else(|e| panic!("{e}"));
    let pm = grant(
        BindingId::from_raw(11),
        STAFF_PM,
        P1,
        Role::ProgrammeManager,
        T0,
    );
    assert!(run(&mut s, &pm).is_ok());
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
    assert!(run(&mut s, &edit).is_ok());
    s
}

fn run(s: &mut Scenario, step: &Step) -> Result<Vec<Record>, Refusal> {
    run_records(s, step, T0).unwrap_or_else(|e| panic!("harness: {e}"))
}

/// The core activation of P1 by `approver`, attested as a tenant admin,
/// naming `creator_builders`.
fn activation(approver: AccountId, creator_builders: &[AccountId]) -> Step {
    Step::by(
        approver,
        Flags::ADMIN,
        activate_with(P1, creator_builders.iter().copied().collect()),
    )
}

fn builders(s: &Scenario) -> BTreeSet<AccountId> {
    reference_builders(&records_of(s).unwrap(), P1)
}

/// I-67, Q1: the opener, the policy author and the grantor of the draft
/// binding are the builders the reference folds from the raw records.
#[test]
fn i67_reference_builders_of_the_story() {
    assert_eq!(builders(&built()), [ADMIN, STAFF_PM].into_iter().collect());
}

/// I-67, Q1: the opener cannot approve the activation.
#[test]
fn i67_core_guard_refuses_the_opener() {
    let mut s = built();
    assert_eq!(run(&mut s, &activation(ADMIN, &[])), Err(builder_refused()));
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-67, Q1: a policy author on the draft cannot approve, even when the
/// shell attests it as a tenant admin.
#[test]
fn i67_core_guard_refuses_a_policy_author() {
    let mut s = built();
    assert_eq!(
        run(&mut s, &activation(STAFF_PM, &[])),
        Err(builder_refused())
    );
}

/// I-67, Q1: a tenant admin who granted a binding on the draft is a
/// builder and cannot approve. Another tenant admin who built nothing can.
#[test]
fn i67_core_guard_refuses_a_draft_grantor() {
    let mut s = built();
    let mut by_approver = grant(
        BindingId::from_raw(12),
        STAFF_DRAFTER,
        P1,
        Role::ProgrammeManager,
        T0,
    );
    by_approver.actor = Actor::Account(APPROVER);
    assert!(
        run(&mut s, &by_approver).is_ok(),
        "the second admin grants on the draft"
    );
    assert!(builders(&s).contains(&APPROVER));
    assert_eq!(
        run(&mut s, &activation(APPROVER, &[])),
        Err(builder_refused())
    );
    let r = run(&mut s, &activation(ADMIN_3, &[]));
    assert!(
        r.is_ok(),
        "I-67: a tenant admin who built nothing approves: {r:?}"
    );
}

/// I-67, D2: an approver whom the creator names as a builder, for a
/// creator record such as an acknowledged warning, is refused by the core
/// even though no core record makes it one.
#[test]
fn i67_core_guard_refuses_a_creator_builder() {
    let mut s = built();
    assert!(!builders(&s).contains(&APPROVER));
    assert_eq!(
        run(&mut s, &activation(APPROVER, &[APPROVER])),
        Err(builder_refused())
    );
    let r = run(&mut s, &activation(APPROVER, &[STAFF_DRAFTER]));
    assert!(
        r.is_ok(),
        "I-67: creator builders that exclude the approver: {r:?}"
    );
}

/// I-67, Q2 B, TH-03: a verified second account of the opener cannot
/// approve, since it shares a verified identity with a builder.
#[test]
fn i67_core_guard_refuses_a_sybil_of_a_builder() {
    let mut s = built();
    assert!(!builders(&s).contains(&SYBIL_OF_ADMIN));
    assert_eq!(
        run(&mut s, &activation(SYBIL_OF_ADMIN, &[])),
        Err(identity_refused())
    );
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-84, O-47, D2: the activation is a tenant admin's. Without the shell's
/// attestation it is refused as the wrong actor.
#[test]
fn i67_core_activation_needs_a_tenant_admin() {
    let mut s = built();
    let mut step = activation(APPROVER, &[]);
    step.flags = Flags::NONE;
    assert_eq!(
        run(&mut s, &step),
        Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor))
    );
}

/// I-85, D2: the activation is high risk and never completes through MCP.
#[test]
fn i85_core_activation_never_completes_through_mcp() {
    let mut s = built();
    let mut ctx = s.ctx(T0, Actor::Account(APPROVER));
    ctx.tenant_admin = true;
    ctx.via = Via::Mcp;
    let r = s.execute(
        fstp_engine::Command::Core(fstp_domain_testkit::activation::activate_command(P1)),
        ctx,
    );
    assert_eq!(
        r,
        Err(ExecError::Refused(Refusal::new(
            RuleRef::I85,
            RefusalReason::NotThroughMcp
        )))
    );
}

/// I-67, D2, D7, overview NOTE 5: an accepted activation records
/// `ProgrammeActivated` with its approver, its decision, the report and
/// revision it names, the builder set it was checked against, the
/// reference builders plus the creator's, and the M4 rules version. The
/// `SameIdentityAsAny` answer is recorded as a vault outcome.
#[test]
fn i67_core_activation_records_approver_and_builders() {
    let mut s = built();
    let records = run(&mut s, &activation(APPROVER, &[STAFF_DRAFTER])).unwrap();
    let a = records
        .iter()
        .find_map(|r| match r {
            Record::ProgrammeActivated(a) => Some(a),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no ProgrammeActivated in {records:?}"));
    assert_eq!(a.programme(), P1);
    assert_eq!(a.approver(), APPROVER);
    assert_eq!(a.decision(), activation_decision(P1));
    assert_eq!(
        a.report(),
        ReportDigest::from_bytes(fstp_domain_testkit::activation::SETUP_REPORT)
    );
    assert_eq!(
        a.revision(),
        fstp_domain_testkit::activation::SETUP_REVISION
    );
    let mut want = builders(&built());
    want.insert(STAFF_DRAFTER);
    assert_eq!(a.builders(), &want);
    assert_eq!(a.rules(), RulesVersion::M4);
    assert!(
        records.iter().any(|r| matches!(
            r,
            Record::VaultOutcome {
                kind: fstp_domain::oracle::QueryKind::SameIdentityAsAny,
                holds: false,
                ..
            }
        )),
        "overview NOTE 5: the identity answer is recorded: {records:?}"
    );
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Active)
    );
}

/// D2: the codec form that the reference runs forge equals the record
/// production appends, so reference runs and production agree.
#[test]
fn d2_forged_programme_activated_equals_decided() {
    let mut s = draft_scenario(activation_truth(), P1).unwrap();
    let records = run(
        &mut s,
        &fstp_domain_testkit::activation::activation_step(P1),
    )
    .unwrap();
    let decided = records
        .iter()
        .find(|r| matches!(r, Record::ProgrammeActivated(_)))
        .cloned()
        .unwrap_or_else(|| panic!("no ProgrammeActivated in {records:?}"));
    let forged = setup_activation_record(P1, &[ADMIN].into_iter().collect(), RulesVersion::M4.0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(forged, decided);
    let other = forge_programme_activated(
        ProgrammeId::from_raw(9),
        DecisionId::from_raw(1),
        [0; 32],
        0,
        APPROVER,
        &BTreeSet::new(),
        RulesVersion::M4.0,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(other, decided, "the forge reads its fields");
}

/// Ledger, D2: the activation decision id is fresh. A second programme
/// cannot reuse the decision of the first one's activation.
#[test]
fn i67_activation_decision_id_is_fresh() {
    let mut s = draft_scenario(activation_truth(), P1).unwrap();
    assert!(
        run(
            &mut s,
            &fstp_domain_testkit::activation::activation_step(P1)
        )
        .is_ok()
    );
    let p2 = ProgrammeId::from_raw(2);
    let create = Step::by(
        ADMIN,
        Flags::ADMIN,
        Command::CreateProgramme {
            policy: Box::new(fstp_domain_testkit::activation::draft_version(p2).unwrap()),
        },
    );
    assert!(run(&mut s, &create).is_ok());
    let reuse = Step::by(
        APPROVER,
        Flags::ADMIN,
        Command::ActivateProgramme {
            programme: p2,
            decision: activation_decision(P1),
            report: ReportDigest::from_bytes([3; 32]),
            revision: 1,
            creator_builders: BTreeSet::new(),
        },
    );
    assert_eq!(
        run(&mut s, &reuse),
        Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused))
    );
}

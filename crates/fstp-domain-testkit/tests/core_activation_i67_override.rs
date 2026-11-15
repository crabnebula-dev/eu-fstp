//! I-67 as amended by ADR-022 (Daniel, 2026-11-15) in the core: the core
//! `ActivateProgramme` guard admits a builder only for an override with a
//! reason, from a tenant admin of the builder set (M4 design section 3.4,
//! D2).
//!
//! Amended I-67: "Activating a programme needs approval by a second
//! person who did not build it, or an override by a tenant admin who
//! built it. Every override is a separate step with a fresh step-up and a
//! written reason, and it leaves its own ledger record."
//!
//! Interim readings of ADR-022, pending Daniel:
//!
//! - Only a tenant admin of the builder set overrides. A tenant admin
//!   outside it is refused with `RuleRef::I67` and `WrongActor`, since the
//!   normal approval is its path. An account the shell does not attest
//!   as a tenant admin is refused as the wrong actor first.
//! - An override asks no `SameIdentityAsAny` question, and its record
//!   carries the reason.
//! - Without an override reason the guard refuses a builder as before
//!   (`core_activation_i67_core_guard.rs`).
//!
//! Every story runs production commands from genesis through the
//! reference driver over the synthetic vault, as the core guard tests do.
//! The override runs as the entry of a creator `OverrideActivation`
//! (`activation::override_record`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::Command;
use fstp_domain::id::{AccountId, BindingId, ContentDigest, PolicyVersionId, TextId, TextRef};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain_testkit::activation::{
    APPROVER, activation_decision, activation_truth, draft_scenario, reference_builders,
};
use fstp_domain_testkit::r#gen::policy::{Edit, apply_edit, next_version};
use fstp_domain_testkit::r#gen::review::{records_of, run_records};
use fstp_domain_testkit::r#gen::roster::{ADMIN, Flags, P1, STAFF_PM, Step, T0, grant};
use fstp_domain_testkit::scenario::Scenario;

/// A synthetic stored reason.
fn reason() -> TextRef {
    TextRef::new(
        TextId::from_raw(4242),
        ContentDigest::from_bytes([0x52; 32]),
    )
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

/// The core activation of P1 by `by` with `flags`, as an override with
/// [`reason`] when `overridden` holds.
fn activation(by: AccountId, flags: Flags, overridden: bool) -> Step {
    Step::by(
        by,
        flags,
        Command::ActivateProgramme {
            programme: P1,
            decision: activation_decision(P1),
            report: ReportDigest::from_bytes([0xa5; 32]),
            revision: 1,
            creator_builders: BTreeSet::new(),
            override_reason: overridden.then(reason),
        },
    )
}

/// I-67, ADR-022: the opener, a tenant admin of the builder set,
/// activates through the override. The record names the opener as the
/// approver, the builder set holds the opener, and it carries the reason.
/// No identity question is asked, so no `SameIdentityAsAny` outcome is
/// recorded.
#[test]
fn i67_adr022_core_override_admits_the_builder_admin_with_its_reason() {
    let mut s = built();
    let builders = reference_builders(&records_of(&s).unwrap(), P1);
    assert!(builders.contains(&ADMIN));
    let records = run(&mut s, &activation(ADMIN, Flags::ADMIN, true))
        .unwrap_or_else(|r| panic!("ADR-022: the builder admin's override: {r:?}"));
    let a = records
        .iter()
        .find_map(|r| match r {
            Record::ProgrammeActivated(a) => Some(a),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no ProgrammeActivated in {records:?}"));
    assert_eq!(a.approver(), ADMIN);
    assert!(a.builders().contains(&ADMIN));
    assert_eq!(a.override_reason(), Some(reason()));
    assert!(
        !records.iter().any(|r| matches!(
            r,
            Record::VaultOutcome {
                kind: fstp_domain::oracle::QueryKind::SameIdentityAsAny,
                ..
            }
        )),
        "ADR-022: an override asks no identity question: {records:?}"
    );
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Active)
    );
}

/// I-67 still holds without the override: the opener's plain activation
/// is refused as a builder's (ADR-022 changes only the override path).
#[test]
fn i67_adr022_core_without_override_still_refuses_the_builder() {
    let mut s = built();
    assert_eq!(
        run(&mut s, &activation(ADMIN, Flags::ADMIN, false)),
        Err(Refusal::new(RuleRef::I67, RefusalReason::GuardFailed))
    );
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Draft)
    );
}

/// I-67, ADR-022: the programme manager who built the draft is no tenant
/// admin, so its override is refused as the wrong actor, and the draft
/// stays a draft.
#[test]
fn i67_adr022_core_override_by_a_non_admin_builder_is_refused() {
    let mut s = built();
    let r = run(&mut s, &activation(STAFF_PM, Flags::NONE, true));
    assert!(
        matches!(
            r,
            Err(Refusal {
                reason: RefusalReason::WrongActor,
                ..
            })
        ),
        "the manager's override: {r:?}"
    );
    assert_eq!(
        programme_status(&s.state().core, P1),
        Some(ProgrammeStatus::Draft)
    );
}

/// ADR-022, interim reading 1: a tenant admin outside the builder set is
/// refused the override with `RuleRef::I67` and `WrongActor`. Its normal
/// approval is accepted.
#[test]
fn i67_adr022_core_override_by_a_non_builder_admin_is_refused() {
    let mut s = built();
    assert_eq!(
        run(&mut s, &activation(APPROVER, Flags::ADMIN, true)),
        Err(Refusal::new(RuleRef::I67, RefusalReason::WrongActor))
    );
    let r = run(&mut s, &activation(APPROVER, Flags::ADMIN, false));
    assert!(r.is_ok(), "the second person approves: {r:?}");
}

/// The fold of `records` as one entry on the state of `s`, after its
/// head, as the driver folds a batch: every record, then the entry's end.
fn fold(s: &Scenario, records: &[fstp_engine::Record]) -> Result<(), String> {
    let mut st = s.state().clone();
    let mut seq = s.engine().head();
    for r in records {
        seq = fstp_ledger::Seq::from_raw(seq.raw().saturating_add(1));
        fstp_engine::apply_in(&mut st, seq, T0, Some([0x0e; 16]), r)
            .map_err(|e| format!("{e:?}"))?;
    }
    fstp_engine::finish(&mut st).map_err(|e| format!("{e:?}"))
}

/// Teeth for the D2e pairing of ADR-022: the engine fold admits an
/// overriding `ProgrammeActivated` only beside the `ActivationOverridden`
/// that names the same actor and reason, and the reverse. An override
/// activation paired with a normal approval, a plain activation paired
/// with an override, either record alone, or another reason is refused.
#[test]
fn i67_adr022_fold_pairs_an_override_only_with_its_record() {
    use fstp_domain_testkit::activation::{
        approval_record, forge_activation, override_record, setup_report,
    };
    use fstp_engine::Record as E;
    let s = built();
    let head = s.state().creator.head(P1).unwrap();
    let builders = s.state().creator.draft(P1).unwrap().builders().clone();
    let decision = activation_decision(P1);
    let report = setup_report(P1, head).unwrap().bytes();
    let mut all = builders.clone();
    all.extend(reference_builders(&records_of(&s).unwrap(), P1));
    let pa = |reason: Option<TextRef>| {
        forge_activation(P1, decision, report, head.seq(), ADMIN, &all, 3, reason)
            .map(E::Core)
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let over = override_record(P1, head, decision, ADMIN, &builders, reason(), T0)
        .map(E::Creator)
        .unwrap_or_else(|e| panic!("{e}"));
    let approved = approval_record(P1, head, decision, ADMIN, &builders)
        .map(E::Creator)
        .unwrap_or_else(|e| panic!("{e}"));
    let other = TextRef::new(TextId::from_raw(7), ContentDigest::from_bytes([1; 32]));
    assert_eq!(fold(&s, &[over.clone(), pa(Some(reason()))]), Ok(()));
    for (what, entry) in [
        ("an override activation alone", vec![pa(Some(reason()))]),
        ("an override record alone", vec![over.clone()]),
        (
            "an approval with an override activation",
            vec![approved.clone(), pa(Some(reason()))],
        ),
        (
            "an override record with a plain activation",
            vec![over.clone(), pa(None)],
        ),
        (
            "an override record with another reason",
            vec![over.clone(), pa(Some(other))],
        ),
    ] {
        assert!(fold(&s, &entry).is_err(), "the fold admits {what}");
    }
}

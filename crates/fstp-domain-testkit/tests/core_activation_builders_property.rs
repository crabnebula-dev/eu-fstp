//! I-67 in the core, as a property: over generated draft histories, the core activation guard accepts exactly the approvals the reference builder set allows (M4 design section 3.4, D2).
//!
//! Each case starts from genesis: ADMIN creates P1, then up to five draft
//! actions run. A tenant admin grants a programme manager binding on the
//! draft, or a programme manager edits the policy. Then an approver,
//! attested as a tenant admin, activates with generated creator builders.
//!
//! The reference (Q1 A and Q2 B interim readings, pending Daniel): the
//! builders are folded from the raw records by
//! `activation::reference_builders`, plus the creator builders. The
//! activation is accepted exactly when the approver is outside that set
//! and the vault finds no verified identity it shares with any of them.
//! An accepted activation records that builder set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{AccountId, BindingId, PolicyVersionId};
use fstp_domain::oracle::Query;
use fstp_domain::record::Record;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain_testkit::activation::{
    ADMIN_3, APPROVER, SYBIL_OF_ADMIN, activate_with, activation_truth, draft_scenario,
    reference_builders,
};
use fstp_domain_testkit::r#gen::policy::{Edit, apply_edit, next_version};
use fstp_domain_testkit::r#gen::review::{records_of, run_records};
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, Flags, P1, STAFF_DRAFTER, STAFF_PM, Step, T0, grant,
};
use fstp_prop::{Gen, check};

/// The tenant admins who grant on the draft.
const ADMINS: [AccountId; 3] = [ADMIN, APPROVER, ADMIN_3];

/// The programme managers of the draft.
const MANAGERS: [AccountId; 2] = [STAFF_PM, STAFF_DRAFTER];

/// The approvers drawn: the admins, a programme manager and a second
/// account of the opener.
const APPROVERS: [AccountId; 5] = [ADMIN, APPROVER, ADMIN_3, STAFF_PM, SYBIL_OF_ADMIN];

/// One generated case.
fn case(g: &mut Gen) -> Result<(), String> {
    let truth = activation_truth();
    let mut s = draft_scenario(truth.clone(), P1)?;
    let steps = g.usize_in(0..=5);
    let mut next_binding: u128 = 11;
    let mut next_version_id: u128 = 2;
    for _ in 0..steps {
        let step = if g.weighted(&[1, 1]) == 0 {
            let by = *g.pick(&ADMINS);
            let to = *g.pick(&MANAGERS);
            let mut st = grant(
                BindingId::from_raw(next_binding),
                to,
                P1,
                Role::ProgrammeManager,
                T0,
            );
            next_binding = next_binding.saturating_add(1);
            st.actor = Actor::Account(by);
            st
        } else {
            let by = *g.pick(&MANAGERS);
            let head = fstp_domain::policy::head(&s.state().core, P1)
                .ok_or("no head")?
                .clone();
            let mut v = next_version(&head, PolicyVersionId::from_raw(next_version_id));
            next_version_id = next_version_id.saturating_add(1);
            apply_edit(&mut v, Edit::P02(*g.pick(&[5_000, 6_000, 7_000])));
            Step::by(
                by,
                Flags::NONE,
                Command::EditPolicy {
                    base: head.id,
                    version: Box::new(v),
                },
            )
        };
        g.note("draft step", &step);
        // A refused draft step records nothing, which the reference folds too.
        let _ = run_records(&mut s, &step, T0)?;
    }
    let approver = *g.pick(&APPROVERS);
    let creator: BTreeSet<AccountId> = APPROVERS
        .iter()
        .chain(MANAGERS.iter())
        .copied()
        .filter(|_| g.weighted(&[5, 1]) == 1)
        .collect();
    g.note("approver", &approver);
    g.note("creator builders", &creator);
    let mut set = reference_builders(&records_of(&s)?, P1);
    set.extend(creator.iter().copied());
    let shares = truth.holds(&Query::SameIdentityAsAny {
        subject: approver,
        others: set.clone(),
    });
    let step = Step::by(approver, Flags::ADMIN, activate_with(P1, creator));
    let outcome = run_records(&mut s, &step, T0)?;
    let context = format!("activation by {approver:?} with builders {set:?}");
    match (set.contains(&approver), shares, outcome) {
        (false, false, Ok(records)) => {
            let recorded = records.iter().find_map(|r| match r {
                Record::ProgrammeActivated(a) => Some(a.builders().clone()),
                _ => None,
            });
            if recorded != Some(set.clone()) {
                return Err(format!("{context}: the record names {recorded:?}"));
            }
            Ok(())
        }
        (true, _, Err(r)) if r.rule == RuleRef::I67 && r.reason == RefusalReason::GuardFailed => {
            Ok(())
        }
        (false, true, Err(r))
            if r.rule == RuleRef::I67 && r.reason == RefusalReason::VaultRefused =>
        {
            Ok(())
        }
        (b, i, other) => Err(format!(
            "I-67: {context}, builder {b}, shared identity {i}, but production gave {other:?}"
        )),
    }
}

/// I-67, Q1 A, Q2 B, D2: over generated draft histories, the core
/// activation guard accepts an approval exactly when the approver is
/// outside the builder set folded from the raw records plus the creator
/// builders and shares no verified identity with them, and the accepted
/// record names that set.
#[test]
fn i67_core_guard_matches_the_reference_builder_set() {
    check("i67_core_guard_matches_the_reference_builder_set", case);
}

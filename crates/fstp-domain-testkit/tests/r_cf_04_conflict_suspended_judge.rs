//! R-CF-04 and Identity discovery: notifiable conflicts on scores already given, and the release of a conflict-suspended judge's assignments.
//!
//! Each story runs production commands from genesis. R1 and R2 score PR1
//! by L1 in stage 1, and the stage closes. R1 also holds an open
//! assignment on PR2 by L2, which has not been scored.
//!
//! - Suspension: the vault merges R1 into the identity of the staff
//!   programme manager, a Drafting binding. In the same step R1's Judging
//!   binding is suspended as a conflict of interest, and R1's open
//!   assignments are released. The scores R1 already gave get a notifiable
//!   conflict with a notification draft for the coordinator (R-CF-04).
//! - Already voided: the vault first puts L1 in an excluded class, which
//!   voids L1's Receiving binding under I-04. It then finds that L1 and R1
//!   share one identity. The notifiable conflict on R1's scores of PR1 is
//!   recorded all the same (decided 2026-10-25).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{L1, L2, PR1, PR2, R1, R2, judge_binding, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, K1, call};
use fstp_domain_testkit::mc::life_model::{Story, assignment_of, life_judges, story_setup};
use fstp_domain_testkit::vault::IdentityTag;

/// The identity of the staff programme manager in the synthetic vault.
const STAFF_PM_IDENTITY: IdentityTag = IdentityTag::new(903);

fn story(backend: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 through stage 1: {e}"));
    s.to_stage1(L2, PR2, &[R1, R2])
        .unwrap_or_else(|e| panic!("PR2 to STAGE1: {e}"));
    s
}

fn notifiable(records: &[Record], account: AccountId, proposal: ProposalId) -> bool {
    let detected = records.iter().any(|r| {
        matches!(r, Record::ConflictDetected(d)
            if d.account == account && d.proposal == proposal && d.notifiable)
    });
    let drafted = records.iter().any(|r| {
        matches!(r, Record::OutboxEnqueued(OutboxEvent::NotifiableConflict { proposal: p })
            if *p == proposal)
    });
    detected && drafted
}

fn released(records: &[Record], proposal: ProposalId) -> bool {
    let id = assignment_of(R1, proposal, call(1), AssignmentKind::Reviewer);
    records
        .iter()
        .any(|r| matches!(r, Record::AssignmentReleased(a) if a.assignment == id))
}

/// R-CF-04, I-06, Identity discovery: a Judging binding suspended as a
/// conflict of interest loses its open assignments in the same step, and
/// the scores it gave get a notifiable conflict.
#[test]
fn r_cf_04_suspended_judge_is_released_and_its_scores_are_notifiable() {
    let mut s = story(Backend::Production);
    let records = s
        .vault(|t| t.set_identity(R1, STAFF_PM_IDENTITY))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::BindingSuspended(b)
            if b.binding == judge_binding(1) && b.rule == RuleRef::I06)),
        "Identity discovery: R1's committee binding is suspended under I-06: {records:?}"
    );
    for p in [PR1, PR2] {
        assert!(
            released(&records, p),
            "Identity discovery: R1's open assignment on {p:?} is released in the same step: {records:?}"
        );
    }
    assert!(
        notifiable(&records, R1, PR1),
        "R-CF-04: R1's scores on PR1 get a notifiable conflict and a notification draft: {records:?}"
    );
}

/// R-CF-04, I-04, I-06, Identity discovery: the notifiable conflict on the
/// matching judge's scores is recorded even when the discovered Receiving
/// binding was already voided under I-04.
#[test]
fn r_cf_04_notifiable_even_when_the_receiving_binding_was_already_voided() {
    let mut s = story(Backend::Production);
    let first = s
        .vault(|t| t.exclude(tag(L1), K1))
        .unwrap_or_else(|e| panic!("the exclusion reaction: {e}"));
    assert!(
        first
            .iter()
            .any(|r| matches!(r, Record::BindingVoided(v) if v.rule == RuleRef::I04)),
        "I-04: L1's Receiving binding is voided: {first:?}"
    );
    assert!(
        !notifiable(&first, R1, PR1),
        "R-CF-04: no identity is shared yet, so no notifiable conflict: {first:?}"
    );
    let second = s
        .vault(|t| t.set_identity(L1, tag(R1)))
        .unwrap_or_else(|e| panic!("the identity reaction: {e}"));
    assert!(
        notifiable(&second, R1, PR1),
        "R-CF-04: L1 and R1 share an identity, so R1's scores on PR1 are notifiable: {second:?}"
    );
}

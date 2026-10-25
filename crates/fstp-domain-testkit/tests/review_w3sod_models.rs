//! Review reproducers for lane L-SOD, model and test strength lens (step W3b).
//!
//! Each test fails against the lane's current code and passes once the
//! named defect is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, Facts, ID_AB, K1, P1, SodSetup, SodWorld, T0, call, draft, grant, sod_truth,
};
use fstp_domain_testkit::vault::PendingFact;

/// I-06, R-CF-04 (Identity discovery, `roles-and-sod.md`): when the vault
/// verifies b, the Sybil of committee member a, the reaction must keep the
/// identity discovery as a fact, so that lane L-REV can raise the
/// notifiable conflict on scores a already gave.
///
/// Story: b drafts in call 1 while unverified, and b's identity carries a
/// pending exclusion in K1, which is in P-13. The verification reveals both
/// facts at once. `decide_reaction` checks I-04 first and records the void
/// under I-04 only. No `BindingVoided` under I-06 and no `ConflictDetected`
/// is written, so `RosterState::identity_discoveries` never lists b's
/// binding and the R-CF-04 fact is lost.
#[test]
fn review_r_cf_04_identity_discovery_kept_when_exclusion_also_applies() {
    let mut setup = SodSetup::one(1, &[1]);
    setup.published = vec![call(1)];
    let mut truth = sod_truth();
    truth.add_pending(
        B,
        PendingFact::Excluded {
            identity: ID_AB,
            class: K1,
        },
    );
    let mut w = SodWorld::from_setup(Backend::Production, truth, &setup)
        .unwrap_or_else(|e| panic!("setup: {e}"));

    let committee = grant(BindingId::from_raw(301), A, P1, Role::CommitteeMember, T0);
    w.exec(&committee, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("a's committee grant refused: {r}"));

    let applicant = BindingId::from_raw(201);
    let proposal = ProposalId::from_raw(1);
    let step = draft(B, proposal, call(1), applicant, false);
    w.exec(&step, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("b's draft refused: {r}"));

    w.truth.verify(B);
    let records = w
        .sync(Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));

    let voided = records
        .iter()
        .any(|r| matches!(r, Record::BindingVoided(v) if v.binding == applicant));
    assert!(voided, "b's binding must be voided: {records:?}");
    let discovery = records.iter().any(|r| match r {
        Record::BindingVoided(v) => v.binding == applicant && v.rule == RuleRef::I06,
        Record::ConflictDetected(c) => c.proposal == proposal,
        _ => false,
    });
    assert!(
        discovery,
        "R-CF-04: b shares a's verified identity, but the reaction records no \
         identity discovery for b's binding, only an I-04 void: {records:?}"
    );
}

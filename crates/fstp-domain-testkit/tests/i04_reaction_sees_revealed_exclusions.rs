//! I-04 under the verification commit protocol (overview NOTE 4, Identity discovery).
//!
//! A provisional verification of b reveals that b's identity, which a
//! shares, is in an excluded class. The reaction sees that fact, and the
//! change query lists every account of the identity, so a's Receiving
//! binding is voided in the reaction step, before the fact takes effect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, Facts, ID_AB, K1, SodSetup, SodWorld, call, draft, reaction_truth, sod_truth,
};
use fstp_domain_testkit::reference::sod::{check_i04, check_voids, expected_voids};
use fstp_domain_testkit::vault::PendingFact;

/// I-04, SoD-06, NOTE 4: the reaction to b's provisional verification
/// voids the Receiving binding of a, the sibling account the revealed
/// exclusion covers, in the same step.
#[test]
fn i04_provisional_verification_voids_an_excluded_sibling_in_the_reaction() {
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
    let applicant = BindingId::from_raw(201);
    let step = draft(A, ProposalId::from_raw(1), call(1), applicant, false);
    w.exec(&step, Facts::Effective)
        .unwrap()
        .unwrap_or_else(|r| panic!("a's draft refused: {r}"));

    w.truth.verify_provisional(B);
    let seen = reaction_truth(&w.truth);
    let expected = expected_voids(&w.view, &seen);
    let records = w
        .sync(Facts::WithProvisional)
        .unwrap_or_else(|e| panic!("reaction: harness: {e}"))
        .unwrap_or_else(|r| panic!("the reaction was refused: {r}"));
    if let Err(e) = check_voids("reaction", &expected, &records) {
        panic!("{e}");
    }
    assert!(
        records.iter().any(|r| matches!(
            r,
            Record::BindingVoided(v) if v.binding == applicant && v.rule == RuleRef::I04
        )),
        "a's binding must be voided under I-04 in the reaction step: {records:?}"
    );
    if let Err(e) = check_i04(&w.view, &seen) {
        panic!("I-04 broken over the facts about to take effect: {e}");
    }
}

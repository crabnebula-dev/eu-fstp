//! Review reproducers for lane L-MONEY, round 2 (adversarial verifier).
//!
//! Each test drives the two-way money story from genesis and fails
//! against the current code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    MoneySetup, MoneyStory, PA, PB, amount_decision, decline_negotiation, determine,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

/// The decline reason of `recs`, if any.
fn reason(recs: &[Record]) -> Option<NegotiationFailure> {
    recs.iter().find_map(|r| match r {
        Record::NegotiationDeclined { reason, .. } => Some(*reason),
        _ => None,
    })
}

/// NOTE 9, I-14, R-NG-03: a non-zero deduction is refused in M2, so the
/// only amount a determination can reach is the effective plan total.
/// Leads a and b share one identity, P-04 = [2.00, 4.00], P-05 = 6.00.
/// a is granted 4.00. b's plan total is 4.00, and 4.00 + 4.00 > 6.00, so
/// every DetermineAmount of b is refused under I-14. The decline still
/// tests the P-04 minimum 2.00, which fits, so it finds no failure and is
/// refused. b can reach neither GRANTED nor DECLINED.
#[test]
fn review_decline_when_only_the_plan_total_exceeds_the_cap() {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    s.grant(PA)
        .unwrap_or_else(|e| panic!("a granted 4.00: {e}"));
    for (n, ded) in [(1u128, vec![]), (2, vec![200i64]), (3, vec![100])] {
        let d = determine(R1, PB, amount_decision(PB, n), plan_of(PB), &ded).unwrap();
        let got = s.attempt(&d).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "a determination of b with deductions {ded:?} was accepted: {got:?}"
        );
    }
    let recs = s
        .attempt(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| {
            panic!(
                "NOTE 9: no DetermineAmount of b can pass I-13 and I-14, yet the programme \
                 manager's decline is refused, so b is stuck in NEGOTIATION"
            )
        });
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinCap));
    assert_eq!(s.state(PB), Some(StateTag::Declined));
}

/// NOTE 9, I-13, R-NG-03: with deductions refused, a plan total above the
/// P-04 maximum can never be granted. a's plan total is 5.00 under P-04 =
/// [2.00, 4.00]. Every DetermineAmount is refused under I-13, yet the
/// decline reports no range failure, because it only checks the plan
/// total against the P-04 minimum.
#[test]
fn review_decline_when_the_plan_total_is_above_p04() {
    let mut setup = MoneySetup::sybil([500, 100, 100]);
    setup.drafts.truncate(1);
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    for (n, ded) in [(1u128, vec![]), (2, vec![100i64])] {
        let d = determine(R1, PA, amount_decision(PA, n), plan_of(PA), &ded).unwrap();
        let got = s.attempt(&d).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "a determination of a with deductions {ded:?} was accepted: {got:?}"
        );
    }
    let recs = s
        .attempt(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| {
            panic!(
                "NOTE 9: no DetermineAmount of a can pass I-13, yet the programme manager's \
                 decline is refused, so a is stuck in NEGOTIATION"
            )
        });
    assert_eq!(reason(&recs), Some(NegotiationFailure::NoAmountWithinRange));
    assert_eq!(s.state(PA), Some(StateTag::Declined));
}

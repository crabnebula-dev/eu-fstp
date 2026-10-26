//! Review reproducers for lane L-MONEY, round 2 (adversarial verifier).
//!
//! Each test drives the two-way money story from genesis. Both tests
//! first expected a decline that NOTE 9 now forbids. Lane w6-decline
//! inverted them after the decision of 2026-10-26 (state-machine.md
//! NOTE 9). A plan total above the cap or above P-04 is no ground for
//! declining while the P-04 minimum fits, since the lead may propose a
//! smaller negotiated plan. The full stories that reach GRANTED on such a
//! plan live in `r_ng_decline_only_when_no_p04_amount_fits.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    MoneySetup, MoneyStory, PA, PB, amount_decision, decline_negotiation, determine,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

/// NOTE 9, I-14, R-NG-03: leads a and b share one identity, P-04 =
/// [2.00, 4.00], P-05 = 6.00. a is granted 4.00. b's plan total is 4.00,
/// and 4.00 + 4.00 > 6.00, so no determination on b's recorded plan
/// passes I-14. The P-04 minimum 2.00 fits b's room 2.00, so a smaller
/// negotiated plan could still fit. The decline is refused and b stays in
/// NEGOTIATION.
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
    let got = s
        .attempt(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got.is_none(),
        "NOTE 9 (decided 2026-10-26): the P-04 minimum 2.00 fits b's room 2.00, so the \
         decline is refused, yet it was accepted: {got:?}"
    );
    assert_eq!(s.state(PB), Some(StateTag::Negotiation));
}

/// NOTE 9, I-13, R-NG-03: a's plan total is 5.00 under P-04 = [2.00,
/// 4.00], so no determination on a's recorded plan passes I-13. The P-04
/// minimum 2.00 lies below the plan total, so an amount within P-04 can
/// still exist on a smaller negotiated plan. The decline is refused and a
/// stays in NEGOTIATION.
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
    let got = s
        .attempt(&decline_negotiation(Actor::Account(STAFF_PM), PA))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got.is_none(),
        "NOTE 9 (decided 2026-10-26): an amount within P-04 can still exist on a smaller \
         negotiated plan, so the decline is refused, yet it was accepted: {got:?}"
    );
    assert_eq!(s.state(PA), Some(StateTag::Negotiation));
}

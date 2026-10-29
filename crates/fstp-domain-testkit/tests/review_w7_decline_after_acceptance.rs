//! Review reproducer for the M2 close-out (W7 fix): the NOTE 9 decline
//! after acceptance and approval.
//!
//! The amount is never locked (NOTE 9, decided 2026-10-28). So the decline
//! for the cap reads the P-04 minimum against the room under P-05 at every
//! point of NEGOTIATION. The test runs production commands from genesis
//! and compares every step with the references in both directions. It
//! fails while production locks the accepted amount.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;

/// NOTE 9 (decided 2026-10-26), I-14, R-NG-03: "cannot reach" for I-14
/// means that even the P-04 minimum does not fit the recipient's room.
/// The spec has no exception for an accepted or approved amount. b starts
/// unverified, reserves 3.00 beside a's 4.00, and the vault then verifies
/// b, which leaves b a room of 2.00 under P-05 = 6.00. After b's
/// acceptance and the programme manager's approval the P-04 minimum 2.00
/// still fits, so the decline for the cap is refused.
#[test]
fn review_w7_decline_after_acceptance_reads_the_p04_minimum() {
    use fstp_domain::command::Actor;
    use fstp_domain::rules::StateTag;
    use fstp_domain_testkit::r#gen::money::{
        LB, MoneySetup, MoneyStory, PA, PB, accept_grant, approve_grant, decline_negotiation,
    };
    use fstp_domain_testkit::r#gen::roster::STAFF_PM;

    let mut setup = MoneySetup::sybil([400, 300, 100]);
    setup.unverified = vec![LB];
    let mut s = MoneyStory::new(&setup, Backend::Production)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b, unverified and so grouped alone, reserves 3.00: {e}"));
    s.world
        .vault(|t| t.verify(LB))
        .unwrap_or_else(|e| panic!("the vault verifies b: {e}"));
    s.run(&accept_grant(LB, PB))
        .unwrap_or_else(|e| panic!("b accepts 3.00: {e}"));
    s.run(&approve_grant(STAFF_PM, PB))
        .unwrap_or_else(|e| panic!("the programme manager approves 3.00: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|e| {
            panic!(
                "NOTE 9: the P-04 minimum 2.00 fits b's room 2.00, so the decline for the cap \
                 is refused after acceptance and approval too: {e}"
            )
        });
    assert_eq!(s.state(PB), Some(StateTag::Negotiation));
}

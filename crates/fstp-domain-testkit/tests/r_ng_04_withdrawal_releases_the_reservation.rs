//! R-NG-04, NOTE 10, I-14: the applicant can decline before signature, and the withdrawal releases the open reservation (design 2.11).
//!
//! Leads a and b share one verified identity under P-04 = [2.00, 4.00]
//! and P-05 = 6.00, both in NEGOTIATION from genesis by production
//! commands. Lead a has a plan of 4.00 and lead b one of 3.00. While a's
//! 4.00 is reserved, b's 3.00 is refused. Once a withdraws, the
//! reservation is released in the same batch, and b's 3.00 fits. A granted
//! proposal can no longer be withdrawn.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, LB, MoneySetup, MoneyStory, PA, PB, amount_decision, determine,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of, withdraw};
use fstp_domain_testkit::r#gen::roster::Backend;

fn released(b: Backend) {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 300, 100]), b)
        .unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let b3 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&b3)
        .unwrap_or_else(|e| panic!("I-14: 4.00 plus 3.00 exceeds 6.00: {e}"));
    let recs = s
        .run(&withdraw(LA, PA))
        .unwrap_or_else(|e| panic!("R-NG-04: a declines: {e}"));
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::CapReleased { proposal, .. } if *proposal == PA)),
        "design 2.11: the withdrawal releases the reservation in the same batch: {recs:?}"
    );
    assert_eq!(s.state(PA), Some(StateTag::Withdrawn));
    s.run(&b3)
        .unwrap_or_else(|e| panic!("I-14: b's 3.00 fits once a withdrew: {e}"));
    s.grant_facts(PB)
        .unwrap_or_else(|e| panic!("b is granted: {e}"));
    assert_eq!(s.state(PB), Some(StateTag::Granted));
    s.refused(&withdraw(LB, PB))
        .unwrap_or_else(|e| panic!("NOTE 10: a granted proposal is not withdrawn: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-04, NOTE 10, I-14: withdrawal in NEGOTIATION releases the reservation.
#[test]
fn r_ng_04_withdrawal_releases_the_reservation() {
    released(Backend::Production);
}

/// R-NG-04: the story passes on the references alone.
#[test]
fn r_ng_04_story_passes_on_the_reference() {
    released(Backend::Reference);
}

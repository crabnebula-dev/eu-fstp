//! Review reproducer for the W7 close-out (independent review).
//!
//! NOTE 9 (decided 2026-10-28): the amount is never locked. M-MONEY, the
//! I-13 and I-14 model of design 6.2, now draws `Determine` after
//! acceptance or approval. Its stored count stayed at 594, so the new
//! action never fires there. This witness asks M-MONEY to reach a new
//! amount that superseded a given acceptance or approval.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_STATES, McState, MoneyMc, determinations, m_money,
};
use fstp_mc::Property;

/// A second determination of a proposal superseded a given acceptance or
/// approval: two determinations, a contract fact, and neither acceptance
/// nor approval left. In M-MONEY the three facts are sent together, so a
/// blocked completing fact leaves the other two recorded. Only a new
/// amount clears both.
fn superseded(s: &McState) -> bool {
    s.world.money.proposals.iter().any(|(p, q)| {
        determinations(&s.world, *p) == 2
            && q.contract.is_some()
            && q.accepted.is_none()
            && q.approved.is_none()
    })
}

/// NOTE 9, R-NG-03, I-14 (decided 2026-10-28): M-MONEY reaches a new
/// amount determined after acceptance or approval.
#[test]
fn review_m_money_reaches_a_determination_after_acceptance() {
    let model = MoneyMc::new(m_money(), Backend::Production)
        .unwrap_or_else(|e| panic!("M-MONEY start from genesis: {e}"));
    let properties = vec![Property::<MoneyMc>::reachable(
        "NOTE 9 witness: a new amount superseded a given acceptance or approval",
        superseded,
    )];
    if let Err(e) = check_exhaustive(&model, &properties, M_MONEY_STATES) {
        panic!("{e}");
    }
}

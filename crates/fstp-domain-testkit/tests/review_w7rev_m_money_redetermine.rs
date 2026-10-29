//! Review reproducer for the W7 close-out (independent review).
//!
//! NOTE 9 (decided 2026-10-28): the amount is never locked. M-MONEY, the
//! I-13 and I-14 model of design 6.2, now draws `Determine` after
//! acceptance or approval. Its stored count stayed at 594, so the new
//! action never fires there. This witness asks M-MONEY to reach a new
//! amount that superseded a given acceptance or approval.
//!
//! Close-out round 2 (Q-W7-4, decided 2026-10-28): a new amount also
//! clears the contract fact of the earlier amount. The witness used to
//! read a contract fact held after the second determination as the mark
//! of a supersede, which encoded the overturned reading that the fact
//! survives. It now asks for the ghost of the supersede and a proposal
//! whose three facts the new amount all cleared.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_STATES, McState, MoneyMc, determinations, m_money,
};
use fstp_mc::Property;

/// A second determination of a proposal superseded a given acceptance or
/// approval: the ghost is set, and a proposal in NEGOTIATION with two
/// determinations holds no acceptance, approval or contract fact. The new
/// amount clears all three (NOTE 9, Q-W7-4, decided 2026-10-28).
fn superseded(s: &McState) -> bool {
    s.superseded
        && s.world.money.proposals.iter().any(|(p, q)| {
            determinations(&s.world, *p) == 2
                && q.state == StateTag::Negotiation
                && q.contract.is_none()
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

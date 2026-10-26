//! Review reproducer for lane w6-decline (decision fidelity).
//!
//! The lane brief asks that the M-MONEY tripwire be re-measured on
//! production after the NOTE 9 change. The exit audit rule is that each
//! shared constant holds the production count. The test fails while
//! `M_MONEY_STATES` holds a count production does not store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{M_MONEY_STATES, MoneyMc, m_money, m_money_properties};

/// I-13, I-14, NOTE 9: `M_MONEY_STATES` is the state count M-MONEY
/// stores on production, so its tripwire is twice the production count.
#[test]
fn review_m_money_tripwire_holds_the_production_count() {
    let model = MoneyMc::new(m_money(), Backend::Production)
        .unwrap_or_else(|e| panic!("M-MONEY start from genesis: {e}"));
    let o = check_exhaustive(&model, &m_money_properties::<MoneyMc>(), M_MONEY_STATES)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        o.stats.states, M_MONEY_STATES,
        "M_MONEY_STATES must be the production count, measured {} on production",
        o.stats.states
    );
}

//! I-13 and I-14 on M-MONEY (design 6.2 and 6.3).
//!
//! Identities {a, b} and {c}, three proposals reaching NEGOTIATION from
//! genesis by production commands, P-04 = [2.00, 4.00] and P-05 = 6.00.
//! The plans are 4.00, 2.00 and 1.00, and the reviewers deduct 0.00 or
//! 1.00. The agreed plan must carry the granted amount (design 2.11), so a
//! deduction comes with the lead's negotiated plan of the reduced total.
//! The model checks `always("I-13")`, `always("I-14")` over granted
//! plus reserved per verified identity, and `transition("I-14")` for the
//! P-05 edit, with every command compared with the money reference in both
//! directions. Witnesses: granted at the P-04 minimum and maximum, a
//! recipient's granted sum exactly P-05, a Sybil pair blocked by the cap,
//! a grant on a recorded deduction (R-NG-03),
//! both amount failures of NOTE 9 recorded as NEGOTIATION to DECLINED, and
//! a new amount that superseded a given acceptance or approval (NOTE 9,
//! decided 2026-10-28). The grant facts come one by one too, so that last
//! witness is reachable (W7 fix round 1).
//!
//! NOTE 9 as decided on 2026-10-26 and 2026-10-28: a decline for the cap
//! needs that even the P-04 minimum lies above the headroom. The amount is
//! never locked, so this holds after acceptance and approval too. The
//! witness is b declined once a holds 4.00 or 3.00 and P-05 is lowered to
//! 4.00. The transition property checks that no step declines for the cap
//! while that amount fits. Lead a was declined
//! that way under the old reading, once P-05 was lowered to 4.00 and b
//! held 2.00. That step is now unreachable, and the state count was
//! measured again on each backend. Production stores `M_MONEY_STATES`
//! and the references store `M_MONEY_REFERENCE_STATES`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_REFERENCE_STATES, M_MONEY_STATES, MoneyMc, m_money, m_money_properties,
};

fn model(backend: Backend, measured: usize) {
    let model = MoneyMc::new(m_money(), backend)
        .unwrap_or_else(|e| panic!("M-MONEY start from genesis: {e}"));
    match check_exhaustive(&model, &m_money_properties::<MoneyMc>(), measured) {
        Ok(o) => eprintln!("M-MONEY on {backend:?}: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-13, I-14, R-NG-03, NOTE 9: M-MONEY passes with every witness reached.
#[test]
fn i13_i14_m_money() {
    model(Backend::Production, M_MONEY_STATES);
}

/// I-13, I-14, NOTE 9: M-MONEY passes on the references alone.
#[test]
fn i13_i14_m_money_reference() {
    model(Backend::Reference, M_MONEY_REFERENCE_STATES);
}

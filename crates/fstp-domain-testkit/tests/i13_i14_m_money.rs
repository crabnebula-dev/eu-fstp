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
//! and both amount failures of NOTE 9 recorded as NEGOTIATION to DECLINED.
//! One decline holds although the P-04 minimum fits the headroom, because
//! only the plan total breaks the cap. It rests on the interim reading that
//! only recorded negotiated plans count, open for Daniel (`fstp_domain::grant`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{M_MONEY_STATES, MoneyMc, m_money, m_money_properties};

fn model(backend: Backend) {
    let model = MoneyMc::new(m_money(), backend)
        .unwrap_or_else(|e| panic!("M-MONEY start from genesis: {e}"));
    match check_exhaustive(&model, &m_money_properties::<MoneyMc>(), M_MONEY_STATES) {
        Ok(o) => eprintln!("M-MONEY: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-13, I-14, R-NG-03: M-MONEY passes with every witness reached.
#[test]
fn i13_i14_m_money() {
    model(Backend::Production);
}

/// I-13, I-14: M-MONEY passes on the references alone.
#[test]
fn i13_i14_m_money_reference() {
    model(Backend::Reference);
}

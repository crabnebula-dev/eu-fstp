//! I-15 on the repeat part of M-MONEY (design 6.2 and 6.3).
//!
//! Leads a and b share one verified identity. From genesis by production
//! commands, a is granted 4.00 and starts execution, and b reaches
//! NEGOTIATION. Lead a requests the first milestone, R1 accepts the line,
//! and the M5 checks record at most one deliverable under a P-26 licence
//! or not, accepted or not. Any grant to b is a repeat grant to the same
//! applicant. `transition("I-15")`: entering GRANTED needs the identity's
//! public deliverable record complete before the step. Witnesses: a repeat
//! grant, a repeat grant after a public deliverable, GRANTED disabled by a
//! missing record, a grant once that record is completed and the refused
//! completing fact is sent again, and NEGOTIATION to DECLINED for an
//! incomplete record. Amendments are not drawn yet: lane L-LIFE refuses
//! plans of origin "amendment", so the "an amendment exists" witness of
//! design 6.2 waits for that refusal to be lifted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::money_model::{
    M_MONEY_REPEAT_REFERENCE_STATES, M_MONEY_REPEAT_STATES, MoneyMc, repeat, repeat_properties,
};

fn model(backend: Backend, measured: usize) {
    let model = MoneyMc::new(repeat(), backend)
        .unwrap_or_else(|e| panic!("I-15 repeat model start from genesis: {e}"));
    match check_exhaustive(&model, &repeat_properties::<MoneyMc>(), measured) {
        Ok(o) => eprintln!("I-15 repeat: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-15, R-NG-05: a repeat grant needs every accepted prior deliverable public under P-26.
#[test]
fn i15_m_money_repeat() {
    model(Backend::Production, M_MONEY_REPEAT_STATES);
}

/// I-15: the repeat model passes on the references alone.
#[test]
fn i15_m_money_repeat_reference() {
    model(Backend::Reference, M_MONEY_REPEAT_REFERENCE_STATES);
}

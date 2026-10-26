//! I-05, SoD-04 and SoD-12 on M-PAY (design 2.12, 6.2 and 6.3).
//!
//! From genesis by production commands, lead c is granted 4.00 over two
//! milestones of 2.00 and starts execution. Assigned reviewers R1, R2 and
//! R3 can accept lines. R1 is also a payment releaser, R2 also a finance
//! approver, FINREL both, and REL a payment releaser only. The vault
//! records R3 as the mentor of lead c. One request of two lines is
//! submitted, then each line is accepted once, the payment is approved
//! once, released once and confirmed. `always("I-05")`: the releaser is
//! never a line acceptor or the approver. `transition("SoD-04")` and
//! `always("SoD-12")` for the mentor. Witnesses: a release by a third
//! account, the confirmation, a refused release by an acceptor or the
//! approver, and the mentor's refused acceptance.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::pay_model::{M_PAY_STATES, PayMc, pay_properties};

fn model(backend: Backend) {
    let model = PayMc::new(backend).unwrap_or_else(|e| panic!("M-PAY start from genesis: {e}"));
    match check_exhaustive(&model, &pay_properties::<PayMc>(), M_PAY_STATES) {
        Ok(o) => eprintln!("M-PAY: {} states", o.stats.states),
        Err(e) => panic!("{e}"),
    }
}

/// I-05, SoD-04, SoD-12, R-EX-04: the releaser is never an acceptor or the approver.
#[test]
fn i05_m_pay() {
    model(Backend::Production);
}

/// I-05: M-PAY passes on the references alone.
#[test]
fn i05_m_pay_reference() {
    model(Backend::Reference);
}

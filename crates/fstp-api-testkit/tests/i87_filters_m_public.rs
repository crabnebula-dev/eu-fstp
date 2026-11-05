//! M-PUBLIC (I-87, I-41, I-42, I-43, R-PB-05; M4 design section 8.5).
//!
//! Universe: one programme, three proposals with choices (one a minor's)
//! and a draft with a full choice, the stages from NEGOTIATION to
//! COMPLETED, synthetic choices from Hidden to Full, and P-50, P-51 and
//! P-54 at two values each. Property: in every state the production view
//! equals the reference filter of `public-transparency.md`. Witnesses: a
//! full-level finished grant, and an aggregate at exactly P-54.
//!
//! Status: `i87_m_public` is red. The W0 stub of
//! `fstp_public::public_view_with` refuses with
//! `PublicError::NotImplemented`. The reference twin is green.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::public_model::{Backend, PublicModel, TRIPWIRE, m_public_properties};
use fstp_domain_testkit::harness::mc::check_exhaustive;

fn run(backend: Backend) {
    let model = PublicModel::new(backend).unwrap_or_else(|e| panic!("M-PUBLIC: {e}"));
    let properties = m_public_properties(&model);
    if let Err(e) = check_exhaustive(&model, &properties, TRIPWIRE) {
        panic!("{e}");
    }
}

/// I-87, I-41, I-42, I-43, R-PB-05: M-PUBLIC on production.
#[test]
fn i87_m_public() {
    run(Backend::Production);
}

/// M-PUBLIC on the reference alone, against the direct predicates.
#[test]
fn i87_m_public_on_the_reference() {
    run(Backend::Reference);
}

//! I-02 on M-SOD (design 6.2 and 6.3).
//!
//! c may hold committee member, committee chair or IRC member, with at
//! most two bindings. Properties: `always("two-way")`, `always("I-02")`,
//! `transition("SoD-02")`, `always("I-01")`, and witnesses that a committee
//! member becomes an IRC member after the committee binding ends, and that
//! committee member and chair may be held together.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::sod_model::{M_SOD_I02_STATES, SodModel, i02_config, i02_properties};

fn run(backend: Backend) {
    let model = SodModel::new(i02_config(), backend)
        .unwrap_or_else(|e| panic!("M-SOD start from genesis: {e}"));
    let properties = i02_properties::<SodModel>();
    if let Err(e) = check_exhaustive(&model, &properties, M_SOD_I02_STATES) {
        panic!("{e}");
    }
}

/// I-02, SoD-02: an IRC binding never coexists with another Judging binding
/// of the account, and a past committee binding never bars an IRC one.
#[test]
fn i02_m_sod_irc_exclusive() {
    run(Backend::Production);
}

/// I-02: the model passes on the reference alone.
#[test]
fn i02_m_sod_irc_exclusive_reference() {
    run(Backend::Reference);
}

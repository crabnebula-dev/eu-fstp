//! Review of lane seams1 (harness fidelity). Each test fails against the
//! lane's working tree and passes once the finding it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::auth_model::{ProdCell, credential_of};
use fstp_celltest::mc::stepup_model::{self as sm, Production, Reference, StepUpBackend};
use fstp_celltest::reference::auth::{self as r, RefMethod, RefStepUp};
use fstp_domain_testkit::r#gen::roster::{B, T0};

/// I-78, M-STEPUP: the production backend commits `ReleasePayment` (command
/// 2) in the admin's passkey session with a fresh strong step-up, as the
/// reference does. The lane leaves the bootstrapped cell without a payment
/// request, so the commit halts with `COMMIT_STATE_SEAM` and
/// `i78_m_stepup` stays red. The fix is in `Production::new`, a production
/// backend of this lane.
#[test]
fn review_i78_m_stepup_production_commits_release_payment() {
    let s = sm::session(sm::S_ADMIN);
    let u = RefStepUp {
        id: [0x5C; 16],
        session: s.id,
        action_digest: sm::digest(2),
        asserted_at: sm::ASSERTED_AT,
        method: RefMethod::Passkey,
        uv: true,
        consumed: false,
    };
    let want = Reference
        .commit(&s, 2, Some(&u), sm::ASSERTED_AT, r::P71_DEFAULT_US)
        .map_err(|e| e.to_string());
    let p = Production::new().unwrap_or_else(|e| panic!("{e}"));
    let got = p
        .commit(&s, 2, Some(&u), sm::ASSERTED_AT, r::P71_DEFAULT_US)
        .map_err(|e| e.to_string());
    assert_eq!(
        got, want,
        "I-78: ReleasePayment commits on the reference only"
    );
}

/// Design section 8.3, I-78 (`AddPasskey`): a second passkey is added only
/// as the high-risk action `AddPasskey`, with a step-up. Every first
/// passkey ceremony (invitation, self-registration, recovery) refuses an
/// account that holds a passkey. `ProdCell::register_passkey`, which its
/// doc calls a first passkey ceremony, records a second passkey with no
/// step-up, a record production never writes.
#[test]
fn review_i78_register_passkey_refuses_a_second_passkey() {
    let mut c = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    c.register_passkey(B, credential_of(B, 0), T0)
        .unwrap_or_else(|e| panic!("first passkey: {e}"));
    let second = c.register_passkey(B, credential_of(B, 1), T0);
    assert!(
        second.is_err(),
        "a second passkey was registered outside AddPasskey: {second:?}"
    );
}

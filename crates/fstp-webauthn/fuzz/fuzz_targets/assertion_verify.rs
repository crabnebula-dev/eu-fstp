//! Fuzz target `assertion_verify` of `fstp-webauthn` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: a mutation of a signed byte never verifies.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use fstp_webauthn::{
        AssertionExpect, AssertionResponse, CoseKey, RelyingParty, StoredCredential,
    };
    let Ok(rp) = RelyingParty::new("cell.example.org") else {
        return;
    };
    let third = data.len() / 3;
    let response = AssertionResponse {
        credential_id: vec![1; 16],
        client_data_json: data.get(..third).unwrap_or_default().to_vec(),
        authenticator_data: data
            .get(third..third.saturating_mul(2))
            .unwrap_or_default()
            .to_vec(),
        signature: data
            .get(third.saturating_mul(2)..)
            .unwrap_or_default()
            .to_vec(),
    };
    let credential = StoredCredential {
        id: vec![1; 16],
        key: CoseKey::Ed25519 { x: [0; 32] },
        sign_count: 0,
    };
    let expect = AssertionExpect {
        rp,
        challenge: [0; 32],
        user_verification: true,
    };
    let shown = format!(
        "{:?}",
        fstp_webauthn::verify_assertion(&response, &credential, &expect)
    );
    assert!(!shown.is_empty());
});

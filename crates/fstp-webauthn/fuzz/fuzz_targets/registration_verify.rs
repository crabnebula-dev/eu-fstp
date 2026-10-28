//! Fuzz target `registration_verify` of `fstp-webauthn` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: a mutation of a signed byte never verifies.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use fstp_webauthn::{RegistrationExpect, RegistrationResponse, RelyingParty};
    let Ok(rp) = RelyingParty::new("cell.example.org") else {
        return;
    };
    let half = data.len() / 2;
    let response = RegistrationResponse {
        client_data_json: data.get(..half).unwrap_or_default().to_vec(),
        attestation_object: data.get(half..).unwrap_or_default().to_vec(),
    };
    let expect = RegistrationExpect {
        rp,
        challenge: [0; 32],
    };
    let shown = format!(
        "{:?}",
        fstp_webauthn::verify_registration(&response, &expect)
    );
    assert!(!shown.is_empty());
});

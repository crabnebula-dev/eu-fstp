//! Fuzz target `assertion_verify` of `fstp-webauthn` (TH-26, H-05, M3
//! design section 15, I-77, I-78, ADR-008).
//!
//! Design checks: no panic; a mutation of a signed byte never verifies.
//! The input draws the stored and asserted counters, whether UV is
//! required, and edits to the authenticator data, the client data, the
//! signature and the credential id of a valid Ed25519 assertion. Ed25519
//! signatures are not malleable, so for every input:
//!
//! - `verify_assertion` never panics and is deterministic.
//! - An accepted assertion has the authenticator data, client data,
//!   signature and credential id of the valid one, unchanged.
//! - It meets the sign count rule: both counts zero, or the new count
//!   greater than the stored one, and it reports the new count.

#![no_main]

mod common;

use common::{Input, assertion, mutate};
use fstp_webauthn::verify_assertion;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let counter = input.u32() % 4;
    let stored = input.u32() % 4;
    let uv = input.byte().is_multiple_of(2);
    let Some((base, cred, expect)) = assertion(counter, stored, uv) else {
        return;
    };
    let mut resp = base.clone();
    mutate(&mut input, &mut resp.authenticator_data);
    mutate(&mut input, &mut resp.client_data_json);
    mutate(&mut input, &mut resp.signature);
    mutate(&mut input, &mut resp.credential_id);
    let got = verify_assertion(&resp, &cred, &expect);
    assert_eq!(
        got,
        verify_assertion(&resp, &cred, &expect),
        "not deterministic"
    );
    let Ok(ok) = got else {
        return;
    };
    assert_eq!(resp, base, "a changed assertion verified");
    assert!(
        (counter == 0 && stored == 0) || counter > stored,
        "count {counter} verified after {stored}"
    );
    assert_eq!(ok.sign_count, counter);
    assert!(ok.user_verified, "the valid assertion carries UV");
});

//! Fuzz target `revocation_request_decode` of `fstp-oauth` (TH-26, H-05,
//! M4 design section 9).
//!
//! Design checks: RFC 7009 revocation bodies; duplicate parameters
//! rejected. An accepted request names a token and a client.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(req) = fstp_oauth::decode_revocation_request(data) else {
        return;
    };
    let Ok(form) = fstp_oauth::decode_form_urlencoded(data) else {
        panic!("an accepted revocation request has no form");
    };
    assert_eq!(form.get("token"), Some(req.token.as_str()));
    assert_eq!(form.get("client_id"), Some(req.client_id.as_str()));
});

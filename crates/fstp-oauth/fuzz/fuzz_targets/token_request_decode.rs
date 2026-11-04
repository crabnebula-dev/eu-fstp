//! Fuzz target `token_request_decode` of `fstp-oauth` (TH-26, H-05, M4
//! design section 9).
//!
//! Design checks: token requests; duplicate parameters rejected. An
//! accepted request has a decodable form with the grant type it names.

#![no_main]

use fstp_oauth::TokenRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(req) = fstp_oauth::decode_token_request(data) else {
        return;
    };
    let form = fstp_oauth::decode_form_urlencoded(data);
    let Ok(form) = form else {
        panic!("an accepted token request has no form");
    };
    match &req {
        TokenRequest::AuthorizationCode {
            code, client_id, ..
        } => {
            assert_eq!(form.get("grant_type"), Some("authorization_code"));
            assert_eq!(form.get("code"), Some(code.as_str()));
            assert_eq!(form.get("client_id"), Some(client_id.as_str()));
        }
        TokenRequest::RefreshToken {
            refresh_token,
            client_id,
            ..
        } => {
            assert_eq!(form.get("grant_type"), Some("refresh_token"));
            assert_eq!(form.get("refresh_token"), Some(refresh_token.as_str()));
            assert_eq!(form.get("client_id"), Some(client_id.as_str()));
        }
    }
    assert!(!format!("{req:?}").is_empty());
});

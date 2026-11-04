//! Fuzz target `authorize_query_decode` of `fstp-oauth` (TH-26, H-05, M4
//! design section 9).
//!
//! Design checks: OAuth surfaces; duplicate parameters rejected. The
//! decoder accepts exactly the queries the form decoder accepts, and each
//! field holds the value of its parameter.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let form = fstp_oauth::decode_form_urlencoded(data);
    let req = fstp_oauth::decode_authorize_query(data);
    assert_eq!(form.is_ok(), req.is_ok());
    let (Ok(form), Ok(req)) = (form, req) else {
        return;
    };
    assert_eq!(req.client_id.as_deref(), form.get("client_id"));
    assert_eq!(req.redirect_uri.as_deref(), form.get("redirect_uri"));
    assert_eq!(req.code_challenge.as_deref(), form.get("code_challenge"));
    assert_eq!(req.resource.as_deref(), form.get("resource"));
    assert_eq!(req.state.as_deref(), form.get("state"));
    assert!(!format!("{req:?}").is_empty());
});

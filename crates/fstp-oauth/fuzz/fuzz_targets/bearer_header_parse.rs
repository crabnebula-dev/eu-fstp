//! Fuzz target `bearer_header_parse` of `fstp-oauth` (TH-26, H-05, M4
//! design section 9).
//!
//! Design checks: `Authorization` header values. An accepted value is the
//! scheme, one space and the credential, which is one `b64token`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = fstp_oauth::parse_bearer_header(data) else {
        return;
    };
    let t = token.as_str();
    assert!(!t.is_empty());
    assert_eq!(data.len(), t.len() + 7);
    assert!(data[..6].eq_ignore_ascii_case(b"bearer") && data[6] == b' ');
    assert_eq!(&data[7..], t.as_bytes());
    assert!(
        t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
    );
});

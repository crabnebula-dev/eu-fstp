//! Fuzz target `base64url_decode` of `fstp-oauth` (TH-26, H-05, M4 design
//! section 9).
//!
//! Design checks: unpadded base64url is canonical. Accepted text is the
//! one encoding of its bytes, and every byte string round-trips.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = fstp_oauth::decode_base64url(data) {
        assert_eq!(
            fstp_oauth::encode_base64url(bytes.as_bytes()).as_bytes(),
            data
        );
    }
    let text = fstp_oauth::encode_base64url(data);
    if text.len() <= fstp_oauth::MAX_BASE64URL_LEN {
        let back = fstp_oauth::decode_base64url(text.as_bytes());
        assert_eq!(back.as_ref().map(|b| b.as_bytes()), Ok(data));
    }
});

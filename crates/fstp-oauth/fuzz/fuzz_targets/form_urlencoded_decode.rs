//! Fuzz target `form_urlencoded_decode` of `fstp-oauth` (TH-26, H-05, M4
//! design section 9).
//!
//! Design checks: OAuth surfaces; duplicate parameters rejected. An
//! accepted form has unique names, and encoding it then decoding it gives
//! the same pairs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(form) = fstp_oauth::decode_form_urlencoded(data) else {
        return;
    };
    let pairs = form.pairs();
    for (i, (k, _)) in pairs.iter().enumerate() {
        assert!(!k.is_empty());
        assert!(pairs.iter().skip(i + 1).all(|(other, _)| other != k));
    }
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let text = fstp_oauth::encode_form_urlencoded(&refs);
    let back = fstp_oauth::decode_form_urlencoded(text.as_bytes());
    assert_eq!(back.as_ref().map(|f| f.pairs()), Ok(pairs));
});

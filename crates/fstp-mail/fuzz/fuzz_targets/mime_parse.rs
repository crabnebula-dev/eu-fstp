//! Fuzz target `mime_parse` of `fstp-mail` (TH-26, M6 design section 5.3).
//!
//! The input is read as a whole message, and also handed to each decoder
//! on its own: base64, quoted-printable and RFC 2047 encoded words. Every
//! call must return a typed result without panicking. A quoted-printable
//! decode of an encoder's output must give the input back.

#![no_main]

use fstp_mail::encode::{base64_decode, decode_unstructured, qp_decode, qp_encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = fstp_mail::parse(data) {
        assert!(m.parts.len() <= fstp_mail::mime::MAX_PARTS);
        for f in &m.fields {
            let _ = f.value();
        }
    }
    let _ = base64_decode(data);
    let _ = qp_decode(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_unstructured(s);
        if !s.contains('\r') {
            let back = qp_decode(qp_encode(s).as_bytes()).expect("own QP output decodes");
            assert_eq!(back, s.replace('\n', "\r\n").into_bytes());
        }
    }
});

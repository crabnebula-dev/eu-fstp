//! Fuzz target `fact_body_decode` of `fstp-vault` (TH-26, H-05, M3 design
//! sections 4.3, 6.3 and 15).
//!
//! Design checks: no panic. For every input:
//!
//! - `decode_fact_body` never panics and is deterministic.
//! - An accepted body has a kind of W1c's proposal or M5 (1 to 18) and
//!   re-encodes as `{"fields":<fields>,"kind":<kind>}` to the input byte
//!   for byte.
//!
//! Against the W0 stub every input is refused, so only the first check
//! has teeth until lane W2d lands the decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault::decode_fact_body(data);
    assert_eq!(
        got,
        fstp_vault::decode_fact_body(data),
        "decode is not deterministic"
    );
    if let Ok(b) = got {
        assert!((1..=18).contains(&b.kind), "unknown kind {}", b.kind);
        let again = format!(
            "{{\"fields\":{},\"kind\":{}}}",
            String::from_utf8_lossy(&b.fields),
            b.kind
        );
        assert_eq!(
            again.as_bytes(),
            data,
            "an accepted body has another spelling"
        );
    }
});

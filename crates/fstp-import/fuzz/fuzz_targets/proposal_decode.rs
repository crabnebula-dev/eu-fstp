//! Fuzz target `proposal_decode` of `fstp-import` (TH-26, TH-47, H-05, M4
//! design section 9).
//!
//! Proposer output never panics the decoder. An accepted proposal keeps
//! its value byte for byte: the value's normal text decodes back to the
//! same value, and the encoded proposal decodes back to the same proposal
//! with the same text.

#![no_main]

use fstp_import::{UntrustedValue, decode_proposal, encode_proposal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(p) = decode_proposal(data) else {
        return;
    };
    assert_eq!(
        UntrustedValue::from_normal_text(p.value.as_data()).as_ref(),
        Ok(&p.value)
    );
    let text = encode_proposal(&p);
    let back = decode_proposal(text.as_bytes());
    assert_eq!(back.as_ref(), Ok(&p));
    if let Ok(back) = back {
        assert_eq!(back.value.as_data(), p.value.as_data());
        assert_eq!(encode_proposal(&back), text);
    }
});

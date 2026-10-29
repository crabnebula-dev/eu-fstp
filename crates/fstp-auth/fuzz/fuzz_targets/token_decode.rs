//! Fuzz target `token_decode` of `fstp-auth` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip; constant-length tokens only.
//!
//! ADR-008 fixes a token at 32 random bytes. The target checks that an
//! accepted input is exactly 32 bytes, that the token holds them
//! unchanged, and that `encode_token` gives the input bytes back.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// ADR-008: a token is 32 bytes.
const TOKEN_LEN: usize = 32;

fuzz_target!(|data: &[u8]| {
    let got = fstp_auth::codec::decode_token(data);
    let shown = format!("{got:?}");
    assert!(!shown.is_empty());
    if let Ok(token) = got {
        assert_eq!(data.len(), TOKEN_LEN, "accepted a token of another length");
        assert_eq!(&token.0[..], data, "the token does not hold its input");
        let bytes = fstp_auth::codec::encode_token(&token);
        assert_eq!(&bytes[..], data, "the token does not re-encode");
    }
});

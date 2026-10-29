//! Fuzz target `auth_command_decode` of `fstp-auth` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip.
//!
//! Every input gets an answer without a panic, and decoding is a function
//! of the input. Each accepted input re-encodes through
//! `encode_auth_command` to exactly the input bytes, so every command has
//! one spelling.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_auth::codec::decode_auth_command(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    if let Ok(command) = first {
        let again = fstp_auth::codec::decode_auth_command(data);
        assert_eq!(
            again.as_ref(),
            Ok(&command),
            "decoding the same input twice differs"
        );
        let bytes = fstp_auth::codec::encode_auth_command(&command);
        assert_eq!(bytes.as_deref(), Ok(data), "the command does not re-encode");
    }
});

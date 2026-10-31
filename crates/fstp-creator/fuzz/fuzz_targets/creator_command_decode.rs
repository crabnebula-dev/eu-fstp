//! Fuzz target `creator_command_decode` of `fstp-creator` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics; round trip. A decoded command encodes to
//! canonical JSON that decodes to the same command.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(cmd) = fstp_creator::decode_command(data) else {
        return;
    };
    let Ok(text) = fstp_creator::encode_command(&cmd) else {
        panic!("a decoded command has no canonical text");
    };
    match fstp_creator::decode_command(text.as_bytes()) {
        Ok(back) => assert_eq!(back, cmd, "round trip changed the command"),
        Err(e) => panic!("the encoded command does not decode: {e}"),
    }
});

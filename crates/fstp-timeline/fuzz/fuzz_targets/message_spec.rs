//! Fuzz target `message_spec` of `fstp-timeline` (M6 design section 4).
//!
//! The input is read as the sealed body of an outbox row. The decoder
//! must return a typed result without panicking. A body that decodes
//! encodes again, and that encoding decodes to the same body.

#![no_main]

use fstp_timeline::message::MessageSpec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(spec) = MessageSpec::decode(data) {
        if let Some(again) = spec.encode() {
            assert_eq!(MessageSpec::decode(&again).ok(), Some(spec));
        }
    }
});

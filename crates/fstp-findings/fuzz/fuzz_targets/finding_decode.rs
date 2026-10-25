//! Fuzz target for the finding decoder (TH-26, H-05, I-11).
//!
//! W0 stub: the finding codec does not exist yet, so the target exercises
//! the closest existing stage, the JSON parser and canonical writer that the
//! codec will sit on. Lane L-FIND-A replaces the body when it lands the
//! codec. The final target checks the round trip, and that `UntrustedText`
//! is preserved byte for byte.

#![no_main]

use fstp_findings as _;
use fstp_json::{parse, to_canonical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    let _ = to_canonical(&v);
});

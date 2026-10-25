//! Fuzz target for the `fstp-domain` policy decoder (TH-26, H-05).
//!
//! W0 stub: the policy codec does not exist yet, so the target exercises the
//! closest existing stage, the JSON parser and canonical writer that the
//! codec will sit on. Lane L-CODEC replaces the body when it lands the
//! codec. The final target decodes policy versions, runs validation, which must be total, and checks the round trip.

#![no_main]

use fstp_domain as _;
use fstp_json::{parse, to_canonical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    let _ = to_canonical(&v);
});

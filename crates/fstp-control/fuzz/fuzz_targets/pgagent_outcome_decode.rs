//! Fuzz target `pgagent_outcome_decode` of `fstp-control` (TH-26, H-05,
//! ADR-011).
//!
//! Design checks: no panic.
//!
//! On every input the decoder returns without a panic. An accepted frame
//! is the one encoding of its outcome, so no byte of it is free.

#![no_main]

use fstp_control::agent::{decode_job_outcome, encode_job_outcome};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = decode_job_outcome(data) {
        assert_eq!(encode_job_outcome(o).as_slice(), data);
    }
});

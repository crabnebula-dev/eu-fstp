//! Fuzz target `pgagent_approved_job_decode` of `fstp-control` (TH-26,
//! H-05, ADR-011 "Two-operator approval"). Lane m3/erase-cell-2.
//!
//! Design checks: no panic; only a destructive job decodes; an accepted
//! frame is the one encoding of its job and approvals.
//!
//! On every input the decoder returns without a panic, its result
//! formats, and a second decode gives the same result. A decoded job is
//! destructive, and it re-encodes to the input byte for byte. A plain job
//! frame never decodes as an approved one, since the version octets
//! differ.

#![no_main]

use fstp_control::pgagent::{
    APPROVED_VERSION, JOB_VERSION, MAX_APPROVED_LEN, decode_approved_job, encode_approved_job,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_approved_job(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_approved_job(data), first);
    let Ok(frame) = first else {
        return;
    };
    assert_ne!(APPROVED_VERSION, JOB_VERSION);
    assert_eq!(data.first(), Some(&APPROVED_VERSION));
    assert!(data.len() <= MAX_APPROVED_LEN);
    assert!(
        frame.job.is_destructive(),
        "{:?} is not destructive",
        frame.job
    );
    assert_eq!(
        encode_approved_job(&frame).as_deref(),
        Ok(data),
        "{frame:?} does not round-trip"
    );
});

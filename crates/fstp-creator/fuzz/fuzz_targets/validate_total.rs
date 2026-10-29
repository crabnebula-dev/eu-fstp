//! Fuzz target `validate_total` of `fstp-creator` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: validate is total over arbitrary drafts and inputs.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2a lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!(
        "{:?}",
        fstp_creator::decode_draft(data).map(|d| fstp_creator::validate(&d))
    );
    assert!(!shown.is_empty());
});

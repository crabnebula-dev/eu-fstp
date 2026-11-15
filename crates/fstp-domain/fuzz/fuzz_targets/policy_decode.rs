//! Fuzz target for the `fstp-domain` policy version decoder (TH-26, H-05,
//! I-12).
//!
//! The input is the JSON form of one policy version. The shared oracle in
//! `common` checks that decoding never panics, rejects unknown members at
//! every object, round-trips with stable canonical bytes and accepts one
//! spelling per policy version. The decoder is structural, so it accepts
//! values that validation refuses.
//!
//! Design section 7 also asks that validation is total on every decoded
//! policy. Lane L-POL has not published a validation entry point yet. When
//! it does, this target runs it on every accepted value and checks that it
//! returns a report without panicking.

#![no_main]

mod common;

use fstp_domain::policy::PolicyVersion;
use libfuzzer_sys::fuzz_target;

use common::{Outcome, codec_for, oracle};

fuzz_target!(|data: &[u8]| {
    // P-57 (lane m9/answers): the reporting periods of an opaque P-57
    // text. Refused or ordered, never a panic.
    if let Ok(text) = core::str::from_utf8(data)
        && let Some(a) = fstp_domain::reporting::periods_of(text)
    {
        assert!(
            a.periods
                .windows(2)
                .all(|w| matches!(w, [x, y] if x.end == y.start && x.end < y.end))
        );
    }
    let codec = codec_for!(PolicyVersion);
    if let Outcome::Accepted(p) = oracle(&codec, data) {
        let _ = format!("{p:?}");
    }
});

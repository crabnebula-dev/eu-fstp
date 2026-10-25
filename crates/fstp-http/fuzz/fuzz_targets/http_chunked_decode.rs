//! TH-26, H-05: the incremental chunked decoder against arbitrary input.
//!
//! Properties checked beyond "no panic":
//!
//! - Agreement with an independent, stateless reference decoder on the
//!   body, the trailers, the bytes left over and the exact error kind.
//! - Differential over splits: pieces at fuzz-chosen points give the same
//!   outcome as the whole input.

#![no_main]

#[path = "../common/mod.rs"]
mod common;

use common::{RefOutcome, control, decode_chunked, reference_chunked};
use fstp_http::ParseErrorKind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(c) = control(data) else {
        return;
    };
    let whole = decode_chunked(c.input, &[], c.limits, c.eof);
    let split = decode_chunked(c.input, &c.splits, c.limits, c.eof);
    assert_eq!(whole, split, "outcome depends on the split");

    match reference_chunked(c.input, &c.limits) {
        RefOutcome::Done(body, trailers, consumed) => {
            assert_eq!(whole.error, None, "reference accepted, decoder failed");
            assert_eq!(whole.body, body, "bodies differ");
            let got: Vec<(Vec<u8>, Vec<u8>)> = whole
                .trailers
                .as_ref()
                .expect("decoder did not finish")
                .iter()
                .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect();
            assert_eq!(got, trailers, "trailers differ");
            assert_eq!(whole.remaining, &c.input[consumed..], "leftover differs");
        }
        RefOutcome::Incomplete => {
            assert!(whole.trailers.is_none(), "decoder finished early");
            if c.eof {
                assert_eq!(whole.error, Some(ParseErrorKind::UnexpectedEof));
            } else {
                assert_eq!(whole.error, None, "decoder failed on a valid prefix");
            }
        }
        RefOutcome::Invalid(kind) => {
            assert_eq!(whole.error, Some(kind), "error kinds differ");
        }
    }
});

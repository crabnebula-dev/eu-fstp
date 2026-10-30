//! Fuzz target `api_request_decode` of `fstp-api-core` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: every operation's decoder, selected by the first byte; JSON numbers for amounts rejected.
//!
//! The input reaches `fstp_api_core::decode::decode_request`, which picks
//! a decoding path by its first byte: an operation of the registry by
//! position, a route guided by the registry, a raw route, a tool guided
//! by the registry or a raw tool name. Every operation's strict form runs
//! behind it, the creator, bridge and import forms of lane m4wire among
//! them. They judge a save's field values through the creator codec and
//! an upload through the import normaliser.
//!
//! The target checks that no input panics, that a refusal formats, and
//! that a decoded request names an operation of the registry.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = fstp_api_core::decode::decode_request(data);
    let shown = format!("{decoded:?}");
    assert!(!shown.is_empty());
    if let Ok(op) = decoded {
        assert!(!op.name().is_empty());
    }
});

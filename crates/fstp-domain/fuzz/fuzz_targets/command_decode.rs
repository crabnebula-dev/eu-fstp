//! Fuzz target for the `fstp-domain` command decoder (TH-26, H-05).
//!
//! The input is the JSON form of one core command. The shared oracle in
//! `common` checks that decoding never panics, rejects unknown members at
//! every object, round-trips with stable canonical bytes and accepts one
//! spelling per command. An accepted command also yields its kind and its
//! high-risk and binding flags without panicking.

#![no_main]

mod common;

use fstp_domain::command::Command;
use libfuzzer_sys::fuzz_target;

use common::{Outcome, codec_for, oracle};

fuzz_target!(|data: &[u8]| {
    let codec = codec_for!(Command);
    if let Outcome::Accepted(c) = oracle(&codec, data) {
        let _ = (c.kind(), c.high_risk(), c.binding_action());
        let _ = format!("{c:?}");
    }
});

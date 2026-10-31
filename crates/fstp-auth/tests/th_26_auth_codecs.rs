//! `fstp_auth::codec::{decode_auth_record, decode_auth_command}`: the auth
//! members of the cell ledger envelope (design sections 5.1 and 15, TH-26,
//! H-05).
//!
//! Design section 15 asks of both decoders: no panic on any input, and a
//! round trip. TH-26 asks that every parser refuses what it does not
//! accept with a typed error.
//!
//! Gap, reported by lane W2b's test author: the stub has no
//! `encode_auth_record` or `encode_auth_command`, and design section 5.1
//! fixes no byte layout for the auth member. So no test here can build an
//! accepted input or check the round trip. Proposed: an encoder per
//! decoder, with `decode(encode(x)) == x` for every variant and
//! `encode(decode(b)) == b` for every accepted `b`. These tests then gain
//! the round-trip properties, and the fuzz targets check re-encoding byte
//! for byte. Until then they check only that arbitrary input gets a real
//! answer.
//!
//! Lane W2b test author. Red until lane W2b lands both decoders, because
//! the W0 stub refuses every input with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{assert_refused, real};
use fstp_auth::codec::{decode_auth_command, decode_auth_record};
use fstp_prop::{Gen, check};

/// TH-26: an empty input is no auth record.
#[test]
fn th_26_empty_auth_record_refused() {
    assert_refused("empty record", &decode_auth_record(&[]));
}

/// TH-26: an empty input is no auth command.
#[test]
fn th_26_empty_auth_command_refused() {
    assert_refused("empty command", &decode_auth_command(&[]));
}

/// TH-26: `decode_auth_record` answers every input without a panic, with
/// a record or a typed refusal.
#[test]
fn th_26_auth_record_decode_answers_arbitrary_input() {
    check(
        "th_26_auth_record_decode_answers_arbitrary_input",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=512);
            real("decode_auth_record", &decode_auth_record(&bytes))
        },
    );
}

/// TH-26: `decode_auth_command` answers every input without a panic, with
/// a command or a typed refusal.
#[test]
fn th_26_auth_command_decode_answers_arbitrary_input() {
    check(
        "th_26_auth_command_decode_answers_arbitrary_input",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=512);
            real("decode_auth_command", &decode_auth_command(&bytes))
        },
    );
}

//! Fuzz target `client_data_decode` of `fstp-webauthn` (TH-26, H-05, M3
//! design section 15).
//!
//! Design checks: no panic. The client data is read through `fstp-json`.
//! The first input byte picks the mode. Odd: the rest is the JSON as it
//! is. Even: the rest is spliced into valid client data, so the member
//! checks are reached. For every input:
//!
//! - `parse_client_data` never panics and is deterministic.
//! - Accepted bytes are UTF-8.

#![no_main]

mod common;

use common::{CHALLENGE, Input, client_data, mutate, origin};
use fstp_webauthn::parse_client_data;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let bytes = if input.byte() % 2 == 1 {
        input.0.to_vec()
    } else {
        let mut b = client_data("webauthn.get", &CHALLENGE, &origin());
        mutate(&mut input, &mut b);
        b
    };
    let got = parse_client_data(&bytes);
    assert_eq!(got, parse_client_data(&bytes), "not deterministic");
    if got.is_ok() {
        assert!(
            std::str::from_utf8(&bytes).is_ok(),
            "accepted bytes that are not UTF-8"
        );
    }
});

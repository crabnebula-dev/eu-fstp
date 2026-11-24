//! Fuzz target `guard_link_decode` of `fstp-keyd` (TH-26, H-05, ADR-004
//! record of lane `m10/guard-key`).
//!
//! Design checks: no panic; one spelling only; limits enforced.
//!
//! The input feeds every decoder of the guard: the request and response
//! frames of the guard link, the clear header of a guarded copy, the
//! pilot's guard state, and the custodian's guard file, event file and
//! guard log. An accepted frame, header, state, event or log encodes back
//! to the input. Every refusal has a short display, so no error carries
//! input bytes.

#![no_main]

use fstp_keyd::guard::copy::{HEADER_LEN, decode_guarded, decode_header};
use fstp_keyd::guard::state::decode_state;
use fstp_keyd::guard::store::{decode_event, decode_guard_file, decode_log};
use fstp_keyd::guard::wire::{
    MAX_REQUEST_LEN, MAX_RESPONSE_LEN, decode_guard_request, decode_guard_response,
};
use libfuzzer_sys::fuzz_target;

fn short<E: std::fmt::Display>(e: &E) {
    let shown = e.to_string();
    assert!(!shown.is_empty() && shown.len() <= 512);
}

fuzz_target!(|data: &[u8]| {
    match decode_guard_request(data) {
        Ok(r) => {
            assert!(data.len() <= MAX_REQUEST_LEN);
            assert_eq!(r.encode(), data);
        }
        Err(e) => short(&e),
    }
    match decode_guard_response(data) {
        Ok(r) => {
            assert!(data.len() <= MAX_RESPONSE_LEN);
            assert_eq!(&r.encode().unwrap()[..], data);
        }
        Err(e) => short(&e),
    }
    if let Some(head) = data.first_chunk::<HEADER_LEN>() {
        match decode_header(head) {
            Ok(h) => assert_eq!(&h.encode(), head),
            Err(e) => short(&e),
        }
    }
    match decode_guarded(data) {
        Ok((h, _, rest)) => {
            assert_eq!(&h.encode()[..], &data[..HEADER_LEN]);
            assert!(rest.len() < data.len());
        }
        Err(e) => short(&e),
    }
    match decode_state(data) {
        Ok(s) => assert_eq!(&s.encode()[..], data),
        Err(e) => short(&e),
    }
    match decode_event(data) {
        Ok(ev) => assert_eq!(&ev.encode()[..], data),
        Err(e) => short(&e),
    }
    match decode_log(data) {
        Ok(records) => {
            let again: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();
            assert_eq!(again, data);
        }
        Err(e) => short(&e),
    }
    if let Err(e) = decode_guard_file(data) {
        short(&e);
    }
});

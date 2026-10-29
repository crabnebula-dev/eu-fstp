//! Teeth of the oracle: the reference encoding in `common::wire` is
//! RFC 8785 canonical JSON (design section 6.2, H-05).
//!
//! The codec tests compare the decoder with `common::wire`. If the
//! reference wrote a non-canonical spelling, a decoder that keeps one
//! spelling would be wrongly red. So this test parses every reference
//! message with `fstp_json` and checks that its canonical serialisation
//! is the same bytes. It is green on the W0 stub, by design.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{gen_request, gen_response, wire};
use fstp_prop::{Gen, prop_assert_eq};

fn canonical(bytes: &[u8]) -> Result<String, String> {
    let v = fstp_json::parse(bytes).map_err(|e| format!("parse: {e:?}"))?;
    fstp_json::to_canonical(&v).map_err(|e| format!("canonical: {e:?}"))
}

/// H-05: every reference request and response is canonical JSON.
#[test]
fn th_26_reference_messages_are_canonical_json() {
    fstp_prop::check(
        "th_26_reference_messages_are_canonical_json",
        |g: &mut Gen| {
            let req = wire::request(&gen_request(g));
            prop_assert_eq!(canonical(&req)?, String::from_utf8_lossy(&req).into_owned());
            let res = wire::response(&gen_response(g));
            prop_assert_eq!(canonical(&res)?, String::from_utf8_lossy(&res).into_owned());
            Ok(())
        },
    );
}

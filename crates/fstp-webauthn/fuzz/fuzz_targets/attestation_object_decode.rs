//! Fuzz target `attestation_object_decode` of `fstp-webauthn` (TH-26,
//! H-05, M3 design section 15, ADR-008 "Attestation").
//!
//! Design checks: no panic; depth and size limits; non-shortest forms and
//! duplicate keys refused. The first input byte picks the mode. Odd: the
//! rest is the object as it is. Even: the rest is spliced into a valid
//! `none` object. For every input:
//!
//! - `parse_attestation_object` never panics and is deterministic.
//! - An accepted object is strict CBOR: a map of exactly `fmt` = `none`,
//!   `attStmt` = the empty map and `authData` bytes.
//! - The reported authenticator data is what `parse_authenticator_data`
//!   reports for those bytes.

#![no_main]

mod common;

use common::{AT, CRED_ID, Input, UP, UV, auth_data, ed25519_cose, mutate, none_attestation};
use fstp_webauthn::cbor::{self, Item};
use fstp_webauthn::{parse_attestation_object, parse_authenticator_data};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let bytes = if input.byte() % 2 == 1 {
        input.0.to_vec()
    } else {
        let cose = ed25519_cose(&[0x33; 32]);
        let mut b = none_attestation(&auth_data(UP | UV | AT, 0, Some((&CRED_ID, &cose))));
        mutate(&mut input, &mut b);
        b
    };
    let got = parse_attestation_object(&bytes);
    assert_eq!(got, parse_attestation_object(&bytes), "not deterministic");
    let Ok(obj) = got else {
        return;
    };
    let Ok(Item::Map(pairs)) = cbor::decode(&bytes) else {
        panic!("accepted an object that is not one strict CBOR map");
    };
    assert_eq!(
        pairs.len(),
        3,
        "accepted an object with {} members",
        pairs.len()
    );
    let member = |name: &str| {
        pairs.iter().find_map(|(k, v)| match k {
            Item::Text(k) if k == name => Some(v.clone()),
            _ => None,
        })
    };
    assert_eq!(member("fmt"), Some(Item::Text("none".to_owned())));
    assert_eq!(member("attStmt"), Some(Item::Map(Vec::new())));
    let Some(Item::Bytes(ad)) = member("authData") else {
        panic!("accepted an object without authData bytes");
    };
    assert_eq!(parse_authenticator_data(&ad), Ok(obj.auth_data));
});

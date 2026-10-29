//! Fuzz target `registration_verify` of `fstp-webauthn` (TH-26, H-05, M3
//! design section 15, I-20, ADR-008).
//!
//! Design checks: no panic; depth and size limits. The input draws edits
//! to the client data and the attestation object of a valid Ed25519
//! registration. A registration carries no signature (`none`), so an
//! edit to the credential id or key bytes can still verify. For every
//! input:
//!
//! - `verify_registration` never panics and is deterministic.
//! - An accepted registration has client data of type `webauthn.create`
//!   with the expected challenge and origin, and authenticator data with
//!   the cell's RP id hash and UP and AT set, and UV set when the
//!   expectation requires it.
//! - The returned credential id and key are those of the attested
//!   credential data, the counter is the data's counter, and
//!   `user_verified` is the UV flag.

#![no_main]

mod common;

use common::{AT, CHALLENGE, ED, HOST, Input, UP, UV, mutate, origin, registration};
use fstp_webauthn::cbor::{self, Item};
use fstp_webauthn::{
    parse_attestation_object, parse_client_data, parse_cose_key, verify_registration,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let uv_required = input.byte().is_multiple_of(2);
    let Some((mut resp, expect)) = registration(uv_required) else {
        return;
    };
    mutate(&mut input, &mut resp.client_data_json);
    mutate(&mut input, &mut resp.attestation_object);
    let got = verify_registration(&resp, &expect);
    assert_eq!(
        got,
        verify_registration(&resp, &expect),
        "not deterministic"
    );
    let Ok(cred) = got else {
        return;
    };
    let cd = parse_client_data(&resp.client_data_json).expect("accepted client data parses");
    assert_eq!(cd.kind, "webauthn.create");
    assert_eq!(cd.challenge, CHALLENGE);
    assert_eq!(cd.origin, origin());
    let ao = parse_attestation_object(&resp.attestation_object).expect("accepted object parses");
    assert_eq!(
        ao.auth_data.rp_id_hash,
        fstp_crypto::sha256(HOST.as_bytes())
    );
    assert_ne!(ao.auth_data.flags & UP, 0, "accepted without UP");
    assert_ne!(ao.auth_data.flags & AT, 0, "accepted without AT");
    if uv_required {
        assert_ne!(ao.auth_data.flags & UV, 0, "accepted without required UV");
    }
    assert_eq!(
        cred.user_verified,
        ao.auth_data.flags & UV != 0,
        "reported another UV"
    );
    assert_eq!(cred.sign_count, ao.auth_data.sign_count);
    // The attested credential data: 37 fixed bytes, a 16-byte AAGUID, a
    // 2-byte id length, the id, then the COSE key.
    let Ok(Item::Map(pairs)) = cbor::decode(&resp.attestation_object) else {
        panic!("accepted an object that is not one strict CBOR map");
    };
    let Some(ad) = pairs.iter().find_map(|(k, v)| match (k, v) {
        (Item::Text(k), Item::Bytes(b)) if k == "authData" => Some(b.clone()),
        _ => None,
    }) else {
        panic!("accepted an object without authData bytes");
    };
    let len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
    assert_eq!(cred.id, ad[55..55 + len], "returned another credential id");
    if ao.auth_data.flags & ED == 0 {
        assert_eq!(
            parse_cose_key(&ad[55 + len..]),
            Ok(cred.key),
            "returned another key"
        );
    }
});

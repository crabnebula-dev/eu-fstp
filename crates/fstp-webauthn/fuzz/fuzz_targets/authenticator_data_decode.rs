//! Fuzz target `authenticator_data_decode` of `fstp-webauthn` (TH-26,
//! H-05, M3 design section 15).
//!
//! Design checks: no panic; size limits. The first input byte picks the
//! mode. Odd: the rest is the authenticator data as it is. Even: the rest
//! is spliced into valid registration data with an Ed25519 key, so the
//! attested credential parser is reached. For every input:
//!
//! - `parse_authenticator_data` never panics and is deterministic.
//! - Accepted data is at least 37 bytes, and its fields are the first 37
//!   bytes: the RP id hash, the flags and the big-endian counter.
//! - Accepted data with AT and ED clear is exactly 37 bytes.

#![no_main]

mod common;

use common::{AT, CRED_ID, ED, Input, UP, UV, auth_data, ed25519_cose, mutate};
use fstp_webauthn::parse_authenticator_data;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let bytes = if input.byte() % 2 == 1 {
        input.0.to_vec()
    } else {
        let cose = ed25519_cose(&[0x33; 32]);
        let mut b = auth_data(UP | UV | AT, 1, Some((&CRED_ID, &cose)));
        mutate(&mut input, &mut b);
        b
    };
    let got = parse_authenticator_data(&bytes);
    assert_eq!(got, parse_authenticator_data(&bytes), "not deterministic");
    let Ok(ad) = got else {
        return;
    };
    assert!(bytes.len() >= 37, "accepted {} bytes", bytes.len());
    assert_eq!(ad.rp_id_hash[..], bytes[..32]);
    assert_eq!(ad.flags, bytes[32]);
    assert_eq!(ad.sign_count.to_be_bytes()[..], bytes[33..37]);
    if ad.flags & (AT | ED) == 0 {
        assert_eq!(
            bytes.len(),
            37,
            "accepted trailing bytes with AT and ED clear"
        );
    }
});

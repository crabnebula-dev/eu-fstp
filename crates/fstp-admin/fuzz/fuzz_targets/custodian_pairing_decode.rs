//! Fuzz target `custodian_pairing_decode` (ADR-028 record of lane
//! `m10/guard-key`): the pairing file that `fstp-admin custodian` reads on
//! the second custodian's machine.
//!
//! Design checks: no panic; an accepted file encodes to a file that
//! decodes to the same pairing; every refusal has a short display, so no
//! error carries input bytes.

#![no_main]

use fstp_admin::custodian::{MAX_PAIRING_LEN, decode_pairing};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_pairing(data) {
        Ok(p) => {
            assert!(data.len() <= MAX_PAIRING_LEN);
            assert_eq!(decode_pairing(p.encode().as_bytes()).ok(), Some(p));
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(!shown.is_empty() && shown.len() <= 128);
        }
    }
});

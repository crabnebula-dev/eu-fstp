//! Fuzz target `snapshot_status_decode` (ADR-012 record of lane L27): the
//! keystore snapshot status file that `fstp-admin status` reads.
//!
//! Design checks: no panic, and one spelling only: an accepted file
//! encodes back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = fstp_obs::snapshot_status::decode(data) {
        assert_eq!(fstp_obs::snapshot_status::encode(&s).as_bytes(), data);
    }
});

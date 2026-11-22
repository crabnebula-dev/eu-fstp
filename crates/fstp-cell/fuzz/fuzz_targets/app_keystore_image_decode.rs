//! Fuzz target `app_keystore_image_decode` of `fstp-cell` (H-05, ADR-012
//! records of lanes L27 and L26): the App keystore snapshot image `"FAK1"`.
//!
//! Design checks: no panic, and one spelling only: an accepted version 2
//! image encodes back to the same bytes. An accepted version 1 image, which
//! has no display name section, encodes as version 2 with an empty one.

#![no_main]

use fstp_cell::tasks::erasure::rows_image::{VERSION, VERSION_1, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((cell, rows)) = decode(data) {
        let again = encode(cell, &rows).unwrap();
        if data.get(4) == Some(&VERSION_1) {
            let mut want = data.to_vec();
            want[4] = VERSION;
            want.extend_from_slice(&0u32.to_be_bytes());
            assert_eq!(again, want);
        } else {
            assert_eq!(again, data);
        }
    }
});

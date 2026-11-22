//! Fuzz target `host_status_decode` of `fstp-obs` (TH-26, H-05, R-NF-02,
//! ADR-028 record of lane L20).
//!
//! Design checks: no panic; the length limit holds; deterministic. A
//! decoded file encodes back to a file that decodes to the same status,
//! and that file holds no string but member names and closed words.

#![no_main]

use fstp_obs::host_status::{MAX_LEN, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode(data);
    assert_eq!(first, decode(data), "not deterministic");
    if let Ok(s) = first {
        assert!(data.len() <= MAX_LEN);
        let text = encode(&s);
        assert!(text.len() <= MAX_LEN);
        assert_eq!(decode(text.as_bytes()), Ok(s), "no round trip");
        assert!(
            text.bytes().all(|b| b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b"{}[]\":,_-\n".contains(&b)),
            "an unexpected byte"
        );
    }
});

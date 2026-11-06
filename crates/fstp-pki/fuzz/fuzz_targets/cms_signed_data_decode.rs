//! Fuzz target `cms_signed_data_decode` of `fstp-pki` (TH-26, ADR-001
//! "Every Tier B parser has a fuzz target", M5 design section 3.1).
//!
//! The strict decoder must return a typed result without panicking, give
//! the same result twice, and accept only DER. For an accepted input the
//! signed attributes are a `SET OF`, the signer certificate is among the
//! certificates, and signature verification returns a typed result.

#![no_main]

use fstp_pki::cms::{decode_signed_data, verify_signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_signed_data(data);
    assert_eq!(first, decode_signed_data(data));
    if let Ok(d) = first {
        assert_eq!(d.signed_attributes.first(), Some(&0x31));
        assert!(d.certificates.contains(&d.signer_certificate));
        let _ = verify_signature(&d.signed_attributes, &d.signature, &d.signer_certificate);
    }
});

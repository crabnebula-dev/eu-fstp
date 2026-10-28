//! Fuzz target `cert_build_roundtrip` of `fstp-pki` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: arbitrary names, serials and lifetimes build certificates that rustls-webpki parses with equal fields.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W1i lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use fstp_pki::cert::{
        CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, tbs,
    };
    let serial = data.get(..data.len().min(20)).unwrap_or_default().to_vec();
    let name = String::from_utf8_lossy(data.get(20..).unwrap_or_default()).into_owned();
    let mut seconds = [0u8; 8];
    for (slot, b) in seconds.iter_mut().zip(data.iter()) {
        *slot = *b;
    }
    let not_before = i64::from_le_bytes(seconds);
    let spec = CertSpec {
        serial,
        issuer: DistinguishedName {
            common_name: name.clone(),
        },
        subject: DistinguishedName { common_name: name },
        validity: Validity {
            not_before,
            not_after: not_before.saturating_add(86_400),
        },
        spki_der: data.to_vec(),
        ca: data.first().is_some_and(|b| b & 1 == 1),
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    match tbs(&spec) {
        Ok(t) => {
            let shown = format!("{:?}", assemble(&t, data));
            assert!(!shown.is_empty());
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});

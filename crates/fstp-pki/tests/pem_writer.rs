//! The in-house PEM writer (design section 1.3: PostgreSQL reads
//! certificates as PEM, and `fstp-pki::pem` writes it with an encoder-only
//! base64).
//!
//! Each output must equal the independent strict RFC 7468 writer in
//! `common::pem`. Design section 1.3 also names a decode check with
//! `fstp_pgwire::base64::decode` in `fstp-celltest`. That test needs a
//! `fstp-pgwire` edge from `fstp-celltest`, which is outside this lane's
//! files (lane report). Layering rule 1 keeps the edge out of `fstp-pki`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::keys::EcKey;
use common::profile::{ca_profile, pki_issue};
use common::time::{DAY, T0};
use fstp_pki::pem::{PemLabel, encode};
use fstp_prop::{Config, check_with, prop_assert_eq};

/// Design section 1.3: `encode(Certificate, der)` equals the strict PEM of
/// RFC 7468 section 2 for any DER bytes: the label lines, base64 lines of
/// 64 characters, LF line ends.
#[test]
fn pem_certificate_matches_the_strict_rfc7468_reference() {
    check_with(
        "pem_certificate_matches_the_strict_rfc7468_reference",
        Config::default().with_cases(512),
        |g| {
            let der = g.bytes(1..=400);
            g.note("der", &der);
            let pem = encode(PemLabel::Certificate, &der).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(pem, common::pem::pem("CERTIFICATE", &der));
            Ok(())
        },
    );
}

/// Design section 1.3: the `CERTIFICATE REQUEST` label is written the same
/// way.
#[test]
fn pem_certificate_request_label_matches_the_reference() {
    let der = [0x30, 0x03, 0x02, 0x01, 0x00];
    let pem = encode(PemLabel::CertificateRequest, &der).expect("fstp-pki writes PEM");
    assert_eq!(pem, common::pem::pem("CERTIFICATE REQUEST", &der));
}

/// Line breaks fall exactly at 64 characters: 48 bytes give one full line,
/// 49 bytes a full line and a short one.
#[test]
fn pem_line_breaks_fall_at_64_characters() {
    for n in [47usize, 48, 49, 96, 97] {
        let der = vec![0xa5; n];
        let pem = encode(PemLabel::Certificate, &der).expect("fstp-pki writes PEM");
        assert_eq!(pem, common::pem::pem("CERTIFICATE", &der), "{n} bytes");
    }
}

/// Design section 1.3: the PEM of a real certificate equals the reference,
/// so PostgreSQL reads the same DER that rustls-webpki checked.
#[test]
fn pem_of_a_built_certificate_matches_the_reference() {
    let key = EcKey::generate();
    let cert = pki_issue(&ca_profile("fstp cluster CA 01", &key, T0, T0 + DAY), &key)
        .expect("fstp-pki writes the certificate");
    let pem = encode(PemLabel::Certificate, &cert).expect("fstp-pki writes PEM");
    assert_eq!(pem, common::pem::pem("CERTIFICATE", &cert));
}

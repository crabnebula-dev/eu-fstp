//! Self-tests for the test cluster CA of `fstp-pgtest` (M3 design sections
//! 1.3 and 2.2, lane W1a). They need no server. Written test first: the CA
//! refuses until lane W1a lands it on the `fstp-pki` writer (lane W1i) and
//! the `fstp-crypto` signing module (lane W1h).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_pgtest::certs::{ClusterCa, IssuedCert};

/// Whether `pem` is exactly one PEM block with `label`, as PostgreSQL
/// reads it.
fn one_block(pem: &[u8], label: &str) -> bool {
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("-----END {label}-----\n");
    text.starts_with(&begin) && text.ends_with(&end) && text.matches("-----BEGIN").count() == 1
}

/// Design section 1.3: a cluster CA certificate is one PEM certificate.
#[test]
fn pgtest_cluster_ca_certificate_is_one_pem_block() {
    let ca = ClusterCa::generate("pgtest-ca").unwrap();
    assert_eq!(ca.name(), "pgtest-ca");
    assert!(
        one_block(ca.cert_pem(), "CERTIFICATE"),
        "{}",
        String::from_utf8_lossy(ca.cert_pem())
    );
}

/// B1, design section 1.3: two CAs with the same name are still two CAs.
#[test]
fn b1_cluster_cas_are_distinct_per_generation() {
    let a = ClusterCa::generate("same-name").unwrap();
    let b = ClusterCa::generate("same-name").unwrap();
    assert_ne!(a.cert_pem(), b.cert_pem());
}

/// Design section 1.3: each role certificate is one PEM certificate with a
/// PKCS#8 private key, and every issue draws a fresh key pair.
#[test]
fn pgtest_role_certificates_are_pem_with_fresh_keys() {
    let ca = ClusterCa::generate("pgtest-ca").unwrap();
    let a = ca.issue_role("fresh_key_role").unwrap();
    let b = ca.issue_role("fresh_key_role").unwrap();
    assert!(one_block(&a.cert_pem, "CERTIFICATE"));
    assert!(one_block(&a.key_pem, "PRIVATE KEY"));
    assert_ne!(a.key_pem, b.key_pem);
    assert_ne!(a.cert_pem, b.cert_pem);
}

/// Design section 1.3: a server certificate is one PEM certificate with a
/// PKCS#8 private key.
#[test]
fn pgtest_server_certificate_is_pem() {
    let ca = ClusterCa::generate("pgtest-ca").unwrap();
    let server = ca.issue_server("vault").unwrap();
    assert!(one_block(&server.cert_pem, "CERTIFICATE"));
    assert!(one_block(&server.key_pem, "PRIVATE KEY"));
}

/// The private key never appears in `IssuedCert`'s `Debug` output.
#[test]
fn issued_cert_debug_hides_the_key() {
    let issued = IssuedCert {
        cert_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
        key_pem: b"-----BEGIN PRIVATE KEY-----secret-key-bytes".to_vec(),
    };
    let shown = format!("{issued:?}");
    assert!(!shown.contains("secret-key-bytes"), "{shown}");
}

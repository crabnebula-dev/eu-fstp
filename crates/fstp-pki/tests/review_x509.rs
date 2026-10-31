//! Reviewer reproducers for the W1i X.509 writer (lens: X.509
//! correctness). Each test fails against the code under review and passes
//! once the named defect is fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::keys::EcKey;
use common::oracle;
use common::profile::{
    BuildError, Dn, Profile, Usage, ca_profile, client_profile, contains, pki_issue, pki_tbs,
};
use common::time::{DAY, T0};

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";
const ROLE: &str = "c_0123456789abcdef0123456789abcdef_app";

/// `id-ce-subjectKeyIdentifier` (2.5.29.14) as an encoded extnID.
const OID_SKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0e];
/// `id-ce-authorityKeyIdentifier` (2.5.29.35) as an encoded extnID.
const OID_AKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x23];

/// ADR-005 "Role certificates" (CA rollover with overlap), RFC 5280
/// sections 4.2.1.1 and 4.2.1.2. A CA certificate must carry a
/// subjectKeyIdentifier. A certificate it issues must carry an
/// authorityKeyIdentifier with a keyIdentifier.
///
/// Without them, OpenSSL picks an issuer by name alone. During a rollover
/// overlap the old and new cluster CA share one name. PostgreSQL then
/// tries the first CA in its root file and refuses half of the role
/// certificates with "certificate signature failure". `openssl verify
/// -x509_strict` also refuses every leaf with "Missing Authority Key
/// Identifier".
#[test]
fn review_ca_has_ski_and_leaf_has_aki() {
    let ca_key = EcKey::generate();
    let ca = pki_issue(
        &ca_profile(CLUSTER_CA, &ca_key, T0 - DAY, T0 + 400 * DAY),
        &ca_key,
    )
    .expect("fstp-pki writes the CA");
    let leaf_key = EcKey::generate();
    let leaf = pki_issue(
        &client_profile(CLUSTER_CA, ROLE, &leaf_key, T0, T0 + DAY),
        &ca_key,
    )
    .expect("fstp-pki writes the role certificate");
    assert!(
        contains(&ca, OID_SKI),
        "the CA certificate has no subjectKeyIdentifier (RFC 5280 4.2.1.2 MUST)"
    );
    assert!(
        contains(&leaf, OID_AKI),
        "the role certificate has no authorityKeyIdentifier (RFC 5280 4.2.1.1 MUST)"
    );
}

/// R-NF-09, RFC 5280 section 4.2.1.6 with RFC 1123 section 2.1: a
/// `dNSName` is never a dotted-decimal address, and its last label is
/// never all digits. rustls-webpki, the design's oracle (section 1.3),
/// drops such an entry. So `fstp-pki` must refuse it, or rustls-webpki
/// must read it back. Today `fstp-pki` writes it and rustls-webpki drops
/// it, so the server certificate silently matches no name.
#[test]
fn review_numeric_last_label_dns_name_is_refused_or_round_trips() {
    let ca_key = EcKey::generate();
    for name in ["127.0.0.1", "10.1.2.3", "pg.1", "42"] {
        let key = EcKey::generate();
        let p = Profile {
            serial: vec![0x21; 16],
            issuer: Dn::cn(CLUSTER_CA),
            subject: Dn {
                cn: "pg-vault-1".to_owned(),
                ou: Some("vault".to_owned()),
            },
            not_before: T0,
            not_after: T0 + DAY,
            spki_der: key.spki_der(),
            issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
            usage: Usage::Server,
            dns_names: vec![name.to_owned()],
            ip_addrs: Vec::new(),
        };
        match pki_tbs(&p) {
            Err(BuildError::Pki(_)) => continue,
            Err(e) => panic!("{name}: unexpected build error {e:?}"),
            Ok(_) => {}
        }
        let der = pki_issue(&p, &ca_key).expect("accepted above");
        let read = oracle::read(&der).expect("rustls-webpki parses the certificate");
        assert_eq!(
            read.dns_names,
            vec![name.to_owned()],
            "fstp-pki wrote dNSName {name:?}, which rustls-webpki does not read back"
        );
    }
}

/// Review round 2, finding 4, RFC 5280 section 4.2.1.1: only a
/// self-signed certificate may leave out the authorityKeyIdentifier, and
/// in this profile only a CA is self-signed. A server or client
/// certificate whose names equal each other is still issued by a CA, so
/// it is refused without an issuer key identifier. Without the AKI,
/// OpenSSL would pick among same-name CAs by name alone.
#[test]
fn review_end_entity_with_equal_names_needs_an_issuer_key_id() {
    for usage in [Usage::Server, Usage::Client] {
        let key = EcKey::generate();
        let mut p = client_profile(CLUSTER_CA, CLUSTER_CA, &key, T0, T0 + DAY);
        p.usage = usage;
        p.issuer_key_id = None;
        let r = pki_tbs(&p);
        assert_eq!(
            r,
            Err(BuildError::Pki(fstp_pki::PkiError::IssuerKeyIdMissing)),
            "{usage:?}"
        );
    }
    // A self-signed CA still needs none.
    let ca_key = EcKey::generate();
    let r = pki_tbs(&ca_profile(CLUSTER_CA, &ca_key, T0, T0 + DAY));
    assert!(r.is_ok(), "{r:?}");
}

/// Review round 2, finding 5, I-83, design section 9.2, ADR-011: the
/// start-up check refuses a server certificate whose OU is not the
/// expected kind, without knowing the server's CN. The exported OU RDN is
/// the first RDN of the subject rustls-webpki reads, for every kind. A
/// subject of another kind, or with no OU, does not start with it.
#[test]
fn review_i83_cluster_kind_ou_rdn_prefixes_the_webpki_subject() {
    use fstp_pki::cert::{ClusterKindOu, cluster_kind_ou_rdn};
    let ca_key = EcKey::generate();
    let issue = |ou: Option<&str>| {
        let mut p = client_profile(
            CLUSTER_CA,
            "pg-1.cluster.test",
            &EcKey::generate(),
            T0,
            T0 + DAY,
        );
        p.usage = Usage::Server;
        p.subject.ou = ou.map(str::to_owned);
        let der = pki_issue(&p, &ca_key).expect("fstp-pki writes the server certificate");
        oracle::read(&der).expect("rustls-webpki parses it").subject
    };
    for kind in ClusterKindOu::ALL {
        let rdn = cluster_kind_ou_rdn(kind);
        assert_eq!(
            rdn,
            der_ou_rdn(kind.as_str()),
            "{kind:?}: the RDN differs from the reference encoding"
        );
        for other in ClusterKindOu::ALL {
            let subject = issue(Some(other.as_str()));
            assert_eq!(
                subject.starts_with(&rdn),
                kind == other,
                "{kind:?} vs {other:?}"
            );
        }
        assert!(!issue(None).starts_with(&rdn), "{kind:?}: no OU");
    }
}

/// The reference OU RDN: `SET { SEQUENCE { id-at-organizationalUnitName,
/// UTF8String } }`.
fn der_ou_rdn(ou: &str) -> Vec<u8> {
    use common::der;
    der::set_of_one(&der::seq(&[der::OID_OU, &der::utf8_string(ou)]))
}

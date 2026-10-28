//! The extensions and name markers of each certificate kind (design
//! sections 1.3 and 4.1, ADR-005 "Role certificates", ADR-009, I-83).
//!
//! rustls-webpki has no accessor for key usage, extended key usage or
//! basic constraints. So each test asks the independent writer in
//! `common::der` for the exact Extension encoding of the reference profile
//! and checks that the TBS holds it. DER has one encoding per value, so a
//! match means the extension says exactly that.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::der;
use common::keys::EcKey;
use common::profile::{
    Dn, Profile, Usage, ca_profile, client_profile, contains, pki_issue, pki_tbs, real_refusal,
};
use common::time::{DAY, T0};

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";
const ROLE: &str = "c_0123456789abcdef0123456789abcdef_writer";

/// Why an extension test can still fail after `fstp-pki` lands: the W0
/// stub `CertSpec` states the usage only as `ca: bool`.
const USAGE_GAP: &str = "the TBS lacks the extension; note that the W0 CertSpec has no \
                         server or client usage field yet (lane W1i report, API gap)";

fn ca_tbs() -> Vec<u8> {
    let key = EcKey::generate();
    pki_tbs(&ca_profile(CLUSTER_CA, &key, T0, T0 + 365 * DAY)).expect("fstp-pki writes a CA TBS")
}

fn client_tbs() -> Vec<u8> {
    let key = EcKey::generate();
    pki_tbs(&client_profile(CLUSTER_CA, ROLE, &key, T0, T0 + DAY))
        .expect("fstp-pki writes a client TBS")
}

fn server_profile(kind: &str) -> Profile {
    let key = EcKey::generate();
    Profile {
        serial: vec![0x21; 16],
        issuer: Dn::cn(CLUSTER_CA),
        subject: Dn {
            cn: format!("pg-{kind}-1.cluster.test"),
            ou: Some(kind.to_owned()),
        },
        not_before: T0,
        not_after: T0 + DAY,
        spki_der: key.spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: vec![format!("pg-{kind}-1.cluster.test")],
        ip_addrs: Vec::new(),
    }
}

/// ADR-009, design section 1.3: a cluster CA has critical basicConstraints
/// with `cA TRUE` and `pathLenConstraint 0`, since it signs only role and
/// server certificates of its own cluster (B1).
#[test]
fn adr009_ca_has_critical_basic_constraints_ca_true_path_len_zero() {
    let ext = der::extension(der::OID_BC, true, &der::basic_constraints_ca());
    assert!(contains(&ca_tbs(), &ext));
}

/// ADR-009: a cluster CA has critical keyUsage `keyCertSign` only.
#[test]
fn adr009_ca_has_critical_key_usage_key_cert_sign_only() {
    let ext = der::extension(der::OID_KU, true, &der::key_usage_ca());
    assert!(contains(&ca_tbs(), &ext));
}

/// ADR-005 D2: a role certificate is an end entity. Its critical
/// basicConstraints leave `cA` false.
#[test]
fn adr005_d2_role_certificate_has_end_entity_basic_constraints() {
    let ext = der::extension(der::OID_BC, true, &der::basic_constraints_leaf());
    let tbs = client_tbs();
    assert!(contains(&tbs, &ext));
    let ca_ext = der::extension(der::OID_BC, true, &der::basic_constraints_ca());
    assert!(!contains(&tbs, &ca_ext));
}

/// ADR-005 D2: a role certificate has critical keyUsage
/// `digitalSignature` only, so it can never sign a certificate.
#[test]
fn adr005_d2_role_certificate_has_digital_signature_key_usage_only() {
    let ext = der::extension(der::OID_KU, true, &der::key_usage_leaf());
    assert!(contains(&client_tbs(), &ext));
}

/// ADR-005 D2, R-NF-09: a role certificate has extKeyUsage `clientAuth`
/// and not `serverAuth`.
#[test]
fn adr005_d2_role_certificate_has_client_auth_extended_key_usage() {
    let tbs = client_tbs();
    let client = der::ext_key_usage(der::OID_KP_CLIENT);
    assert!(contains(&tbs, &client), "{USAGE_GAP}");
    assert!(!contains(&tbs, der::OID_KP_SERVER));
}

/// R-NF-09, ADR-005: a cluster server certificate has extKeyUsage
/// `serverAuth` and not `clientAuth`.
#[test]
fn r_nf_09_server_certificate_has_server_auth_extended_key_usage() {
    let mut p = server_profile("application");
    // The SAN and OU have their own tests; this one checks the usage.
    p.dns_names.clear();
    p.subject.ou = None;
    let tbs = pki_tbs(&p).expect("fstp-pki writes a server TBS");
    let server = der::ext_key_usage(der::OID_KP_SERVER);
    assert!(contains(&tbs, &server), "{USAGE_GAP}");
    assert!(!contains(&tbs, der::OID_KP_CLIENT));
}

/// ADR-009: a CA certificate names no extended key usage purpose.
#[test]
fn adr009_ca_has_no_extended_key_usage() {
    let tbs = ca_tbs();
    assert!(!contains(&tbs, der::OID_EKU));
}

/// I-83, design sections 1.3 and 9.2: each cluster kind appears as the
/// subject OU of its server certificate, encoded as the reference Name.
#[test]
fn i83_server_certificate_subject_carries_the_cluster_kind_ou() {
    for kind in ["application", "vault", "witness"] {
        let mut p = server_profile(kind);
        p.dns_names.clear();
        let tbs = pki_tbs(&p).expect("fstp-pki writes a server TBS");
        let subject = der::name(&p.subject.cn, Some(kind));
        assert!(contains(&tbs, &subject), "kind {kind}");
    }
}

/// I-83: the OU of an application cluster never reads as `vault`. Teeth
/// for the start-up check of design section 9.2, which compares the OU.
#[test]
fn i83_application_server_certificate_has_no_vault_ou() {
    let mut p = server_profile("application");
    p.dns_names.clear();
    let tbs = pki_tbs(&p).expect("fstp-pki writes a server TBS");
    let vault_ou = der::seq(&[der::OID_OU, &der::utf8_string("vault")]);
    assert!(!contains(&tbs, &vault_ou));
}

/// R-NF-09, design section 1.3: a server certificate carries its DNS
/// names in a subjectAltName, encoded as the reference writes it.
#[test]
fn r_nf_09_server_certificate_has_the_reference_subject_alt_name() {
    let p = server_profile("vault");
    let tbs = pki_tbs(&p).expect("fstp-pki writes a server TBS");
    let san = der::subject_alt_name(&p.dns_names, &p.ip_addrs);
    assert!(contains(&tbs, &der::octet_string(&san)));
}

/// RFC 5280 section 4.2.1.2, ADR-005 "Role certificates": a CA
/// certificate carries a non-critical subjectKeyIdentifier, the RFC 7093
/// method 1 identifier of its own key.
#[test]
fn adr005_ca_has_the_subject_key_identifier_of_its_key() {
    let key = EcKey::generate();
    let tbs = pki_tbs(&ca_profile(CLUSTER_CA, &key, T0, T0 + 365 * DAY))
        .expect("fstp-pki writes a CA TBS");
    let ext = der::extension(
        der::OID_SKI,
        false,
        &der::subject_key_identifier(&key.key_id()),
    );
    assert!(contains(&tbs, &ext));
}

/// RFC 5280 section 4.2.1.1, ADR-005 "Role certificates": a role
/// certificate carries a non-critical authorityKeyIdentifier equal to the
/// subjectKeyIdentifier of the cluster CA that signed it. During a CA
/// rollover the old and new CA share one name, and this is how a verifier
/// tells them apart.
#[test]
fn adr005_role_certificate_names_the_key_of_its_cluster_ca() {
    let ca_key = EcKey::generate();
    let ca = pki_issue(
        &ca_profile(CLUSTER_CA, &ca_key, T0, T0 + 365 * DAY),
        &ca_key,
    )
    .expect("fstp-pki writes the CA");
    let leaf = pki_issue(
        &client_profile(CLUSTER_CA, ROLE, &EcKey::generate(), T0, T0 + DAY),
        &ca_key,
    )
    .expect("fstp-pki writes the role certificate");
    let aki = der::extension(
        der::OID_AKI,
        false,
        &der::authority_key_identifier(&ca_key.key_id()),
    );
    let ski = der::extension(
        der::OID_SKI,
        false,
        &der::subject_key_identifier(&ca_key.key_id()),
    );
    assert!(contains(&leaf, &aki), "the leaf names another key");
    assert!(contains(&ca, &ski), "the CA states another key");
}

/// RFC 5280 section 4.2.1.1: only a self-signed certificate may leave the
/// authorityKeyIdentifier out. A self-signed cluster CA has none, and a
/// role certificate without an issuer key identifier is refused.
#[test]
fn adr005_certificate_without_issuer_key_id_is_refused_unless_self_signed() {
    let key = EcKey::generate();
    let ca = pki_tbs(&ca_profile(CLUSTER_CA, &key, T0, T0 + DAY)).expect("a self-signed CA");
    assert!(!contains(&ca, der::OID_AKI));
    let mut leaf = client_profile(CLUSTER_CA, ROLE, &EcKey::generate(), T0, T0 + DAY);
    leaf.issuer_key_id = None;
    let r = pki_tbs(&leaf);
    assert!(real_refusal(&r), "{r:?}");
}

/// I-83, design section 9.2: a server certificate's OU is one of the
/// closed cluster kind markers. A near miss such as `Vault` is refused at
/// issue, not only later at the vault's start-up check.
#[test]
fn i83_server_certificate_ou_outside_the_cluster_kinds_is_refused() {
    for ou in ["Vault", "vault ", "app", "applications", "x"] {
        let mut p = server_profile("vault");
        p.dns_names.clear();
        p.subject.ou = Some(ou.to_owned());
        let r = pki_tbs(&p);
        assert!(real_refusal(&r), "{ou:?}: {r:?}");
    }
}

/// I-83: every closed cluster kind marker is accepted as a server OU, and
/// each spells the kind of design section 4.1.
#[test]
fn i83_every_cluster_kind_marker_is_a_valid_server_ou() {
    use fstp_pki::cert::{ClusterKindOu, DistinguishedName};
    let spelled: Vec<&str> = ClusterKindOu::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(spelled, ["application", "vault", "control", "witness"]);
    for kind in ClusterKindOu::ALL {
        let dn = DistinguishedName::cluster_server(kind, "pg-1.cluster.test");
        let mut p = server_profile(kind.as_str());
        p.dns_names.clear();
        p.subject.ou = dn.organizational_unit.clone();
        let tbs = pki_tbs(&p).expect("fstp-pki writes a server TBS");
        assert!(contains(
            &tbs,
            &der::name(&p.subject.cn, Some(kind.as_str()))
        ));
    }
}

/// R-NF-09, RFC 5280 section 4.2.1.6 with RFC 1123 section 2.1: a
/// `dNSName` whose last label is all digits is refused, so an IP literal
/// never hides in a DNS entry that rustls-webpki would drop.
#[test]
fn r_nf_09_dns_name_with_an_all_numeric_last_label_is_refused() {
    for name in ["127.0.0.1", "10.1.2.3", "pg.1", "42"] {
        let mut p = server_profile("vault");
        p.dns_names = vec![name.to_owned()];
        let r = pki_tbs(&p);
        assert!(real_refusal(&r), "{name}: {r:?}");
    }
}

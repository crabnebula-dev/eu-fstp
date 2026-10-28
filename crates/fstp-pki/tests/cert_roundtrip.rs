//! rustls-webpki reads back every field `fstp-pki` writes (design sections
//! 1.3 and 15, ADR-009 "Certificate authorities", R-NF-09).
//!
//! Each certificate is built through `fstp-pki` and signed with aws-lc-rs,
//! as a caller would. rustls-webpki then parses it, and each field must
//! equal the independent reference of `common::der`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::der;
use common::keys::EcKey;
use common::oracle;
use common::profile::{
    Dn, Profile, Usage, ca_profile, client_profile, name_content, pki_issue, pki_tbs,
};
use common::time::{CLIENT_MAX_SPAN, DAY, MAX_TIME, MIN_TIME, T0};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";
const ROLE: &str = "c_0123456789abcdef0123456789abcdef_app";

fn cluster_ca() -> (EcKey, Profile, Vec<u8>) {
    let key = EcKey::generate();
    let p = ca_profile(CLUSTER_CA, &key, T0, T0 + 365 * DAY);
    let cert = pki_issue(&p, &key).expect("fstp-pki writes the cluster CA certificate");
    (key, p, cert)
}

/// R-NF-09, ADR-009: the cluster CA certificate parses, and rustls-webpki
/// reads back its serial, its subject and issuer (equal, since it is
/// self-signed) and its SPKI.
#[test]
fn r_nf_09_cluster_ca_certificate_reads_back_equal_fields() {
    let (key, p, cert) = cluster_ca();
    let read = oracle::read(&cert).expect("rustls-webpki parses the CA certificate");
    assert_eq!(read.serial, der::serial_content(&p.serial).unwrap());
    assert_eq!(read.subject, name_content(&p.subject));
    assert_eq!(read.issuer, name_content(&p.issuer));
    assert_eq!(read.spki, key.spki_der());
}

/// R-NF-09, ADR-009: rustls-webpki accepts the cluster CA certificate as a
/// trust anchor.
#[test]
fn r_nf_09_cluster_ca_certificate_is_a_webpki_trust_anchor() {
    let (_, _, cert) = cluster_ca();
    oracle::is_anchor(&cert).expect("rustls-webpki takes the CA as a trust anchor");
}

/// ADR-005 D2: a role client certificate carries CN equal to the role, the
/// cluster CA as issuer, and the role key's SPKI.
#[test]
fn adr005_d2_role_certificate_reads_back_role_cn_and_ca_issuer() {
    let (ca_key, _, ca_cert) = cluster_ca();
    let role_key = EcKey::generate();
    let p = client_profile(CLUSTER_CA, ROLE, &role_key, T0, T0 + CLIENT_MAX_SPAN);
    let cert = pki_issue(&p, &ca_key).expect("fstp-pki writes the role certificate");
    let read = oracle::read(&cert).expect("rustls-webpki parses the role certificate");
    let ca = oracle::read(&ca_cert).expect("rustls-webpki parses the CA certificate");
    assert_eq!(read.subject, name_content(&Dn::cn(ROLE)));
    assert_eq!(read.issuer, ca.subject);
    assert_eq!(read.spki, role_key.spki_der());
    assert_eq!(read.serial, der::serial_content(&p.serial).unwrap());
}

/// R-NF-09, design section 1.3: a leaf chains to its cluster CA. The
/// certificate is exactly the TBS `fstp-pki` returned, the ECDSA SHA-256
/// algorithm and the signature, and the CA key that rustls-webpki reads
/// from the CA certificate verifies that signature over that TBS.
#[test]
fn r_nf_09_role_certificate_signature_verifies_under_its_cluster_ca() {
    let (ca_key, _, ca_cert) = cluster_ca();
    let role_key = EcKey::generate();
    let p = client_profile(CLUSTER_CA, ROLE, &role_key, T0, T0 + DAY);
    let spec = common::profile::to_spec(&p).expect("the stub API states a client profile");
    let t = fstp_pki::cert::tbs(&spec).expect("fstp-pki writes the TBS");
    let tbs = t.as_der().to_vec();
    let sig = ca_key.sign(&tbs);
    let cert = fstp_pki::cert::assemble(&t, &sig).expect("fstp-pki assembles the certificate");
    assert_eq!(cert, der::certificate(&tbs, der::ALG_ECDSA_SHA256, &sig));
    oracle::verify_by(&ca_cert, &tbs, &sig).expect("the cluster CA key verifies the leaf");
}

/// R-NF-09, design section 1.3: a certificate signed by another CA's key
/// does not verify under the cluster CA. Teeth for the test above.
#[test]
fn r_nf_09_role_certificate_of_another_ca_does_not_verify_under_the_cluster_ca() {
    let (_, _, ca_cert) = cluster_ca();
    let other_ca_key = EcKey::generate();
    let role_key = EcKey::generate();
    let p = client_profile(CLUSTER_CA, ROLE, &role_key, T0, T0 + DAY);
    let tbs = pki_tbs(&p).expect("fstp-pki writes the TBS");
    let sig = other_ca_key.sign(&tbs);
    assert!(oracle::verify_by(&ca_cert, &tbs, &sig).is_err());
}

/// I-83, design section 1.3: the server certificate of a vault cluster
/// carries the cluster kind `vault` in its subject OU, and rustls-webpki
/// reads that subject back byte for byte.
#[test]
fn i83_server_certificate_reads_back_cluster_kind_ou() {
    let ca_key = EcKey::generate();
    let server_key = EcKey::generate();
    let p = Profile {
        serial: vec![0x11; 16],
        issuer: Dn::cn(CLUSTER_CA),
        subject: Dn {
            cn: "pg-vault-1.cluster.test".to_owned(),
            ou: Some("vault".to_owned()),
        },
        not_before: T0,
        not_after: T0 + DAY,
        spki_der: server_key.spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
    };
    let cert = pki_issue(&p, &ca_key).expect("fstp-pki writes the server certificate");
    let read = oracle::read(&cert).expect("rustls-webpki parses the server certificate");
    assert_eq!(read.subject, name_content(&p.subject));
}

/// R-NF-09, ADR-005: a cluster server certificate is valid, through its
/// subjectAltName, for its DNS name and its IP address, and for no other.
#[test]
fn r_nf_09_server_certificate_san_names_its_dns_name_and_ip() {
    let ca_key = EcKey::generate();
    let server_key = EcKey::generate();
    let p = Profile {
        serial: vec![0x12; 16],
        issuer: Dn::cn(CLUSTER_CA),
        subject: Dn {
            cn: "pg-app-1.cluster.test".to_owned(),
            ou: Some("application".to_owned()),
        },
        not_before: T0,
        not_after: T0 + DAY,
        spki_der: server_key.spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: vec!["pg-app-1.cluster.test".to_owned()],
        ip_addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let cert = pki_issue(&p, &ca_key).expect("fstp-pki writes the server certificate");
    let read = oracle::read(&cert).expect("rustls-webpki parses the server certificate");
    assert_eq!(read.dns_names, vec!["pg-app-1.cluster.test".to_owned()]);
    oracle::valid_for_name(&cert, "pg-app-1.cluster.test").expect("valid for its DNS name");
    oracle::valid_for_name(&cert, "127.0.0.1").expect("valid for its IP address");
    assert!(oracle::valid_for_name(&cert, "pg-app-2.cluster.test").is_err());
    assert!(oracle::valid_for_name(&cert, "127.0.0.2").is_err());
}

/// Design section 15 (`cert_build_roundtrip`), TH-26: arbitrary names,
/// serials and lifetimes build certificates that rustls-webpki parses with
/// equal fields. The property draws every kind (CA, server, client), an
/// optional OU on both names (a cluster kind marker on a server subject),
/// and, off a CA, SAN DNS names up to the 63-byte label and 253-byte name
/// limits and IP addresses. rustls-webpki must read back the serial, the
/// issuer, the subject, the SPKI and the DNS names, and must accept each
/// IP address and refuse one the SAN lacks.
#[test]
fn cert_build_roundtrip_webpki_reads_back_equal_fields() {
    let ca_key = EcKey::generate();
    let leaf_key = EcKey::generate();
    let spki = leaf_key.spki_der();
    let absent_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255));
    check_with(
        "cert_build_roundtrip_webpki_reads_back_equal_fields",
        Config::default().with_cases(256),
        |g| {
            let usage = *g.pick(&[Usage::Ca, Usage::Server, Usage::Client]);
            let not_before = g.i64_in(MIN_TIME..=MAX_TIME - CLIENT_MAX_SPAN);
            let lifetime = if usage == Usage::Client {
                g.i64_in(0..=CLIENT_MAX_SPAN)
            } else {
                g.i64_in(0..=MAX_TIME - not_before)
            };
            let (dns_names, ip_addrs) = if usage == Usage::Ca {
                (Vec::new(), Vec::new())
            } else {
                let dns = g.vec(0..=3, common::gen_dns_name);
                let ips = g.vec(0..=3, common::gen_ip);
                (dns, ips)
            };
            let p = Profile {
                serial: common::gen_valid_serial(g),
                issuer: Dn {
                    cn: common::gen_cn(g),
                    ou: common::gen_ou(g, false),
                },
                subject: Dn {
                    cn: common::gen_cn(g),
                    ou: common::gen_ou(g, usage == Usage::Server),
                },
                not_before,
                not_after: not_before + lifetime,
                spki_der: spki.clone(),
                issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
                usage,
                dns_names,
                ip_addrs,
            };
            g.note("profile", &p);
            let cert = pki_issue(&p, &ca_key).map_err(|e| format!("fstp-pki refused: {e:?}"))?;
            let read = oracle::read(&cert)?;
            prop_assert_eq!(read.serial, der::serial_content(&p.serial).unwrap());
            prop_assert_eq!(read.issuer, name_content(&p.issuer));
            prop_assert_eq!(read.subject, name_content(&p.subject));
            prop_assert_eq!(read.spki, spki.clone());
            prop_assert_eq!(read.dns_names, p.dns_names.clone());
            for ip in &p.ip_addrs {
                oracle::valid_for_ip(&cert, *ip).map_err(|e| format!("{ip}: {e}"))?;
            }
            if !p.ip_addrs.contains(&absent_ip) {
                prop_assert!(oracle::valid_for_ip(&cert, absent_ip).is_err());
            }
            Ok(())
        },
    );
}

/// Design section 15 (`cert_build_roundtrip`): every TBS starts with the
/// reference encoding of version 3, the serial, ecdsa-with-SHA256, the
/// issuer, the validity, the subject and the SPKI, in that order, and then
/// holds one `[3]` extensions field and nothing else.
#[test]
fn cert_build_roundtrip_tbs_holds_the_reference_fields_then_extensions() {
    let leaf_key = EcKey::generate();
    let spki = leaf_key.spki_der();
    check_with(
        "cert_build_roundtrip_tbs_holds_the_reference_fields_then_extensions",
        Config::default().with_cases(256),
        |g| {
            let not_before = common::gen_time(g);
            let not_after = g.i64_in(not_before..=MAX_TIME);
            let p = Profile {
                serial: common::gen_valid_serial(g),
                issuer: Dn::cn(&common::gen_cn(g)),
                subject: Dn::cn(&common::gen_cn(g)),
                not_before,
                not_after,
                spki_der: spki.clone(),
                issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
                usage: Usage::Ca,
                dns_names: Vec::new(),
                ip_addrs: Vec::new(),
            };
            g.note("profile", &p);
            let tbs = pki_tbs(&p).map_err(|e| format!("fstp-pki refused: {e:?}"))?;
            let prefix = common::profile::tbs_prefix(&p).unwrap();
            let rest = common::split_sequence(&tbs)?
                .strip_prefix(prefix.as_slice())
                .ok_or("the TBS does not start with the reference fields")?
                .to_vec();
            common::single_tlv(0xa3, &rest)?;
            Ok(())
        },
    );
}

/// I-83, design section 9.2: the exported expected-name encoder equals
/// the subject rustls-webpki reads from a cluster server certificate, so
/// the start-up checks of `fstp-vault` and `fstp-cell` compare bytes with
/// no DER reader. `name_der` is the same content inside one SEQUENCE.
#[test]
fn i83_exported_name_content_equals_the_webpki_subject() {
    use fstp_pki::cert::{ClusterKindOu, DistinguishedName, name_content as pki_name_content};
    let ca_key = EcKey::generate();
    for kind in ClusterKindOu::ALL {
        let cn = format!("pg-{}-1.cluster.test", kind.as_str());
        let dn = DistinguishedName::cluster_server(kind, &cn);
        let p = Profile {
            serial: vec![0x13; 16],
            issuer: Dn::cn(CLUSTER_CA),
            subject: Dn {
                cn: cn.clone(),
                ou: Some(kind.as_str().to_owned()),
            },
            not_before: T0,
            not_after: T0 + DAY,
            spki_der: EcKey::generate().spki_der(),
            issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
            usage: Usage::Server,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
        };
        let cert = pki_issue(&p, &ca_key).expect("fstp-pki writes the server certificate");
        let read = oracle::read(&cert).expect("rustls-webpki parses the server certificate");
        let expected = pki_name_content(&dn).expect("a valid name");
        assert_eq!(read.subject, expected, "{kind:?}");
        assert_eq!(
            fstp_pki::cert::name_der(&dn).expect("a valid name"),
            der::name(&cn, Some(kind.as_str()))
        );
    }
}

//! Self-tests of the W1i references and oracles (design section 14.1:
//! teeth for every oracle).
//!
//! Each test runs an oracle on certificates from the independent reference
//! writer in `common`, never on `fstp-pki` output. They are green while
//! the `fstp-pki` stub stands. So when a test in another file is red, the
//! oracle works and the cause is `fstp-pki`.

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
use std::time::{SystemTime, UNIX_EPOCH};

use common::der;
use common::keys::{EcKey, P256_G_SPKI};
use common::oracle;
use common::pg::{ClientFiles, Pg, ServerFiles};
use common::profile::{
    BuildError, Dn, Gap, Profile, Usage, ca_profile, client_profile, contains, name_content,
    real_refusal, reference_issue, reference_tbs,
};
use common::time::{DAY, GENERALIZED_FROM, MAX_TIME, MIN_TIME, T0};
use fstp_pki::PkiError;

const CA: &str = "fstp reference CA";
const ROLE: &str = "c_00112233445566778899aabbccddeeff_app";

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// The reference CA and a reference role certificate both parse with
/// rustls-webpki, and every field reads back equal.
#[test]
fn harness_reference_certificates_read_back_equal_with_webpki() {
    let ca_key = EcKey::generate();
    let ca_p = ca_profile(CA, &ca_key, T0, T0 + DAY);
    let ca = reference_issue(&ca_p, &ca_key).unwrap();
    oracle::is_anchor(&ca).unwrap();
    let read_ca = oracle::read(&ca).unwrap();
    assert_eq!(read_ca.subject, name_content(&ca_p.subject));
    assert_eq!(read_ca.spki, ca_key.spki_der());

    let leaf_key = EcKey::generate();
    let p = client_profile(CA, ROLE, &leaf_key, T0, T0 + DAY);
    let leaf = reference_issue(&p, &ca_key).unwrap();
    let read = oracle::read(&leaf).unwrap();
    assert_eq!(read.serial, der::serial_content(&p.serial).unwrap());
    assert_eq!(read.issuer, read_ca.subject);
    assert_eq!(read.subject, name_content(&Dn::cn(ROLE)));
    assert_eq!(read.spki, leaf_key.spki_der());
}

/// The CA signature check of the oracle accepts the reference leaf and
/// refuses it under another CA key.
#[test]
fn harness_reference_leaf_verifies_only_under_its_ca() {
    let ca_key = EcKey::generate();
    let ca = reference_issue(&ca_profile(CA, &ca_key, T0, T0 + DAY), &ca_key).unwrap();
    let other_key = EcKey::generate();
    let other = reference_issue(&ca_profile(CA, &other_key, T0, T0 + DAY), &other_key).unwrap();
    let p = client_profile(CA, ROLE, &EcKey::generate(), T0, T0 + DAY);
    let tbs = reference_tbs(&p).unwrap();
    let sig = ca_key.sign(&tbs);
    oracle::verify_by(&ca, &tbs, &sig).unwrap();
    assert!(oracle::verify_by(&other, &tbs, &sig).is_err());
}

/// The OU, SAN and extension encodings of the reference parse with
/// rustls-webpki, and the SAN oracle tells the names apart.
#[test]
fn harness_reference_server_certificate_has_ou_and_san() {
    let ca_key = EcKey::generate();
    let p = Profile {
        serial: vec![0x11; 16],
        issuer: Dn::cn(CA),
        subject: Dn {
            cn: "pg-vault-1.cluster.test".to_owned(),
            ou: Some("vault".to_owned()),
        },
        not_before: T0,
        not_after: T0 + DAY,
        spki_der: EcKey::generate().spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: vec!["pg-vault-1.cluster.test".to_owned()],
        ip_addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let cert = reference_issue(&p, &ca_key).unwrap();
    let read = oracle::read(&cert).unwrap();
    assert_eq!(read.subject, name_content(&p.subject));
    assert_eq!(read.dns_names, p.dns_names);
    oracle::valid_for_name(&cert, "pg-vault-1.cluster.test").unwrap();
    oracle::valid_for_name(&cert, "127.0.0.1").unwrap();
    assert!(oracle::valid_for_name(&cert, "pg-app-1.cluster.test").is_err());
    let ext = der::extension(der::OID_EKU, false, &der::ext_key_usage(der::OID_KP_SERVER));
    assert!(contains(&cert, &ext));
}

/// The reference time writer gives the RFC 5280 strings at the edges.
#[test]
fn harness_reference_times_match_known_strings() {
    let cases: [(i64, u8, &[u8]); 6] = [
        (MIN_TIME, 0x17, b"500101000000Z"),
        (0, 0x17, b"700101000000Z"),
        (T0, 0x17, b"261028000000Z"),
        (GENERALIZED_FROM - 1, 0x17, b"491231235959Z"),
        (GENERALIZED_FROM, 0x18, b"20500101000000Z"),
        (MAX_TIME, 0x18, b"99991231235959Z"),
    ];
    for (t, tag, text) in cases {
        assert_eq!(common::time::time(t), Some(der::tlv(tag, text)), "{t}");
    }
    assert_eq!(common::time::time(MIN_TIME - 1), None);
    assert_eq!(common::time::time(MAX_TIME + 1), None);
}

/// The reference serial rule at its edges.
#[test]
fn harness_reference_serial_rule_edges() {
    assert_eq!(der::serial_content(&[]), None);
    assert_eq!(der::serial_content(&[0, 0]), None);
    assert_eq!(der::serial_content(&[0, 0x05]), Some(vec![0x05]));
    assert_eq!(der::serial_content(&[0x80]), Some(vec![0, 0x80]));
    assert_eq!(der::serial_content(&[0x7f; 20]).map(|s| s.len()), Some(20));
    assert_eq!(der::serial_content(&[0x80; 20]), None);
}

/// The reference length writer gives the X.690 short and long forms.
#[test]
fn harness_reference_der_length_forms() {
    assert_eq!(der::len(0), vec![0x00]);
    assert_eq!(der::len(127), vec![0x7f]);
    assert_eq!(der::len(128), vec![0x81, 0x80]);
    assert_eq!(der::len(255), vec![0x81, 0xff]);
    assert_eq!(der::len(256), vec![0x82, 0x01, 0x00]);
    assert_eq!(
        common::tlv_content(0x30, &der::seq(&[&[0u8; 300]]))
            .unwrap()
            .len(),
        300
    );
    assert!(common::tlv_content(0x30, &[0x30, 0x05, 0x00]).is_err());
}

/// The reference base64 writer gives the RFC 4648 section 10 test vectors.
#[test]
fn harness_reference_base64_matches_rfc4648_vectors() {
    let vectors: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (input, out) in vectors {
        assert_eq!(common::pem::base64(input), out);
    }
}

/// The reference proof-of-possession message verifies with aws-lc-rs under
/// the SPKI's key and not under another key.
#[test]
fn harness_reference_pop_message_is_signed_by_the_spki_key() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    let key = EcKey::generate();
    let spki = key.spki_der();
    let ctx = common::pop::Ctx::role([1; 16], "c_0123456789abcdef0123456789abcdef_app");
    let msg = common::pop::pop_message(&spki, &ctx, &[7; 32]);
    assert_eq!(msg.len(), 16 + 1 + 16 + 1 + ctx.name.len() + 32 + 32);
    let sig = key.sign(&msg);
    let point = &spki[spki.len() - 65..];
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&msg, &sig)
        .unwrap();
    let g_point = &P256_G_SPKI[P256_G_SPKI.len() - 65..];
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, g_point)
            .verify(&msg, &sig)
            .is_err()
    );
}

/// The refusal predicate never counts the W0 stub as a refusal, and counts
/// an API gap as none either.
#[test]
fn harness_real_refusal_rejects_stub_and_gap() {
    let stub: Result<(), BuildError> = Err(BuildError::Pki(PkiError::NotImplemented("x")));
    assert!(!real_refusal(&stub));
    let gap: Result<(), BuildError> = Err(BuildError::Gap(Gap::SubjectAltName));
    assert!(!real_refusal(&gap));
    let ok: Result<(), BuildError> = Ok(());
    assert!(!real_refusal(&ok));
}

fn ref_cluster(roles: &[&str]) -> (EcKey, String, Pg) {
    let ca_key = EcKey::generate();
    let t = now();
    let ca = reference_issue(&ca_profile(CA, &ca_key, t - 300, t + DAY), &ca_key).unwrap();
    let ca_pem = common::pem::pem("CERTIFICATE", &ca);
    let server_key = EcKey::generate();
    let server = Profile {
        serial: vec![0x31; 16],
        issuer: Dn::cn(CA),
        subject: Dn {
            cn: "127.0.0.1".to_owned(),
            ou: Some("application".to_owned()),
        },
        not_before: t - 300,
        not_after: t + DAY,
        spki_der: server_key.spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: Vec::new(),
        ip_addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let server_der = reference_issue(&server, &ca_key).unwrap();
    let pg = Pg::start(
        &ServerFiles {
            ca_pem: &ca_pem,
            cert_pem: &common::pem::pem("CERTIFICATE", &server_der),
            key_pem: &common::pem::pem("PRIVATE KEY", server_key.pkcs8_der()),
        },
        roles,
    )
    .unwrap();
    (ca_key, ca_pem, pg)
}

fn ref_login(
    pg: &Pg,
    ca_pem: &str,
    issuer: &EcKey,
    cn: &str,
    as_role: &str,
) -> Result<String, String> {
    let t = now();
    let key = EcKey::generate();
    let leaf = reference_issue(&client_profile(CA, cn, &key, t - 300, t + DAY), issuer).unwrap();
    pg.login(
        as_role,
        &ClientFiles {
            ca_pem,
            cert_pem: &common::pem::pem("CERTIFICATE", &leaf),
            key_pem: &common::pem::pem("PRIVATE KEY", key.pkcs8_der()),
        },
    )
}

/// The PostgreSQL harness accepts a reference role certificate with CN
/// equal to the role.
#[test]
fn harness_postgres_accepts_a_reference_role_certificate() {
    let (ca_key, ca_pem, pg) = ref_cluster(&[ROLE]);
    let who = ref_login(&pg, &ca_pem, &ca_key, ROLE, ROLE);
    assert_eq!(who.as_deref(), Ok(ROLE), "server log:\n{}", pg.log());
}

/// Teeth: the harness refuses a reference certificate whose CN names
/// another role.
#[test]
fn harness_postgres_refuses_a_reference_certificate_of_another_role() {
    let other = "c_00112233445566778899aabbccddeeff_writer";
    let (ca_key, ca_pem, pg) = ref_cluster(&[ROLE, other]);
    assert!(ref_login(&pg, &ca_pem, &ca_key, ROLE, other).is_err());
}

/// Teeth: the harness refuses a reference certificate from another CA key
/// under the same CA name.
#[test]
fn harness_postgres_refuses_a_reference_certificate_from_another_ca() {
    let (_, ca_pem, pg) = ref_cluster(&[ROLE]);
    let other = EcKey::generate();
    assert!(ref_login(&pg, &ca_pem, &other, ROLE, ROLE).is_err());
}

/// The `verify_for_usage` oracle of `webpki_path.rs` accepts a reference
/// chain inside its validity and refuses it one second after.
#[test]
fn harness_reference_chain_validates_with_webpki_verify_for_usage() {
    let ca_key = EcKey::generate();
    let ca = reference_issue(&ca_profile(CA, &ca_key, T0, T0 + 400 * DAY), &ca_key).unwrap();
    let p = client_profile(CA, ROLE, &EcKey::generate(), T0, T0 + DAY);
    let leaf = reference_issue(&p, &ca_key).unwrap();
    let verify_at = |t: i64| {
        common::oracle::verify_for_usage(&ca, &leaf, &[], t, webpki::KeyUsage::client_auth())
    };
    verify_at(T0 + DAY).unwrap();
    assert!(verify_at(T0 + DAY + 1).is_err());
}

/// The `UnixTime` that `oracle::verify_for_usage` takes from its synthetic
/// CRL is the instant the caller named, for every instant from 1970 to
/// 9999 and across the UTCTime to GeneralizedTime switch. So the path
/// checks of `webpki_path.rs` run at the second they state.
#[test]
fn harness_crl_time_carrier_returns_the_named_instant() {
    fstp_prop::check_with(
        "harness_crl_time_carrier_returns_the_named_instant",
        fstp_prop::Config::default().with_cases(256),
        |g| {
            let t = match g.weighted(&[2, 1, 1, 1]) {
                0 => g.i64_in(0..=MAX_TIME),
                1 => g.i64_in(GENERALIZED_FROM - 2..=GENERALIZED_FROM + 1),
                2 => g.i64_in(0..=1),
                _ => g.i64_in(MAX_TIME - 1..=MAX_TIME),
            };
            g.note("t", &t);
            let got = oracle::unix_secs_via_crl(t)?;
            fstp_prop::prop_assert_eq!(got, u64::try_from(t).unwrap());
            Ok(())
        },
    );
}

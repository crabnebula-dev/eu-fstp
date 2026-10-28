//! A real PostgreSQL 16 server accepts a role certificate that `fstp-pki`
//! issued under the cluster CA, and refuses every other (ADR-005 D2,
//! R-NF-09, design sections 1.3 and 4.1, ADR-009 B1).
//!
//! The server runs with `clientcert=verify-full` and SCRAM on every
//! `hostssl` line, as production `pg_hba` lines do. libpq connects with
//! `sslmode=verify-full`, as ADR-005 requires. The CA, server and
//! client certificates all come from `fstp-pki`, PEM included. Only the
//! PKCS#8 key files come from the reference PEM writer, since
//! `fstp_pki::pem` writes certificates only.
//!
//! Each test needs `FSTP_PG_BIN`. `harness_self_test.rs` runs the same
//! server with reference certificates, so a red test here is red because
//! of `fstp-pki`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use common::keys::EcKey;
use common::pg::{ClientFiles, Pg, ServerFiles};
use common::profile::{Dn, Profile, Usage, ca_profile, client_profile, pki_issue};
use common::time::{CLIENT_MAX_SPAN, DAY};
use fstp_pki::cert::{ClusterKindOu, DistinguishedName};
use fstp_pki::pem::{PemLabel, encode};

const CELL: &str = "0123456789abcdef0123456789abcdef";

fn now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    i64::try_from(secs).expect("the clock fits in i64")
}

fn cert_pem(der: &[u8]) -> String {
    encode(PemLabel::Certificate, der).expect("fstp-pki writes PEM")
}

fn key_pem(key: &EcKey) -> String {
    common::pem::pem("PRIVATE KEY", key.pkcs8_der())
}

/// One cluster: its CA and a running server whose certificate the CA
/// issued. The server certificate has the design shape (design sections
/// 1.3 and 4.1, ADR-005): the subject from
/// `DistinguishedName::cluster_server`, so the kind is the OU, and a
/// subjectAltName with the host name and `127.0.0.1`. libpq checks it with
/// `sslmode=verify-full`.
struct Cluster {
    host: String,
    ca_name: String,
    ca_key: EcKey,
    ca_pem: String,
    pg: Pg,
}

fn cluster(roles: &[&str]) -> Cluster {
    cluster_with_roots(roles, str::to_owned)
}

/// The host name of the server of a cluster of kind `kind`.
fn host_of(kind: ClusterKindOu) -> String {
    format!("pg-{}-1.cluster.test", kind.as_str())
}

/// Like [`cluster`], with the server trusting the client CAs that `roots`
/// returns for the cluster CA PEM, such as an old and a new CA during a
/// rollover.
fn cluster_with_roots(roles: &[&str], roots: impl FnOnce(&str) -> String) -> Cluster {
    cluster_of_kind(ClusterKindOu::Application, roles, roots)
}

/// Like [`cluster_with_roots`], for a cluster of kind `kind`.
fn cluster_of_kind(
    kind: ClusterKindOu,
    roles: &[&str],
    roots: impl FnOnce(&str) -> String,
) -> Cluster {
    let host = host_of(kind);
    let subject = DistinguishedName::cluster_server(kind, &host);
    let ca_name = format!("fstp cluster CA {CELL}");
    let ca_key = EcKey::generate();
    let t = now();
    let ca = ca_profile(&ca_name, &ca_key, t - 300, t + 400 * DAY);
    let ca_pem = cert_pem(&pki_issue(&ca, &ca_key).expect("fstp-pki writes the cluster CA"));
    let server_key = EcKey::generate();
    let server = Profile {
        serial: vec![0x31; 16],
        issuer: Dn::cn(&ca_name),
        subject: Dn {
            cn: subject.common_name,
            ou: subject.organizational_unit,
        },
        not_before: t - 300,
        not_after: t + DAY,
        spki_der: server_key.spki_der(),
        issuer_key_id: Some(common::profile::UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Server,
        dns_names: vec![host.clone()],
        ip_addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let server_der = pki_issue(&server, &ca_key).expect("fstp-pki writes the server cert");
    let pg = Pg::start(
        &ServerFiles {
            ca_pem: &roots(&ca_pem),
            cert_pem: &cert_pem(&server_der),
            key_pem: &key_pem(&server_key),
        },
        roles,
    )
    .expect("the test server starts");
    Cluster {
        host,
        ca_name,
        ca_key,
        ca_pem,
        pg,
    }
}

fn role(suffix: &str) -> String {
    format!("c_{CELL}_{suffix}")
}

/// A key and its role certificate for `cn`, issued by `issuer_key` under
/// the name `issuer_name`.
fn role_cert(issuer_name: &str, issuer_key: &EcKey, cn: &str, nb: i64, na: i64) -> (EcKey, String) {
    let key = EcKey::generate();
    let p = client_profile(issuer_name, cn, &key, nb, na);
    let pem = cert_pem(&pki_issue(&p, issuer_key).expect("fstp-pki writes the role certificate"));
    (key, pem)
}

fn login(c: &Cluster, as_role: &str, key: &EcKey, pem: &str) -> Result<String, String> {
    login_to(c, "127.0.0.1", as_role, key, pem)
}

/// Like [`login`], with libpq checking the server certificate against
/// `host` under `sslmode=verify-full`.
fn login_to(
    c: &Cluster,
    host: &str,
    as_role: &str,
    key: &EcKey,
    pem: &str,
) -> Result<String, String> {
    c.pg.login_to(
        host,
        as_role,
        &ClientFiles {
            ca_pem: &c.ca_pem,
            cert_pem: pem,
            key_pem: &key_pem(key),
        },
    )
}

/// ADR-005 D2, R-NF-09: PostgreSQL accepts the role certificate that
/// `fstp-pki` issued under the cluster CA, CN equal to the role, and the
/// session runs as that role.
#[test]
fn r_nf_09_adr005_d2_postgres_accepts_a_role_certificate_issued_by_the_cluster_ca() {
    let app = role("app");
    let c = cluster(&[&app]);
    let t = now();
    let (key, pem) = role_cert(
        &c.ca_name,
        &c.ca_key,
        &app,
        t - 300,
        t - 300 + CLIENT_MAX_SPAN,
    );
    let who = login(&c, &app, &key, &pem);
    assert_eq!(
        who.as_deref(),
        Ok(app.as_str()),
        "server log:\n{}",
        c.pg.log()
    );
}

/// ADR-005 D2: PostgreSQL refuses a valid role certificate presented for
/// another role, since its CN names the wrong role.
#[test]
fn adr005_d2_postgres_refuses_a_certificate_naming_another_role() {
    let app = role("app");
    let writer = role("writer");
    let c = cluster(&[&app, &writer]);
    let t = now();
    let (key, pem) = role_cert(
        &c.ca_name,
        &c.ca_key,
        &app,
        t - 300,
        t - 300 + CLIENT_MAX_SPAN,
    );
    let r = login(&c, &writer, &key, &pem);
    assert!(r.is_err(), "{r:?}");
}

/// ADR-009 B1, B7: PostgreSQL refuses a certificate with the right CN from
/// another cluster's CA. A cluster trusts only its own cluster CA.
#[test]
fn adr009_b1_postgres_refuses_a_role_certificate_from_another_cluster_ca() {
    let app = role("app");
    let c = cluster(&[&app]);
    let other_name = format!("fstp cluster CA {}", "f".repeat(32));
    let other_key = EcKey::generate();
    let t = now();
    let (key, pem) = role_cert(
        &other_name,
        &other_key,
        &app,
        t - 300,
        t - 300 + CLIENT_MAX_SPAN,
    );
    let r = login(&c, &app, &key, &pem);
    assert!(r.is_err(), "{r:?}");
}

/// ADR-005 "Role certificates": the 7-day lifetime bounds a lost key, so
/// PostgreSQL refuses a role certificate whose validity has ended.
#[test]
fn adr005_postgres_refuses_an_expired_role_certificate() {
    let app = role("app");
    let c = cluster(&[&app]);
    let t = now();
    let (key, pem) = role_cert(&c.ca_name, &c.ca_key, &app, t - 7 * DAY, t - 60);
    let r = login(&c, &app, &key, &pem);
    assert!(r.is_err(), "{r:?}");
}

/// ADR-005 "Role certificates": a role certificate that is not valid yet
/// is refused too.
#[test]
fn adr005_postgres_refuses_a_role_certificate_that_is_not_valid_yet() {
    let app = role("app");
    let c = cluster(&[&app]);
    let t = now();
    let (key, pem) = role_cert(&c.ca_name, &c.ca_key, &app, t + DAY, t + 2 * DAY);
    let r = login(&c, &app, &key, &pem);
    assert!(r.is_err(), "{r:?}");
}

/// ADR-005 "Role certificates" (yearly CA rollover with an overlap), RFC
/// 5280 sections 4.2.1.1 and 4.2.1.2: while the server trusts the old and
/// the new cluster CA, which share one name, PostgreSQL accepts a role
/// certificate from either CA, whatever the order of its root file. The
/// authorityKeyIdentifier lets OpenSSL pick the CA that signed.
#[test]
fn adr005_postgres_accepts_role_certificates_of_both_cas_during_a_rollover() {
    let app = role("app");
    let t = now();
    let new_key = EcKey::generate();
    let mut new_ca = ca_profile(
        &format!("fstp cluster CA {CELL}"),
        &new_key,
        t - 300,
        t + 400 * DAY,
    );
    new_ca.serial = vec![0x02, 0x46, 0x8a, 0xce];
    let new_pem = cert_pem(&pki_issue(&new_ca, &new_key).expect("fstp-pki writes the new CA"));
    for old_first in [true, false] {
        let c = cluster_with_roots(&[&app], |old| {
            if old_first {
                format!("{old}{new_pem}")
            } else {
                format!("{new_pem}{old}")
            }
        });
        for (which, issuer_key) in [("old", &c.ca_key), ("new", &new_key)] {
            let (key, pem) = role_cert(
                &c.ca_name,
                issuer_key,
                &app,
                t - 300,
                t - 300 + CLIENT_MAX_SPAN,
            );
            let who = login(&c, &app, &key, &pem);
            assert_eq!(
                who.as_deref(),
                Ok(app.as_str()),
                "{which} CA, old first {old_first}, server log:\n{}",
                c.pg.log()
            );
        }
    }
}

/// I-83, ADR-005, design sections 1.3 and 4.1: for every cluster kind,
/// libpq accepts with `sslmode=verify-full` the server certificate that
/// `fstp-pki` issued in the design shape. Its subject comes from
/// `DistinguishedName::cluster_server`, so the kind is the OU. libpq
/// checks the DNS name and the IP address of its subjectAltName, and the
/// role login then succeeds.
#[test]
fn i83_adr005_libpq_verify_full_accepts_the_cluster_server_certificate_of_each_kind() {
    let app = role("app");
    let t = now();
    for kind in ClusterKindOu::ALL {
        let c = cluster_of_kind(kind, &[&app], str::to_owned);
        let (key, pem) = role_cert(
            &c.ca_name,
            &c.ca_key,
            &app,
            t - 300,
            t - 300 + CLIENT_MAX_SPAN,
        );
        for host in [c.host.as_str(), "127.0.0.1"] {
            let who = login_to(&c, host, &app, &key, &pem);
            assert_eq!(
                who.as_deref(),
                Ok(app.as_str()),
                "{kind:?} as {host}, server log:\n{}",
                c.pg.log()
            );
        }
    }
}

/// Teeth for the test above (ADR-005 `verify-full`): libpq refuses the
/// server certificate for a DNS name or an IP address that its
/// subjectAltName does not list. So the host name check runs.
#[test]
fn adr005_libpq_verify_full_refuses_a_host_the_server_certificate_does_not_name() {
    let app = role("app");
    let c = cluster(&[&app]);
    let t = now();
    let (key, pem) = role_cert(
        &c.ca_name,
        &c.ca_key,
        &app,
        t - 300,
        t - 300 + CLIENT_MAX_SPAN,
    );
    for host in ["pg-application-2.cluster.test", "127.0.0.2"] {
        let r = login_to(&c, host, &app, &key, &pem);
        let msg = r.expect_err(host);
        assert!(msg.contains("does not match host name"), "{host}: {msg}");
    }
}

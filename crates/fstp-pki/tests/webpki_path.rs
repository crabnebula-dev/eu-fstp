//! Path validation with rustls-webpki `verify_for_usage` (R-NF-09, ADR-005
//! "Role certificates", ADR-009, design section 1.3): validity at both
//! ends, extended key usage and the CA flag along a path.
//!
//! `common::oracle::verify_for_usage` runs the check, so this file names
//! no `rustls-pki-types` type (see `common::oracle`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::keys::EcKey;
use common::profile::{Profile, ca_profile, client_profile, pki_issue};
use common::time::{CLIENT_MAX_SPAN, DAY, T0};
use webpki::KeyUsage;

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";
const ROLE: &str = "c_0123456789abcdef0123456789abcdef_app";

/// `id-kp-clientAuth`, the OID value octets rustls-webpki takes.
const ID_KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

struct Chain {
    ca: Vec<u8>,
    leaf: Vec<u8>,
    leaf_key: EcKey,
    leaf_profile: Profile,
}

fn chain() -> Chain {
    let ca_key = EcKey::generate();
    let ca = pki_issue(
        &ca_profile(CLUSTER_CA, &ca_key, T0 - DAY, T0 + 400 * DAY),
        &ca_key,
    )
    .expect("fstp-pki writes the CA");
    let leaf_key = EcKey::generate();
    let p = client_profile(CLUSTER_CA, ROLE, &leaf_key, T0, T0 + CLIENT_MAX_SPAN);
    let leaf = pki_issue(&p, &ca_key).expect("fstp-pki writes the leaf");
    Chain {
        ca,
        leaf,
        leaf_key,
        leaf_profile: p,
    }
}

fn verify(ca: &[u8], leaf: &[u8], t: i64, usage: KeyUsage) -> Result<(), webpki::Error> {
    common::oracle::verify_for_usage(ca, leaf, &[], t, usage)
}

/// R-NF-09: a role certificate validates under its cluster CA for client
/// authentication at its first and last valid second.
#[test]
fn r_nf_09_role_certificate_validates_under_the_cluster_ca_at_both_ends() {
    let c = chain();
    let p = &c.leaf_profile;
    verify(&c.ca, &c.leaf, p.not_before, KeyUsage::client_auth()).unwrap();
    verify(&c.ca, &c.leaf, p.not_after, KeyUsage::client_auth()).unwrap();
}

/// ADR-005 "Role certificates": one second before `notBefore` the role
/// certificate is not valid yet.
#[test]
fn adr005_role_certificate_is_not_valid_one_second_early() {
    let c = chain();
    let r = verify(
        &c.ca,
        &c.leaf,
        c.leaf_profile.not_before - 1,
        KeyUsage::client_auth(),
    );
    assert!(
        matches!(r, Err(webpki::Error::CertNotValidYet { .. })),
        "{r:?}"
    );
}

/// ADR-005 "Role certificates": one second after `notAfter` the role
/// certificate has expired.
#[test]
fn adr005_role_certificate_has_expired_one_second_late() {
    let c = chain();
    let r = verify(
        &c.ca,
        &c.leaf,
        c.leaf_profile.not_after + 1,
        KeyUsage::client_auth(),
    );
    assert!(matches!(r, Err(webpki::Error::CertExpired { .. })), "{r:?}");
}

/// ADR-005 D2: a role certificate requires `clientAuth` and is refused as
/// a server certificate.
#[test]
fn adr005_d2_role_certificate_is_refused_for_server_auth() {
    let c = chain();
    verify(&c.ca, &c.leaf, T0, KeyUsage::required(ID_KP_CLIENT_AUTH)).unwrap();
    assert!(verify(&c.ca, &c.leaf, T0, KeyUsage::server_auth()).is_err());
}

/// ADR-009: a CA certificate is refused as an end entity.
#[test]
fn adr009_ca_certificate_is_refused_as_an_end_entity() {
    let c = chain();
    let r = verify(&c.ca, &c.ca, T0, KeyUsage::client_auth());
    assert!(matches!(r, Err(webpki::Error::CaUsedAsEndEntity)), "{r:?}");
}

/// ADR-009 B1, design section 1.3: a leaf is refused when it is used as
/// an intermediate, since its basicConstraints leave `cA` false.
#[test]
fn adr009_leaf_cannot_act_as_an_intermediate() {
    let c = chain();
    let grandchild = client_profile(
        ROLE,
        "c_0123456789abcdef0123456789abcdef_keys",
        &EcKey::generate(),
        T0,
        T0 + DAY,
    );
    // Signed by the leaf's own key under the leaf's name, so the name and
    // the signature both chain. Only the leaf's CA flag can stop the path.
    let gc = pki_issue(&grandchild, &c.leaf_key).expect("fstp-pki writes the grandchild");
    let r = common::oracle::verify_for_usage(
        &c.ca,
        &gc,
        &[c.leaf.as_slice()],
        T0,
        KeyUsage::client_auth(),
    );
    assert!(matches!(r, Err(webpki::Error::EndEntityUsedAsCa)), "{r:?}");
}

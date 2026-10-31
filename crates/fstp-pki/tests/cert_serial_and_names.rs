//! Serials and names (design section 1.3, ADR-005 D2, RFC 5280 sections
//! 4.1.2.2 and 4.1.2.4, `ub-common-name`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::der;
use common::keys::EcKey;
use common::oracle;
use common::profile::{Dn, Profile, ca_profile, pki_issue, pki_tbs, real_refusal};
use common::time::{DAY, T0};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";

fn ca_with_serial(key: &EcKey, serial: Vec<u8>) -> Profile {
    let mut p = ca_profile(CLUSTER_CA, key, T0, T0 + DAY);
    p.serial = serial;
    p
}

fn ca_with_cn(key: &EcKey, cn: &str) -> Profile {
    ca_profile(cn, key, T0, T0 + DAY)
}

/// RFC 5280 section 4.1.2.2: a serial is accepted exactly when it is
/// positive and its INTEGER needs at most 20 octets. rustls-webpki reads
/// an accepted serial back as the minimal two's complement encoding.
#[test]
fn cert_serial_is_accepted_iff_positive_and_at_most_20_octets() {
    let key = EcKey::generate();
    check_with(
        "cert_serial_is_accepted_iff_positive_and_at_most_20_octets",
        Config::default().with_cases(512),
        |g| {
            let serial = common::gen_serial(g);
            g.note("serial", &serial);
            let p = ca_with_serial(&key, serial.clone());
            let r = pki_issue(&p, &key);
            match der::serial_content(&serial) {
                Some(expected) => {
                    let cert = r.map_err(|e| format!("refused a valid serial: {e:?}"))?;
                    prop_assert_eq!(oracle::read(&cert)?.serial, expected);
                }
                None => prop_assert!(real_refusal(&r), "accepted or stub-refused: {r:?}"),
            }
            Ok(())
        },
    );
}

/// RFC 5280 section 4.1.2.2: twenty bytes with the high bit set need a
/// 21st sign octet, so they are refused.
#[test]
fn cert_serial_of_twenty_bytes_with_the_high_bit_set_is_refused() {
    let key = EcKey::generate();
    let r = pki_tbs(&ca_with_serial(&key, vec![0x80; 20]));
    assert!(real_refusal(&r), "{r:?}");
}

/// RFC 5280 section 4.1.2.2: twenty bytes with the high bit clear fit in
/// 20 octets, so they are accepted.
#[test]
fn cert_serial_of_twenty_bytes_with_the_high_bit_clear_is_accepted() {
    let key = EcKey::generate();
    let r = pki_tbs(&ca_with_serial(&key, vec![0x7f; 20]));
    assert!(r.is_ok(), "{r:?}");
}

/// RFC 5280 section 4.1.2.2: zero is not positive, in any spelling.
#[test]
fn cert_serial_zero_and_empty_are_refused() {
    let key = EcKey::generate();
    for serial in [vec![], vec![0], vec![0; 20]] {
        let r = pki_tbs(&ca_with_serial(&key, serial.clone()));
        assert!(real_refusal(&r), "{serial:?}: {r:?}");
    }
}

/// Leading zero bytes of a serial magnitude are dropped, so a random
/// 16-byte serial with a zero first byte still encodes minimally.
#[test]
fn cert_serial_leading_zero_bytes_are_dropped() {
    let key = EcKey::generate();
    let cert = pki_issue(&ca_with_serial(&key, vec![0, 0, 0x05, 0x39]), &key)
        .expect("fstp-pki writes the certificate");
    assert_eq!(oracle::read(&cert).unwrap().serial, vec![0x05, 0x39]);
}

/// ADR-005 D2: a role name of 63 bytes, the longest PostgreSQL allows
/// (design section 4.1), round-trips as the CN.
#[test]
fn adr005_d2_role_name_of_63_bytes_round_trips_as_the_cn() {
    let key = EcKey::generate();
    let role = format!("c_{}_migrator", "a".repeat(32));
    let role = format!("{role}{}", "x".repeat(63 - role.len()));
    assert_eq!(role.len(), 63);
    let cert = pki_issue(&ca_with_cn(&key, &role), &key).expect("fstp-pki writes the cert");
    let read = oracle::read(&cert).unwrap();
    assert_eq!(read.subject, der::name_content(&role, None));
}

/// RFC 5280 `ub-common-name`: a CN of 64 characters is accepted, and one
/// of 65 is refused.
#[test]
fn cert_common_name_of_at_most_64_characters_is_accepted() {
    let key = EcKey::generate();
    let ok = pki_tbs(&ca_with_cn(&key, &"é".repeat(64)));
    assert!(ok.is_ok(), "{ok:?}");
    let r = pki_tbs(&ca_with_cn(&key, &"é".repeat(65)));
    assert!(real_refusal(&r), "{r:?}");
}

/// An empty CN names nothing, so it is refused: a role certificate with an
/// empty CN could match no role, and a CA with one could not be told apart.
#[test]
fn cert_empty_common_name_is_refused() {
    let key = EcKey::generate();
    let mut p = ca_with_cn(&key, "x");
    p.subject = Dn::cn("");
    let r = pki_tbs(&p);
    assert!(real_refusal(&r), "{r:?}");
}

/// Design section 15: an arbitrary CN of 1 to 64 characters round-trips
/// byte for byte as a UTF8String.
#[test]
fn cert_build_roundtrip_any_common_name_reads_back_equal() {
    let key = EcKey::generate();
    check_with(
        "cert_build_roundtrip_any_common_name_reads_back_equal",
        Config::default().with_cases(256),
        |g| {
            let cn = common::gen_cn(g);
            g.note("cn", &cn);
            let cert = pki_issue(&ca_with_cn(&key, &cn), &key)
                .map_err(|e| format!("refused a valid CN: {e:?}"))?;
            let read = oracle::read(&cert)?;
            prop_assert_eq!(read.subject, der::name_content(&cn, None));
            Ok(())
        },
    );
}

//! Validity and lifetimes (design section 1.3, ADR-005 "Role
//! certificates", ADR-009, RFC 5280 section 4.1.2.5).
//!
//! A refusal test asserts a refusal by real code, never the W0
//! `NotImplemented` stub, so each one is red while the stub stands.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::der;
use common::keys::EcKey;
use common::profile::{Profile, ca_profile, client_profile, contains, pki_tbs, real_refusal};
use common::time::{CLIENT_MAX_SPAN, DAY, GENERALIZED_FROM, MAX_TIME, MIN_TIME, T0};
use fstp_prop::{Config, check_with, prop_assert};

const CLUSTER_CA: &str = "fstp cluster CA 7f3a0c1e";
const ROLE: &str = "c_0123456789abcdef0123456789abcdef_keys";

fn client(not_before: i64, not_after: i64) -> Profile {
    client_profile(CLUSTER_CA, ROLE, &EcKey::generate(), not_before, not_after)
}

fn ca(not_before: i64, not_after: i64) -> Profile {
    ca_profile(CLUSTER_CA, &EcKey::generate(), not_before, not_after)
}

/// ADR-005: a validity whose `notBefore` is one second after its
/// `notAfter` is refused.
#[test]
fn adr005_not_before_after_not_after_is_refused() {
    let r = pki_tbs(&client(T0 + 1, T0));
    assert!(real_refusal(&r), "{r:?}");
}

/// ADR-005: a validity whose `notBefore` is far after its `notAfter` is
/// refused for a CA too.
#[test]
fn adr005_inverted_ca_validity_is_refused() {
    let r = pki_tbs(&ca(T0 + 365 * DAY, T0));
    assert!(real_refusal(&r), "{r:?}");
}

/// ADR-005 "Role certificates": a role certificate valid for exactly 7
/// days is accepted. RFC 5280 section 4.1.2.5 counts both ends, so its
/// `notAfter` is `notBefore` plus 7 days minus one second.
#[test]
fn adr005_role_certificate_of_seven_days_is_accepted() {
    let r = pki_tbs(&client(T0, T0 + CLIENT_MAX_SPAN));
    assert!(r.is_ok(), "{r:?}");
}

/// ADR-005 "Role certificates", design section 1.3: a client certificate
/// valid one second longer than 7 days is refused, since the lifetime
/// alone bounds a lost key (no revocation list is used). With both ends
/// valid (RFC 5280 section 4.1.2.5), `notAfter = notBefore + 7 days` is
/// that certificate.
#[test]
fn adr005_role_certificate_over_seven_days_is_refused() {
    let r = pki_tbs(&client(T0, T0 + CLIENT_MAX_SPAN + 1));
    assert!(real_refusal(&r), "{r:?}");
}

/// ADR-005, design section 1.3: a client certificate is accepted exactly
/// when `notBefore <= notAfter` and it is valid for at most 7 days, both
/// ends included (RFC 5280 section 4.1.2.5).
#[test]
fn adr005_client_lifetime_is_accepted_iff_ordered_and_at_most_seven_days() {
    let key = EcKey::generate();
    check_with(
        "adr005_client_lifetime_is_accepted_iff_ordered_and_at_most_seven_days",
        Config::default().with_cases(512),
        |g| {
            let not_before = g.i64_in(T0 - 400 * DAY..=T0 + 400 * DAY);
            let delta = match g.weighted(&[1, 1, 1, 2]) {
                0 => g.i64_in(-2..=1),
                1 => g.i64_in(CLIENT_MAX_SPAN - 1..=CLIENT_MAX_SPAN + 1),
                2 => g.i64_in(-CLIENT_MAX_SPAN * 3..=-1),
                _ => g.i64_in(0..=CLIENT_MAX_SPAN * 3),
            };
            let p = client_profile(CLUSTER_CA, ROLE, &key, not_before, not_before + delta);
            g.note("lifetime", &delta);
            let r = pki_tbs(&p);
            let expect_ok = (0..=CLIENT_MAX_SPAN).contains(&delta);
            if expect_ok {
                prop_assert!(r.is_ok(), "refused a valid lifetime: {r:?}");
            } else {
                prop_assert!(real_refusal(&r), "accepted or stub-refused: {r:?}");
            }
            Ok(())
        },
    );
}

/// RFC 5280 section 4.1.2.5, design section 15: the validity is written
/// as the reference writes it, UTCTime through 2049 and GeneralizedTime
/// from 2050, for every encodable pair.
#[test]
fn cert_validity_encoding_matches_the_rfc5280_reference() {
    let key = EcKey::generate();
    check_with(
        "cert_validity_encoding_matches_the_rfc5280_reference",
        Config::default().with_cases(512),
        |g| {
            let not_before = common::gen_time(g);
            let not_after = g.i64_in(not_before..=MAX_TIME);
            let p = ca_profile(CLUSTER_CA, &key, not_before, not_after);
            g.note("validity", &(not_before, not_after));
            let tbs = pki_tbs(&p).map_err(|e| format!("fstp-pki refused: {e:?}"))?;
            let validity = common::time::validity(not_before, not_after).unwrap();
            prop_assert!(
                contains(&tbs, &validity),
                "the reference validity is missing"
            );
            Ok(())
        },
    );
}

/// RFC 5280 section 4.1.2.5: an instant before 1950 or after 9999 cannot
/// be encoded in the profile, so it is refused. Every instant inside is
/// accepted.
#[test]
fn cert_validity_outside_1950_to_9999_is_refused() {
    let key = EcKey::generate();
    check_with(
        "cert_validity_outside_1950_to_9999_is_refused",
        Config::default().with_cases(512),
        |g| {
            let a = common::gen_any_time(g);
            let b = common::gen_any_time(g);
            let (not_before, not_after) = if a <= b { (a, b) } else { (b, a) };
            let p = ca_profile(CLUSTER_CA, &key, not_before, not_after);
            g.note("validity", &(not_before, not_after));
            let r = pki_tbs(&p);
            let in_range = |t: i64| (MIN_TIME..=MAX_TIME).contains(&t);
            if in_range(not_before) && in_range(not_after) {
                prop_assert!(r.is_ok(), "refused an encodable validity: {r:?}");
            } else {
                prop_assert!(real_refusal(&r), "accepted or stub-refused: {r:?}");
            }
            Ok(())
        },
    );
}

/// RFC 5280 section 4.1.2.5: the last second of 2049 is UTCTime
/// `491231235959Z`, and the first second of 2050 is GeneralizedTime
/// `20500101000000Z`.
#[test]
fn cert_validity_switches_from_utctime_to_generalized_time_at_2050() {
    let tbs = pki_tbs(&ca(GENERALIZED_FROM - 1, GENERALIZED_FROM)).expect("fstp-pki writes it");
    let expected = der::seq(&[
        &der::tlv(0x17, b"491231235959Z"),
        &der::tlv(0x18, b"20500101000000Z"),
    ]);
    assert!(contains(&tbs, &expected));
}

/// The validity bounds `fstp-pki` writes read the same instants back: one
/// TBS per edge instant equals the reference prefix in full.
#[test]
fn cert_validity_edge_instants_match_the_reference_prefix() {
    let key = EcKey::generate();
    for (nb, na) in [
        (MIN_TIME, MIN_TIME),
        (MAX_TIME, MAX_TIME),
        (MIN_TIME, MAX_TIME),
        (-1, 0),
        (0, 1),
    ] {
        let p = ca_profile(CLUSTER_CA, &key, nb, na);
        let tbs = pki_tbs(&p).expect("fstp-pki writes the edge validity");
        let content = common::split_sequence(&tbs).expect("the TBS is one SEQUENCE");
        let prefix = common::profile::tbs_prefix(&p).unwrap();
        assert_eq!(
            &content[..prefix.len().min(content.len())],
            prefix.as_slice()
        );
    }
}

/// Same input, same bytes: `fstp-pki` writes a TBS deterministically.
#[test]
fn cert_tbs_is_deterministic() {
    let p = ca(T0, T0 + DAY);
    let a = pki_tbs(&p).expect("fstp-pki writes the TBS");
    let b = pki_tbs(&p).expect("fstp-pki writes the TBS again");
    assert_eq!(a, b);
}

/// The 7-day maximum of a client certificate does not apply to a CA: the
/// design rolls CAs over yearly with an overlap (ADR-005 "Role
/// certificates"), so a CA of 400 days is accepted.
#[test]
fn adr005_ca_lifetime_covers_a_yearly_rollover_with_overlap() {
    let r = pki_tbs(&ca(T0, T0 + 400 * DAY));
    assert!(r.is_ok(), "{r:?}");
}

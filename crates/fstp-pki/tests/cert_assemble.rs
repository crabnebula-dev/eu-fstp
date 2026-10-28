//! Assembly of a certificate from its TBS and the caller's signature
//! (design sections 1.3 and 2.1: `fstp-pki` returns the bytes to sign and
//! assembles the certificate from a signature).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::der;
use common::keys::EcKey;
use common::profile::{ca_profile, to_spec};
use common::time::{DAY, T0};
use fstp_pki::cert::{assemble, tbs};
use fstp_prop::{Config, check_with, prop_assert_eq};

/// Design section 1.3: the certificate is exactly `SEQUENCE { tbs,
/// ecdsa-with-SHA256, BIT STRING signature }`, for any signature bytes the
/// caller's signer returns.
#[test]
fn cert_assemble_wraps_tbs_algorithm_and_signature_exactly() {
    let key = EcKey::generate();
    let spec = to_spec(&ca_profile("fstp cell CA 01", &key, T0, T0 + DAY)).unwrap();
    check_with(
        "cert_assemble_wraps_tbs_algorithm_and_signature_exactly",
        Config::default().with_cases(256),
        |g| {
            let sig = g.bytes(1..=200);
            g.note("signature", &sig);
            let t = tbs(&spec).map_err(|e| format!("tbs refused: {e:?}"))?;
            let cert = assemble(&t, &sig).map_err(|e| format!("assemble refused: {e:?}"))?;
            prop_assert_eq!(
                cert,
                der::certificate(t.as_der(), der::ALG_ECDSA_SHA256, &sig)
            );
            Ok(())
        },
    );
}

/// An empty signature signs nothing, so assembly refuses it.
#[test]
fn cert_assemble_refuses_an_empty_signature() {
    let key = EcKey::generate();
    let spec = to_spec(&ca_profile("fstp cell CA 01", &key, T0, T0 + DAY)).unwrap();
    let t = tbs(&spec).expect("fstp-pki writes the TBS");
    let r = assemble(&t, &[]);
    assert!(common::profile::real_pki_refusal(&r), "{r:?}");
}

/// Design section 1.3: a real aws-lc-rs signature over the TBS gives a
/// certificate that rustls-webpki parses, and the TBS signature algorithm
/// equals the outer one (rustls-webpki refuses a mismatch).
#[test]
fn cert_assemble_with_a_real_signature_parses_with_webpki() {
    let key = EcKey::generate();
    let spec = to_spec(&ca_profile("fstp cell CA 01", &key, T0, T0 + DAY)).unwrap();
    let t = tbs(&spec).expect("fstp-pki writes the TBS");
    let cert = assemble(&t, &key.sign(t.as_der())).expect("fstp-pki assembles");
    common::oracle::read(&cert).expect("rustls-webpki parses the certificate");
}

/// A raw `r || s` half, biased to leading zero bytes and to a set high
/// bit, the two cases where the minimal INTEGER differs from the raw form.
fn gen_half(g: &mut fstp_prop::Gen) -> Vec<u8> {
    let mut half = g.bytes(32..=32);
    match g.weighted(&[2, 1, 1, 1]) {
        0 => {}
        1 => half[0] |= 0x80,
        2 => {
            let zeros = g.usize_in(1..=32);
            half[..zeros].fill(0);
        }
        _ => {
            half.fill(0);
            half[31] = g.u8() | 0x80;
        }
    }
    half
}

/// ADR-004 K14: a custody signer may return raw `r || s`. The encoder
/// writes exactly the reference `ECDSA-Sig-Value` with minimal positive
/// INTEGERs, for every pair of halves.
#[test]
fn adr004_raw_signature_encodes_as_the_reference_ecdsa_sig_value() {
    check_with(
        "adr004_raw_signature_encodes_as_the_reference_ecdsa_sig_value",
        Config::default().with_cases(512),
        |g| {
            let r = gen_half(g);
            let s = gen_half(g);
            g.note("r", &r);
            g.note("s", &s);
            let mut raw = [0u8; 64];
            raw[..32].copy_from_slice(&r);
            raw[32..].copy_from_slice(&s);
            prop_assert_eq!(
                fstp_pki::cert::ecdsa_sig_value_from_raw(&raw),
                der::ecdsa_sig_value(&r, &s)
            );
            Ok(())
        },
    );
}

/// ADR-004 K14, design section 1.3: a certificate signed in the raw
/// `r || s` form and converted by the encoder verifies under the CA key
/// in rustls-webpki.
#[test]
fn adr004_raw_signature_converted_by_the_encoder_verifies_in_webpki() {
    let key = EcKey::generate();
    let spec = to_spec(&ca_profile("fstp cell CA 01", &key, T0, T0 + DAY)).unwrap();
    let t = tbs(&spec).expect("fstp-pki writes the TBS");
    let ca = assemble(&t, &key.sign(t.as_der())).expect("fstp-pki assembles");
    check_with(
        "adr004_raw_signature_converted_by_the_encoder_verifies_in_webpki",
        Config::default().with_cases(64),
        |g| {
            let msg = g.bytes(0..=64);
            let raw = key.sign_fixed(&msg);
            let sig = fstp_pki::cert::ecdsa_sig_value_from_raw(&raw);
            common::oracle::verify_by(&ca, &msg, &sig)?;
            Ok(())
        },
    );
}

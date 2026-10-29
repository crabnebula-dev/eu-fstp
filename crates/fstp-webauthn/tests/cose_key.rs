//! COSE key decoding, `fstp_webauthn::parse_cose_key` (ADR-008
//! "Algorithms", design section 8.1, TH-26).
//!
//! ADR-008 admits ES256 (kty 2, alg -7, crv 1), EdDSA over Ed25519 (kty 1,
//! alg -8, crv 6) and RS256 (kty 3, alg -257) with a modulus of at least
//! 2048 bits. Every other key is refused. The keys here are synthetic.
//! P-256 and Ed25519 keys come from `fstp_crypto::sig`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{Key, ed25519_cose, es256_cose, rs256_cose};
use common::{assert_refused, cbor, hex, refused};
use fstp_prop::{check, prop_assert_eq};
use fstp_webauthn::{CoseKey, parse_cose_key};

use common::rsa::{E as RSA_E, N as RSA_N};

/// R-LG-01, ADR-008: an ES256 key decodes to its coordinates.
#[test]
fn adr008_cose_es256_key_decodes() {
    let key = Key::es256();
    assert_eq!(parse_cose_key(&key.cose()), Ok(key.expected()));
}

/// R-LG-01, ADR-008: an EdDSA Ed25519 key decodes to its public key.
#[test]
fn adr008_cose_ed25519_key_decodes() {
    let key = Key::ed25519(7);
    assert_eq!(parse_cose_key(&key.cose()), Ok(key.expected()));
}

/// R-LG-01, ADR-008: an RS256 key with a 2048-bit modulus decodes.
#[test]
fn adr008_cose_rs256_key_of_2048_bits_decodes() {
    let n = hex(RSA_N);
    assert_eq!(n.len(), 256);
    assert_eq!(
        parse_cose_key(&rs256_cose(&n, &RSA_E)),
        Ok(CoseKey::Rs256 {
            n,
            e: RSA_E.to_vec()
        })
    );
}

/// ADR-008 "RSA modulus floor": a modulus of 2047 bits is refused, as is
/// a 1024-bit one.
#[test]
fn adr008_cose_rs256_modulus_below_2048_bits_refused() {
    let mut n2047 = hex(RSA_N);
    n2047[0] = 0x7f;
    assert_refused(
        "2047-bit modulus",
        &parse_cose_key(&rs256_cose(&n2047, &RSA_E)),
    );
    let n1024 = hex(RSA_N)[..128].to_vec();
    assert_refused(
        "1024-bit modulus",
        &parse_cose_key(&rs256_cose(&n1024, &RSA_E)),
    );
}

/// ADR-008 and RFC 8230 section 4: RSA parameters use the minimum
/// number of octets. A modulus with a leading zero octet is refused, so a
/// 2040-bit modulus cannot pass the floor as 256 bytes.
#[test]
fn adr008_cose_rs256_leading_zero_octet_refused() {
    let mut padded = vec![0x00];
    padded.extend(hex(RSA_N));
    assert_refused(
        "modulus with a zero octet",
        &parse_cose_key(&rs256_cose(&padded, &RSA_E)),
    );
    let mut short = hex(RSA_N);
    short[0] = 0x00;
    assert_refused(
        "256 bytes holding 2040 bits",
        &parse_cose_key(&rs256_cose(&short, &RSA_E)),
    );
    assert_refused(
        "exponent with a zero octet",
        &parse_cose_key(&rs256_cose(&hex(RSA_N), &[0x00, 0x01, 0x00, 0x01])),
    );
}

/// ADR-008 "Algorithms": an algorithm outside ES256, EdDSA and RS256 is
/// refused, even with a key type that fits it.
#[test]
fn adr008_cose_algorithm_outside_the_allowlist_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    let ec2 = |alg: i64, crv: i64| {
        cbor::map(&[
            (cbor::int(1), cbor::int(2)),
            (cbor::int(3), cbor::int(alg)),
            (cbor::int(-1), cbor::int(crv)),
            (cbor::int(-2), cbor::bytes(&x)),
            (cbor::int(-3), cbor::bytes(&y)),
        ])
    };
    // ES384, ES512, ES256K and PS256.
    for (alg, crv) in [(-35, 2), (-36, 3), (-47, 8), (-37, 1)] {
        assert_refused(&format!("alg {alg}"), &parse_cose_key(&ec2(alg, crv)));
    }
    // ES256 on the P-384 curve.
    assert_refused("ES256 on P-384", &parse_cose_key(&ec2(-7, 2)));
    let n = hex(RSA_N);
    let rsa = |alg: i64| {
        cbor::map(&[
            (cbor::int(1), cbor::int(3)),
            (cbor::int(3), cbor::int(alg)),
            (cbor::int(-1), cbor::bytes(&n)),
            (cbor::int(-2), cbor::bytes(&RSA_E)),
        ])
    };
    // PS256 and RS1.
    for alg in [-37, -65535] {
        assert_refused(&format!("RSA alg {alg}"), &parse_cose_key(&rsa(alg)));
    }
}

/// ADR-008: the key type, algorithm and curve must agree. An EdDSA
/// algorithm on an EC2 key, ES256 on an OKP key, and X25519 or Ed448
/// curves are refused.
#[test]
fn adr008_cose_key_type_algorithm_and_curve_must_agree() {
    let ec = Key::es256();
    let (x, y) = ec.point();
    let ed = Key::ed25519(9);
    let ed_x = match ed.expected() {
        CoseKey::Ed25519 { x } => x,
        other => panic!("not Ed25519: {other:?}"),
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "EC2 with alg -8",
            cbor::map(&[
                (cbor::int(1), cbor::int(2)),
                (cbor::int(3), cbor::int(-8)),
                (cbor::int(-1), cbor::int(1)),
                (cbor::int(-2), cbor::bytes(&x)),
                (cbor::int(-3), cbor::bytes(&y)),
            ]),
        ),
        (
            "OKP with alg -7",
            cbor::map(&[
                (cbor::int(1), cbor::int(1)),
                (cbor::int(3), cbor::int(-7)),
                (cbor::int(-1), cbor::int(6)),
                (cbor::int(-2), cbor::bytes(&ed_x)),
            ]),
        ),
        (
            "OKP X25519",
            cbor::map(&[
                (cbor::int(1), cbor::int(1)),
                (cbor::int(3), cbor::int(-8)),
                (cbor::int(-1), cbor::int(4)),
                (cbor::int(-2), cbor::bytes(&ed_x)),
            ]),
        ),
        (
            "OKP Ed448",
            cbor::map(&[
                (cbor::int(1), cbor::int(1)),
                (cbor::int(3), cbor::int(-8)),
                (cbor::int(-1), cbor::int(7)),
                (cbor::int(-2), cbor::bytes(&[0x11; 57])),
            ]),
        ),
        (
            "RSA with alg -7",
            cbor::map(&[
                (cbor::int(1), cbor::int(3)),
                (cbor::int(3), cbor::int(-7)),
                (cbor::int(-1), cbor::bytes(&hex(RSA_N))),
                (cbor::int(-2), cbor::bytes(&RSA_E)),
            ]),
        ),
        (
            "symmetric kty 4",
            cbor::map(&[
                (cbor::int(1), cbor::int(4)),
                (cbor::int(3), cbor::int(-7)),
                (cbor::int(-1), cbor::bytes(&[0x22; 32])),
            ]),
        ),
    ];
    for (what, input) in cases {
        assert_refused(what, &parse_cose_key(&input));
    }
}

/// ADR-008: a key without its algorithm, key type, curve or a coordinate
/// is refused. WebAuthn credential keys always carry `alg`.
#[test]
fn adr008_cose_missing_parameter_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    let full = [
        (cbor::int(1), cbor::int(2)),
        (cbor::int(3), cbor::int(-7)),
        (cbor::int(-1), cbor::int(1)),
        (cbor::int(-2), cbor::bytes(&x)),
        (cbor::int(-3), cbor::bytes(&y)),
    ];
    for drop in 0..full.len() {
        let pairs: Vec<_> = full
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != drop)
            .map(|(_, p)| p.clone())
            .collect();
        assert_refused(
            &format!("ES256 without entry {drop}"),
            &parse_cose_key(&cbor::map(&pairs)),
        );
    }
    let no_x = cbor::map(&[
        (cbor::int(1), cbor::int(1)),
        (cbor::int(3), cbor::int(-8)),
        (cbor::int(-1), cbor::int(6)),
    ]);
    assert_refused("Ed25519 without x", &parse_cose_key(&no_x));
    let rsa_no_e = cbor::map(&[
        (cbor::int(1), cbor::int(3)),
        (cbor::int(3), cbor::int(-257)),
        (cbor::int(-1), cbor::bytes(&hex(RSA_N))),
    ]);
    assert_refused("RS256 without e", &parse_cose_key(&rsa_no_e));
}

/// ADR-008: coordinates and keys have their exact lengths. A 31- or
/// 33-byte P-256 coordinate and a 31- or 33-byte Ed25519 key are refused.
#[test]
fn adr008_cose_wrong_coordinate_length_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    assert_refused("31-byte x", &parse_cose_key(&es256_cose(&x[..31], &y)));
    let mut x33 = vec![0x00];
    x33.extend_from_slice(&x);
    assert_refused("33-byte x", &parse_cose_key(&es256_cose(&x33, &y)));
    assert_refused("31-byte y", &parse_cose_key(&es256_cose(&x, &y[..31])));
    assert_refused(
        "31-byte Ed25519 key",
        &parse_cose_key(&ed25519_cose(&[0x44; 31])),
    );
    assert_refused(
        "33-byte Ed25519 key",
        &parse_cose_key(&ed25519_cose(&[0x44; 33])),
    );
}

/// ADR-008: a P-256 point that is not on the curve is refused when the
/// key is decoded, before any assertion arrives.
#[test]
fn adr008_cose_es256_point_off_the_curve_refused() {
    let key = Key::es256();
    let (x, mut y) = key.point();
    y[31] ^= 0x01;
    assert_refused("point off the curve", &parse_cose_key(&es256_cose(&x, &y)));
    assert_refused(
        "all-zero point",
        &parse_cose_key(&es256_cose(&[0; 32], &[0; 32])),
    );
}

/// ADR-008, TH-26: a COSE key that carries private key material (label
/// -4, `d`) is refused, for EC2 and OKP keys.
#[test]
fn adr008_cose_key_with_private_part_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    let ec = cbor::map(&[
        (cbor::int(1), cbor::int(2)),
        (cbor::int(3), cbor::int(-7)),
        (cbor::int(-1), cbor::int(1)),
        (cbor::int(-2), cbor::bytes(&x)),
        (cbor::int(-3), cbor::bytes(&y)),
        (cbor::int(-4), cbor::bytes(&[0x55; 32])),
    ]);
    assert_refused("EC2 with d", &parse_cose_key(&ec));
    let okp = cbor::map(&[
        (cbor::int(1), cbor::int(1)),
        (cbor::int(3), cbor::int(-8)),
        (cbor::int(-1), cbor::int(6)),
        (cbor::int(-2), cbor::bytes(&[0x33; 32])),
        (cbor::int(-4), cbor::bytes(&[0x55; 32])),
    ]);
    assert_refused("OKP with d", &parse_cose_key(&okp));
}

/// ADR-008: parameters of the wrong CBOR type are refused: a text
/// algorithm, an integer coordinate, a byte-string key type.
#[test]
fn adr008_cose_parameter_of_wrong_type_refused() {
    let key = Key::es256();
    let (x, y) = key.point();
    let with = |label: i64, value: Vec<u8>| {
        let mut pairs = vec![
            (cbor::int(1), cbor::int(2)),
            (cbor::int(3), cbor::int(-7)),
            (cbor::int(-1), cbor::int(1)),
            (cbor::int(-2), cbor::bytes(&x)),
            (cbor::int(-3), cbor::bytes(&y)),
        ];
        for p in &mut pairs {
            if p.0 == cbor::int(label) {
                p.1 = value.clone();
            }
        }
        cbor::map(&pairs)
    };
    assert_refused("text alg", &parse_cose_key(&with(3, cbor::text("ES256"))));
    assert_refused("integer x", &parse_cose_key(&with(-2, cbor::int(5))));
    assert_refused("bytes kty", &parse_cose_key(&with(1, cbor::bytes(&[2]))));
    assert_refused(
        "array, not a map",
        &parse_cose_key(&cbor::array(&[cbor::int(1)])),
    );
}

/// ADR-008, TH-26: `parse_cose_key` reads exactly one key. Trailing bytes,
/// empty input and non-shortest heads are refused.
#[test]
fn adr008_cose_trailing_bytes_and_non_canonical_cbor_refused() {
    let key = Key::ed25519(3);
    let mut trailing = key.cose();
    trailing.push(0x00);
    assert_refused("trailing byte", &parse_cose_key(&trailing));
    assert_refused("empty", &parse_cose_key(&[]));
    // The kty label 1 written as 0x18 0x01.
    let mut wide = key.cose();
    assert_eq!(wide[1], 0x01);
    wide.splice(1..2, [0x18, 0x01]);
    assert_refused("non-shortest label", &parse_cose_key(&wide));
}

/// TH-26: one changed byte of a valid ES256 or Ed25519 key either is
/// refused for a real reason, or decodes to a key whose re-encoding is
/// the changed input.
#[test]
fn th_26_cose_mutated_key_is_refused_or_reencodes() {
    let es = Key::es256().cose();
    let ed = Key::ed25519(5).cose();
    check("th_26_cose_mutated_key_is_refused_or_reencodes", |g| {
        let mut input = if g.bool() { es.clone() } else { ed.clone() };
        let at = g.usize_in(0..=input.len() - 1);
        input[at] ^= g.u8_in(1..=255);
        g.note("input", &input);
        match parse_cose_key(&input) {
            Ok(CoseKey::Es256 { x, y }) => {
                prop_assert_eq!(es256_cose(&x, &y), input);
                Ok(())
            }
            Ok(CoseKey::Ed25519 { x }) => {
                prop_assert_eq!(ed25519_cose(&x), input);
                Ok(())
            }
            other => refused("mutated key", &other),
        }
    });
}

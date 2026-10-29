//! Fuzz target `cose_key_decode` of `fstp-webauthn` (TH-26, H-05, M3
//! design section 15, ADR-008 "Algorithms").
//!
//! Design checks: no panic; depth and size limits; non-shortest forms and
//! duplicate keys refused. The first input byte picks the mode. Odd: the
//! rest is the key bytes as they are. Even: the rest builds a COSE map of
//! labels and values near the admitted keys, so the decoder's branches
//! for each key type, algorithm and curve are reached. For every input:
//!
//! - `parse_cose_key` never panics and is deterministic.
//! - An accepted key is strict CBOR (`cbor::decode` accepts it).
//! - An accepted ES256 point lies on P-256, an accepted Ed25519 key is 32
//!   bytes, and an accepted RS256 modulus is at least 2048 bits with no
//!   leading zero octet.

#![no_main]

mod common;

use common::{Input, head};
use fstp_webauthn::{CoseKey, cbor, parse_cose_key};
use libfuzzer_sys::fuzz_target;

/// The labels and integer values that the admitted keys use, and a few
/// beside them.
const LABELS: [i64; 8] = [1, 3, -1, -2, -3, -4, 2, 4];
const INTS: [i64; 12] = [1, 2, 3, 4, 6, -7, -8, -257, -35, -37, 7, 0];

fn int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 {
        head(out, 0, v as u64);
    } else {
        head(out, 1, (-1 - v) as u64);
    }
}

/// A COSE-like map drawn from `input`.
fn build(input: &mut Input<'_>) -> Vec<u8> {
    let n = input.byte() % 7;
    let mut out = Vec::new();
    head(&mut out, 5, u64::from(n));
    for _ in 0..n {
        int(&mut out, LABELS[usize::from(input.byte()) % LABELS.len()]);
        let pick = input.byte();
        if pick.is_multiple_of(2) {
            int(&mut out, INTS[usize::from(pick / 2) % INTS.len()]);
        } else {
            let len = match pick % 6 {
                1 => 32,
                3 => 256,
                _ => usize::from(input.byte()),
            };
            let bytes = input.take(len);
            head(&mut out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let key = if input.byte() % 2 == 1 {
        input.0.to_vec()
    } else {
        build(&mut input)
    };
    let got = parse_cose_key(&key);
    assert_eq!(
        got,
        parse_cose_key(&key),
        "parse_cose_key is not deterministic"
    );
    let Ok(parsed) = got else {
        return;
    };
    assert!(
        cbor::decode(&key).is_ok(),
        "accepted a key that is not strict CBOR"
    );
    match parsed {
        CoseKey::Es256 { x, y } => {
            let mut point = [0x04; 65];
            point[1..33].copy_from_slice(&x);
            point[33..].copy_from_slice(&y);
            assert!(
                fstp_crypto::sig::p256_point_check(&point).is_ok(),
                "accepted a P-256 point off the curve"
            );
        }
        CoseKey::Ed25519 { x } => assert_eq!(x.len(), 32),
        CoseKey::Rs256 { n, e } => {
            assert!(n.len() >= 256, "accepted a modulus of {} bytes", n.len());
            assert_ne!(n.first(), Some(&0), "accepted a modulus with a zero octet");
            assert_ne!(
                e.first(),
                Some(&0),
                "accepted an exponent with a zero octet"
            );
        }
    }
});

//! Self-tests of the software authenticator's byte builders and faults
//! (M3 design section 14.3, lane W1a). Written by the W1a implementer.
//! Each fault must change exactly the field it names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use fstp_celltest::soft_authn::{
    Alg, Ceremony, Fault, FaultRefused, SoftAuthenticator, client_data_json, cose_key, flags,
    none_attestation_object,
};

/// WebAuthn Level 2 section 5.8.1: the client data names the ceremony,
/// the challenge in unpadded base64url and the origin.
#[test]
fn harness_soft_authn_client_data_json_shape() {
    let json = client_data_json(Ceremony::Get, &[0xfb; 4], "https://cell.test");
    assert_eq!(
        String::from_utf8(json).unwrap(),
        "{\"type\":\"webauthn.get\",\"challenge\":\"-_v7-w\",\"origin\":\"https://cell.test\",\"crossOrigin\":false}"
    );
}

/// Design section 14.3: `WrongOrigin` changes the origin only, and
/// `ReplayedChallenge` carries the previous challenge.
#[test]
fn harness_soft_authn_client_data_faults() {
    let mut a = SoftAuthenticator::for_rp("cell.test");
    let first = a.client_data(Ceremony::Get, [1; 32], &[]).unwrap();
    let wrong = a
        .client_data(Ceremony::Get, [1; 32], &[Fault::WrongOrigin])
        .unwrap();
    assert_eq!(
        String::from_utf8(wrong).unwrap(),
        String::from_utf8(first)
            .unwrap()
            .replace("https://cell.test", "https://wrong.cell.test")
    );
    let replay = a
        .client_data(Ceremony::Get, [2; 32], &[Fault::ReplayedChallenge])
        .unwrap();
    assert_eq!(
        replay,
        client_data_json(Ceremony::Get, &[1; 32], "https://cell.test")
    );
}

/// WebAuthn Level 2 section 6.1, design section 14.3: assertion data is
/// the RP id hash, the flags and a rising counter. `NoUserVerification`,
/// `WrongRpIdHash` and `CounterRegression` each change their field only.
#[test]
fn harness_soft_authn_assertion_data_faults() {
    let mut a = SoftAuthenticator::for_rp("cell.test");
    let good = a.assertion_data(&[]).unwrap();
    assert_eq!(good.len(), 37);
    assert_eq!(good[..32], fstp_crypto::sha256(b"cell.test"));
    assert_eq!(good[32], flags::UP | flags::UV);
    assert_eq!(good[33..37], 1u32.to_be_bytes());
    let no_uv = a.assertion_data(&[Fault::NoUserVerification]).unwrap();
    assert_eq!(no_uv[32], flags::UP);
    assert_eq!(no_uv[33..37], 2u32.to_be_bytes());
    let wrong_rp = a.assertion_data(&[Fault::WrongRpIdHash]).unwrap();
    assert_eq!(wrong_rp[..32], fstp_crypto::sha256(b"wrong.cell.test"));
    let regressed = a.assertion_data(&[Fault::CounterRegression]).unwrap();
    assert_eq!(regressed[33..37], 2u32.to_be_bytes());
}

/// RFC 9053, CTAP2 canonical CBOR: an ES256 COSE key is the five-entry
/// map 1: 2, 3: -7, -1: 1, -2: x, -3: y in that order.
#[test]
fn harness_soft_authn_es256_cose_key_is_canonical() {
    let key = cose_key(Alg::Es256, &[0x11; 32], Some(&[0x22; 32]));
    let mut want = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    want.extend([0x11; 32]);
    want.extend([0x22, 0x58, 0x20]);
    want.extend([0x22; 32]);
    assert_eq!(key, want);
}

/// WebAuthn Level 2 section 6.5.4: a `none` attestation object holds
/// `fmt`, an empty `attStmt` and `authData`, in canonical key order.
#[test]
fn harness_soft_authn_none_attestation_object_layout() {
    let obj = none_attestation_object(&[0xaa, 0xbb]);
    let mut want = vec![0xa3, 0x63];
    want.extend(b"fmt");
    want.push(0x64);
    want.extend(b"none");
    want.push(0x67);
    want.extend(b"attStmt");
    want.extend([0xa0, 0x68]);
    want.extend(b"authData");
    want.extend([0x42, 0xaa, 0xbb]);
    assert_eq!(obj, want);
}

/// Design section 14.3: a replayed challenge needs an earlier, other
/// challenge. Without one the builder refuses, rather than send the fresh
/// challenge as if it were a replay. A replay of an earlier challenge is
/// produced first, so a builder that refuses every replay fails here.
#[test]
fn harness_soft_authn_replay_without_an_earlier_challenge_is_refused() {
    let mut a = SoftAuthenticator::for_rp("cell.test");
    let first = a.client_data(Ceremony::Get, [1; 32], &[Fault::ReplayedChallenge]);
    let same = {
        a.client_data(Ceremony::Get, [1; 32], &[]).unwrap();
        a.client_data(Ceremony::Get, [1; 32], &[Fault::ReplayedChallenge])
    };
    let replay = a.client_data(Ceremony::Get, [2; 32], &[Fault::ReplayedChallenge]);
    assert_eq!(
        (first, same, replay.is_ok()),
        (
            Err(FaultRefused::NoEarlierChallenge),
            Err(FaultRefused::NoEarlierChallenge),
            true
        )
    );
}

/// Design section 14.3, WebAuthn Level 2 section 6.1.1: a counter
/// regression from 0 cannot be written, so the builder refuses it and the
/// counter stays at 0. After one assertion the regression is produced.
#[test]
fn harness_soft_authn_counter_regression_from_zero_is_refused() {
    let mut a = SoftAuthenticator::for_rp("cell.test");
    let refused = a.assertion_data(&[Fault::CounterRegression]);
    let first = a.assertion_data(&[]).unwrap();
    let regressed = a.assertion_data(&[Fault::CounterRegression]).unwrap();
    assert_eq!(
        (refused, first[33..37].to_vec(), regressed[33..37].to_vec()),
        (
            Err(FaultRefused::CounterAtZero),
            1u32.to_be_bytes().to_vec(),
            0u32.to_be_bytes().to_vec()
        )
    );
}

/// Design section 14.3: each builder refuses a fault it does not write,
/// so no faulted call returns an unfaulted value. A refusal leaves the
/// state unchanged: the next counter is still 1 and no challenge is
/// recorded for a replay.
#[test]
fn harness_soft_authn_builders_refuse_faults_of_the_other_builder() {
    // Which builder writes each fault, written out here, apart from the
    // production classifier.
    let client_faults = [Fault::WrongOrigin, Fault::ReplayedChallenge];
    let auth_faults = [
        Fault::WrongRpIdHash,
        Fault::NoUserVerification,
        Fault::CounterRegression,
    ];
    let mut seen = Vec::new();
    for f in client_faults {
        let mut a = SoftAuthenticator::for_rp("cell.test");
        let refused = a.assertion_data(&[f]);
        let counter = a.assertion_data(&[]).unwrap()[33..37].to_vec();
        seen.push((refused.err(), counter));
    }
    for f in auth_faults {
        let mut a = SoftAuthenticator::for_rp("cell.test");
        let refused = a.client_data(Ceremony::Get, [1; 32], &[f, Fault::WrongOrigin]);
        let replay = a.client_data(Ceremony::Get, [2; 32], &[Fault::ReplayedChallenge]);
        let marker = match replay {
            Err(FaultRefused::NoEarlierChallenge) => vec![0],
            _ => vec![1],
        };
        seen.push((refused.err(), marker));
    }
    let one = 1u32.to_be_bytes().to_vec();
    let not = FaultRefused::NotThisBuilder;
    assert_eq!(
        seen,
        vec![
            (Some(not(Fault::WrongOrigin)), one.clone()),
            (Some(not(Fault::ReplayedChallenge)), one),
            (Some(not(Fault::WrongRpIdHash)), vec![0]),
            (Some(not(Fault::NoUserVerification)), vec![0]),
            (Some(not(Fault::CounterRegression)), vec![0]),
        ]
    );
}

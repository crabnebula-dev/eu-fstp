//! Review reproducer: the proof-of-possession message must bind the
//! request context (design section 9.1, ADR-005 "Role certificates").
//!
//! `RoleCredential` names a role and `CertRenewal` names a component. A
//! proof should only pass for the request it was made for. Before the fix
//! the signed bytes depended on the SPKI and the challenge alone, so one
//! signature verified for every role, component and cluster that shared
//! the challenge. The fix added a `PopContext` argument; this test now
//! calls that API.

#![allow(clippy::expect_used, reason = "test code asserts on known-good values")]

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use fstp_pki::pop::{POP_DOMAIN, PopContext, PopPurpose, message};

const CHALLENGE: [u8; 32] = [0x5a; 32];

fn ctx(purpose: PopPurpose, scope: u8, name: &str) -> PopContext {
    PopContext {
        purpose,
        scope_id: [scope; 16],
        name: name.to_owned(),
    }
}

/// Design section 9.1: the signed message must hold more than the domain
/// prefix, the SPKI digest and the challenge. Without a role, component
/// or cluster in it, a proof made for `c_<cell>_app` also verifies as a
/// proof for `c_<cell>_keys` or for a `CertRenewal`.
#[test]
fn review_pop_message_binds_the_request_context() {
    let rng = SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("aws-lc-rs generates a key");
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref())
        .expect("aws-lc-rs reads its key");
    let spki = key
        .public_key()
        .as_der()
        .expect("aws-lc-rs encodes the SPKI")
        .as_ref()
        .to_vec();
    let app = "c_0123456789abcdef0123456789abcdef_app";
    let keys = "c_0123456789abcdef0123456789abcdef_keys";

    // The proof a component makes for one request.
    let made_for = ctx(PopPurpose::RoleCredential, 1, app);
    let msg = message(&spki, &made_for, &CHALLENGE).expect("a P-256 SPKI");
    let sig = key.sign(&rng, &msg).expect("aws-lc-rs signs");
    let point = spki.get(26..).expect("an uncompressed point");
    let verifies = |m: &[u8]| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(m, sig.as_ref())
            .is_ok()
    };
    assert!(
        verifies(&msg),
        "precondition: the oracle verifies the proof"
    );

    // The bytes an issuer would check for any other request with the same
    // key and challenge. None of them may accept the proof.
    for other in [
        ctx(PopPurpose::RoleCredential, 1, keys),
        ctx(PopPurpose::RoleCredential, 2, app),
        ctx(PopPurpose::CertRenewal, 1, app),
    ] {
        let other_request = message(&spki, &other, &CHALLENGE).expect("a P-256 SPKI");
        assert!(
            !verifies(&other_request),
            "a proof for {made_for:?} replays as a proof for {other:?}"
        );
    }

    let mut bare = POP_DOMAIN.to_vec();
    bare.extend_from_slice(&fstp_crypto::sha256(&spki));
    bare.extend_from_slice(&CHALLENGE);
    assert_ne!(
        msg, bare,
        "the PoP message binds only the SPKI digest and the challenge, \
         so it can be replayed for another role, component or cluster"
    );
}

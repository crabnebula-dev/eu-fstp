//! Fuzz target `licence_token_decode` of `fstp-release` (TH-26, H-05, M3
//! design section 15, I-39).
//!
//! Design checks: no panic; signature checked before use.
//!
//! The first byte picks a mode. Mode 0 passes the rest as a token. Mode 1
//! treats the rest as a token body and signs it with the pinned key, so
//! the fuzzer reaches the field checks behind the signature. Every
//! accepted token must be exactly a body and a valid signature by the
//! key, with fields read from that signed body (W1g token proposal).
//! Once lane W2j lands `verify_token`, a well-formed signed body must
//! also verify. The W0 stub refuses everything, which these checks allow.

#![no_main]

use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use fstp_release::ReleaseError;
use fstp_release::licence::{Ed25519Public, verify_token};
use libfuzzer_sys::fuzz_target;

const MAGIC: &[u8; 8] = b"FSTPLT01";
const CONTEXT: &[u8] = b"fstp-licence-token-v1";
const BODY_LEN: usize = 49;
const TOKEN_LEN: usize = BODY_LEN + 64;

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut msg = CONTEXT.to_vec();
    msg.push(0);
    msg.extend_from_slice(body);
    msg
}

fn be(body: &[u8], at: usize) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&body[at..at + 8]);
    i64::from_be_bytes(b)
}

/// Whether a body is well formed: magic, a kind of 1 or 2, ordered
/// instants.
fn well_formed(body: &[u8]) -> bool {
    body.len() == BODY_LEN
        && &body[..8] == MAGIC
        && matches!(body[24], 1 | 2)
        && be(body, 25) <= be(body, 33)
        && be(body, 33) <= be(body, 41)
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(key) = Ed25519SigningKey::from_seed(&[0x11; 32]) else {
        return;
    };
    let public = key.public_key();
    let bytes = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        let Ok(sig) = key.sign(&signed_message(rest)) else {
            return;
        };
        [rest, sig.as_slice()].concat()
    };
    let result = verify_token(&bytes, &Ed25519Public(public));
    assert!(!format!("{result:?}").is_empty());
    match result {
        Ok(t) => {
            assert_eq!(bytes.len(), TOKEN_LEN, "accepted another length");
            let (body, sig) = bytes.split_at(BODY_LEN);
            assert!(
                ed25519_verify(&public, &signed_message(body), sig).is_ok(),
                "accepted a token the key did not sign"
            );
            assert!(well_formed(body), "accepted a malformed body");
            assert_eq!(&t.licence.0[..], &body[8..24]);
            assert_eq!(t.issued_at, be(body, 25));
            assert_eq!(t.refresh_after, be(body, 33));
            assert_eq!(t.not_after, be(body, 41));
        }
        Err(ReleaseError::NotImplemented(_)) => {}
        #[allow(unreachable_patterns)]
        Err(_) => {
            assert!(
                !(mode & 1 == 1 && well_formed(rest)),
                "refused a well-formed token signed by the key"
            );
        }
    }
});

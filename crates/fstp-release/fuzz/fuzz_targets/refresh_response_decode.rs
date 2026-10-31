//! Fuzz target `refresh_response_decode` of `fstp-release` (TH-26, H-05,
//! M3 design sections 10.2 and 15, I-39).
//!
//! Design checks: no panic; signature checked before use.
//!
//! A refresh response body is `"FSTPRR01" || flag || transition? ||
//! token` (W1g proposal), applied by `apply_refresh` to the stored token
//! and key set. The first byte picks a mode. Bit 0 clear passes the rest
//! as the body. Bit 0 set builds the body from the rest: a flags byte,
//! then a transition body if the flags ask for one, then a token body,
//! each signed by a fixed key the flags choose. Bit 1 picks a pinned set
//! of one key or a full set of `MAX_KEYS` keys.
//!
//! An accepted response is all or nothing: its token was signed by a key
//! in force in the resulting set, names the stored licence, is not older
//! than the stored token, and its fields are read from the signed body.
//! The set changes only by the key of a transition a key in force
//! signed, and only below the cap. The inputs are borrowed, so a refusal
//! leaves the token and set as they were.

#![no_main]

use std::sync::OnceLock;

use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use fstp_release::licence::{
    Ed25519Public, KeySet, LicenceId, LicenceKind, MAX_KEYS, PinnedKey, RESPONSE_MAGIC,
    TOKEN_BODY_LEN, TOKEN_CONTEXT, TOKEN_LEN, TOKEN_MAGIC, TRANSITION_BODY_LEN, TRANSITION_CONTEXT,
    TRANSITION_LEN, TRANSITION_MAGIC, VerifiedToken, apply_refresh, refresh_response,
};
use libfuzzer_sys::fuzz_target;

const NOW: i64 = 1_800_000_000;
const LICENCE: [u8; 16] = [0x4c; 16];

/// The stored token, issued a day before `NOW`.
const STORED: VerifiedToken = VerifiedToken {
    licence: LicenceId(LICENCE),
    kind: LicenceKind::Commercial,
    issued_at: NOW - 86_400,
    refresh_after: NOW,
    not_after: NOW + 86_400,
};

struct Fixture {
    pinned: Ed25519SigningKey,
    next: Ed25519SigningKey,
    small: KeySet,
    full: KeySet,
}

fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let pinned = Ed25519SigningKey::from_seed(&[0x11; 32]).ok()?;
            let next = Ed25519SigningKey::from_seed(&[0x12; 32]).ok()?;
            let first = Ed25519Public(pinned.public_key());
            let small = KeySet::shipped(&[first]).ok()?;
            let mut keys = vec![first];
            for i in 0..MAX_KEYS - 1 {
                let k = Ed25519SigningKey::from_seed(&[0x40 + i as u8; 32]).ok()?;
                keys.push(Ed25519Public(k.public_key()));
            }
            let full = KeySet::shipped(&keys).ok()?;
            Some(Fixture {
                pinned,
                next,
                small,
                full,
            })
        })
        .as_ref()
}

fn message(context: &[u8], body: &[u8]) -> Vec<u8> {
    let mut msg = context.to_vec();
    msg.push(0);
    msg.extend_from_slice(body);
    msg
}

fn be(body: &[u8], at: usize) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&body[at..at + 8]);
    i64::from_be_bytes(b)
}

fn signed(key: &Ed25519SigningKey, context: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let sig = key.sign(&message(context, body)).ok()?;
    Some([body, sig.as_slice()].concat())
}

/// What the structured mode built, for the acceptance check.
struct Built {
    response: Vec<u8>,
    /// The response must be accepted: no transition, a well-formed token
    /// body for the stored licence, newer than the stored token, signed
    /// by the pinned key.
    must_accept: bool,
}

fn build(f: &Fixture, rest: &[u8]) -> Option<Built> {
    let (flags, rest) = rest.split_first()?;
    let with_transition = flags & 1 == 1;
    let (transition, token_body) = if with_transition {
        let mut body = [0u8; TRANSITION_BODY_LEN];
        let take = rest.len().min(TRANSITION_BODY_LEN);
        body[..take].copy_from_slice(&rest[..take]);
        if flags & 4 == 4 {
            body[..8].copy_from_slice(&TRANSITION_MAGIC);
            body[8..40].copy_from_slice(&f.next.public_key());
        }
        let signer = if flags & 2 == 2 { &f.next } else { &f.pinned };
        (
            Some(signed(signer, TRANSITION_CONTEXT, &body)?),
            &rest[take..],
        )
    } else {
        (None, rest)
    };
    let mut token_body = token_body.to_vec();
    if flags & 16 == 16 && token_body.len() >= 24 {
        token_body[..8].copy_from_slice(&TOKEN_MAGIC);
        token_body[8..24].copy_from_slice(&LICENCE);
    }
    let by_pinned = flags & 8 == 0;
    let signer = if by_pinned { &f.pinned } else { &f.next };
    let token = signed(signer, TOKEN_CONTEXT, &token_body)?;
    let well_formed = token_body.len() == TOKEN_BODY_LEN
        && token_body[..8] == TOKEN_MAGIC
        && token_body[8..24] == LICENCE
        && matches!(token_body[24], 1 | 2)
        && be(&token_body, 25) <= be(&token_body, 33)
        && be(&token_body, 33) <= be(&token_body, 41)
        && be(&token_body, 25) > STORED.issued_at;
    Some(Built {
        response: refresh_response(transition.as_deref(), &token),
        must_accept: !with_transition && by_pinned && well_formed,
    })
}

fn check(keys: &KeySet, response: &[u8], must_accept: bool) {
    let keys_before = keys.clone();
    let result = apply_refresh(&STORED, keys, response, NOW);
    assert!(!format!("{result:?}").is_empty());
    assert_eq!(keys, &keys_before, "the stored set moved");
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            assert!(
                !must_accept,
                "refused a fresh token of the pinned key: {e:?}"
            );
            return;
        }
    };
    let rest = response
        .strip_prefix(RESPONSE_MAGIC.as_slice())
        .expect("accepted another magic");
    let (flag, rest) = rest.split_first().expect("accepted no flag");
    let (transition, token) = match flag {
        0 => (None, rest),
        1 => {
            let (t, token) = rest.split_at(TRANSITION_LEN);
            (Some(t), token)
        }
        _ => panic!("accepted flag {flag}"),
    };
    assert_eq!(token.len(), TOKEN_LEN, "accepted another token length");
    let (body, sig) = token.split_at(TOKEN_BODY_LEN);
    assert!(
        r.keys
            .in_force(NOW)
            .any(|k| ed25519_verify(&k.0, &message(TOKEN_CONTEXT, body), sig).is_ok()),
        "adopted a token no key in force signed"
    );
    assert_eq!(&body[..8], &TOKEN_MAGIC, "accepted another token magic");
    assert_eq!(r.token.licence, STORED.licence, "adopted another licence");
    assert_eq!(&r.token.licence.0[..], &body[8..24]);
    assert_eq!(r.token.kind.code(), body[24]);
    assert_eq!(r.token.issued_at, be(body, 25));
    assert_eq!(r.token.refresh_after, be(body, 33));
    assert_eq!(r.token.not_after, be(body, 41));
    assert!(
        r.token.issued_at > STORED.issued_at || r.token == STORED,
        "adopted a stale token"
    );
    let before = keys.keys();
    match transition {
        None => assert_eq!(r.keys, *keys, "the set moved without a transition"),
        Some(t) => {
            let (t_body, t_sig) = t.split_at(TRANSITION_BODY_LEN);
            assert_eq!(&t_body[..8], &TRANSITION_MAGIC);
            assert!(
                keys.in_force(NOW).any(|k| ed25519_verify(
                    &k.0,
                    &message(TRANSITION_CONTEXT, t_body),
                    t_sig
                )
                .is_ok()),
                "kept a transition no key in force signed"
            );
            let mut next = [0u8; 32];
            next.copy_from_slice(&t_body[8..40]);
            let next = Ed25519Public(next);
            assert!(!next.is_small_order(), "kept a small-order key");
            let held = before.iter().any(|p| p.key == next);
            if held || before.len() >= MAX_KEYS {
                assert_eq!(r.keys, *keys, "the set moved past the cap or twice");
            } else {
                let joined = PinnedKey {
                    key: next,
                    not_before: be(t_body, 40),
                };
                assert_eq!(&r.keys.keys()[..before.len()], before, "moved a key");
                assert_eq!(
                    &r.keys.keys()[before.len()..],
                    &[joined],
                    "joined another key"
                );
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Some(f) = fixture() else {
        return;
    };
    let keys = if mode & 2 == 0 { &f.small } else { &f.full };
    if mode & 1 == 0 {
        check(keys, rest, false);
    } else if let Some(built) = build(f, rest) {
        check(keys, &built.response, built.must_accept);
    }
});

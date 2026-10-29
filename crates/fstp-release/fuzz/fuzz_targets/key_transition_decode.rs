//! Fuzz target `key_transition_decode` of `fstp-release` (TH-26, H-05, M3
//! design section 15, I-39).
//!
//! Design checks: no panic; signature checked before use.
//!
//! A transition is `"FSTPKT01" || next_key || not_before || signature`
//! (W1g proposal). The first byte picks a mode:
//!
//! - 0: the rest goes to `decode_key_transition`, under the shipped keys.
//! - 1: the rest goes to a pinned `KeySet`, through both
//!   `KeySet::verify_transition` and `KeySet::apply_transition`.
//! - 2: the rest is a transition body, signed by the key in force.
//! - 3: the rest is a transition body, signed by a key the set announces
//!   for later, so it is not yet in force.
//!
//! An accepted transition has exactly the format's length and magic, is
//! signed by a key in force, names the fields of its signed body, and
//! never names a key of small order. A refusal leaves the set unchanged.
//! A well-formed body signed by the key in force is accepted.

#![no_main]

use std::sync::OnceLock;

use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use fstp_release::licence::{
    Ed25519Public, KeySet, PinnedKey, TRANSITION_BODY_LEN, TRANSITION_CONTEXT, TRANSITION_LEN,
    TRANSITION_MAGIC, decode_key_transition, sign_transition,
};
use libfuzzer_sys::fuzz_target;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    in_force: Ed25519SigningKey,
    later: Ed25519SigningKey,
    set: KeySet,
}

/// The pinned set: one shipped key in force, and one key that an
/// accepted transition announces for a day after `NOW`.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let in_force = Ed25519SigningKey::from_seed(&[0x11; 32]).ok()?;
            let later = Ed25519SigningKey::from_seed(&[0x12; 32]).ok()?;
            let mut set = KeySet::shipped(&[Ed25519Public(in_force.public_key())]).ok()?;
            let announce =
                sign_transition(&Ed25519Public(later.public_key()), NOW + 86_400, &in_force)
                    .ok()?;
            set.apply_transition(&announce, NOW).ok()?;
            Some(Fixture {
                in_force,
                later,
                set,
            })
        })
        .as_ref()
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut msg = TRANSITION_CONTEXT.to_vec();
    msg.push(0);
    msg.extend_from_slice(body);
    msg
}

fn next_key_of(body: &[u8]) -> Ed25519Public {
    let mut k = [0u8; 32];
    k.copy_from_slice(&body[8..40]);
    Ed25519Public(k)
}

fn not_before_of(body: &[u8]) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&body[40..48]);
    i64::from_be_bytes(b)
}

fn shipped_mode(data: &[u8]) {
    let result = decode_key_transition(data);
    assert!(!format!("{result:?}").is_empty());
    if let Ok(key) = result {
        assert_eq!(data.len(), TRANSITION_LEN, "accepted another length");
        assert_eq!(&data[..8], &TRANSITION_MAGIC, "accepted another magic");
        assert_eq!(
            &key.0[..],
            &data[8..40],
            "named a key the body does not carry"
        );
    }
}

fn pinned_mode(f: &Fixture, mode: u8, rest: &[u8]) {
    let bytes = match mode {
        1 => rest.to_vec(),
        _ => {
            let signer = if mode == 2 { &f.in_force } else { &f.later };
            let Ok(sig) = signer.sign(&signed_message(rest)) else {
                return;
            };
            [rest, sig.as_slice()].concat()
        }
    };
    let verified = f.set.verify_transition(&bytes, NOW);
    let mut after = f.set.clone();
    let applied = after.apply_transition(&bytes, NOW);
    assert!(!format!("{applied:?}").is_empty());
    assert_eq!(applied, verified, "apply and verify disagree");
    match applied {
        Ok(t) => {
            assert_eq!(bytes.len(), TRANSITION_LEN, "accepted another length");
            let (body, sig) = bytes.split_at(TRANSITION_BODY_LEN);
            assert_eq!(&body[..8], &TRANSITION_MAGIC, "accepted another magic");
            assert!(
                ed25519_verify(&f.in_force.public_key(), &signed_message(body), sig).is_ok(),
                "accepted a transition no key in force signed"
            );
            assert_eq!(t.next_key(), next_key_of(body), "named another key");
            assert_eq!(t.not_before(), not_before_of(body), "named another instant");
            assert!(!t.next_key().is_small_order(), "pinned a small-order key");
            let before = f.set.keys();
            assert_eq!(&after.keys()[..before.len()], before, "moved a pinned key");
            if before.iter().any(|p| p.key == t.next_key()) {
                assert_eq!(after.keys().len(), before.len(), "pinned a key twice");
            } else {
                let joined = PinnedKey {
                    key: t.next_key(),
                    not_before: t.not_before(),
                };
                assert_eq!(
                    &after.keys()[before.len()..],
                    &[joined],
                    "joined another key"
                );
            }
        }
        Err(e) => {
            assert_eq!(after, f.set, "a refusal changed the set");
            let well_formed = rest.len() == TRANSITION_BODY_LEN
                && rest[..8] == TRANSITION_MAGIC
                && !next_key_of(rest).is_small_order();
            assert!(
                !(mode == 2 && well_formed),
                "refused a well-formed transition signed by the key in force: {e:?}"
            );
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
    match mode & 3 {
        0 => shipped_mode(rest),
        m => pinned_mode(f, m, rest),
    }
});

//! Tests of the limits of the licence key set (I-39, design section
//! 10.2): the cap of `MAX_KEYS`, one spelling of a stored set, and no key
//! of small order. Lane W2j wrote them in fix round 1.
//!
//! A key joins a built set only through `KeySet::apply_transition` or
//! `apply_refresh`, each of which verifies the transition under that same
//! set. `KeySet::with` is private, so a transition verified under another
//! set cannot be applied here. The compiler holds that, so no test does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_crypto::composite::{self, CompositePublicKey};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_release::ReleaseError;
use fstp_release::licence::{
    self, DAY_S, Ed25519Public, Ed25519SigningKey, KeySet, LicenceId, LicenceKind, MAX_KEYS,
    PinnedKey, VerifiedToken,
};

const T0: i64 = 1_800_000_000;
const LICENCE: LicenceId = LicenceId([0x4c; 16]);

/// The small-order encodings with bit 255 clear, as `fstp-crypto` tests
/// them (`crates/fstp-crypto/tests/composite_small_order.rs`).
const SMALL_ORDER_HEX: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn unhex(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Every small-order spelling: each row with bit 255 clear and set.
fn small_order_spellings() -> Vec<Ed25519Public> {
    let mut out = Vec::new();
    for h in SMALL_ORDER_HEX {
        let e = unhex(h);
        let mut neg = e;
        neg[31] |= 0x80;
        out.push(Ed25519Public(e));
        out.push(Ed25519Public(neg));
    }
    out
}

fn key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn public(k: &Ed25519SigningKey) -> Ed25519Public {
    Ed25519Public(k.public_key())
}

fn token(issued_at: i64) -> VerifiedToken {
    VerifiedToken {
        licence: LICENCE,
        kind: LicenceKind::Commercial,
        issued_at,
        refresh_after: issued_at + 7 * DAY_S,
        not_after: issued_at + 14 * DAY_S,
    }
}

/// I-39, design section 10.2: a transition signed by a pinned key that
/// names a key of small order, in any spelling, is refused with
/// `WeakKey`, and the set stays as it was. Signatures under such a key
/// can be forged, so it never joins the set.
#[test]
fn i39_transition_to_a_small_order_key_is_refused() {
    let a = key(0x11);
    let mut set = KeySet::shipped(&[public(&a)]).unwrap();
    let before = set.clone();
    for weak in small_order_spellings() {
        let signed = licence::sign_transition(&weak, T0, &a).unwrap();
        assert_eq!(
            set.verify_transition(&signed, T0),
            Err(ReleaseError::WeakKey),
            "I-39: a transition to {weak:?} verified"
        );
        assert_eq!(
            set.apply_transition(&signed, T0),
            Err(ReleaseError::WeakKey),
            "I-39: a transition to {weak:?} was applied"
        );
        assert_eq!(set, before, "I-39: a refused transition changed the set");
    }
}

/// I-39, design section 10.2: a set shipped or restored with a key of
/// small order is refused with `WeakKey`.
#[test]
fn i39_key_set_refuses_a_small_order_key() {
    let a = public(&key(0x11));
    for weak in small_order_spellings() {
        assert_eq!(
            KeySet::shipped(&[a, weak]),
            Err(ReleaseError::WeakKey),
            "{weak:?}"
        );
        let pinned = [PinnedKey {
            key: weak,
            not_before: T0,
        }];
        assert_eq!(
            KeySet::from_pinned(&pinned),
            Err(ReleaseError::WeakKey),
            "{weak:?}"
        );
    }
}

/// I-39, I-90: the small-order table of `fstp-release` refuses exactly
/// the Ed25519 halves that `fstp_crypto::composite` refuses, over every
/// small-order spelling, real keys and arbitrary bytes.
#[test]
fn i39_small_order_table_matches_fstp_crypto() {
    let composite_key = composite::generate().unwrap().public_key().to_bytes();
    let ed_at = composite::PUBLIC_KEY_LEN - 32;
    let crypto_refuses = |e: &Ed25519Public| {
        let mut bytes = composite_key;
        bytes[ed_at..].copy_from_slice(&e.0);
        CompositePublicKey::from_bytes(&bytes).is_err()
    };
    for weak in small_order_spellings() {
        assert!(weak.is_small_order(), "{weak:?}");
        assert!(crypto_refuses(&weak), "{weak:?}");
    }
    check("i39_small_order_table_matches_fstp_crypto", |g| {
        let e = if g.bool() {
            public(&key(g.u8()))
        } else {
            let mut b = [0u8; 32];
            b.copy_from_slice(&g.bytes(32..=32));
            Ed25519Public(b)
        };
        prop_assert_eq!(e.is_small_order(), crypto_refuses(&e), "{e:?}");
        Ok(())
    });
}

/// I-39, design section 10.2: a stored set has one spelling, so a set
/// that names a key twice is refused with `DuplicateKey`, whatever the
/// `not_before` of each copy.
#[test]
fn i39_key_set_refuses_a_key_named_twice() {
    check("i39_key_set_refuses_a_key_named_twice", |g| {
        let keys: Vec<Ed25519Public> = (0..g.usize_in(1..=4))
            .map(|i| public(&key(0x20 + i as u8)))
            .collect();
        let mut pinned: Vec<PinnedKey> = keys
            .iter()
            .map(|k| PinnedKey {
                key: *k,
                not_before: g.i64_in(T0 - DAY_S..=T0 + DAY_S),
            })
            .collect();
        prop_assert!(KeySet::from_pinned(&pinned).is_ok());
        let copy = PinnedKey {
            key: *g.pick(&keys),
            not_before: g.i64_in(T0 - DAY_S..=T0 + DAY_S),
        };
        pinned.insert(g.usize_in(0..=pinned.len()), copy);
        prop_assert_eq!(
            KeySet::from_pinned(&pinned),
            Err(ReleaseError::DuplicateKey)
        );
        let shipped: Vec<Ed25519Public> = pinned.iter().map(|p| p.key).collect();
        prop_assert_eq!(KeySet::shipped(&shipped), Err(ReleaseError::DuplicateKey));
        Ok(())
    });
}

/// The set of `MAX_KEYS` keys: `first` and the keys of seeds 0x40 on.
fn full_set(first: &Ed25519SigningKey) -> KeySet {
    let mut keys = vec![public(first)];
    keys.extend((0..MAX_KEYS - 1).map(|i| public(&key(0x40 + i as u8))));
    KeySet::shipped(&keys).unwrap()
}

/// I-39, design section 10.2: at the cap, a refresh whose transition
/// names a new key still adopts a token signed by a key already in
/// force. The transition is left out and the set stays as it was, while
/// `apply_transition` alone refuses it with `KeySetFull`.
#[test]
fn i39_refresh_at_the_key_cap_adopts_a_token_signed_by_a_pinned_key() {
    let a = key(0x11);
    let next = key(0x12);
    let keys = full_set(&a);
    assert_eq!(keys.keys().len(), MAX_KEYS);
    let stored = token(T0);
    let transition = licence::sign_transition(&public(&next), T0, &a).unwrap();
    let t2 = token(T0 + DAY_S);
    let signed = licence::sign_token(&t2, &a).unwrap();
    let response = licence::refresh_response(Some(&transition), &signed);
    let got = licence::apply_refresh(&stored, &keys, &response, T0 + DAY_S).unwrap();
    assert_eq!(got.token, t2, "I-39: the refreshed token");
    assert_eq!(got.keys, keys, "I-39: the full set changed");
    let mut alone = keys.clone();
    assert_eq!(
        alone.apply_transition(&transition, T0 + DAY_S),
        Err(ReleaseError::KeySetFull)
    );
    assert_eq!(alone, keys, "I-39: a refused transition changed the set");
}

/// I-39, design section 10.2: at the cap, a token signed only by the new
/// key of a left-out transition is refused, and nothing changes. A key
/// already pinned that the transition names again keeps the refresh
/// whole.
#[test]
fn i39_refresh_at_the_key_cap_refuses_a_token_of_the_left_out_key() {
    let a = key(0x11);
    let next = key(0x12);
    let keys = full_set(&a);
    let stored = token(T0);
    let t2 = token(T0 + DAY_S);
    let transition = licence::sign_transition(&public(&next), T0, &a).unwrap();
    let by_next = licence::sign_token(&t2, &next).unwrap();
    let response = licence::refresh_response(Some(&transition), &by_next);
    assert_eq!(
        licence::apply_refresh(&stored, &keys, &response, T0 + DAY_S),
        Err(ReleaseError::Signature)
    );
    let pinned_again = public(&key(0x40));
    let again = licence::sign_transition(&pinned_again, T0, &a).unwrap();
    let by_a = licence::sign_token(&t2, &a).unwrap();
    let response = licence::refresh_response(Some(&again), &by_a);
    let got = licence::apply_refresh(&stored, &keys, &response, T0 + DAY_S).unwrap();
    assert_eq!((got.token, got.keys), (t2, keys));
}

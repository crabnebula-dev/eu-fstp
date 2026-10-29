//! Tests of the licence key set and its transitions (I-39, TH-32, design
//! sections 10.2 and 15, ADR-004 "Licence token key").
//!
//! The cell pins the key set shipped with its release. A transition
//! `"FSTPKT01" || next_key || not_before || signature`, signed by a key
//! of the set in force at `now`, adds the next key from `not_before` on.
//! A token or transition signed by a key outside the set is refused.
//!
//! The W0 stub has no key set ([`seams::KEY_SET_SEAM`]), so these tests
//! are red until lane W2j adds one and maps it in `support/seams.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

use oracle::{
    DAY_S, KeySet, T0, TRANSITION_LEN, Transition, current, gen_token, key, shipped, sign_token,
    sign_transition, verify_token, verify_transition, with,
};
use seams::ProdKeySet;

fn not_before(g: &mut Gen) -> i64 {
    T0 + g.i64_in(-DAY_S..=30 * DAY_S)
}

/// An instant on either side of `at`, at it, or anywhere in 60 days.
fn around(g: &mut Gen, at: i64) -> i64 {
    match g.u8_in(0..=3) {
        0 => at - 1,
        1 => at,
        2 => at + 1,
        _ => T0 + g.i64_in(-DAY_S..=60 * DAY_S),
    }
}

/// I-39, TH-32 (design section 10.2): a transition signed by a shipped
/// key is accepted at any instant. Production names the same next key
/// and `not_before`, and its set gains exactly that key.
#[test]
fn i39_key_set_accepts_a_transition_signed_by_a_shipped_key() {
    let a = key(0x11);
    let b = key(0x22);
    check(
        "i39_key_set_accepts_a_transition_signed_by_a_shipped_key",
        |g| {
            let pinned = [a.public_key()];
            let mut set = ProdKeySet::shipped(&pinned)?;
            let t = Transition {
                next_key: b.public_key(),
                not_before: not_before(g),
            };
            let now = around(g, T0);
            prop_assert_eq!(
                set.apply_transition(&sign_transition(&t, &a), now)?,
                Some(t)
            );
            prop_assert_eq!(set.keys()?, with(&shipped(&pinned), &t));
            Ok(())
        },
    );
}

/// I-39, TH-32 ("licence key rotation only through a pinned key"): a
/// transition signed by a key outside the set is refused, and the set is
/// unchanged. This includes a transition signed by the very key it
/// announces.
#[test]
fn i39_key_set_refuses_a_transition_signed_outside_the_set() {
    let a = key(0x11);
    check(
        "i39_key_set_refuses_a_transition_signed_outside_the_set",
        |g| {
            let pinned = [a.public_key()];
            let mut set = ProdKeySet::shipped(&pinned)?;
            let outsider = key(g.u8_in(0x12..=0xff));
            let next_key = if g.bool() {
                outsider.public_key()
            } else {
                key(0x22).public_key()
            };
            let t = Transition {
                next_key,
                not_before: not_before(g),
            };
            let got = set.apply_transition(&sign_transition(&t, &outsider), T0)?;
            prop_assert_eq!(got, None);
            prop_assert_eq!(set.keys()?, shipped(&pinned));
            Ok(())
        },
    );
}

/// I-39, design section 15 ("signature checked before use"): a signed
/// transition with any one bit flipped, or of any other length, is
/// refused and changes nothing.
#[test]
fn i39_key_set_refuses_a_mutated_transition() {
    let a = key(0x11);
    let b = key(0x22);
    check("i39_key_set_refuses_a_mutated_transition", |g| {
        let pinned = [a.public_key()];
        let mut set = ProdKeySet::shipped(&pinned)?;
        let t = Transition {
            next_key: b.public_key(),
            not_before: not_before(g),
        };
        let mut bytes = sign_transition(&t, &a);
        match g.u8_in(0..=2) {
            0 => {
                let i = g.usize_in(0..=TRANSITION_LEN - 1);
                bytes[i] ^= 1u8 << g.u8_in(0..=7);
            }
            1 => bytes.truncate(g.usize_in(0..=TRANSITION_LEN - 1)),
            _ => bytes.extend_from_slice(&g.bytes(1..=32)),
        }
        prop_assert_eq!(set.apply_transition(&bytes, T0)?, None);
        prop_assert_eq!(set.keys()?, shipped(&pinned));
        Ok(())
    });
}

/// I-39, design section 10.2: an announced key verifies tokens only from
/// its `not_before` on, and the shipped key keeps verifying.
#[test]
fn i39_key_set_announced_key_verifies_tokens_only_from_not_before() {
    let a = key(0x11);
    let b = key(0x22);
    check(
        "i39_key_set_announced_key_verifies_tokens_only_from_not_before",
        |g| {
            let pinned = [a.public_key()];
            let mut set = ProdKeySet::shipped(&pinned)?;
            let t = Transition {
                next_key: b.public_key(),
                not_before: not_before(g),
            };
            prop_assert!(
                set.apply_transition(&sign_transition(&t, &a), T0)?
                    .is_some()
            );
            let now = around(g, t.not_before);
            let signer = if g.bool() { &a } else { &b };
            let token = gen_token(g);
            let got = set.verify(&sign_token(&token, signer), now)?;
            let want_set = with(&shipped(&pinned), &t);
            prop_assert_eq!(
                got,
                verify_token(&sign_token(&token, signer), &current(&want_set, now)),
                "at {now}, not_before {}",
                t.not_before
            );
            Ok(())
        },
    );
}

/// I-39, design section 10.2. Reading (W1g): "signed by a current key"
/// means a key in force at `now`, so an announced key cannot sign a
/// further transition before its own `not_before`.
#[test]
fn i39_key_set_announced_key_signs_no_transition_before_not_before() {
    let a = key(0x11);
    let b = key(0x22);
    let c = key(0x33);
    check(
        "i39_key_set_announced_key_signs_no_transition_before_not_before",
        |g| {
            let pinned = [a.public_key()];
            let mut set = ProdKeySet::shipped(&pinned)?;
            let first = Transition {
                next_key: b.public_key(),
                not_before: not_before(g),
            };
            prop_assert!(
                set.apply_transition(&sign_transition(&first, &a), T0)?
                    .is_some()
            );
            let second = Transition {
                next_key: c.public_key(),
                not_before: first.not_before + g.i64_in(0..=DAY_S),
            };
            let now = around(g, first.not_before);
            let bytes = sign_transition(&second, &b);
            let want_set: KeySet = with(&shipped(&pinned), &first);
            let want = verify_transition(&bytes, &want_set, now);
            prop_assert_eq!(set.apply_transition(&bytes, now)?, want, "at {now}");
            let after = match want {
                Some(t) => with(&want_set, &t),
                None => want_set,
            };
            prop_assert_eq!(set.keys()?, after);
            Ok(())
        },
    );
}

/// I-39, design section 10.2. Reading (W1g): a transition naming a key
/// that is already in the set is accepted but keeps the key's earlier
/// `not_before`, so a replayed or later transition never delays a key in
/// force, and a shipped key never loses force.
#[test]
fn i39_key_set_known_key_keeps_its_earlier_not_before() {
    let a = key(0x11);
    let b = key(0x22);
    check("i39_key_set_known_key_keeps_its_earlier_not_before", |g| {
        let pinned = [a.public_key()];
        let mut set = ProdKeySet::shipped(&pinned)?;
        let first = Transition {
            next_key: b.public_key(),
            not_before: not_before(g),
        };
        let again = Transition {
            next_key: if g.bool() {
                b.public_key()
            } else {
                a.public_key()
            },
            not_before: first.not_before + g.i64_in(1..=DAY_S),
        };
        prop_assert!(
            set.apply_transition(&sign_transition(&first, &a), T0)?
                .is_some()
        );
        prop_assert_eq!(
            set.apply_transition(&sign_transition(&again, &a), T0)?,
            Some(again)
        );
        prop_assert_eq!(set.keys()?, with(&shipped(&pinned), &first));
        Ok(())
    });
}

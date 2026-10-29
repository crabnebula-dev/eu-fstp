//! Self-tests of the crate test oracle (`support/oracle.rs`), so the
//! production comparisons in the other files are not vacuous. These run
//! green now, on the oracle alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;

use fstp_prop::{check, prop_assert, prop_assert_eq};

use oracle::{
    DAY_S, T0, TOKEN_LEN, TRANSITION_LEN, Transition, apply_refresh, base64, gen_token, key,
    refresh_response, shipped, sign_token, sign_transition, verify_token, verify_transition, with,
};

/// I-39, design section 10.2: the oracle verifies what it signs, under
/// the signing key only, at the fixed token length.
#[test]
fn i39_oracle_token_round_trips_under_its_key_only() {
    let a = key(0x11);
    let b = key(0x99);
    check("i39_oracle_token_round_trips_under_its_key_only", |g| {
        let t = gen_token(g);
        let bytes = sign_token(&t, &a);
        prop_assert_eq!(bytes.len(), TOKEN_LEN);
        prop_assert_eq!(verify_token(&bytes, &[a.public_key()]), Some(t));
        prop_assert_eq!(verify_token(&bytes, &[b.public_key()]), None);
        Ok(())
    });
}

/// I-39, design section 10.2: the oracle accepts a transition signed by a
/// key in force, and refuses one signed by the key it announces.
#[test]
fn i39_oracle_transition_needs_a_key_in_force() {
    let a = key(0x11);
    let b = key(0x22);
    check("i39_oracle_transition_needs_a_key_in_force", |g| {
        let t = Transition {
            next_key: b.public_key(),
            not_before: T0 + g.i64_in(0..=DAY_S),
        };
        let set = shipped(&[a.public_key()]);
        let ok = sign_transition(&t, &a);
        prop_assert_eq!(ok.len(), TRANSITION_LEN);
        prop_assert_eq!(verify_transition(&ok, &set, T0), Some(t));
        prop_assert_eq!(verify_transition(&sign_transition(&t, &b), &set, T0), None);
        Ok(())
    });
}

/// I-39, design section 10.2: the oracle refresh adopts a newer signed
/// token for the stored licence, and refuses the same response with any
/// one bit flipped.
#[test]
fn i39_oracle_refresh_adopts_newer_and_refuses_mutated() {
    let a = key(0x11);
    check("i39_oracle_refresh_adopts_newer_and_refuses_mutated", |g| {
        let s = gen_token(g);
        let mut t = s;
        t.issued_at = s.issued_at + 1;
        t.refresh_after = t.refresh_after.max(t.issued_at);
        t.not_after = t.not_after.max(t.refresh_after);
        let set = shipped(&[a.public_key()]);
        let resp = refresh_response(None, &sign_token(&t, &a));
        prop_assert_eq!(apply_refresh(&s, &set, &resp, T0), Some((t, set.clone())));
        let mut bad = resp.clone();
        let i = g.usize_in(0..=bad.len() - 1);
        bad[i] ^= 1u8 << g.u8_in(0..=7);
        prop_assert!(apply_refresh(&s, &set, &bad, T0).is_none(), "byte {i}");
        Ok(())
    });
}

/// The oracle's key set keeps a known key's earlier `not_before`.
#[test]
fn i39_oracle_key_set_keeps_earlier_not_before() {
    let a = key(0x11);
    let set = shipped(&[a.public_key()]);
    let again = Transition {
        next_key: a.public_key(),
        not_before: T0,
    };
    assert_eq!(with(&set, &again), set);
}

/// Q41: the oracle's base64 is RFC 4648 section 10's test vectors.
#[test]
fn i38_oracle_base64_matches_rfc4648_vectors() {
    let vectors = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (input, want) in vectors {
        assert_eq!(base64(input.as_bytes()), want, "{input:?}");
    }
}

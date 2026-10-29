//! Tests of the licence refresh step (I-39, design sections 10.2 and 15).
//!
//! A refresh response body is `"FSTPRR01" || flag || transition? ||
//! token` (W1g proposal). The step checks the framing, then any
//! transition under the keys in force at `now`, then the token under the
//! resulting set. It refuses a token for another licence and a token
//! older than the stored one. A refused response changes neither the
//! stored token nor the key set.
//!
//! The W0 stub has no refresh step ([`seams::REFRESH_SEAM`]), so these
//! tests are red until lane W2j adds one and maps it in
//! `support/seams.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_crypto::sig::Ed25519SigningKey;
use fstp_prop::{Gen, check, prop_assert_eq};

use oracle::{
    DAY_S, KeySet, T0, Token, Transition, gen_token, key, refresh_response, shipped, sign_token,
    sign_transition, with,
};
use seams::apply_refresh;

const LICENCE: [u8; 16] = [0x4c; 16];

fn stored(g: &mut Gen) -> Token {
    Token {
        licence: LICENCE,
        ..gen_token(g)
    }
}

/// A token for the stored licence, issued `ahead` seconds after it.
fn newer(g: &mut Gen, s: &Token, ahead: i64) -> Token {
    let issued_at = s.issued_at + ahead;
    let refresh_after = issued_at + g.i64_in(0..=14 * DAY_S);
    Token {
        licence: s.licence,
        kind: s.kind,
        issued_at,
        refresh_after,
        not_after: refresh_after + g.i64_in(0..=14 * DAY_S),
    }
}

fn keys(a: &Ed25519SigningKey) -> KeySet {
    shipped(&[a.public_key()])
}

/// I-39, design section 10.2: a newer token for the stored licence,
/// signed by a pinned key, is adopted, and the key set is unchanged.
#[test]
fn i39_refresh_adopts_a_newer_token_signed_by_a_pinned_key() {
    let a = key(0x11);
    check(
        "i39_refresh_adopts_a_newer_token_signed_by_a_pinned_key",
        |g| {
            let s = stored(g);
            let ahead = g.i64_in(1..=30 * DAY_S);
            let t = newer(g, &s, ahead);
            let resp = refresh_response(None, &sign_token(&t, &a));
            let now = T0 + g.i64_in(-DAY_S..=60 * DAY_S);
            prop_assert_eq!(
                apply_refresh(&s, &keys(&a), &resp, now)?,
                Some((t, keys(&a)))
            );
            Ok(())
        },
    );
}

/// I-39, design section 10.2: a validly signed token for another licence
/// is refused.
#[test]
fn i39_refresh_refuses_a_token_for_another_licence() {
    let a = key(0x11);
    check("i39_refresh_refuses_a_token_for_another_licence", |g| {
        let s = stored(g);
        let ahead = g.i64_in(1..=DAY_S);
        let mut t = newer(g, &s, ahead);
        t.licence[g.usize_in(0..=15)] ^= g.u8_in(1..=255);
        let resp = refresh_response(None, &sign_token(&t, &a));
        prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, T0)?, None);
        Ok(())
    });
}

/// I-39, design section 10.2: a replay of an older token is refused, so
/// a replay never shortens the licence.
#[test]
fn i39_refresh_refuses_an_older_token() {
    let a = key(0x11);
    check("i39_refresh_refuses_an_older_token", |g| {
        let s = stored(g);
        let behind = g.i64_in(1..=30 * DAY_S);
        let t = newer(g, &s, -behind);
        let resp = refresh_response(None, &sign_token(&t, &a));
        prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, T0)?, None);
        Ok(())
    });
}

/// I-39, design section 10.2. Reading (W1g): the service issues one token
/// per instant. So the stored token again is accepted and changes
/// nothing, and another token with the same `issued_at` is refused.
#[test]
fn i39_refresh_same_issue_instant_accepts_only_the_stored_token() {
    let a = key(0x11);
    check(
        "i39_refresh_same_issue_instant_accepts_only_the_stored_token",
        |g| {
            let s = stored(g);
            let t = if g.bool() { s } else { newer(g, &s, 0) };
            let resp = refresh_response(None, &sign_token(&t, &a));
            let want = (t == s).then(|| (s, keys(&a)));
            prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, T0)?, want);
            Ok(())
        },
    );
}

/// I-39, design section 15: a body that is not exactly the framing is
/// refused: another magic, a flag other than 0 or 1, a missing or extra
/// byte, an HTML error page.
#[test]
fn i39_refresh_refuses_bad_framing() {
    let a = key(0x11);
    check("i39_refresh_refuses_bad_framing", |g| {
        let s = stored(g);
        let token = sign_token(&newer(g, &s, 1), &a);
        let mut resp = refresh_response(None, &token);
        match g.u8_in(0..=4) {
            0 => resp[g.usize_in(0..=7)] ^= g.u8_in(1..=255),
            1 => resp[8] = g.u8_in(2..=255),
            2 => {
                resp.pop();
            }
            3 => resp.push(g.u8()),
            _ => resp = b"<html><body>502 Bad Gateway</body></html>".to_vec(),
        }
        prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, T0)?, None);
        Ok(())
    });
}

/// I-39, design section 10.2. Reading (W1g): a response is all or
/// nothing. A valid transition that comes with a refused token is
/// dropped too, so the key set never changes on a refused response.
#[test]
fn i39_refresh_is_all_or_nothing() {
    let a = key(0x11);
    let b = key(0x22);
    let outsider = key(0x99);
    check("i39_refresh_is_all_or_nothing", |g| {
        let s = stored(g);
        let tr = Transition {
            next_key: b.public_key(),
            not_before: T0,
        };
        let mut t = newer(g, &s, 1);
        let signer = match g.u8_in(0..=2) {
            0 => &outsider,
            1 => {
                t.licence = [0x4d; 16];
                &a
            }
            _ => {
                t = newer(g, &s, -1);
                &a
            }
        };
        let resp = refresh_response(Some(&sign_transition(&tr, &a)), &sign_token(&t, signer));
        prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, T0)?, None);
        Ok(())
    });
}

/// I-39, design section 10.2: a token signed by a key announced in the
/// same response verifies only from that key's `not_before` on. Before
/// then the whole response is refused.
#[test]
fn i39_refresh_token_under_an_announced_key_only_from_not_before() {
    let a = key(0x11);
    let b = key(0x22);
    check(
        "i39_refresh_token_under_an_announced_key_only_from_not_before",
        |g| {
            let s = stored(g);
            let tr = Transition {
                next_key: b.public_key(),
                not_before: T0 + g.i64_in(0..=DAY_S),
            };
            let t = newer(g, &s, 1);
            let resp = refresh_response(Some(&sign_transition(&tr, &a)), &sign_token(&t, &b));
            let now = tr.not_before + g.i64_in(-1..=1);
            let want = (now >= tr.not_before).then(|| (t, with(&keys(&a), &tr)));
            prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, now)?, want, "at {now}");
            Ok(())
        },
    );
}

/// I-39, design sections 10.2 and 15: production's step equals the
/// oracle's over responses of every kind a service, an attacker or a
/// fault can send. They come with or without a transition, and are signed
/// by the shipped key, the announced key or an outsider. Some are
/// replays, some name other licences, and some have one flipped byte.
#[test]
fn i39_refresh_matches_the_oracle() {
    let a = key(0x11);
    let b = key(0x22);
    let outsider = key(0x99);
    check("i39_refresh_matches_the_oracle", |g| {
        let s = stored(g);
        let tr = Transition {
            next_key: b.public_key(),
            not_before: T0 + g.i64_in(0..=DAY_S),
        };
        let transition = g
            .bool()
            .then(|| sign_transition(&tr, if g.bool() { &a } else { &outsider }));
        let ahead = g.i64_in(-DAY_S..=DAY_S);
        let mut t = newer(g, &s, ahead);
        if g.u8_in(0..=3) == 0 {
            t.licence = [0x4d; 16];
        }
        if g.u8_in(0..=3) == 0 {
            t = s;
        }
        let signer = *g.pick(&[&a, &b, &outsider]);
        let mut resp = refresh_response(transition.as_deref(), &sign_token(&t, signer));
        if g.u8_in(0..=4) == 0 {
            let i = g.usize_in(0..=resp.len() - 1);
            resp[i] ^= 1u8 << g.u8_in(0..=7);
        }
        let now = tr.not_before + g.i64_in(-1..=1);
        let want = oracle::apply_refresh(&s, &keys(&a), &resp, now);
        prop_assert_eq!(apply_refresh(&s, &keys(&a), &resp, now)?, want, "at {now}");
        Ok(())
    });
}

//! Tests of `fstp_release::licence::licence_state` (I-39, P-43, design
//! section 10.2, `self-hosted-services.md`).
//!
//! A token is valid before `not_after`, in the P-43 grace period from
//! `not_after`, and expired from the grace end on (W1g reading). The
//! state is read from the token alone, and sums saturate.
//!
//! The tests are red until lane W2j lands `licence_state`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

use oracle::{DAY_S, P43_DAYS, State, T0, Token, gen_token, grace_len, licence_state};
use seams::state;

/// An instant one tick around `not_after` or the grace end, or anywhere
/// in 120 days.
fn instant(g: &mut Gen, t: &Token, p43: u16) -> i64 {
    let edges = [t.not_after, t.not_after.saturating_add(grace_len(p43))];
    let at = *g.pick(&edges);
    match g.u8_in(0..=3) {
        0 => at - 1,
        1 => at,
        2 => at + 1,
        _ => T0 + g.i64_in(-30 * DAY_S..=90 * DAY_S),
    }
}

/// The order of the states as time passes.
fn rank(s: State) -> u8 {
    match s {
        State::Valid { .. } => 0,
        State::Grace { .. } => 1,
        State::Expired { .. } => 2,
        State::Missing => 3,
    }
}

/// I-39, P-43 (design section 10.2): production's state equals the
/// oracle's one tick around each edge, for any grace length.
#[test]
fn i39_licence_state_matches_the_p43_oracle() {
    check("i39_licence_state_matches_the_p43_oracle", |g| {
        let t = gen_token(g);
        let p43 = if g.bool() {
            P43_DAYS
        } else {
            g.u16_in(0..=365)
        };
        let now = instant(g, &t, p43);
        prop_assert_eq!(
            state(Some(&t), None, now, p43)?,
            licence_state(Some(&t), now, p43),
            "{t:?} at {now}, P-43 {p43} days"
        );
        Ok(())
    });
}

/// I-39, design section 10.2: with no imported token the state is
/// missing, at any instant and for any last successful refresh.
#[test]
fn i39_licence_state_is_missing_without_a_token() {
    check("i39_licence_state_is_missing_without_a_token", |g| {
        let now = g.i64();
        let last_ok = g.option(|g| g.i64());
        prop_assert_eq!(state(None, last_ok, now, P43_DAYS)?, State::Missing);
        Ok(())
    });
}

/// I-39, design section 10.2. Reading (W1g): a successful refresh
/// replaces the token, so `last_ok` changes no state.
#[test]
fn i39_licence_state_ignores_last_ok() {
    check("i39_licence_state_ignores_last_ok", |g| {
        let t = gen_token(g);
        let now = instant(g, &t, P43_DAYS);
        let last_ok = Some(now - g.i64_in(-DAY_S..=60 * DAY_S));
        prop_assert_eq!(
            state(Some(&t), last_ok, now, P43_DAYS)?,
            state(Some(&t), None, now, P43_DAYS)?
        );
        Ok(())
    });
}

/// I-39, design section 10.2: the grace end saturates, so a token whose
/// `not_after` is near the end of time never wraps into the past and
/// never reads as expired before `not_after`.
#[test]
fn i39_licence_state_saturates_near_the_end_of_time() {
    check("i39_licence_state_saturates_near_the_end_of_time", |g| {
        let not_after = i64::MAX - g.i64_in(0..=grace_len(P43_DAYS));
        let t = Token {
            licence: [1; 16],
            kind: oracle::Kind::Noncommercial,
            issued_at: T0,
            refresh_after: T0,
            not_after,
        };
        let now = not_after.saturating_add(g.i64_in(-1..=DAY_S));
        let got = state(Some(&t), None, now, P43_DAYS)?;
        prop_assert_eq!(got, licence_state(Some(&t), now, P43_DAYS), "at {now}");
        Ok(())
    });
}

/// I-39, design section 10.2: as time passes the state of one token only
/// moves from valid to grace to expired, never back. A skewed clock that
/// runs ahead can only make it look later, not better.
#[test]
fn i39_licence_state_never_improves_as_time_passes() {
    check("i39_licence_state_never_improves_as_time_passes", |g| {
        let t = gen_token(g);
        let a = instant(g, &t, P43_DAYS);
        let b = a.saturating_add(g.i64_in(0..=60 * DAY_S));
        let (sa, sb) = (
            state(Some(&t), None, a, P43_DAYS)?,
            state(Some(&t), None, b, P43_DAYS)?,
        );
        prop_assert!(rank(sa) <= rank(sb), "{sa:?} at {a} then {sb:?} at {b}");
        Ok(())
    });
}

/// I-39, P-43: with a grace period of zero days the token expires at
/// `not_after`, and is never in grace.
#[test]
fn i39_licence_state_with_no_grace_expires_at_not_after() {
    check(
        "i39_licence_state_with_no_grace_expires_at_not_after",
        |g| {
            let t = gen_token(g);
            let now = t.not_after + g.i64_in(-1..=1);
            let want = if now < t.not_after {
                State::Valid { until: t.not_after }
            } else {
                State::Expired { since: t.not_after }
            };
            prop_assert_eq!(state(Some(&t), None, now, 0)?, want);
            Ok(())
        },
    );
}

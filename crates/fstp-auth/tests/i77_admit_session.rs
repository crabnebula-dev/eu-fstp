//! `fstp_auth::admit_session`: I-77 on every request and the P-72 session
//! lifetimes (`authentication.md` "Sessions", ADR-008 "Sessions", design
//! sections 5.4 and 8.2).
//!
//! - I-77 holds on every request, not only at login. A weak session of an
//!   account that now holds a management role is refused.
//! - P-72: 30 minutes idle and 12 hours absolute (proposed, interim
//!   defaults). Reading, as P-71 reads "no older than": a session whose
//!   idle or absolute age equals the limit is still live, and one
//!   microsecond more ends it.
//! - Every time comparison fails closed: a clock before the session start
//!   or last use, and an age that overflows, refuse.
//!
//! The binding-end rule of design section 8.2 lives in `Gate::admit` (lane
//! W2c), since `SessionView` carries no binding instants. The W1b tests in
//! `fstp-celltest` check it.
//!
//! Lane W2b test author. Red until lane W2b lands `admit_session`, because
//! the W0 stub refuses every call with `NotImplemented`, which each test
//! treats as a failure.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{
    P72, P72_ABSOLUTE_US, P72_IDLE_US, T0, account, assert_real, assert_refused, at, real,
    want_session,
};
use fstp_auth::{Method, SessionDeny, SessionLifetimes, SessionView, admit_session};
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

/// A session of account 101 by `method`, started at `started` and last
/// used at `last_used`.
fn session(method: Method, started: Timestamp, last_used: Timestamp) -> SessionView {
    SessionView {
        id: [0x5a; 16],
        account: account(101),
        method,
        started,
        last_used,
    }
}

/// P-72: a session used exactly the idle lifetime ago is live, and one
/// microsecond later it has ended.
#[test]
fn p72_idle_lifetime_boundary() {
    let s = session(Method::Passkey, T0, T0);
    let at_limit = admit_session(false, &s, at(P72_IDLE_US), &P72);
    let past = admit_session(false, &s, at(P72_IDLE_US + 1), &P72);
    assert_real("at the idle limit", &at_limit);
    assert_eq!(at_limit, Ok(()), "idle age equal to P-72");
    assert_eq!(past, Err(SessionDeny::SessionEnded), "idle age P-72 + 1 µs");
}

/// P-72: a session kept busy ends at its absolute lifetime. It is live at
/// exactly the limit and ended one microsecond later.
#[test]
fn p72_absolute_lifetime_boundary() {
    let used = at(P72_ABSOLUTE_US - 1);
    let s = session(Method::Passkey, T0, used);
    let at_limit = admit_session(false, &s, at(P72_ABSOLUTE_US), &P72);
    let past = admit_session(false, &s, at(P72_ABSOLUTE_US + 1), &P72);
    assert_real("at the absolute limit", &at_limit);
    assert_eq!(at_limit, Ok(()), "absolute age equal to P-72");
    assert_eq!(
        past,
        Err(SessionDeny::SessionEnded),
        "absolute age P-72 + 1 µs"
    );
}

/// P-72, fail closed: a clock before the session start refuses.
#[test]
fn p72_clock_before_start_refuses() {
    let s = session(Method::Passkey, T0, T0);
    assert_refused(
        "now before the start",
        &admit_session(false, &s, at(-1), &P72),
    );
}

/// P-72, fail closed: a clock before the last use refuses.
#[test]
fn p72_clock_before_last_use_refuses() {
    let s = session(Method::Passkey, T0, at(10));
    assert_refused(
        "now before the last use",
        &admit_session(false, &s, at(9), &P72),
    );
}

/// P-72, fail closed: an age that overflows `i64` refuses and never
/// panics, even under the longest lifetimes.
#[test]
fn p72_age_overflow_refuses() {
    let longest = SessionLifetimes {
        idle_us: i64::MAX,
        absolute_us: i64::MAX,
    };
    let s = session(
        Method::Passkey,
        Timestamp::from_micros(i64::MIN),
        Timestamp::from_micros(i64::MIN),
    );
    assert_refused(
        "age overflows",
        &admit_session(false, &s, Timestamp::from_micros(i64::MAX), &longest),
    );
}

/// P-72, fail closed: a negative lifetime admits no session, not even one
/// used at this instant.
#[test]
fn p72_negative_lifetime_admits_no_session() {
    let s = session(Method::Passkey, T0, T0);
    for p72 in [
        SessionLifetimes {
            idle_us: -1,
            absolute_us: P72_ABSOLUTE_US,
        },
        SessionLifetimes {
            idle_us: P72_IDLE_US,
            absolute_us: -1,
        },
    ] {
        assert_refused("negative lifetime", &admit_session(false, &s, T0, &p72));
    }
}

/// I-77: a live magic-link session of an account that holds a management
/// role is refused as `WeakSessionForRole`.
#[test]
fn i77_holder_magic_link_session_refused_as_weak() {
    let s = session(Method::MagicLink, T0, T0);
    let got = admit_session(true, &s, at(1), &P72);
    assert_real("holder magic-link session", &got);
    assert_eq!(got, Err(SessionDeny::WeakSessionForRole));
}

/// I-77: a live OPAQUE session of a holder is refused as
/// `WeakSessionForRole`. OPAQUE is not phishing resistant.
#[test]
fn i77_holder_opaque_session_refused_as_weak() {
    let s = session(Method::Opaque, T0, T0);
    let got = admit_session(true, &s, at(1), &P72);
    assert_real("holder OPAQUE session", &got);
    assert_eq!(got, Err(SessionDeny::WeakSessionForRole));
}

/// I-77: a live passkey session of a holder is admitted.
#[test]
fn i77_holder_passkey_session_admitted() {
    let s = session(Method::Passkey, T0, T0);
    let got = admit_session(true, &s, at(1), &P72);
    assert_real("holder passkey session", &got);
    assert_eq!(got, Ok(()));
}

/// I-77, `authentication.md`: a magic-link session of an account with no
/// management role is admitted. Applicants draft and submit that way.
#[test]
fn i77_non_holder_magic_link_session_admitted() {
    let s = session(Method::MagicLink, T0, T0);
    let got = admit_session(false, &s, at(1), &P72);
    assert_real("non-holder magic-link session", &got);
    assert_eq!(got, Ok(()));
}

/// I-77, P-72: `admit_session` admits exactly what the spec rule admits,
/// for holders and others, around both lifetimes and both clocks.
#[test]
fn i77_admit_session_matches_the_spec_rule() {
    check("i77_admit_session_matches_the_spec_rule", |g: &mut Gen| {
        let holds = g.bool();
        let method = *g.pick(&[Method::Passkey, Method::MagicLink, Method::Opaque]);
        let used_after = g.i64_in(0..=P72_ABSOLUTE_US);
        let last_used = at(used_after);
        let near = |g: &mut Gen, limit: i64| limit + g.i64_in(-2..=2);
        let now = match g.u8_in(0..=2) {
            0 => Timestamp::from_micros(last_used.micros() + near(g, P72_IDLE_US)),
            1 => at(near(g, P72_ABSOLUTE_US)),
            _ => Timestamp::from_micros(last_used.micros() + g.i64_in(-2..=2)),
        };
        let s = session(method, T0, last_used);
        let got = admit_session(holds, &s, now, &P72);
        real("admit_session", &got)?;
        let want = want_session(holds, method, T0, last_used, now, P72);
        prop_assert_eq!(
            got.is_ok(),
            want.is_ok(),
            "holds {holds}, {s:?}, now {now:?}"
        );
        Ok(())
    });
}

/// I-77: no weak session of a holder is admitted at any instant, under
/// any lifetimes.
#[test]
fn i77_no_weak_session_of_a_holder_is_ever_admitted() {
    check(
        "i77_no_weak_session_of_a_holder_is_ever_admitted",
        |g: &mut Gen| {
            let method = *g.pick(&[Method::MagicLink, Method::Opaque]);
            let started = Timestamp::from_micros(g.i64());
            let last_used = Timestamp::from_micros(g.i64());
            let now = Timestamp::from_micros(g.i64());
            let p72 = SessionLifetimes {
                idle_us: g.i64(),
                absolute_us: g.i64(),
            };
            let got = admit_session(true, &session(method, started, last_used), now, &p72);
            real("admit_session", &got)?;
            prop_assert_eq!(got.is_ok(), false, "{method:?} at {now:?} under {p72:?}");
            Ok(())
        },
    );
}

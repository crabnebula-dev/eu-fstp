//! Shared helpers for the `fstp-auth` crate tests (lane W2b, test author).
//!
//! The cross-crate references and models of lane W1b live in
//! `fstp-celltest`. That crate cannot be a dev-dependency here, because
//! layering rule 1 (design section 2.4) reads every dependency kind of a
//! pure core, and `fstp-celltest` reaches tokio. So the small oracles below
//! are written again from `SPEC/03-architecture/authentication.md`,
//! ADR-008 and design section 8. They name no production predicate.
//!
//! [`Stub`] tells a real answer from the W0 stub's `NotImplemented`. A
//! refusal test that accepted `NotImplemented` would pass against the stub
//! for the wrong reason.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

use fstp_auth::{AuthError, EnabledMethods, LoginDeny, Method, SessionDeny, SessionLifetimes};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

/// One second in microseconds.
pub(crate) const SECOND_US: i64 = 1_000_000;
/// One minute in microseconds.
pub(crate) const MINUTE_US: i64 = 60 * SECOND_US;
/// One hour in microseconds.
pub(crate) const HOUR_US: i64 = 60 * MINUTE_US;

/// P-72 idle lifetime: 30 minutes (proposed, ADR-008 "Constants").
pub(crate) const P72_IDLE_US: i64 = 30 * MINUTE_US;
/// P-72 absolute lifetime: 12 hours (proposed, ADR-008 "Constants").
pub(crate) const P72_ABSOLUTE_US: i64 = 12 * HOUR_US;

/// The P-72 defaults as the production type holds them.
pub(crate) const P72: SessionLifetimes = SessionLifetimes {
    idle_us: P72_IDLE_US,
    absolute_us: P72_ABSOLUTE_US,
};

/// A fixed instant well inside the `i64` range.
pub(crate) const T0: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);

/// Every login method.
pub(crate) const METHODS: [Method; 4] = [
    Method::Passkey,
    Method::EudiWallet,
    Method::Opaque,
    Method::MagicLink,
];

/// `T0` plus `us` microseconds.
pub(crate) const fn at(us: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros() + us)
}

/// The account with raw id `n`.
pub(crate) const fn account(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

/// Whether `authentication.md` counts `m` as phishing resistant:
/// passkeys and the EUDI Wallet; OPAQUE and magic links are not.
pub(crate) const fn phishing_resistant(m: Method) -> bool {
    matches!(m, Method::Passkey | Method::EudiWallet)
}

/// Whether M3 builds `m` at all: passkeys and magic links (Q10 A,
/// ADR-008 "Methods in M3").
pub(crate) const fn built_in_m3(m: Method) -> bool {
    matches!(m, Method::Passkey | Method::MagicLink)
}

/// Whether the tenant setting `e` offers `m` (P-70). Passkeys are always
/// available, whatever the list holds.
pub(crate) fn offers(e: &EnabledMethods, m: Method) -> bool {
    m == Method::Passkey || e.methods.contains(&m)
}

/// The login rule of I-77 and P-70 as the spec states it.
///
/// A holder of a management role never logs in with a weak method, so
/// that refusal comes first. M3 then refuses every method it does not
/// build and every method the tenant does not enable.
pub(crate) fn want_method(holds: bool, m: Method, e: &EnabledMethods) -> Result<(), LoginDeny> {
    if holds && !phishing_resistant(m) {
        return Err(LoginDeny::WeakMethodForRole);
    }
    if !built_in_m3(m) || !offers(e, m) {
        return Err(LoginDeny::MethodDisabled);
    }
    Ok(())
}

/// Whether `now - from` lies in `0..=limit`. An overflow is false, so it
/// refuses (fail closed).
pub(crate) fn within(from: Timestamp, now: Timestamp, limit_us: i64) -> bool {
    match now.micros().checked_sub(from.micros()) {
        Some(age) => age >= 0 && age <= limit_us,
        None => false,
    }
}

/// The session rule of P-72 and I-77 as the spec states it. Reading, as
/// P-71 reads "no older than": a session is live while its idle and
/// absolute ages are at most the limits.
pub(crate) fn want_session(
    holds: bool,
    method: Method,
    started: Timestamp,
    last_used: Timestamp,
    now: Timestamp,
    p72: SessionLifetimes,
) -> Result<(), SessionDeny> {
    if !within(started, now, p72.absolute_us) || !within(last_used, now, p72.idle_us) {
        return Err(SessionDeny::SessionEnded);
    }
    if holds && !phishing_resistant(method) {
        return Err(SessionDeny::WeakSessionForRole);
    }
    Ok(())
}

/// The W0 stub marker of each error type.
pub(crate) trait Stub {
    /// The operation the stub names, when this is the stub's refusal.
    fn stub(&self) -> Option<&'static str>;
}

impl Stub for LoginDeny {
    fn stub(&self) -> Option<&'static str> {
        match self {
            LoginDeny::NotImplemented(op) => Some(op),
            LoginDeny::WeakMethodForRole | LoginDeny::MethodDisabled => None,
        }
    }
}

impl Stub for SessionDeny {
    fn stub(&self) -> Option<&'static str> {
        match self {
            SessionDeny::NotImplemented(op) => Some(op),
            SessionDeny::SessionEnded | SessionDeny::WeakSessionForRole => None,
        }
    }
}

impl Stub for AuthError {
    fn stub(&self) -> Option<&'static str> {
        match self {
            AuthError::NotImplemented(op) => Some(op),
            #[allow(
                unreachable_patterns,
                reason = "the W0 stub has only NotImplemented; W2b adds the refusal reasons"
            )]
            _ => None,
        }
    }
}

/// The codecs refuse with their own typed error, which has no stub
/// variant (lane W2b compile fix: the decoders no longer return
/// `AuthError`).
impl Stub for fstp_auth::codec::CodecError {
    fn stub(&self) -> Option<&'static str> {
        None
    }
}

/// `Err` naming the stub when `r` is the W0 stub's refusal, so a property
/// fails on the stub rather than passing for the wrong reason.
pub(crate) fn real<T, E: Stub>(what: &str, r: &Result<T, E>) -> Result<(), String> {
    match r {
        Err(e) => match e.stub() {
            Some(op) => Err(format!("{what}: {op} is the W0 stub (NotImplemented)")),
            None => Ok(()),
        },
        Ok(_) => Ok(()),
    }
}

/// `Ok` when `r` is a refusal other than the W0 stub's `NotImplemented`.
pub(crate) fn refused<T: std::fmt::Debug, E: Stub + std::fmt::Debug>(
    what: &str,
    r: &Result<T, E>,
) -> Result<(), String> {
    real(what, r)?;
    match r {
        Err(_) => Ok(()),
        Ok(v) => Err(format!("{what}: accepted, but must be refused: {v:?}")),
    }
}

/// Panics unless `r` is a real refusal (see [`refused`]).
#[track_caller]
pub(crate) fn assert_refused<T: std::fmt::Debug, E: Stub + std::fmt::Debug>(
    what: &str,
    r: &Result<T, E>,
) {
    if let Err(msg) = refused(what, r) {
        panic!("{msg}");
    }
}

/// Panics when `r` is the W0 stub's refusal.
#[track_caller]
pub(crate) fn assert_real<T, E: Stub>(what: &str, r: &Result<T, E>) {
    if let Err(msg) = real(what, r) {
        panic!("{msg}");
    }
}

/// Every subset of [`METHODS`] as an enabled list, in method order.
pub(crate) fn every_enabled_list() -> Vec<EnabledMethods> {
    (0u8..16)
        .map(|mask| EnabledMethods {
            methods: METHODS
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, m)| *m)
                .collect(),
        })
        .collect()
}

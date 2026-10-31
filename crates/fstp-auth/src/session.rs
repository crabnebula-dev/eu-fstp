//! Logins and sessions (I-77, P-72, R-LG-04, design section 8.2).
//!
//! The binding end rule is the design's Q16 A reading. ADR-008 marks it
//! "Interim, pending Daniel (Q16)": no session records which binding it
//! relied on, so every session of the account that started before the
//! end instant ends at that instant.
//!
//! - [`admit_login`] adds the user verification rule of ADR-008 to
//!   [`crate::admit_method`]. [`verify_passkey_login`] runs the passkey
//!   assertion through `fstp-webauthn` and then that rule.
//! - [`admit_session_at`] adds the binding end rule to
//!   [`crate::admit_session`]. A session that started before a binding end
//!   of its account is refused from the end instant on, even before
//!   `EndSessionsAtBindingEnd` records its end.
//! - [`ended_by_grant`] and [`ended_by_binding_end`] list the sessions the
//!   batch of a grant or of a binding end ends.

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_webauthn::{
    AssertionExpect, AssertionOk, AssertionResponse, RelyingParty, StoredCredential, WebAuthnError,
    verify_assertion,
};

use crate::{
    AuthRecord, EnabledMethods, LoginDeny, Method, SessionDeny, SessionLifetimes, SessionView,
    admit_method, admit_session,
};

/// Why a login was refused, user verification and the assertion included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginRefusal {
    /// The method rule of I-77 and P-70 refused it.
    Method(LoginDeny),
    /// A holder's passkey gave no user verification (ADR-008 "User
    /// verification").
    NoUserVerification,
    /// The passkey assertion did not verify.
    Assertion(WebAuthnError),
    /// The assertion verified, but its sign count went down. The cell
    /// records [`AuthRecord::CredentialSuspect`].
    CredentialSuspect,
}

/// The login rule of I-77 and ADR-008: the method rule, then user
/// verification for every login of a holder.
pub fn admit_login(
    holdings: bool,
    m: Method,
    uv: bool,
    enabled: &EnabledMethods,
) -> Result<(), LoginRefusal> {
    admit_method(holdings, m, enabled).map_err(LoginRefusal::Method)?;
    if holdings && !uv {
        return Err(LoginRefusal::NoUserVerification);
    }
    Ok(())
}

/// A passkey login over `challenge` (design section 8.1).
///
/// The assertion is verified through `fstp-webauthn`, with user
/// verification required when the account holds a management role. A
/// regressed sign count refuses as [`LoginRefusal::CredentialSuspect`].
///
/// Precondition: `stored` is the credential that the assertion's id names,
/// built from its registration record ([`AuthRecord::stored_credential`]).
/// `holdings` is its owner's, and the session it opens is for that owner.
pub fn verify_passkey_login(
    holdings: bool,
    enabled: &EnabledMethods,
    assertion: &AssertionResponse,
    stored: &StoredCredential,
    rp: &RelyingParty,
    challenge: [u8; 32],
) -> Result<AssertionOk, LoginRefusal> {
    admit_method(holdings, Method::Passkey, enabled).map_err(LoginRefusal::Method)?;
    let expect = AssertionExpect {
        rp: rp.clone(),
        challenge,
        user_verification: holdings,
    };
    let ok = verify_assertion(assertion, stored, &expect).map_err(|e| match e {
        WebAuthnError::SignCountRegression { .. } => LoginRefusal::CredentialSuspect,
        WebAuthnError::UserVerification => LoginRefusal::NoUserVerification,
        other => LoginRefusal::Assertion(other),
    })?;
    admit_login(holdings, Method::Passkey, ok.user_verified, enabled)?;
    Ok(ok)
}

/// Whether any of `ends` lies after `after` and at or before `upto`
/// (design section 5.4 step 2).
///
/// `ends` are the end instants of every binding and tenant admin grant of
/// the account, recorded or scheduled, in any group. A session that
/// started at an end instant did not start before it, so it stays live.
pub fn ended_between(ends: &[Timestamp], after: Timestamp, upto: Timestamp) -> bool {
    ends.iter()
        .any(|e| after.micros() < e.micros() && e.micros() <= upto.micros())
}

/// [`admit_session`] plus the binding end rule (Q16 A, interim, pending
/// Daniel).
///
/// `ends` are the end instants of the account's bindings and tenant admin
/// grants. A session that started before one of them is refused as
/// [`SessionDeny::SessionEnded`] from that instant on.
pub fn admit_session_at(
    holdings: bool,
    s: &SessionView,
    ends: &[Timestamp],
    now: Timestamp,
    p72: &SessionLifetimes,
) -> Result<(), SessionDeny> {
    admit_session(holdings, s, now, p72)?;
    if ended_between(ends, s.started, now) {
        return Err(SessionDeny::SessionEnded);
    }
    Ok(())
}

/// The sessions that a grant of a management role to `account` ends in
/// its own batch: every weak session of the account (ADR-008). `live`
/// lists the live sessions.
pub fn ended_by_grant(live: &[SessionView], account: AccountId) -> Vec<[u8; 16]> {
    live.iter()
        .filter(|s| s.account == account && !s.method.phishing_resistant())
        .map(|s| s.id)
        .collect()
}

/// The sessions that the batch of a binding end, suspension or voiding
/// of `account` recorded at `at` ends: every live session of the account
/// that started at or before `at` (design section 5.1, Q16 A, interim,
/// pending Daniel).
pub fn ended_by_binding_end(
    live: &[SessionView],
    account: AccountId,
    at: Timestamp,
) -> Vec<[u8; 16]> {
    live.iter()
        .filter(|s| s.account == account && s.started.micros() <= at.micros())
        .map(|s| s.id)
        .collect()
}

/// One [`AuthRecord::SessionEnded`] per session id, in order.
pub fn session_end_records(sessions: &[[u8; 16]]) -> Vec<AuthRecord> {
    sessions
        .iter()
        .map(|s| AuthRecord::SessionEnded { session: *s })
        .collect()
}

/// Whether `actor` may end session `id` (`DELETE /auth/sessions/{id}`,
/// R-LG-04): only the session's own account, and only a live session.
pub fn may_end_session(live: &[SessionView], actor: AccountId, id: [u8; 16]) -> bool {
    live.iter().any(|s| s.id == id && s.account == actor)
}

/// The sessions `account` sees in `GET /auth/sessions` (R-LG-04): its own
/// sessions that the gate admits at `now`, and no other account's.
pub fn listed_sessions(
    holdings: bool,
    live: &[SessionView],
    account: AccountId,
    ends: &[Timestamp],
    now: Timestamp,
    p72: &SessionLifetimes,
) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = live
        .iter()
        .filter(|s| s.account == account)
        .filter(|s| admit_session_at(holdings, s, ends, now, p72).is_ok())
        .map(|s| s.id)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Which credential logged a passkey session in. `SessionView` names no
/// device, so the shell keeps this side table beside `auth.session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLogin {
    /// The session id.
    pub session: [u8; 16],
    /// The credential id the session logged in with.
    pub credential: Vec<u8>,
}

/// One live credential and its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOwner {
    /// The owning account.
    pub account: AccountId,
    /// The credential id.
    pub credential: Vec<u8>,
}

/// Whether `actor` may revoke `credential` of `account` through
/// `DELETE /auth/devices/{id}` (R-LG-04: users end their own linked
/// devices). Only the credential's own account may, and only a live
/// credential. The route is also the high-risk action
/// `ChangeLoginMethods`, so the gate asks for a step-up as well.
pub fn may_revoke_credential(
    live: &[CredentialOwner],
    actor: AccountId,
    account: AccountId,
    credential: &[u8],
) -> bool {
    actor == account
        && live
            .iter()
            .any(|c| c.account == account && c.credential.as_slice() == credential)
}

/// The sessions that revoking `account`'s `credential` ends in the same
/// batch: every live passkey session of the account that the credential
/// logged in (R-LG-04).
///
/// Reading, shared with the W1b reference `ended_by_credential_revocation`:
/// removing a device ends the sessions that device logged in, and no
/// other session.
pub fn ended_by_credential_revocation(
    live: &[SessionView],
    logins: &[SessionLogin],
    account: AccountId,
    credential: &[u8],
) -> Vec<[u8; 16]> {
    live.iter()
        .filter(|s| s.account == account && s.method.phishing_resistant())
        .filter(|s| {
            logins
                .iter()
                .any(|l| l.session == s.id && l.credential.as_slice() == credential)
        })
        .map(|s| s.id)
        .collect()
}

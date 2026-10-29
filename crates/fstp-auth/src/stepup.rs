//! Step-up (I-78, ADR-008 "Step-up", design section 8.4, Q15).
//!
//! - `action_digest = SHA-256(canonical(command) || command_id)`.
//! - `challenge = SHA-256("fstp-stepup-v1" || cell || session ||
//!   action_digest || nonce)`, with a 16-byte cell id, a 16-byte session
//!   id and a 32-byte nonce. Every part has a fixed length, so the input
//!   is unambiguous.
//! - [`verify_step_up`] verifies a passkey assertion with user
//!   verification over that challenge, and gives the
//!   [`AuthRecord::StepUpGranted`] record.
//! - [`admit_step_up`] is the rule the gate applies at admission and
//!   again at commit. One step-up authorises one command.

use fstp_crypto::constant_time_eq;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_webauthn::{
    AssertionExpect, AssertionOk, AssertionResponse, RelyingParty, StoredCredential, WebAuthnError,
    verify_assertion,
};

use crate::{AuthRecord, MINUTE_US, Method, SessionView, within};

/// P-71, step-up freshness: 5 minutes (proposed, interim pending Daniel,
/// Q37). A tenant may only shorten it.
pub const P71_DEFAULT_US: i64 = 5 * MINUTE_US;

/// The domain separation prefix of a step-up challenge.
pub const CHALLENGE_PREFIX: &[u8] = b"fstp-stepup-v1";

/// `SHA-256(canonical(command) || command_id)` (design section 8.4).
pub fn action_digest(canonical_command: &[u8], command_id: [u8; 16]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(canonical_command);
    h.update(&command_id);
    h.finish()
}

/// The step-up challenge of design section 8.4.
pub fn challenge(
    cell: [u8; 16],
    session: [u8; 16],
    action_digest: [u8; 32],
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(CHALLENGE_PREFIX);
    h.update(&cell);
    h.update(&session);
    h.update(&action_digest);
    h.update(&nonce);
    h.finish()
}

/// The P-71 that a tenant value gives: the value when it is positive and
/// no longer than the default, and the default otherwise. P-71 may only
/// shorten, so a longer value never lengthens it.
pub const fn effective_p71(tenant_us: i64) -> i64 {
    if tenant_us > 0 && tenant_us <= P71_DEFAULT_US {
        tenant_us
    } else {
        P71_DEFAULT_US
    }
}

/// Why a tenant login policy value is refused (`SetLoginPolicy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDeny {
    /// P-71 above the default: it may only shorten.
    P71Longer,
    /// P-71 of zero or less.
    P71NotPositive,
}

/// The rule for a tenant P-71 value in `SetLoginPolicy` (I-78, P-71).
pub const fn validate_p71(tenant_us: i64) -> Result<(), PolicyDeny> {
    if tenant_us <= 0 {
        Err(PolicyDeny::P71NotPositive)
    } else if tenant_us > P71_DEFAULT_US {
        Err(PolicyDeny::P71Longer)
    } else {
        Ok(())
    }
}

/// A step-up as the fold holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUp {
    /// The step-up id.
    pub id: [u8; 16],
    /// The session it was made in.
    pub session: [u8; 16],
    /// The action digest it authorises.
    pub action_digest: [u8; 32],
    /// When the assertion was made.
    pub asserted_at: Timestamp,
    /// The method of the assertion.
    pub method: Method,
    /// Whether the authenticator gave user verification.
    pub uv: bool,
    /// Whether a committed command consumed it.
    pub consumed: bool,
}

/// Why a high-risk action or a step-up was refused (I-78).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepUpDeny {
    /// The session is not phishing resistant, such as a magic-link
    /// session. It never performs a high-risk action.
    MagicLinkSession,
    /// No step-up was named.
    Required,
    /// The step-up belongs to another session.
    OtherSession,
    /// The step-up authorises another command.
    OtherCommand,
    /// The step-up used a method that is not phishing resistant.
    WeakMethod,
    /// The step-up gave no user verification.
    NoUserVerification,
    /// The step-up is older than P-71, or dated after `now`.
    Stale,
    /// A committed command already consumed the step-up.
    Consumed,
    /// The asserting credential belongs to another account than the
    /// session's.
    OtherAccount,
    /// The assertion verified, but its sign count went down. The cell
    /// records [`AuthRecord::CredentialSuspect`], as at login (ADR-008
    /// "Sign counts").
    CredentialSuspect,
    /// The step-up assertion did not verify.
    Assertion(WebAuthnError),
}

/// The step-up rule for one high-risk command at `now` (I-78, ADR-008).
/// It holds at admission and again at commit.
///
/// `p71_us` is the tenant's value. [`effective_p71`] applies to it, so a
/// value above the default never lengthens freshness.
pub fn admit_step_up(
    session: &SessionView,
    digest: [u8; 32],
    stepup: Option<&StepUp>,
    now: Timestamp,
    p71_us: i64,
) -> Result<(), StepUpDeny> {
    if !session.method.phishing_resistant() {
        return Err(StepUpDeny::MagicLinkSession);
    }
    let Some(u) = stepup else {
        return Err(StepUpDeny::Required);
    };
    if u.session != session.id {
        return Err(StepUpDeny::OtherSession);
    }
    if !constant_time_eq(&u.action_digest, &digest) {
        return Err(StepUpDeny::OtherCommand);
    }
    if !u.method.phishing_resistant() {
        return Err(StepUpDeny::WeakMethod);
    }
    if !u.uv {
        return Err(StepUpDeny::NoUserVerification);
    }
    if !within(u.asserted_at, now, effective_p71(p71_us)) {
        return Err(StepUpDeny::Stale);
    }
    if u.consumed {
        return Err(StepUpDeny::Consumed);
    }
    Ok(())
}

/// A verified step-up: its record and the new sign count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    /// The [`AuthRecord::StepUpGranted`] record.
    pub record: AuthRecord,
    /// The step-up as the fold holds it.
    pub stepup: StepUp,
    /// The assertion's result, with the new sign count.
    pub assertion: AssertionOk,
}

/// What a step-up assertion must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpRequest {
    /// The new step-up id, drawn by the shell.
    pub id: [u8; 16],
    /// The cell id.
    pub cell: [u8; 16],
    /// The action digest of the command it is for.
    pub action_digest: [u8; 32],
    /// The nonce of the challenge, drawn by the shell.
    pub nonce: [u8; 32],
    /// The relying party.
    pub rp: RelyingParty,
}

/// `POST /auth/stepup` (design section 8.4): verifies a passkey assertion
/// with user verification over the challenge of `req`, in `session`, at
/// `now`.
///
/// A magic-link session never steps up, so it is refused first.
/// `owner` is the account whose registration record holds `stored`
/// ([`AuthRecord::stored_credential`]). Only a credential of the
/// session's own account steps up, so a stolen cookie with the thief's
/// own passkey is refused.
pub fn verify_step_up(
    session: &SessionView,
    req: &StepUpRequest,
    assertion: &AssertionResponse,
    stored: &StoredCredential,
    owner: AccountId,
    now: Timestamp,
) -> Result<Granted, StepUpDeny> {
    if !session.method.phishing_resistant() {
        return Err(StepUpDeny::MagicLinkSession);
    }
    if owner != session.account {
        return Err(StepUpDeny::OtherAccount);
    }
    let expect = AssertionExpect {
        rp: req.rp.clone(),
        challenge: challenge(req.cell, session.id, req.action_digest, req.nonce),
        user_verification: true,
    };
    let ok = verify_assertion(assertion, stored, &expect).map_err(|e| match e {
        WebAuthnError::UserVerification => StepUpDeny::NoUserVerification,
        WebAuthnError::SignCountRegression { .. } => StepUpDeny::CredentialSuspect,
        other => StepUpDeny::Assertion(other),
    })?;
    if !ok.user_verified {
        return Err(StepUpDeny::NoUserVerification);
    }
    let stepup = StepUp {
        id: req.id,
        session: session.id,
        action_digest: req.action_digest,
        asserted_at: now,
        method: Method::Passkey,
        uv: true,
        consumed: false,
    };
    Ok(Granted {
        record: AuthRecord::StepUpGranted {
            id: req.id,
            action_digest: req.action_digest,
            session: session.id,
        },
        stepup,
        assertion: ok,
    })
}

/// The record that a high-risk command's batch carries for `stepup`.
pub const fn consumption(stepup: &StepUp) -> AuthRecord {
    AuthRecord::StepUpConsumed { id: stepup.id }
}

//! The operator login of the control plane (ADR-008 "Control plane",
//! ADR-011 "Two-operator approval", `authentication.md`).
//!
//! Staff log in to `fstp-control` with passkeys only, a phishing-resistant
//! method, with user verification on every assertion. The relying party
//! id is the control-plane host. The staff credentials are pinned in the
//! process configuration. Staff hold no binding in any cell (SoD-08).
//!
//! The ceremony:
//!
//! 1. [`OperatorLogin::begin`] draws a random 32-byte challenge for one
//!    purpose. It is single use and lives [`CHALLENGE_LIFETIME_SECS`].
//! 2. [`OperatorLogin::finish_login`] verifies the assertion through
//!    `fstp_webauthn::verify_assertion` and opens a session that lives
//!    [`SESSION_LIFETIME_SECS`].
//! 3. [`OperatorLogin::finish_step_up`] verifies a fresh assertion of the
//!    same staff member inside the session.
//! 4. [`OperatorLogin::authorise`] admits a request. A non-destructive
//!    request that changes state (`provision-cell`) needs a step-up within
//!    [`STEP_UP_WINDOW_SECS`], and consumes it. A destructive request is
//!    refused there with [`ControlError::ApprovalRequired`].
//! 5. A destructive job goes through the two-operator check instead
//!    ([`crate::approval`]). Each approver calls
//!    [`OperatorLogin::begin_approval`] and
//!    [`OperatorLogin::finish_approval`] in their own session. The
//!    requester then calls [`OperatorLogin::authorise_destructive`].
//!
//! Interim, pending Daniel: the three lifetimes. `SPEC/` and the ADRs fix
//! none of them for staff. P-71 and P-72 are tenant parameters, and staff
//! hold no tenant binding (Q37). The step-up window is the 5 minutes that
//! ADR-011 proposes for an approval. The session lifetime is the 15
//! minutes proposed for the staff assertion. Sign counts live in memory
//! only, since `cp.staff_credential` has no column for them yet.
//!
//! The transport of the ceremony is not built: no HTTPS page serves it
//! yet. [`crate::service`] does not listen for operators.

use std::collections::BTreeMap;

use fstp_cp_proto::StaffRef;
use fstp_webauthn::{AssertionExpect, AssertionResponse, CoseKey, RelyingParty, StoredCredential};

use crate::ControlError;
use crate::api::CpApiRequest;
use crate::approval::{ApprovalBook, ApprovedJob, DestructiveJob, JobDigest, job_digest};

/// How long a challenge may be answered, in seconds. Interim.
pub const CHALLENGE_LIFETIME_SECS: i64 = 120;

/// How long an operator session lasts from its login, in seconds.
/// Interim.
pub const SESSION_LIFETIME_SECS: i64 = 900;

/// How long a step-up stays fresh, in seconds. Interim.
pub const STEP_UP_WINDOW_SECS: i64 = 300;

/// The most challenges that may wait for an answer at once.
pub const MAX_PENDING: usize = 1024;

/// The most open sessions at once.
pub const MAX_SESSIONS: usize = 1024;

/// A pinned staff passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaffCredential {
    /// The staff member, by random reference.
    pub staff: StaffRef,
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The public key.
    pub key: CoseKey,
}

/// Why the operator login refused. Closed, and no variant holds input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorRefusal {
    /// The challenge was never issued, was used, or is for another
    /// purpose.
    Challenge,
    /// The challenge is older than [`CHALLENGE_LIFETIME_SECS`].
    ChallengeExpired,
    /// No pinned credential has this id.
    Credential,
    /// The assertion did not verify, user verification included.
    Assertion,
    /// No open session has this token.
    Session,
    /// The session is older than [`SESSION_LIFETIME_SECS`].
    SessionExpired,
    /// The request needs a fresh step-up.
    StepUpRequired,
    /// A step-up came from another staff member's credential.
    OtherStaff,
    /// Too many challenges or sessions are open.
    Capacity,
    /// The random source failed.
    Random,
    /// The relying party host is refused.
    Host,
}

/// What a challenge is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A login.
    Login,
    /// A step-up inside a session.
    StepUp,
}

/// An operator session, by its random token.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperatorSession(pub [u8; 32]);

impl std::fmt::Debug for OperatorSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorSession(<redacted>)")
    }
}

struct Pending {
    purpose: Purpose,
    issued_at: i64,
}

struct Session {
    staff: StaffRef,
    started_at: i64,
    step_up_at: Option<i64>,
}

/// An approval challenge that waits for its assertion (ADR-011).
struct PendingApproval {
    session: [u8; 32],
    job: DestructiveJob,
    issued_at: i64,
}

/// The domain label of an approval challenge.
const APPROVAL_LABEL: &[u8] = b"fstp-cp-approval-v1";

/// The challenge of an approval: SHA-256 over the label, the job digest
/// and 32 random octets, so the assertion over it binds the job.
fn approval_challenge(digest: JobDigest, nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = APPROVAL_LABEL.to_vec();
    m.extend_from_slice(&digest.0);
    m.extend_from_slice(nonce);
    fstp_crypto::sha256(&m)
}

/// The operator login state of one `fstp-control` process.
pub struct OperatorLogin {
    rp: RelyingParty,
    credentials: Vec<(StaffCredential, u32)>,
    pending: BTreeMap<[u8; 32], Pending>,
    sessions: BTreeMap<[u8; 32], Session>,
    approvals: BTreeMap<[u8; 32], PendingApproval>,
    book: ApprovalBook,
}

impl std::fmt::Debug for OperatorLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorLogin")
            .field("rp", &self.rp)
            .field("credentials", &self.credentials.len())
            .field("pending", &self.pending.len())
            .field("sessions", &self.sessions.len())
            .field("approvals", &self.approvals.len())
            .finish()
    }
}

fn refuse(r: OperatorRefusal) -> ControlError {
    ControlError::Operator(r)
}

fn fresh(at: i64, now: i64, lifetime: i64) -> bool {
    now >= at && now.saturating_sub(at) <= lifetime
}

impl OperatorLogin {
    /// The login for the control-plane host `host` and the pinned staff
    /// credentials `staff`.
    ///
    /// # Errors
    ///
    /// [`OperatorRefusal::Host`] when `host` is not a relying party host
    /// (ADR-008 "Relying party id").
    pub fn new(host: &str, staff: &[StaffCredential]) -> Result<OperatorLogin, ControlError> {
        Ok(OperatorLogin {
            rp: RelyingParty::new(host).map_err(|_| refuse(OperatorRefusal::Host))?,
            credentials: staff.iter().map(|c| (c.clone(), 0)).collect(),
            pending: BTreeMap::new(),
            sessions: BTreeMap::new(),
            approvals: BTreeMap::new(),
            book: ApprovalBook::default(),
        })
    }

    /// The relying party staff assert for.
    pub fn relying_party(&self) -> &RelyingParty {
        &self.rp
    }

    fn prune(&mut self, now: i64) {
        self.pending
            .retain(|_, p| fresh(p.issued_at, now, CHALLENGE_LIFETIME_SECS));
        self.sessions
            .retain(|_, s| fresh(s.started_at, now, SESSION_LIFETIME_SECS));
        self.approvals
            .retain(|_, p| fresh(p.issued_at, now, CHALLENGE_LIFETIME_SECS));
    }

    /// Draws a challenge for `purpose` at `now` (seconds).
    ///
    /// # Errors
    ///
    /// [`OperatorRefusal::Capacity`] when [`MAX_PENDING`] challenges wait,
    /// and [`OperatorRefusal::Random`] when the random source fails.
    pub fn begin(&mut self, purpose: Purpose, now: i64) -> Result<[u8; 32], ControlError> {
        self.prune(now);
        if self.pending.len() >= MAX_PENDING {
            return Err(refuse(OperatorRefusal::Capacity));
        }
        let challenge: [u8; 32] =
            fstp_crypto::random_array().map_err(|_| refuse(OperatorRefusal::Random))?;
        self.pending.insert(
            challenge,
            Pending {
                purpose,
                issued_at: now,
            },
        );
        Ok(challenge)
    }

    /// Takes the challenge, whatever the outcome, and verifies the
    /// assertion against it with user verification required. Returns the
    /// staff member of the credential.
    fn verify(
        &mut self,
        purpose: Purpose,
        challenge: [u8; 32],
        assertion: &AssertionResponse,
        now: i64,
    ) -> Result<StaffRef, ControlError> {
        let pending = self
            .pending
            .remove(&challenge)
            .filter(|p| p.purpose == purpose)
            .ok_or(refuse(OperatorRefusal::Challenge))?;
        if !fresh(pending.issued_at, now, CHALLENGE_LIFETIME_SECS) {
            return Err(refuse(OperatorRefusal::ChallengeExpired));
        }
        self.check_assertion(challenge, assertion)
    }

    /// Verifies `assertion` over `challenge` against the pinned credential
    /// it names, with user verification required, and returns its staff
    /// member.
    fn check_assertion(
        &mut self,
        challenge: [u8; 32],
        assertion: &AssertionResponse,
    ) -> Result<StaffRef, ControlError> {
        let (cred, count) = self
            .credentials
            .iter_mut()
            .find(|(c, _)| c.credential_id == assertion.credential_id)
            .ok_or(refuse(OperatorRefusal::Credential))?;
        let stored = StoredCredential {
            id: cred.credential_id.clone(),
            key: cred.key.clone(),
            sign_count: *count,
        };
        let expect = AssertionExpect {
            rp: self.rp.clone(),
            challenge,
            user_verification: true,
        };
        let ok = fstp_webauthn::verify_assertion(assertion, &stored, &expect)
            .map_err(|_| refuse(OperatorRefusal::Assertion))?;
        *count = ok.sign_count;
        Ok(cred.staff)
    }

    /// Finishes a login and opens a session.
    ///
    /// # Errors
    ///
    /// The [`OperatorRefusal`] of the first check that fails.
    pub fn finish_login(
        &mut self,
        challenge: [u8; 32],
        assertion: &AssertionResponse,
        now: i64,
    ) -> Result<(OperatorSession, StaffRef), ControlError> {
        let staff = self.verify(Purpose::Login, challenge, assertion, now)?;
        self.prune(now);
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(refuse(OperatorRefusal::Capacity));
        }
        let token: [u8; 32] =
            fstp_crypto::random_array().map_err(|_| refuse(OperatorRefusal::Random))?;
        self.sessions.insert(
            token,
            Session {
                staff,
                started_at: now,
                step_up_at: None,
            },
        );
        Ok((OperatorSession(token), staff))
    }

    fn session(&mut self, s: OperatorSession, now: i64) -> Result<&mut Session, ControlError> {
        let started = self
            .sessions
            .get(&s.0)
            .map(|x| x.started_at)
            .ok_or(refuse(OperatorRefusal::Session))?;
        if !fresh(started, now, SESSION_LIFETIME_SECS) {
            self.sessions.remove(&s.0);
            return Err(refuse(OperatorRefusal::SessionExpired));
        }
        self.sessions
            .get_mut(&s.0)
            .ok_or(refuse(OperatorRefusal::Session))
    }

    /// Finishes a step-up inside `session`. The credential must belong to
    /// the session's staff member.
    ///
    /// # Errors
    ///
    /// The [`OperatorRefusal`] of the first check that fails.
    pub fn finish_step_up(
        &mut self,
        session: OperatorSession,
        challenge: [u8; 32],
        assertion: &AssertionResponse,
        now: i64,
    ) -> Result<(), ControlError> {
        self.session(session, now)?;
        let staff = self.verify(Purpose::StepUp, challenge, assertion, now)?;
        let s = self.session(session, now)?;
        if s.staff != staff {
            return Err(refuse(OperatorRefusal::OtherStaff));
        }
        s.step_up_at = Some(now);
        Ok(())
    }

    /// Admits `request` in `session` and returns the staff member.
    ///
    /// # Errors
    ///
    /// [`ControlError::ApprovalRequired`] for a destructive request
    /// (ADR-011). [`OperatorRefusal::StepUpRequired`] for
    /// `provision-cell` without a step-up within [`STEP_UP_WINDOW_SECS`].
    /// The session refusals.
    pub fn authorise(
        &mut self,
        session: OperatorSession,
        request: &CpApiRequest,
        now: i64,
    ) -> Result<StaffRef, ControlError> {
        let s = self.session(session, now)?;
        match request {
            CpApiRequest::EraseCell { .. } => Err(ControlError::ApprovalRequired),
            CpApiRequest::ProvisionCell { .. } => {
                let ok = s
                    .step_up_at
                    .is_some_and(|at| fresh(at, now, STEP_UP_WINDOW_SECS));
                if !ok {
                    return Err(refuse(OperatorRefusal::StepUpRequired));
                }
                s.step_up_at = None;
                Ok(s.staff)
            }
            CpApiRequest::PrivilegeAudit { .. } => Ok(s.staff),
        }
    }

    /// Draws the challenge of an approval of `job` inside `session`
    /// (ADR-011 "Two-operator approval"). The challenge binds the job
    /// digest. It is single use and lives [`CHALLENGE_LIFETIME_SECS`].
    ///
    /// # Errors
    ///
    /// The session refusals, [`OperatorRefusal::Capacity`] and
    /// [`OperatorRefusal::Random`].
    pub fn begin_approval(
        &mut self,
        session: OperatorSession,
        job: &DestructiveJob,
        now: i64,
    ) -> Result<[u8; 32], ControlError> {
        self.session(session, now)?;
        self.prune(now);
        if self.approvals.len() >= MAX_PENDING {
            return Err(refuse(OperatorRefusal::Capacity));
        }
        let nonce: [u8; 32] =
            fstp_crypto::random_array().map_err(|_| refuse(OperatorRefusal::Random))?;
        let challenge = approval_challenge(job_digest(job), &nonce);
        self.approvals.insert(
            challenge,
            PendingApproval {
                session: session.0,
                job: job.clone(),
                issued_at: now,
            },
        );
        Ok(challenge)
    }

    /// Finishes an approval: a fresh passkey assertion with user
    /// verification over the approval challenge, from the session's own
    /// staff member. It is that member's step-up for this one job. The
    /// approval is recorded and logged, and the staff member returned.
    ///
    /// # Errors
    ///
    /// [`OperatorRefusal::Challenge`] for a challenge never drawn, used,
    /// or drawn in another session. [`OperatorRefusal::ChallengeExpired`],
    /// [`OperatorRefusal::OtherStaff`] for another member's credential, and
    /// the assertion and session refusals.
    pub fn finish_approval(
        &mut self,
        session: OperatorSession,
        challenge: [u8; 32],
        assertion: &AssertionResponse,
        now: i64,
    ) -> Result<StaffRef, ControlError> {
        let pending = self
            .approvals
            .remove(&challenge)
            .filter(|p| p.session == session.0)
            .ok_or(refuse(OperatorRefusal::Challenge))?;
        if !fresh(pending.issued_at, now, CHALLENGE_LIFETIME_SECS) {
            return Err(refuse(OperatorRefusal::ChallengeExpired));
        }
        let owner = self.session(session, now)?.staff;
        let staff = self.check_assertion(challenge, assertion)?;
        if staff != owner {
            return Err(refuse(OperatorRefusal::OtherStaff));
        }
        self.book.approve(staff, &pending.job, now)?;
        Ok(staff)
    }

    /// Admits the destructive `job` for the requester of `session`. The
    /// requester and a second, distinct staff member must each hold a
    /// fresh approval of the job digest. The approvals are consumed and
    /// the run is logged.
    ///
    /// # Errors
    ///
    /// [`ControlError::ApprovalRequired`] without both approvals, and the
    /// session refusals.
    pub fn authorise_destructive(
        &mut self,
        session: OperatorSession,
        job: &DestructiveJob,
        now: i64,
    ) -> Result<ApprovedJob, ControlError> {
        let requester = self.session(session, now)?.staff;
        self.book.take(requester, job, now)
    }

    /// Logs a custody call of an admitted job, before the call
    /// (ADR-004 "Reconciliation").
    pub fn log_custody_call(&mut self, job: &ApprovedJob, request: [u8; 16], now: i64) {
        self.book.log_custody_call(job, request, now);
    }

    /// The approval log, oldest first.
    pub fn approval_log(&self) -> &[crate::approval::ApprovalEvent] {
        self.book.log()
    }
}

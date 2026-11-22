//! `Sessions` and `StepUp` over the cell's own sessions and step-up
//! ceremony (ADR-026, ADR-008, I-77, I-78).
//!
//! - A session cookie resolves to its `auth.session` row as the cell's
//!   routes resolve it, and the gate's session checks run on it: an ended
//!   session, a session past P-72, or one of a suspect passkey is no
//!   session. A weak session of a management holder is a principal: the
//!   API core refuses each operation it is too weak for (I-77), and the
//!   gate refuses its commands again.
//! - A step-up challenge is a row of `auth.challenge` for the session and
//!   the API core's request digest, whose id is the wire id of the API
//!   core (`fstp_api_core::step_up_challenge_id`). The browser proves it at
//!   `POST /auth/stepup`, the cell's own route, which records
//!   `StepUpGranted` under the challenge id. A proof is that grant: in the
//!   same session, for the same digest, unconsumed and within P-71. The
//!   batch that uses it consumes it, and the store checks it again at
//!   commit.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_api_core::port::{
    PortError, SessionId, SessionPrincipal, StepUp, StepUpChallenge, StepUpProof, StepUpRef,
    StepUpRequired,
};
use fstp_api_core::{ActionDigest, Credential, RequestHead};
use fstp_auth::{Method, SessionView};
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, ReadAction};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_rt::Runtime;

use super::{Inner, login_method, phishing_resistant, session_bytes, session_id};
use crate::routes::{Backend, ChallengePurpose, ChallengeRow};

/// The most sessions and begun step-ups the ports remember. Past it the
/// memory is cleared, and a step-up in flight is asked for again.
const MAX_REMEMBERED: usize = 65_536;

/// The policy of the API core's admissions: the P-71 default, which the
/// gate shortens to the tenant's value.
pub(super) const POLICY: LoginPolicy = LoginPolicy {
    stepup_freshness_us: fstp_cell_core::tenant::P71_DEFAULT_US,
};

/// The step-up challenge ids begun for each session and digest.
type Challenges = BTreeMap<([u8; 16], [u8; 32]), Vec<[u8; 16]>>;

/// What the ports remember between calls: the account and method of each
/// resolved session, and the step-up challenges begun for each session
/// and digest. Memory only: a restart forgets them, which fails closed.
#[derive(Default)]
pub(crate) struct Begun {
    sessions: Mutex<BTreeMap<[u8; 16], (AccountId, Method)>>,
    challenges: Mutex<Challenges>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Begun {
    fn session(&self, id: [u8; 16], account: AccountId, method: Method) {
        let mut m = lock(&self.sessions);
        if m.len() >= MAX_REMEMBERED {
            m.clear();
        }
        m.insert(id, (account, method));
    }

    /// The account and method of session `id`, once a call resolved it.
    pub(super) fn of(&self, id: [u8; 16]) -> Option<(AccountId, Method)> {
        lock(&self.sessions).get(&id).copied()
    }

    fn begin(&self, session: [u8; 16], digest: [u8; 32], challenge: [u8; 16]) {
        let mut m = lock(&self.challenges);
        if m.len() >= MAX_REMEMBERED {
            m.clear();
        }
        let ids = m.entry((session, digest)).or_default();
        if ids.len() >= 16 {
            ids.remove(0);
        }
        ids.push(challenge);
    }

    fn begun(&self, session: [u8; 16], digest: [u8; 32]) -> Vec<[u8; 16]> {
        lock(&self.challenges)
            .get(&(session, digest))
            .cloned()
            .unwrap_or_default()
    }
}

/// The sessions port.
pub(crate) struct CellSessions<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> fstp_api_core::port::Sessions for CellSessions<R, V> {
    async fn principal(
        &self,
        head: &RequestHead,
        cred: &Credential,
        now: Timestamp,
    ) -> Result<SessionPrincipal, PortError> {
        let _ = head;
        let Credential::SessionCookie(value) = cred else {
            return Err(PortError::Refused);
        };
        let mut field = crate::http::cookie::COOKIE_NAME.as_bytes().to_vec();
        field.push(b'=');
        field.extend_from_slice(value);
        let cookie =
            crate::http::cookie::read_session_cookie_values(self.0.cell, [field.as_slice()])
                .map_err(|_| PortError::Refused)?
                .ok_or(PortError::Refused)?;
        let digest = fstp_crypto::sha256(&cookie.token().0);
        let row = self
            .0
            .backend
            .session(digest)
            .await
            .map_err(|_| PortError::Unavailable)?
            .ok_or(PortError::Refused)?;
        let s = self.0.engine.state();
        // ADR-008, decided 2026-11-19: a session of a suspect passkey has
        // ended, as the cell's routes read it.
        if let Some(credential) = row.credential.as_deref()
            && s.auth().credential(credential).is_some_and(|c| c.suspect)
        {
            return Err(PortError::Refused);
        }
        let view = SessionView {
            id: row.id,
            account: row.account,
            method: row.method,
            started: row.started,
            last_used: row.last_used,
        };
        match gate::admit(
            &s,
            &view,
            Action::Read(ReadAction::ReadContent),
            None,
            now,
            &POLICY,
        ) {
            // I-77 is judged per operation by the API core, and again by the
            // gate for each command.
            Ok(_) | Err(Deny::WeakSessionForRole) => {}
            Err(Deny::NotImplemented(_)) => return Err(PortError::Unavailable),
            Err(_) => return Err(PortError::Refused),
        }
        let _ = self.0.backend.touch_session(row.id, now).await;
        self.0.stepups.session(row.id, row.account, row.method);
        Ok(SessionPrincipal {
            account: row.account,
            session: session_id(row.id),
            method: login_method(row.method),
            phishing_resistant: phishing_resistant(row.method),
            tenant_admin: s.tenant().is_admin(row.account),
        })
    }
}

/// The step-up port.
pub(crate) struct CellStepUp<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> StepUp for CellStepUp<R, V> {
    async fn begin(
        &self,
        s: SessionId,
        action: ActionDigest,
    ) -> Result<StepUpChallenge, PortError> {
        let session = session_bytes(s);
        // A session of a method that is not phishing resistant gets no
        // challenge: the API core then asks for a passkey (I-78).
        match self.0.stepups.of(session) {
            Some((_, m)) if phishing_resistant(m) => {}
            Some(_) => return Err(PortError::Refused),
            None => return Err(PortError::Unavailable),
        }
        let nonce: [u8; 32] = fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        let challenge = fstp_auth::stepup::challenge(self.0.cell, session, action.0, nonce);
        let id = fstp_api_core::step_up_challenge_id(&challenge);
        let row = ChallengeRow {
            id,
            purpose: ChallengePurpose::StepUp,
            session: Some(session),
            action_digest: Some(action.0),
            nonce,
            issued_at: self.0.now(),
        };
        self.0
            .backend
            .put_challenge(row)
            .await
            .map_err(|_| PortError::Unavailable)?;
        self.0.stepups.begin(session, action.0, id);
        Ok(StepUpChallenge {
            action,
            challenge: challenge.to_vec(),
        })
    }

    /// The browser proves a challenge at `POST /auth/stepup`, the cell's
    /// own route, so the API core never finishes one.
    async fn finish(&self, s: SessionId, response: &[u8]) -> Result<StepUpRef, PortError> {
        let _ = (s, response);
        Err(PortError::Refused)
    }

    async fn take(
        &self,
        s: SessionId,
        action: ActionDigest,
        now: Timestamp,
    ) -> Result<StepUpProof, StepUpRequired> {
        let session = session_bytes(s);
        let state = self.0.engine.state();
        let p71 = fstp_cell_core::tenant::P71_DEFAULT_US.min(state.tenant().policy().p71_us());
        for id in self.0.stepups.begun(session, action.0).into_iter().rev() {
            let Some(grant) = state.auth().stepup_grant(id) else {
                continue;
            };
            let age = now.micros().checked_sub(grant.granted_at.micros());
            if grant.session == session
                && fstp_crypto::constant_time_eq(&grant.action_digest, &action.0)
                && !state.auth().consumed(id)
                && age.is_some_and(|a| (0..=p71).contains(&a))
            {
                return Ok(StepUpProof {
                    step_up: StepUpRef(u128::from_be_bytes(id)),
                    action,
                });
            }
        }
        Err(StepUpRequired)
    }

    /// I-78, ADR-026 record of lane L12: spends the step-up `proof` of an
    /// operation that executes no command, `agents.consent`. The gate
    /// admits `ApproveAgentConsent` in the step-up's own session, for the
    /// request digest `action`, with every check of a web command: the
    /// session, a phishing-resistant session for `LinkDevice`, a strong
    /// step-up of this session for this digest, within P-71 and unused.
    /// Its batch records the step-up as consumed, and the store checks
    /// freshness and use again at commit. A spent step-up is refused.
    async fn spend(
        &self,
        s: SessionId,
        proof: StepUpRef,
        action: ActionDigest,
        now: Timestamp,
    ) -> Result<(), PortError> {
        let session = session_bytes(s);
        let id = proof.0.to_be_bytes();
        let (account, _) = self.0.stepups.of(session).ok_or(PortError::Refused)?;
        let state = self.0.engine.state();
        let row = self
            .0
            .backend
            .sessions_of(account)
            .await
            .map_err(|_| PortError::Unavailable)?
            .into_iter()
            .find(|r| r.id == session && r.account == account)
            .ok_or(PortError::Refused)?;
        let view = SessionView {
            id: row.id,
            account: row.account,
            method: row.method,
            started: row.started,
            last_used: row.last_used,
        };
        let stepup = super::engine::stepup_view_of(&self.0, &state, id).await?;
        let command = fstp_cell_core::CellCommand::Ops(
            fstp_cell_core::ops::OpsCommand::ApproveAgentConsent {
                request_digest: action.0,
            },
        );
        let command_id: [u8; 16] =
            fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        let admitted = gate::admit_api_command(
            &state,
            &view,
            Action::Command(command),
            command_id,
            action.0,
            stepup.as_ref(),
            now,
            &POLICY,
        )
        .map_err(|_| PortError::Refused)?;
        match self.0.engine.execute(admitted).await {
            Ok(_) => Ok(()),
            Err(crate::engine::EngineError::Exec(_)) => Err(PortError::Refused),
            Err(_) => Err(PortError::Unavailable),
        }
    }
}

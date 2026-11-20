//! `SessionsAdmin` and `Recovery` over the cell's own sessions and
//! ceremonies (ADR-026 record of lane L5, R-LG-04, I-77, I-78, I-79).
//!
//! Each port runs the rule of the cell's `/auth` route it stands for:
//!
//! - `list` is `GET /auth/sessions`: the live rows of the account in
//!   `auth.session`, by the routes' own liveness rule.
//! - `end` is `DELETE /auth/sessions/{id}`: `EndSession` through the gate,
//!   decided with the account's live rows, for a live session of the
//!   account only. The API core passes no session of the caller, so the
//!   gate admits the command in the session it ends, which must be a live
//!   session of the caller's account. Interim, pending Daniel.
//! - `approve` is `POST /auth/recovery/{case}/approve`:
//!   `ApproveRecovery` through `gate::admit_api_command`, in the session of
//!   the API core's step-up, bound to its request digest (I-78). The
//!   holder then receives a fresh enrolment token by mail, as after the
//!   route's approval. The completion stays on the route, which ends every
//!   earlier session and agent grant (I-79, H-21).
//!
//! The passkey registration of `add_passkey` stays on `POST
//! /auth/passkeys`: its step-up is bound to the passkey digest of the
//! registration, not to the API core's request digest. The port refuses
//! it, pending Daniel.

use std::sync::Arc;

use fstp_api_core::port::{
    PasskeyRegistration, PortError, Recovery, RecoveryId, SessionId, SessionInfo, SessionsAdmin,
    StepUpProof,
};
use fstp_auth::SessionView;
use fstp_auth::session::SessionLogin;
use fstp_cell_core::gate::{self, Action};
use fstp_cell_core::{CellCommand, CellState, SessionRows};
use fstp_domain::id::AccountId;
use fstp_rt::Runtime;

use super::session::POLICY;
use super::{Inner, login_method, session_bytes, session_id};
use crate::engine::VaultClient;
use crate::routes::{Backend, SessionRow};

fn view_of(row: &SessionRow) -> SessionView {
    SessionView {
        id: row.id,
        account: row.account,
        method: row.method,
        started: row.started,
        last_used: row.last_used,
    }
}

fn session_rows(rows: &[SessionRow]) -> SessionRows {
    let logins = rows
        .iter()
        .filter_map(|r| {
            r.credential.as_ref().map(|c| SessionLogin {
                session: r.id,
                credential: c.clone(),
            })
        })
        .collect();
    SessionRows::new(rows.iter().map(view_of).collect(), logins)
}

/// The live sessions of `a` on `s`, by id, as `GET /auth/sessions` lists
/// them.
async fn live_rows<R: Runtime, V>(
    inner: &Inner<R, V>,
    s: &CellState,
    a: AccountId,
) -> Result<Vec<SessionRow>, PortError> {
    let now = inner.now();
    let holdings = crate::routes::holds(s, a, now);
    let mut rows = inner
        .backend
        .sessions_of(a)
        .await
        .map_err(|_| PortError::Unavailable)?;
    rows.retain(|r| r.account == a && crate::routes::live_session(s, r, holdings, now));
    rows.sort_by_key(|r| r.id);
    Ok(rows)
}

/// The sessions admin port.
pub(crate) struct CellSessionsAdmin<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: VaultClient> SessionsAdmin for CellSessionsAdmin<R, V> {
    async fn list(&self, a: AccountId) -> Result<Vec<SessionInfo>, PortError> {
        let s = self.0.engine.state();
        Ok(live_rows(&self.0, &s, a)
            .await?
            .iter()
            .map(|r| SessionInfo {
                session: session_id(r.id),
                method: login_method(r.method),
                started: r.started,
            })
            .collect())
    }

    async fn end(&self, a: AccountId, s: SessionId) -> Result<(), PortError> {
        let id = session_bytes(s);
        let state = self.0.engine.state();
        let rows = live_rows(&self.0, &state, a).await?;
        let views: Vec<SessionView> = rows.iter().map(view_of).collect();
        // R-LG-04: only the session's own account ends it.
        if !fstp_auth::session::may_end_session(&views, a, id) {
            return Err(PortError::Refused);
        }
        let row = rows.iter().find(|r| r.id == id).ok_or(PortError::Refused)?;
        let command = CellCommand::Auth(fstp_auth::AuthCommand::EndSession { session: id });
        let command_id = fstp_crypto::random_array::<16>().map_err(|_| PortError::Unavailable)?;
        let admitted = gate::admit_command(
            &state,
            &view_of(row),
            Action::Command(command),
            command_id,
            None,
            self.0.now(),
            &POLICY,
        )
        .map_err(|_| PortError::Refused)?
        .with_sessions(session_rows(&rows));
        match self.0.engine.execute(admitted).await {
            Ok(_) => Ok(()),
            Err(crate::engine::EngineError::Exec(_)) => Err(PortError::Refused),
            Err(_) => Err(PortError::Unavailable),
        }
    }

    /// Served by `POST /auth/passkeys` (module documentation).
    async fn add_passkey(
        &self,
        a: AccountId,
        s: SessionId,
        reg: PasskeyRegistration,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = (a, s, reg, proof);
        Err(PortError::Unavailable)
    }
}

/// The recovery approval port.
pub(crate) struct CellRecovery<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: VaultClient> Recovery for CellRecovery<R, V> {
    async fn approve(
        &self,
        approver: AccountId,
        r: RecoveryId,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let case = r.raw().to_be_bytes();
        let state = self.0.engine.state();
        let stepup_id = proof.step_up.0.to_be_bytes();
        let stepup = super::engine::stepup_view_of(&self.0, &state, stepup_id)
            .await?
            .ok_or(PortError::Refused)?;
        // The step-up names the session that proved it (I-78).
        let rows = self
            .0
            .backend
            .sessions_of(approver)
            .await
            .map_err(|_| PortError::Unavailable)?;
        let row = rows
            .iter()
            .find(|r| r.id == stepup.session && r.account == approver)
            .ok_or(PortError::Refused)?;
        let command = CellCommand::Auth(fstp_auth::AuthCommand::ApproveRecovery { case });
        let command_id = fstp_crypto::random_array::<16>().map_err(|_| PortError::Unavailable)?;
        let admitted = gate::admit_api_command(
            &state,
            &view_of(row),
            Action::Command(command),
            command_id,
            proof.action.0,
            Some(&stepup),
            self.0.now(),
            &POLICY,
        )
        .map_err(|_| PortError::Refused)?;
        match self.0.engine.execute(admitted).await {
            Ok(_) => {
                // The holder receives a fresh enrolment token, as after the
                // route's approval (design section 8.5).
                crate::routes::send_enrolment_by(&*self.0.backend, case).await;
                Ok(())
            }
            Err(crate::engine::EngineError::Exec(_)) => Err(PortError::Refused),
            Err(_) => Err(PortError::Unavailable),
        }
    }
}

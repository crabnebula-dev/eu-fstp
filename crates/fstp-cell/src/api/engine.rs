//! `AsyncEngine` over the cell's engine (ADR-026 "Composition", "Agent
//! admission", "API step-up admission" and "Dry run"; production design
//! gaps G2a to G2c).
//!
//! Every execution passes the gate:
//!
//! - an MCP call through `gate::admit_agent_command`, under the live
//!   grant the token store names for the account and agent client;
//! - a web call through `gate::admit_api_command`, in the caller's
//!   session, with the step-up the API core took for its request digest.
//!
//! The admitted command carries the call's audit event and the pending
//! action it confirms, so both commit in the command's own append
//! (ADR-010 amendment of 2026-11-20, I-85). A dry run passes
//! `gate::admit_dry_run`, which the engine never executes.

use std::sync::Arc;

use fstp_api_core::port::{AsyncEngine, AuditEntry, ExecError, ExecMeta, Outcome, PortError};
use fstp_auth::SessionView;
use fstp_auth::session::SessionLogin;
use fstp_cell_core::driver::ExecError as CellExecError;
use fstp_cell_core::gate::{self, Action, Admitted, Deny, StepUpView};
use fstp_cell_core::{ApiEffects, CellCommand, CellRefusal, CellState, SessionRows};
use fstp_domain::command::Actor;
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answer;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_domain::{Ctx, Via};
use fstp_engine::EngineState;
use fstp_ledger::Seq;
use fstp_rt::Runtime;

use super::session::POLICY;
use super::{CellTokens, Inner, session_bytes};
use crate::engine::{EngineError, VaultClient};
use crate::routes::{Backend, SessionRow};

/// The engine port.
pub(crate) struct CellAsyncEngine<R: Runtime, V, T> {
    inner: Arc<Inner<R, V>>,
    tokens: Arc<T>,
}

impl<R: Runtime, V, T> CellAsyncEngine<R, V, T> {
    pub(super) fn new(inner: Arc<Inner<R, V>>, tokens: Arc<T>) -> CellAsyncEngine<R, V, T> {
        CellAsyncEngine { inner, tokens }
    }
}

/// The refusal of a gate denial, as the API core reports it.
fn denied(d: Deny) -> ExecError {
    let rule = match d {
        Deny::StepUpRequired(_)
        | Deny::StepUpStale
        | Deny::StepUpMismatch
        | Deny::StepUpFromWeakMethod
        | Deny::MagicLinkSessionHighRisk => RuleRef::I78,
        Deny::NotImplemented(_) => return ExecError::Port(PortError::Unavailable),
        Deny::NoSession | Deny::SessionEnded => return ExecError::Port(PortError::Refused),
        Deny::WeakSessionForRole | Deny::EnrolPasskeyFirst | Deny::NotPermitted => RuleRef::Actor,
    };
    ExecError::Refused(Refusal::new(rule, RefusalReason::GuardFailed))
}

/// The API core's error of an engine failure.
fn failed(e: EngineError) -> ExecError {
    match e {
        EngineError::Exec(CellExecError::Refused(CellRefusal::Domain(r))) => ExecError::Refused(r),
        EngineError::Exec(CellExecError::Refused(CellRefusal::NotImplemented(_))) => {
            ExecError::Port(PortError::Unavailable)
        }
        EngineError::Exec(
            CellExecError::ReservedCommandId
            | CellExecError::NotASystemCommandId
            | CellExecError::NoCommandId
            | CellExecError::NotACommand
            | CellExecError::CommandIdMismatch,
        ) => ExecError::Port(PortError::Refused),
        EngineError::Exec(_) | EngineError::ShuttingDown | EngineError::Stopped => {
            ExecError::Port(PortError::Unavailable)
        }
    }
}

/// The session rows of the cell, as the cell's command route passes them,
/// so a batch names every session it ends (design section 5.1).
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

fn view_of(row: &SessionRow) -> SessionView {
    SessionView {
        id: row.id,
        account: row.account,
        method: row.method,
        started: row.started,
        last_used: row.last_used,
    }
}

impl<R, V, T> CellAsyncEngine<R, V, T>
where
    R: Runtime,
    V: VaultClient,
    T: CellTokens,
{
    /// The creator facts and Guide inputs a command reads, as the cell's
    /// command route adds them.
    fn with_facts(&self, s: &CellState, a: Admitted) -> Admitted {
        let facts = match a.action() {
            Action::Command(CellCommand::Engine(fstp_engine::Command::Creator(c))) => {
                Some(self.inner.backend.creator_facts(s, c))
            }
            Action::Command(CellCommand::Engine(fstp_engine::Command::Core(
                fstp_domain::command::Command::PublishCall { call, .. },
            ))) => Some(fstp_cell_core::creator::CreatorFacts {
                guide: self.inner.backend.guide_inputs(s, *call),
                ..Default::default()
            }),
            _ => None,
        };
        match facts {
            Some(f) => a.with_creator(f),
            None => a,
        }
    }

    /// The gate's admission of an execution (module documentation).
    async fn admit(
        &self,
        s: &CellState,
        account: AccountId,
        action: Action,
        id: [u8; 16],
        now: Timestamp,
        meta: &ExecMeta,
    ) -> Result<Admitted, ExecError> {
        match meta.via {
            Via::Mcp => {
                let client = meta.agent.ok_or(ExecError::Port(PortError::Refused))?;
                let grant = self
                    .tokens
                    .agent_grant(account, client, now)
                    .await
                    .filter(|g| g.account == account)
                    .ok_or(ExecError::Port(PortError::Refused))?;
                gate::admit_agent_command(s, &grant, action, id, now).map_err(denied)
            }
            Via::Web => {
                let session = meta
                    .session
                    .map(session_bytes)
                    .ok_or(ExecError::Port(PortError::Refused))?;
                let rows = self
                    .inner
                    .backend
                    .sessions_of(account)
                    .await
                    .map_err(|_| ExecError::Port(PortError::Unavailable))?;
                let row = rows
                    .iter()
                    .find(|r| r.id == session && r.account == account)
                    .ok_or(ExecError::Port(PortError::Refused))?;
                let stepup = match meta.step_up {
                    Some(r) => self.stepup_view(s, r.0.to_be_bytes()).await?,
                    None => None,
                };
                gate::admit_api_command(
                    s,
                    &view_of(row),
                    action,
                    id,
                    meta.request.0,
                    stepup.as_ref(),
                    now,
                    &POLICY,
                )
                .map_err(denied)
            }
        }
    }

    /// The step-up `id` as the gate sees it: the ledger's grant, with its
    /// logged assertion instant (as the cell's routes read it).
    async fn stepup_view(
        &self,
        s: &CellState,
        id: [u8; 16],
    ) -> Result<Option<StepUpView>, ExecError> {
        let Some(grant) = s.auth().stepup_grant(id) else {
            return Ok(None);
        };
        let asserted_at = self
            .inner
            .backend
            .stepup_asserted_at(id)
            .await
            .map_err(|_| ExecError::Port(PortError::Unavailable))?
            .ok_or(ExecError::Port(PortError::Unavailable))?;
        Ok(Some(StepUpView {
            id,
            session: grant.session,
            action_digest: grant.action_digest,
            asserted_at,
            // The ledger grants a step-up only after a passkey assertion
            // with user verification (design section 8.4).
            strong: true,
            consumed: s.auth().consumed(id),
        }))
    }

    async fn dry(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> (Result<(), Refusal>, Vec<Answer>) {
        let down = || Refusal::new(RuleRef::OracleDown, RefusalReason::OracleUnavailable);
        let Actor::Account(account) = ctx.actor else {
            return (
                Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)),
                Vec::new(),
            );
        };
        let s = self.inner.engine.state();
        let action = Action::Command(CellCommand::Engine(cmd.clone()));
        let admitted = match gate::admit_dry_run(&s, account, action, ctx.command.bytes(), ctx.now)
        {
            Ok(a) => self.with_facts(&s, a),
            Err(d) => {
                let r = match denied(d) {
                    ExecError::Refused(r) => r,
                    ExecError::Port(_) => down(),
                };
                return (Err(r), Vec::new());
            }
        };
        match self.inner.engine.dry_run(admitted).await {
            Ok(d) => {
                let r = d.result.map_err(|e| match failed(EngineError::Exec(e)) {
                    ExecError::Refused(r) => r,
                    ExecError::Port(_) => down(),
                });
                (r, d.answers)
            }
            Err(_) => (Err(down()), Vec::new()),
        }
    }
}

impl<R, V, T> AsyncEngine for CellAsyncEngine<R, V, T>
where
    R: Runtime,
    V: VaultClient,
    T: CellTokens,
{
    async fn execute(
        &self,
        cmd: fstp_engine::Command,
        ctx: Ctx,
        meta: ExecMeta,
    ) -> Result<Seq, ExecError> {
        let Actor::Account(account) = ctx.actor else {
            return Err(ExecError::Port(PortError::Refused));
        };
        if ctx.via != meta.via {
            return Err(ExecError::Port(PortError::Refused));
        }
        let s = self.inner.engine.state();
        let action = Action::Command(CellCommand::Engine(cmd));
        let admitted = self
            .admit(&s, account, action, ctx.command.bytes(), ctx.now, &meta)
            .await?;
        let rows = self
            .inner
            .backend
            .all_sessions()
            .await
            .map_err(|_| ExecError::Port(PortError::Unavailable))?;
        // The audit event of the call and the pending action it confirms
        // commit with the command (ADR-010 amendment, I-85).
        let event = super::audit::call_event(&AuditEntry {
            actor: Some(account),
            via: meta.via,
            agent: meta.agent,
            op: meta.op,
            outcome: Outcome::Accepted,
            request: meta.request,
            step_up: meta.step_up,
        })
        .ok_or(ExecError::Port(PortError::Refused))?;
        let admitted = self
            .with_facts(&s, admitted)
            .with_sessions(session_rows(&rows))
            .with_api(ApiEffects {
                pending: meta.pending.map(|p| p.raw().to_be_bytes()),
                events: vec![event],
            });
        let done = self.inner.engine.execute(admitted).await.map_err(failed)?;
        match done.duplicate {
            // A retry of a committed command id is no new execution.
            Some(_) => Err(ExecError::Port(PortError::Refused)),
            None => Ok(done.head),
        }
    }

    async fn dry_run(&self, cmd: &fstp_engine::Command, ctx: Ctx) -> Result<(), Refusal> {
        self.dry(cmd, ctx).await.0
    }

    async fn dry_run_answers(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> (Result<(), Refusal>, Vec<Answer>) {
        self.dry(cmd, ctx).await
    }

    fn snapshot(&self) -> Arc<EngineState> {
        Arc::new(self.inner.engine.state().engine().clone())
    }

    fn ledger(&self) -> Option<Vec<fstp_ledger::Entry<fstp_engine::Record>>> {
        Some(self.inner.engine.engine_entries_after(Seq::ZERO))
    }

    fn ledger_after(&self, after: Seq) -> Option<Vec<fstp_ledger::Entry<fstp_engine::Record>>> {
        Some(self.inner.engine.engine_entries_after(after))
    }
}

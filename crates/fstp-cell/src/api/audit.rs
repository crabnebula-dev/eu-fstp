//! `AuditSink` and `VaultAudit` as kind 2 events of the App chain (ADR-010
//! amendment of 2026-11-20, I-24, R-AU-01, `overview.md` NOTE 5).
//!
//! Each entry is one canonical JSON body of ids, enums, digests and the
//! rule name of a refusal. `record` queues it. `flush` makes every entry
//! queued before it durable: one caller writes the queue through the
//! engine's single writer ([`CellEngine::append_events`]), and the
//! callers that flush meanwhile wait for the write that holds their
//! entries. So concurrent calls share one chain transaction. A failed
//! write fails every flush that waits for it, and the API core answers
//! those calls with 503.
//!
//! The audit event of an executed command is not queued here: the engine
//! port puts it in the command's own append (`super::engine`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_api_core::port::{AuditEntry, AuditSink, Outcome, PortError, QueryDigest, Tx, VaultAudit};
use fstp_domain::Via;
use fstp_domain::id::VaultEpoch;
use fstp_json::{Object, Value};
use fstp_rt::Runtime;

use super::Inner;
use crate::engine::CellEngine;
use crate::engine::chan::{self, ReplyTx};

/// The most entries the queue holds. A record past it is refused, and the
/// API core refuses the call (I-24).
const MAX_QUEUED: usize = 65_536;

/// The most events one chain transaction writes.
const MAX_BATCH: usize = 512;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decimal(n: u128) -> Value {
    Value::String(n.to_string())
}

/// The canonical body of the audit event of one API call (ADR-010
/// amendment of 2026-11-20): `kind`, `actor`, `via`, `agent`, `op`,
/// `outcome`, `rule` for a refusal, `request` and `step_up`.
pub(super) fn call_event(e: &AuditEntry) -> Option<Vec<u8>> {
    let mut o = Object::new();
    let _ = o.insert("kind", Value::from("api_call"));
    let _ = o.insert("actor", e.actor.map_or(Value::Null, |a| decimal(a.raw())));
    let _ = o.insert(
        "via",
        Value::from(match e.via {
            Via::Web => "web",
            Via::Mcp => "mcp",
        }),
    );
    let _ = o.insert("agent", e.agent.map_or(Value::Null, |a| decimal(a.raw())));
    let _ = o.insert("op", Value::from(e.op.0));
    match e.outcome {
        Outcome::Accepted => {
            let _ = o.insert("outcome", Value::from("accepted"));
        }
        Outcome::Refused(rule) => {
            let _ = o.insert("outcome", Value::from("refused"));
            let _ = o.insert("rule", Value::from(rule));
        }
    }
    let _ = o.insert("request", Value::String(e.request.hex()));
    let _ = o.insert("step_up", e.step_up.map_or(Value::Null, |s| decimal(s.0)));
    fstp_json::to_canonical(&Value::Object(o))
        .ok()
        .map(String::into_bytes)
}

/// The canonical body of a vault answer that commits no command
/// (`overview.md` NOTE 5): the query digest, the answer bit and its epoch.
fn vault_event(q: QueryDigest, answer: bool, epoch: VaultEpoch) -> Option<Vec<u8>> {
    let mut o = Object::new();
    let _ = o.insert("kind", Value::from("vault_answer"));
    let _ = o.insert("query", Value::String(hex(&q.0)));
    let _ = o.insert("answer", Value::Bool(answer));
    let _ = o.insert("epoch", Value::String(epoch.raw().to_string()));
    fstp_json::to_canonical(&Value::Object(o))
        .ok()
        .map(String::into_bytes)
}

#[derive(Default)]
struct Queue {
    /// Queued events with their tickets, oldest first.
    queued: Vec<(u64, Vec<u8>)>,
    /// The tickets issued so far.
    issued: u64,
    /// Every ticket up to this one has been written or failed.
    settled: u64,
    /// Whether a caller is writing the queue.
    writing: bool,
    /// The flushes waiting for a ticket to settle.
    waiters: Vec<(u64, ReplyTx<Result<(), PortError>>)>,
}

/// The event queue of one cell's API core.
pub(crate) struct Buffer {
    engine: CellEngine,
    queue: Mutex<Queue>,
}

impl Buffer {
    pub(super) fn new(engine: CellEngine) -> Buffer {
        Buffer {
            engine,
            queue: Mutex::new(Queue::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, body: Option<Vec<u8>>) -> Result<(), PortError> {
        let body = body.ok_or(PortError::Refused)?;
        let mut q = self.lock();
        if q.queued.len() >= MAX_QUEUED {
            return Err(PortError::Unavailable);
        }
        q.issued = q.issued.saturating_add(1);
        let t = q.issued;
        q.queued.push((t, body));
        Ok(())
    }

    /// Makes every event queued before the call durable.
    async fn flush(&self) -> Result<(), PortError> {
        let (target, wait) = {
            let mut q = self.lock();
            let target = q.issued;
            if q.settled >= target {
                return Ok(());
            }
            if q.writing {
                let (reply, rx) = chan::reply();
                q.waiters.push((target, reply));
                (target, Some(rx))
            } else {
                q.writing = true;
                (target, None)
            }
        };
        if let Some(rx) = wait {
            return rx.recv().await.unwrap_or(Err(PortError::Unavailable));
        }
        let mut mine: Result<(), PortError> = Ok(());
        // Once a write of this run fails, every waiter it resolves later
        // fails too: its own events may have been in the failed write.
        let mut failed = false;
        loop {
            let batch: Vec<(u64, Vec<u8>)> = {
                let mut q = self.lock();
                let n = q.queued.len().min(MAX_BATCH);
                if n == 0 {
                    q.writing = false;
                    // Every ticket is settled: a waiter left over was
                    // settled by a write that happened before it waited.
                    for (_, reply) in std::mem::take(&mut q.waiters) {
                        reply.send(if failed {
                            Err(PortError::Unavailable)
                        } else {
                            Ok(())
                        });
                    }
                    break;
                }
                q.queued.drain(..n).collect()
            };
            let from = batch.first().map_or(0, |(t, _)| *t);
            let upto = batch.last().map_or(0, |(t, _)| *t);
            let at = self.engine.now();
            let events = batch.into_iter().map(|(_, b)| b).collect();
            let r = self
                .engine
                .append_events(at, events)
                .await
                .map_err(|_| PortError::Unavailable);
            if r.is_err() {
                failed = true;
                if from <= target {
                    mine = r;
                }
            }
            let mut q = self.lock();
            q.settled = upto;
            for (t, reply) in std::mem::take(&mut q.waiters) {
                if t <= upto {
                    reply.send(if failed {
                        Err(PortError::Unavailable)
                    } else {
                        r
                    });
                } else {
                    q.waiters.push((t, reply));
                }
            }
        }
        mine
    }
}

/// The audit sink.
pub(crate) struct CellAudit<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> AuditSink for CellAudit<R, V> {
    fn record(&self, tx: &mut Tx, e: AuditEntry) -> Result<(), PortError> {
        let _ = tx;
        self.0.audit.push(call_event(&e))
    }

    fn flush(&self) -> impl std::future::Future<Output = Result<(), PortError>> + Send {
        self.0.audit.flush()
    }
}

/// The recorder of vault answers that commit no command.
pub(crate) struct CellVaultAudit<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> VaultAudit for CellVaultAudit<R, V> {
    async fn record(
        &self,
        q: QueryDigest,
        answer: bool,
        epoch: VaultEpoch,
    ) -> Result<(), PortError> {
        self.0.audit.push(vault_event(q, answer, epoch))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fstp_api_core::ActionDigest;
    use fstp_api_core::port::{AgentClientId, OpName, StepUpRef};
    use fstp_domain::id::AccountId;

    /// I-24, ADR-010 amendment of 2026-11-20: the event of a call names
    /// its actor, channel, agent, operation, outcome, request digest and
    /// step-up, and holds ids, enums, digests and rule names only.
    #[test]
    fn i24_call_event_names_the_call_and_holds_no_content() {
        let e = AuditEntry {
            actor: Some(AccountId::from_raw(7)),
            via: Via::Mcp,
            agent: Some(AgentClientId::from_raw(9)),
            op: OpName("programme.prepare_draft"),
            outcome: Outcome::Refused("I-85"),
            request: ActionDigest([0xAB; 32]),
            step_up: Some(StepUpRef(3)),
        };
        let body = String::from_utf8(call_event(&e).unwrap()).unwrap();
        assert_eq!(
            body,
            format!(
                "{{\"actor\":\"7\",\"agent\":\"9\",\"kind\":\"api_call\",\"op\":\"programme.prepare_draft\",\"outcome\":\"refused\",\"request\":\"{}\",\"rule\":\"I-85\",\"step_up\":\"3\",\"via\":\"mcp\"}}",
                "ab".repeat(32)
            )
        );
    }
}

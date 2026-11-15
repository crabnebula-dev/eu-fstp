//! `agents.list` and `agents.activity`: the caller's own connected agent
//! clients and what each did (R-MC-03, `mcp-server.md`, ADR-013; M4
//! design sections 2.2 J9 and 3.6).
//!
//! - `agents.list` reads the token port: each live agent client of the
//!   caller, the scopes its tokens hold, how the consenting session
//!   logged in and, where the store knows them, when the grant started
//!   and ends. A client name is the client's own registration text,
//!   untrusted and unverified.
//! - `agents.activity` shows the caller's own calls through one agent
//!   client, newest first, with the operation, the outcome and its rule,
//!   and the time. Dispatch records each call of an agent client here as
//!   its audit entry records it (design section 3.7 step 9).
//!
//! Interim, pending a read of the audit sink (a port seam the lead
//! owns): the audit port is write-only, so this core keeps the activity
//! in memory beside its pending actions, bounded per client and in all.
//! A restarted core starts with no activity.
//!
//! Both replies name the caller's own clients only. They hold no other
//! account, no name of a person and no request content (I-17, I-86). The
//! registry gives them no tool, so they are web only.

use std::collections::{BTreeMap, VecDeque};

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ToJson, Value};

use super::{ApiError, Call, ErrorCode, Op, Seams, forms, lock, port_failed, refused_rule};
use crate::OpResult;
use crate::port::{AgentClientId, AgentInfo, LoginMethod, Tokens};

/// The most entries kept for one client of one account.
pub(crate) const PER_CLIENT: usize = 50;

/// The most clients whose activity is kept. Past it, a new client's
/// calls are not kept until the core restarts.
const MAX_CLIENTS: usize = 100_000;

/// How a call through an agent client ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityOutcome {
    /// The call completed.
    Accepted,
    /// The call waits for a web confirmation (I-85).
    Pending,
    /// The call was refused under this rule.
    Refused(&'static str),
}

/// One call through an agent client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityItem {
    /// The operation.
    pub op: &'static str,
    /// The outcome.
    pub outcome: ActivityOutcome,
    /// When the call ran.
    pub at: Timestamp,
}

/// The activity of every agent client, by account and client, in memory.
#[derive(Debug, Default)]
pub(crate) struct ActivityLog {
    by: BTreeMap<(AccountId, AgentClientId), VecDeque<ActivityItem>>,
}

impl ActivityLog {
    /// Records one call of `account` through `client`. The oldest entry
    /// of a full client leaves first.
    pub(crate) fn record(
        &mut self,
        account: AccountId,
        client: AgentClientId,
        op: &'static str,
        result: &Result<OpResult, ApiError>,
        at: Timestamp,
    ) {
        let outcome = match result {
            Ok(OpResult::Done { .. }) => ActivityOutcome::Accepted,
            Ok(OpResult::Pending(_)) => ActivityOutcome::Pending,
            Ok(OpResult::StepUpRequired(_)) => ActivityOutcome::Refused("I-78"),
            Ok(OpResult::StrongMethodRequired) => ActivityOutcome::Refused("I-77"),
            Err(e) => ActivityOutcome::Refused(refused_rule(e)),
        };
        let key = (account, client);
        if !self.by.contains_key(&key) && self.by.len() >= MAX_CLIENTS {
            return;
        }
        let items = self.by.entry(key).or_default();
        if items.len() >= PER_CLIENT {
            let _ = items.pop_front();
        }
        items.push_back(ActivityItem { op, outcome, at });
    }

    /// The calls of `account` through `client`, newest first.
    pub(crate) fn of(&self, account: AccountId, client: AgentClientId) -> Vec<ActivityItem> {
        self.by
            .get(&(account, client))
            .map(|v| v.iter().rev().copied().collect())
            .unwrap_or_default()
    }
}

/// The `agents.list` reply: the caller's live agent clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyAgents(pub Vec<AgentInfo>);

/// The `agents.activity` reply: the caller's calls through one client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentActivity(pub Vec<ActivityItem>);

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// The wire name of a login method.
const fn method_name(m: LoginMethod) -> &'static str {
    match m {
        LoginMethod::Passkey => "passkey",
        LoginMethod::MagicLink => "magic_link",
        LoginMethod::Opaque => "opaque",
        LoginMethod::EudiWallet => "eudi_wallet",
    }
}

impl ToJson for MyAgents {
    fn to_json(&self) -> Value {
        let mut out = Array::new();
        for a in &self.0 {
            let mut o = Object::new();
            let _ = o.insert("client", dec(a.client.raw()));
            if let Some(n) = &a.name {
                let _ = o.insert("name", Value::from(n.as_str()));
            }
            let _ = o.insert(
                "scopes",
                Value::Array(a.scopes.iter().map(|s| Value::from(s.as_str())).collect()),
            );
            let _ = o.insert("method", Value::from(method_name(a.method)));
            if let Some(t) = a.since {
                let _ = o.insert("since", dec(t.micros()));
            }
            if let Some(t) = a.until {
                let _ = o.insert("until", dec(t.micros()));
            }
            out.push(Value::Object(o));
        }
        Value::Array(out)
    }
}

impl ToJson for AgentActivity {
    fn to_json(&self) -> Value {
        let mut out = Array::new();
        for i in &self.0 {
            let mut o = Object::new();
            let _ = o.insert("op", Value::from(i.op));
            let (outcome, rule) = match i.outcome {
                ActivityOutcome::Accepted => ("accepted", None),
                ActivityOutcome::Pending => ("pending", None),
                ActivityOutcome::Refused(r) => ("refused", Some(r)),
            };
            let _ = o.insert("outcome", Value::from(outcome));
            if let Some(r) = rule {
                let _ = o.insert("rule", Value::from(r));
            }
            let _ = o.insert("at", dec(i.at.micros()));
            out.push(Value::Object(o));
        }
        Value::Array(out)
    }
}

/// `agents.list` for `account`.
pub(super) async fn list<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
) -> Result<MyAgents, ApiError> {
    let mut agents = call
        .ports
        .tokens()
        .agents(account, call.now)
        .await
        .map_err(|e| call.refuse(port_failed(e, "R-MC-03")))?;
    agents.sort_by_key(|a| a.client);
    agents.dedup_by_key(|a| a.client);
    Ok(MyAgents(agents))
}

/// `agents.activity` for `account`: the calls through the client the
/// path names. A client the caller never used shows no call, so the
/// reply tells nothing of another account's clients.
pub(super) fn activity<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<AgentActivity, ApiError> {
    let client = forms::id_param(&op.request, "client")
        .map(AgentClientId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    Ok(AgentActivity(lock(&call.st.activity).of(account, client)))
}

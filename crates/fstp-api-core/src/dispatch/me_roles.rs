//! `me.roles`: the caller's own active roles, for the home page of the
//! web pages (I-86; M4 design sections 2.2 J0 to J8, 3.6 and 3.9).
//!
//! Interim, pending Daniel (design section 15.0, 2026-10-31): design
//! section 2.2 names no home page and no read behind one. Daniel reported
//! that a person who signs in finds no way to their work. This read
//! gives the home page what it needs to link to it:
//!
//! - each active binding of the caller: its role, its programme, the
//!   proposal of a Receiving binding, and the published calls it
//!   reaches (the proposal's call, or every published call of the
//!   programme);
//! - the title of each call named there, which is the published call
//!   text that anyone may read (R-PB-01);
//! - the open cut-off round of each call where the caller sits on the
//!   committee (change D5), as this core folded it;
//! - the programmes of the caller's programme manager bindings that hold
//!   a creator draft, so the home page links the creator and people pages
//!   only where they can load (both read the draft);
//! - whether the caller is a tenant admin of the attested admin set.
//!
//! The reply names the caller's own bindings only. It holds no name, no
//! email, no identity attribute and nothing about any other account
//! (I-86, I-17). The registry gives it no tool, so it is web only.

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, CallId, DecisionId, ProgrammeId, ProposalId, TextRef};
use fstp_domain::programme::CallStatus;
use fstp_domain::roles::{BindingScope, Role};
use fstp_json::{Array, Object, ToJson, Value};

use super::{Call, Seams, lock};
use crate::port::TextStore;

/// One active binding of the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleItem {
    /// The role.
    pub role: Role,
    /// The programme of the binding.
    pub programme: ProgrammeId,
    /// The proposal of a Receiving binding.
    pub proposal: Option<ProposalId>,
    /// The published calls the binding reaches, ascending.
    pub calls: Vec<CallId>,
}

/// One call that a binding reaches, with its published title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallItem {
    /// The call.
    pub call: CallId,
    /// The published call text, left out when the text store cannot give it.
    pub title: Option<String>,
}

/// One open cut-off round of a call where the caller sits on the committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundItem {
    /// The round.
    pub round: DecisionId,
    /// Its call.
    pub call: CallId,
}

/// The `me.roles` reply: the caller's own roles and nothing else (I-86).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyRoles {
    /// Whether the caller is a tenant admin of the attested admin set.
    pub tenant_admin: bool,
    /// The caller's active bindings, by programme, role and proposal.
    pub roles: Vec<RoleItem>,
    /// Each call named in `roles`, ascending.
    pub calls: Vec<CallItem>,
    /// The open rounds of the caller's committee calls, by call.
    pub rounds: Vec<RoundItem>,
    /// The programmes of the caller's programme manager bindings that hold
    /// a creator draft, ascending.
    pub drafts: Vec<ProgrammeId>,
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

impl ToJson for MyRoles {
    fn to_json(&self) -> Value {
        let mut roles = Array::new();
        for r in &self.roles {
            let mut o = Object::new();
            let _ = o.insert("role", Value::from(fstp_access::role_wire_name(r.role)));
            let _ = o.insert("programme", dec(r.programme.raw()));
            if let Some(p) = r.proposal {
                let _ = o.insert("proposal", dec(p.raw()));
            }
            let _ = o.insert(
                "calls",
                Value::Array(r.calls.iter().map(|c| dec(c.raw())).collect()),
            );
            roles.push(Value::Object(o));
        }
        let mut calls = Array::new();
        for c in &self.calls {
            let mut o = Object::new();
            let _ = o.insert("call", dec(c.call.raw()));
            if let Some(t) = &c.title {
                let _ = o.insert("title", Value::from(t.as_str()));
            }
            calls.push(Value::Object(o));
        }
        let mut rounds = Array::new();
        for r in &self.rounds {
            let mut o = Object::new();
            let _ = o.insert("round", dec(r.round.raw()));
            let _ = o.insert("call", dec(r.call.raw()));
            rounds.push(Value::Object(o));
        }
        let mut o = Object::new();
        let _ = o.insert("tenant_admin", Value::Bool(self.tenant_admin));
        let _ = o.insert("roles", Value::Array(roles));
        let _ = o.insert("calls", Value::Array(calls));
        let _ = o.insert("rounds", Value::Array(rounds));
        let _ = o.insert(
            "drafts",
            Value::Array(self.drafts.iter().map(|p| dec(p.raw())).collect()),
        );
        Value::Object(o)
    }
}

/// The text behind `r`, or `None`. A title the store cannot give is left
/// out of the reply, never refused, so a missing text audits nothing.
async fn title_of<P: Seams>(call: &Call<'_, P>, r: TextRef) -> Option<String> {
    if let Some(t) = lock(&call.st.content).text(r) {
        return Some(t.to_owned());
    }
    let bytes = call
        .ports
        .texts()
        .get_public(crate::port::PublicTextRef(r.id().raw()))
        .await
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// The roles of `account`, the caller, at the instant of the call.
pub(super) async fn read<P: Seams>(call: &Call<'_, P>, account: AccountId) -> MyRoles {
    let state = &call.state;
    let core = &state.core;
    let mut published: Vec<(CallId, ProgrammeId)> = call
        .ports
        .call_ids(state)
        .into_iter()
        .filter_map(|c| {
            core.calls()
                .get(c)
                .filter(|v| v.status() == CallStatus::Published)
                .map(|v| (c, v.programme()))
        })
        .collect();
    published.sort();
    let mut roles: Vec<RoleItem> = Vec::new();
    for (_, b) in core.roster().bindings() {
        if b.account != account || !b.active_at(call.now) {
            continue;
        }
        let (proposal, calls) = match b.scope {
            BindingScope::Proposal { proposal, call } => (Some(proposal), vec![call]),
            BindingScope::Programme => (
                None,
                published
                    .iter()
                    .filter(|(_, p)| *p == b.programme)
                    .map(|(c, _)| *c)
                    .collect(),
            ),
        };
        let item = RoleItem {
            role: b.role,
            programme: b.programme,
            proposal,
            calls,
        };
        if !roles.contains(&item) {
            roles.push(item);
        }
    }
    roles.sort_by_key(|r| (r.programme, r.role, r.proposal));
    let named: BTreeSet<CallId> = roles.iter().flat_map(|r| r.calls.iter().copied()).collect();
    let committee: BTreeSet<CallId> = roles
        .iter()
        .filter(|r| matches!(r.role, Role::CommitteeMember | Role::CommitteeChair))
        .flat_map(|r| r.calls.iter().copied())
        .collect();
    let rounds: Vec<RoundItem> = {
        let journal = lock(&call.st.journal);
        committee
            .iter()
            .filter_map(|c| {
                journal
                    .open_round(*c)
                    .map(|round| RoundItem { round, call: *c })
            })
            .collect()
    };
    let mut calls = Vec::new();
    for c in named {
        let title = match core.calls().get(c) {
            Some(v) => title_of(call, v.text()).await,
            None => None,
        };
        calls.push(CallItem { call: c, title });
    }
    let drafts: Vec<ProgrammeId> = roles
        .iter()
        .filter(|r| r.role == Role::ProgrammeManager && r.proposal.is_none())
        .map(|r| r.programme)
        .filter(|p| state.creator.draft(*p).is_some())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    MyRoles {
        tenant_admin: call.caller.p.tenant_admin(),
        roles,
        calls,
        rounds,
        drafts,
    }
}

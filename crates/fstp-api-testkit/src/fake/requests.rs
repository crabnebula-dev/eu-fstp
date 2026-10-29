//! The operations of the I-85 tests, built through the adapter-facing
//! decoders `fstp_api_core::decode::{decode_route, decode_tool}`.
//!
//! Routes and tool names are the design's (sections 2.2 and 3.8). The
//! request members follow the command codec of `fstp-domain`: ids,
//! instants and money as decimal strings (ADR-006), a `currency` member
//! beside amounts, and free text as a plain JSON string, which dispatch
//! stores in the text store. Ids that the server draws, and values the
//! server takes from attested records, are never request members.
//! Digests are lowercase hex. This is the W3b test author's reading,
//! interim, pending the production agent's decoders. Every request form
//! lives here, so a change touches one file.

use fstp_api_core::decode::{Method, decode_route, decode_tool};
use fstp_api_core::port::{AgentClientId, BreakGlassId, PendingId, RecoveryId};
use fstp_api_core::{ActionDigest, ApiError, Op};
use fstp_domain::id::{AccountId, CallId, PlanVersionId, ProgrammeId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_json::{Object, Value};

/// The tool that prepares a call publication (Q32, prepare-only).
pub const TOOL_PREPARE_PUBLICATION: &str = "fstp_prepare_call_publication";
/// The tool that edits a call (binding).
pub const TOOL_EDIT_CALL: &str = "fstp_edit_call";
/// The tool that lists open calls (a read).
pub const TOOL_LIST_OPEN_CALLS: &str = "fstp_list_open_calls";
/// The tool that submits a proposal (binding).
pub const TOOL_SUBMIT_PROPOSAL: &str = "fstp_submit_proposal";

/// Lowercase hex of `d`.
pub fn hex(d: &ActionDigest) -> String {
    let mut s = String::with_capacity(64);
    for b in d.0 {
        for nibble in [b >> 4, b & 0x0f] {
            s.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    s
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// The compact JSON bytes of an object of `members`.
fn body(members: Vec<(&str, Value)>) -> Vec<u8> {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o).to_compact().into_bytes()
}

/// The fields of an `EditCall` request, beside the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallEdit {
    /// When the call opens.
    pub opens: Timestamp,
    /// The deadline.
    pub deadline: Timestamp,
    /// The deadline's IANA zone.
    pub deadline_zone: String,
    /// The budget in EUR cents, never negative. The request carries it as
    /// an ADR-006 string such as `"1000000.00"`.
    pub budget_cents: i64,
    /// The call text.
    pub text: String,
}

impl CallEdit {
    /// The budget as an ADR-006 string in the EUR scale.
    pub fn budget(&self) -> String {
        let c = self.budget_cents.max(0);
        format!(
            "{}.{:02}",
            c.checked_div(100).unwrap_or(0),
            c.checked_rem(100).unwrap_or(0)
        )
    }

    /// The JSON members of the edit, beside the call.
    fn members(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("opens", dec(self.opens.micros())),
            ("deadline", dec(self.deadline.micros())),
            ("deadline_zone", Value::String(self.deadline_zone.clone())),
            ("currency", Value::String("EUR".to_owned())),
            ("budget", Value::String(self.budget())),
            ("text", Value::String(self.text.clone())),
        ]
    }

    /// The tool arguments of the edit of `call`.
    pub fn arguments(&self, call: CallId) -> Vec<u8> {
        let mut m = vec![("call", dec(call.raw()))];
        m.extend(self.members());
        body(m)
    }
}

/// `call.publish` through the web: `POST /calls/{c}/publication`.
pub fn publish_web(call: CallId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/calls/{}/publication", call.raw()),
        &body(Vec::new()),
    )
}

/// `call.publish` through MCP: the prepare-only tool.
pub fn publish_mcp(call: CallId) -> Result<Op, ApiError> {
    decode_tool(
        TOOL_PREPARE_PUBLICATION,
        &body(vec![("call", dec(call.raw()))]),
    )
}

/// `call.edit` through the web: `PUT /calls/{c}`.
pub fn edit_web(call: CallId, edit: &CallEdit) -> Result<Op, ApiError> {
    decode_route(
        Method::Put,
        &format!("/calls/{}", call.raw()),
        &body(edit.members()),
    )
}

/// `call.edit` through MCP: `fstp_edit_call`.
pub fn edit_mcp(call: CallId, edit: &CallEdit) -> Result<Op, ApiError> {
    decode_tool(TOOL_EDIT_CALL, &edit.arguments(call))
}

/// The authenticated read of open calls through MCP.
pub fn list_open_calls_mcp() -> Result<Op, ApiError> {
    decode_tool(TOOL_LIST_OPEN_CALLS, &body(Vec::new()))
}

/// `proposal.submit` through MCP: `fstp_submit_proposal`, with the
/// ethics self-declaration (R-SB-05) and the notice version (R-NG-06).
pub fn submit_mcp(
    proposal: ProposalId,
    plan: PlanVersionId,
    issues_declared: bool,
    ethics_text: &str,
) -> Result<Op, ApiError> {
    let mut ethics = Object::new();
    let _ = ethics.insert("issues_declared", Value::Bool(issues_declared));
    let _ = ethics.insert("text", Value::String(ethics_text.to_owned()));
    decode_tool(
        TOOL_SUBMIT_PROPOSAL,
        &body(vec![
            ("proposal", dec(proposal.raw())),
            ("plan", dec(plan.raw())),
            ("ethics", Value::Object(ethics)),
            ("notice", Value::Number(fstp_json::Number::from(1u32))),
        ]),
    )
}

/// `proposal.add_member` through the web: `POST /proposals/{x}/team`.
/// The server draws the binding id.
pub fn add_member_web(proposal: ProposalId, account: AccountId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/proposals/{}/team", proposal.raw()),
        &body(vec![("account", dec(account.raw()))]),
    )
}

/// `pending.list`: `GET /me/pending-actions`.
pub fn pending_list() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/me/pending-actions", &[])
}

/// `pending.confirm`: `POST /pending-actions/{id}/confirmation`, with the
/// digest the user was shown and nothing else.
pub fn pending_confirm(id: PendingId, shown: &ActionDigest) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/pending-actions/{}/confirmation", id.raw()),
        &body(vec![("shown", Value::String(hex(shown)))]),
    )
}

/// `pending.confirm` with extra members beside the digest, as a browser
/// that resends arguments would send.
pub fn pending_confirm_with(
    id: PendingId,
    shown: &ActionDigest,
    extra: Vec<(&str, Value)>,
) -> Result<Op, ApiError> {
    let mut m = vec![("shown", Value::String(hex(shown)))];
    m.extend(extra);
    decode_route(
        Method::Post,
        &format!("/pending-actions/{}/confirmation", id.raw()),
        &body(m),
    )
}

/// `pending.discard`: `POST /pending-actions/{id}/discard`.
pub fn pending_discard(id: PendingId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/pending-actions/{}/discard", id.raw()),
        &body(Vec::new()),
    )
}

/// `agents.revoke`: `POST /me/agents/{client}/revocation` (R-MC-03).
pub fn agent_revoke(client: AgentClientId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/me/agents/{}/revocation", client.raw()),
        &body(Vec::new()),
    )
}

/// `creator.approve_activation`: `POST /programmes/{p}/activation`
/// (high-risk, no tool).
pub fn approve_activation(programme: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/activation", programme.raw()),
        &body(Vec::new()),
    )
}

/// `admin.approve_recovery`: `POST /admin/recoveries/{r}/approval`
/// (high-risk, web only).
pub fn approve_recovery(r: RecoveryId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/admin/recoveries/{}/approval", r.raw()),
        &body(Vec::new()),
    )
}

/// `admin.approve_break_glass`: `POST /admin/break-glass/{b}/approval`
/// (high-risk, web only).
pub fn approve_break_glass(b: BreakGlassId, approve: bool) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/admin/break-glass/{}/approval", b.raw()),
        &body(vec![("approve", Value::Bool(approve))]),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The hex form is lowercase and two digits per byte.
    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        let mut d = [0u8; 32];
        d[0] = 0xab;
        d[31] = 0x01;
        let h = hex(&ActionDigest(d));
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab00"));
        assert!(h.ends_with("0001"));
    }
}

//! The team and member pages and the display name (SA-11, Daniel
//! 2026-11-15 night; `docs/design/spec-amendments.md`).
//!
//! - `team.list`: every Drafting, Judging and Operations role of one
//!   programme, open invitations included. The read rule admitted the
//!   programme's manager or a tenant admin.
//! - `admin.members`: every member account of the organisation with its
//!   roles across programmes. The read rule admitted a tenant admin.
//! - `me.display_name`: the caller's own display name.
//! - `me.set_display_name`: the caller sets or clears it ([`checked_name`]).
//!
//! Each row joins three sources: the roster (bindings, held, voided or
//! ended), the creator draft (open invitations, with the invitation email
//! of an invitee who has no account yet), and the accounts port (the login
//! email of an account, from the cell's login email index). Display names
//! come from the text store under the read's clearance, which releases
//! them to these reads only (I-17, P-11, I-27).
//!
//! Receiving bindings are never listed, so no applicant and no applicant
//! team appears. A row names a rule only for a suspension or a voiding,
//! never an account (R-CF-03).
//!
//! Interim readings, pending Daniel:
//!
//! - A voided binding (Identity discovery) shows as ended, with its rule.
//! - The roster keeps ended bindings of Drafting and Judging only, so an
//!   ended Operations role is no longer listed.
//! - An invitation whose role the invitee already holds is listed once,
//!   as its binding.
//! - The tenant-wide Financial and Legal signatories (NOTE 5) appear on
//!   the member page, with no programme, and on no team page.
//! - The team page offers `invite` while the programme has a creator
//!   draft, since `creator.invite` acts on the draft. The member page
//!   offers the per-role actions only.

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{InvitationId, Invitee};
use fstp_domain::id::{AccountId, BindingId, ProgrammeId};
use fstp_domain::oracle::Query;
use fstp_domain::roles::{BindingStatus, Group, Role};
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ToJson, Value};

use super::{Call, Seams, ask_vault, port_failed, salted_text, vault_read_admitted};
use crate::forms;
use crate::port::{Accounts as _, TextStore as _};
use crate::{ApiError, ErrorCode, Op};

/// The longest display name, in characters (SA-11).
pub(crate) const DISPLAY_NAME_MAX: usize = 100;

/// The status of one role on the team and member pages (SA-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// An open invitation, not yet accepted.
    Invited,
    /// The invitee accepted the terms.
    Accepted,
    /// The invitee accepted and verified identity.
    Verified,
    /// A held binding that acts.
    Active,
    /// A suspended binding.
    Suspended,
    /// An ended or voided binding.
    Ended,
}

impl Status {
    /// The wire name.
    pub const fn wire(self) -> &'static str {
        match self {
            Status::Invited => "invited",
            Status::Accepted => "accepted",
            Status::Verified => "verified",
            Status::Active => "active",
            Status::Suspended => "suspended",
            Status::Ended => "ended",
        }
    }
}

/// An action a page may offer the viewer. The server decides each again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// `roles.grant`.
    Grant,
    /// `roles.end`.
    End,
    /// `roles.reinstate`.
    Reinstate,
    /// `creator.invite`.
    Invite,
}

impl Action {
    /// The wire name.
    pub const fn wire(self) -> &'static str {
        match self {
            Action::Grant => "grant",
            Action::End => "end",
            Action::Reinstate => "reinstate",
            Action::Invite => "invite",
        }
    }
}

/// One role: a binding or an open invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleRow {
    /// The account, or `None` for an invitee with no account yet.
    pub account: Option<AccountId>,
    /// The programme, or `None` for a tenant-wide signatory role.
    pub programme: Option<ProgrammeId>,
    /// The binding, for a role granted.
    pub binding: Option<BindingId>,
    /// The open invitation, for a role not granted yet.
    pub invitation: Option<InvitationId>,
    /// The role.
    pub role: Role,
    /// Its status.
    pub status: Status,
    /// The rule of a suspension or a voiding, when it is a spec rule.
    pub rule: Option<&'static str>,
    /// When it starts.
    pub start: Option<Timestamp>,
    /// When it ends, if scheduled.
    pub end: Option<Timestamp>,
    /// The invitation email, for an invitation by address.
    pub contact: Option<String>,
}

/// One row of the team page: a role with the display name and email.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamRow {
    /// The role.
    pub role: RoleRow,
    /// The display name, if the account set one.
    pub display_name: Option<String>,
    /// The invitation or login email, if known.
    pub email: Option<String>,
}

/// The `team.list` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamView {
    /// What the viewer may offer.
    pub actions: Vec<Action>,
    /// The rows.
    pub rows: Vec<TeamRow>,
}

/// One member account of the organisation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The account.
    pub account: AccountId,
    /// The display name, if the account set one.
    pub display_name: Option<String>,
    /// The login email, if known.
    pub email: Option<String>,
    /// Whether the account is a tenant admin.
    pub tenant_admin: bool,
    /// Its roles across programmes.
    pub roles: Vec<RoleRow>,
}

/// The `admin.members` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembersView {
    /// What the viewer may offer.
    pub actions: Vec<Action>,
    /// The members, by account id.
    pub members: Vec<Member>,
}

/// The `me.display_name` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayNameView(pub Option<String>);

/// The display name a request sets, checked (SA-11): plain text of at
/// most [`DISPLAY_NAME_MAX`] characters, trimmed, with no markup and no
/// control character. Its comparison form
/// (`crate::display_name::normalised`) must not be empty (ADR-029, lane
/// L26). A missing, `null` or blank name clears it. Anything else refuses
/// under SA-11.
pub(crate) fn checked_name(request: &Object) -> Result<Option<String>, ApiError> {
    let refused = || ApiError::bad_request("SA-11");
    let name = match request.get("display_name") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.trim(),
        Some(_) => return Err(refused()),
    };
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > DISPLAY_NAME_MAX
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>'))
        || crate::display_name::normalised(name).is_empty()
    {
        return Err(refused());
    }
    Ok(Some(name.to_owned()))
}

/// The status and rule of a held or voided binding.
fn binding_status(s: BindingStatus) -> (Status, Option<&'static str>) {
    match s {
        BindingStatus::Active => (Status::Active, None),
        BindingStatus::Suspended(r) => (Status::Suspended, r.spec_id()),
        BindingStatus::Voided(r) => (Status::Ended, r.spec_id()),
    }
}

/// The roles of programme `p`: its staff bindings, held, voided or
/// ended, then its open invitations not yet granted. An invitation email
/// is read under `clearance`, a read of `p`, so only the team read asks
/// for them.
async fn programme_roles<P: Seams>(
    call: &Call<'_, P>,
    p: ProgrammeId,
    viewer: AccountId,
    clearance: Option<&fstp_access::ReadClearance>,
) -> Result<Vec<RoleRow>, ApiError> {
    let roster = call.state.core.roster();
    let mut rows = Vec::new();
    for (id, b) in roster.bindings() {
        if b.programme != p || b.group() == Group::Receiving {
            continue;
        }
        let (status, rule) = binding_status(b.status);
        rows.push(RoleRow {
            account: Some(b.account),
            programme: Some(p),
            binding: Some(id),
            invitation: None,
            role: b.role,
            status,
            rule,
            start: Some(b.start),
            end: b.scheduled_end,
            contact: None,
        });
    }
    for (id, e) in roster.ended() {
        let b = &e.binding;
        if b.programme != p || b.group() == Group::Receiving {
            continue;
        }
        let rule = match b.status {
            BindingStatus::Active => None,
            BindingStatus::Suspended(r) | BindingStatus::Voided(r) => r.spec_id(),
        };
        rows.push(RoleRow {
            account: Some(b.account),
            programme: Some(p),
            binding: Some(id),
            invitation: None,
            role: b.role,
            status: Status::Ended,
            rule,
            start: Some(b.start),
            end: b.scheduled_end,
            contact: None,
        });
    }
    let Some(d) = call.state.creator.draft(p) else {
        return Ok(rows);
    };
    let open: Vec<_> = d
        .live_invitations()
        .filter(|(_, i)| {
            !i.account().is_some_and(|a| {
                roster.bindings().any(|(_, b)| {
                    b.account == a && b.programme == p && b.role == i.role && b.held()
                })
            })
        })
        .collect();
    let accepted: BTreeSet<AccountId> = open.iter().filter_map(|(_, i)| i.accepted).collect();
    // H-07: each `IsVerified` question is rate-limited for the viewer, as
    // the invitation list asks it.
    if !accepted.is_empty() {
        vault_read_admitted(call, viewer)?;
    }
    let mut verified = BTreeMap::new();
    for a in accepted {
        let ans = ask_vault(call, &Query::IsVerified { account: a }).await?;
        let _ = verified.insert(a, ans.holds);
    }
    for (id, i) in open {
        let status = match i.accepted {
            Some(a) if verified.get(&a) == Some(&true) => Status::Verified,
            Some(_) => Status::Accepted,
            None => Status::Invited,
        };
        let contact = match (i.invitee, clearance) {
            (Invitee::Pending { contact }, Some(c)) => Some(salted_text(call, contact, c).await?),
            _ => None,
        };
        rows.push(RoleRow {
            account: i.account(),
            programme: Some(p),
            binding: None,
            invitation: Some(id),
            role: i.role,
            status,
            rule: None,
            start: Some(i.start),
            end: i.end,
            contact,
        });
    }
    Ok(rows)
}

/// The login email of each of `accounts`, from the accounts port. An
/// account with none is left out. A port that cannot answer fails the
/// read closed.
async fn emails<P: Seams>(
    call: &Call<'_, P>,
    accounts: &BTreeSet<AccountId>,
) -> Result<BTreeMap<AccountId, String>, ApiError> {
    let mut out = BTreeMap::new();
    for a in accounts {
        let e = call
            .ports
            .accounts()
            .login_email(*a)
            .await
            .map_err(|e| call.refuse(port_failed(e, "SA-11")))?;
        if let Some(e) = e {
            let _ = out.insert(*a, e);
        }
    }
    Ok(out)
}

/// The display names of `accounts` under `clearance`.
async fn names<P: Seams>(
    call: &Call<'_, P>,
    accounts: &BTreeSet<AccountId>,
    clearance: &fstp_access::ReadClearance,
) -> Result<BTreeMap<AccountId, String>, ApiError> {
    call.ports
        .texts()
        .display_names(accounts.iter().copied().collect(), clearance)
        .await
        .map_err(|e| call.refuse(port_failed(e, "SA-11")))
}

/// Whether the viewer is a tenant admin.
fn admin<P: Seams>(call: &Call<'_, P>) -> bool {
    call.caller.p.tenant_admin()
}

/// `team.list` of the programme `op` names.
pub(super) async fn team<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    viewer: AccountId,
    clearance: &fstp_access::ReadClearance,
) -> Result<TeamView, ApiError> {
    let p = forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))?;
    let state = &call.state;
    let draft = state.creator.draft(p).is_some();
    if !draft && state.core.policy().programme(p).is_none() {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    }
    let roles = programme_roles(call, p, viewer, Some(clearance)).await?;
    let accounts: BTreeSet<AccountId> = roles.iter().filter_map(|r| r.account).collect();
    let emails = emails(call, &accounts).await?;
    let names = names(call, &accounts, clearance).await?;
    let rows = roles
        .into_iter()
        .map(|r| {
            let email = r
                .account
                .and_then(|a| emails.get(&a).cloned())
                .or_else(|| r.contact.clone());
            TeamRow {
                display_name: r.account.and_then(|a| names.get(&a).cloned()),
                email,
                role: r,
            }
        })
        .collect();
    let mut actions = Vec::new();
    if admin(call) {
        actions.extend([Action::Grant, Action::End, Action::Reinstate]);
    }
    if draft {
        actions.push(Action::Invite);
    }
    Ok(TeamView { actions, rows })
}

/// `admin.members`: every account that holds or held a staff role, was
/// invited to one and accepted, is a tenant-wide signatory, or is a
/// tenant admin, with its roles across programmes.
pub(super) async fn members<P: Seams>(
    call: &Call<'_, P>,
    viewer: AccountId,
    clearance: &fstp_access::ReadClearance,
) -> Result<MembersView, ApiError> {
    let state = &call.state;
    let mut programmes: BTreeSet<ProgrammeId> = state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b.programme)
        .chain(
            state
                .core
                .roster()
                .ended()
                .map(|(_, e)| e.binding.programme),
        )
        .collect();
    programmes.extend(state.creator.drafts().map(|(p, _)| p));
    let mut by_account: BTreeMap<AccountId, Vec<RoleRow>> = BTreeMap::new();
    for p in programmes {
        for r in programme_roles(call, p, viewer, None).await? {
            if let Some(a) = r.account {
                by_account.entry(a).or_default().push(r);
            }
        }
    }
    let mut admins = BTreeSet::new();
    if let Some(ts) = state.tenant.state() {
        admins.extend(ts.admins().iter().copied());
        for (role, a) in ts.signatories() {
            let role = match role {
                fstp_tenant::SignatoryRole::Financial => Role::FinancialSignatory,
                fstp_tenant::SignatoryRole::Legal => Role::LegalSignatory,
            };
            by_account.entry(*a).or_default().push(RoleRow {
                account: Some(*a),
                programme: None,
                binding: None,
                invitation: None,
                role,
                status: Status::Active,
                rule: None,
                start: None,
                end: None,
                contact: None,
            });
        }
    }
    for a in &admins {
        by_account.entry(*a).or_default();
    }
    let accounts: BTreeSet<AccountId> = by_account.keys().copied().collect();
    let emails = emails(call, &accounts).await?;
    let names = names(call, &accounts, clearance).await?;
    let members = by_account
        .into_iter()
        .map(|(account, roles)| Member {
            account,
            display_name: names.get(&account).cloned(),
            email: emails.get(&account).cloned(),
            tenant_admin: admins.contains(&account)
                || super::tenant::is_admin(call.ports, state, account),
            roles,
        })
        .collect();
    Ok(MembersView {
        actions: vec![Action::Grant, Action::End, Action::Reinstate],
        members,
    })
}

/// `me.display_name`: the caller's own display name.
pub(super) async fn own<P: Seams>(
    call: &Call<'_, P>,
    viewer: AccountId,
    clearance: &fstp_access::ReadClearance,
) -> Result<DisplayNameView, ApiError> {
    let one: BTreeSet<AccountId> = [viewer].into_iter().collect();
    Ok(DisplayNameView(
        names(call, &one, clearance).await?.remove(&viewer),
    ))
}

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// `null`, or the decimal string of `x`.
fn opt_dec(x: Option<impl std::fmt::Display>) -> Value {
    x.map_or(Value::Null, dec)
}

/// `null`, or the string `x`.
fn opt_str(x: Option<&String>) -> Value {
    x.map_or(Value::Null, |s| Value::String(s.clone()))
}

/// The role members of a row, shared by both pages.
fn role_members(o: &mut Object, r: &RoleRow) {
    let _ = o.insert("binding", opt_dec(r.binding.map(BindingId::raw)));
    let _ = o.insert("invitation", opt_dec(r.invitation.map(InvitationId::raw)));
    let _ = o.insert("role", Value::from(fstp_access::role_wire_name(r.role)));
    let _ = o.insert("status", Value::from(r.status.wire()));
    if let Some(x) = r.rule {
        let _ = o.insert("rule", Value::from(x));
    }
    let _ = o.insert("start", opt_dec(r.start.map(Timestamp::micros)));
    let _ = o.insert("end", opt_dec(r.end.map(Timestamp::micros)));
}

fn actions_json(actions: &[Action]) -> Value {
    Value::Array(actions.iter().map(|a| Value::from(a.wire())).collect())
}

impl ToJson for TeamView {
    fn to_json(&self) -> Value {
        let mut rows = Array::new();
        for r in &self.rows {
            let mut o = Object::new();
            let _ = o.insert("account", opt_dec(r.role.account.map(AccountId::raw)));
            let _ = o.insert("display_name", opt_str(r.display_name.as_ref()));
            let _ = o.insert("email", opt_str(r.email.as_ref()));
            role_members(&mut o, &r.role);
            rows.push(Value::Object(o));
        }
        let mut o = Object::new();
        let _ = o.insert("actions", actions_json(&self.actions));
        let _ = o.insert("rows", Value::Array(rows));
        Value::Object(o)
    }
}

impl ToJson for MembersView {
    fn to_json(&self) -> Value {
        let mut members = Array::new();
        for m in &self.members {
            let mut roles = Array::new();
            for r in &m.roles {
                let mut o = Object::new();
                let _ = o.insert("programme", opt_dec(r.programme.map(ProgrammeId::raw)));
                role_members(&mut o, r);
                roles.push(Value::Object(o));
            }
            let mut o = Object::new();
            let _ = o.insert("account", dec(m.account.raw()));
            let _ = o.insert("display_name", opt_str(m.display_name.as_ref()));
            let _ = o.insert("email", opt_str(m.email.as_ref()));
            let _ = o.insert("tenant_admin", Value::Bool(m.tenant_admin));
            let _ = o.insert("roles", Value::Array(roles));
            members.push(Value::Object(o));
        }
        let mut o = Object::new();
        let _ = o.insert("actions", actions_json(&self.actions));
        let _ = o.insert("members", Value::Array(members));
        Value::Object(o)
    }
}

impl ToJson for DisplayNameView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("display_name", opt_str(self.0.as_ref()));
        Value::Object(o)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn req(v: Value) -> Object {
        let mut o = Object::new();
        let _ = o.insert("display_name", v);
        o
    }

    /// SA-11: a display name is plain text of at most 100 characters,
    /// trimmed. A blank, `null` or missing name clears it.
    #[test]
    fn sa11_display_name_is_plain_text_of_at_most_100_characters() {
        let hundred = "é".repeat(100);
        assert_eq!(
            checked_name(&req(Value::from(hundred.as_str()))).unwrap(),
            Some(hundred.clone())
        );
        assert_eq!(
            checked_name(&req(Value::from("  Synthetic Name  "))).unwrap(),
            Some("Synthetic Name".to_owned())
        );
        for clear in [req(Value::Null), req(Value::from("   ")), Object::new()] {
            assert_eq!(checked_name(&clear).unwrap(), None, "{clear:?}");
        }
        let long = "a".repeat(101);
        for bad in [
            req(Value::from(long.as_str())),
            req(Value::from("<b>Synthetic</b>")),
            req(Value::from("Synthetic>")),
            req(Value::from("Line\nbreak")),
            // ADR-029, lane L26: a name of default ignorables only.
            req(Value::from("\u{200d}\u{ad}")),
            req(Value::Bool(true)),
            req(Value::from(3_i64)),
        ] {
            assert!(checked_name(&bad).is_err(), "SA-11 accepted {bad:?}");
        }
    }
}

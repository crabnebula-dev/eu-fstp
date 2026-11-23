//! Team invitations (F-079, ADR-038; I-17, TH-07, TH-08, R-AN-01).
//!
//! Daniel decided on 2026-11-23 that a person accepts an invitation
//! before any binding and before any vault question about them, as staff
//! do. The operations:
//!
//! - `proposal.add_member` and `proposal.add_guardian` (body `{email}`):
//!   the lead invites an address. The core `InviteToTeam` binds nobody and
//!   asks the vault nothing about the invitee. Nothing resolves the
//!   address to an account, so the answer, its refusals and its work are
//!   the same whatever the address names. The address is stored as a
//!   salted confidential text of the proposal (ADR-007).
//! - `proposal.team_invitations`: the lead's invitations of the proposal,
//!   each `open`, `joined` or `not_joined`. A decline, a withdrawal and an
//!   expiry all read `not_joined`.
//! - `proposal.withdraw_team_invitation`: the lead closes one.
//! - `me.team_invitations`: the open invitations addressed to the
//!   caller's login email. The text store answers one bit per invitation
//!   (`TextStore::text_equals`), so no text of a proposal the caller is
//!   not on is read.
//! - `me.accept_team_invitation` and `me.decline_team_invitation`: the
//!   invitee answers. An invitation that is unknown, closed, expired or
//!   addressed to someone else gets one refusal, `not_found` with rule
//!   `Input`. Only the acceptance asks the vault, and its refusal names
//!   its rule to the invitee only.
//!
//! Interim readings of the lane, for Daniel (ADR-038): no mail is sent;
//! addresses compare in ASCII lower case after trimming; the invitee's
//! list names the proposal id, the role and the expiry only.

use fstp_domain::id::{ContentDigest, TeamInvitationId, TextId};
use fstp_domain::proposal::team::{self as domain_team, TeamInvitation};
use fstp_json::{Array, ToJson};

use super::*;
use crate::port::{TextClass, TextOwner};

/// The rule a lead's invitation past the bounds is refused under.
pub(crate) const BOUND_RULE: &str = "ADR-038";

/// The comparison form of an address: trimmed, ASCII lower case (ADR-038).
/// The cell's login email index compares the same way
/// (`fstp_cell::tasks::erasure::normalise_email`).
pub(crate) fn normalised(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// The one refusal of an invitation the caller may not answer.
fn not_found() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

/// The execution metadata of a call that appends one command.
fn meta<P: Seams>(call: &Call<'_, P>) -> ExecMeta {
    ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    }
}

/// Dry runs `cmd` by `account`, recording any vault answer (NOTE 5), then
/// executes it.
async fn run_command<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    trial: &Command,
    cmd: Command,
) -> Result<OpResult, ApiError> {
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, trial, call.caller.via(), command_id);
    dry_run(call, account, trial, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    match call.ports.engine().execute(cmd, ctx, meta(call)).await {
        Ok(seq) => Ok(OpResult::Done {
            body: ReadModel::Accepted,
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// The proposal of the route, or a bad request.
fn proposal_of<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<ProposalId, ApiError> {
    forms::id_param(&op.request, "proposal")
        .map(ProposalId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The invitation of the route, or a bad request.
fn invitation_of<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<TeamInvitationId, ApiError> {
    forms::id_param(&op.request, "invitation")
        .map(TeamInvitationId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// An actor refusal for anyone but the proposal's active lead. A former
/// lead of a proposal in a final state is refused on the target.
fn lead_only<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    p: ProposalId,
) -> Result<(), ApiError> {
    match proposal_lead(&call.state, account, p, call.now) {
        Lead::Active => Ok(()),
        Lead::Former => Err(call.refuse(ApiError::refused(ErrorCode::Refused, "Input"))),
        Lead::Not => Err(call.refuse(ApiError::refused(ErrorCode::Refused, "actor"))),
    }
}

/// `proposal.add_member` and `proposal.add_guardian` (module
/// documentation). Every check reads the lead, the proposal, the bounds or
/// the input. None reads the invitee.
pub(super) async fn invite<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
    guardian: bool,
) -> Result<OpResult, ApiError> {
    let p = proposal_of(call, op)?;
    lead_only(call, account, p)?;
    let email = crate::tenant::invite_email(&op.request).map_err(|e| call.refuse(e))?;
    let address = normalised(&email);
    if !domain_team::invitation_allowed(&call.state.core, p, account, call.now) {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, BOUND_RULE)));
    }
    let invitation = TeamInvitationId::from_raw(call.draw().map_err(|e| call.refuse(e))?);
    let command = |contact| {
        Command::Core(fstp_domain::command::Command::InviteToTeam {
            proposal: p,
            invitation,
            contact,
            guardian,
        })
    };
    // The trial names a stand-in text, so a refused invitation stores no
    // address. The executed command names the stored one.
    let trial = command(forms::text_ref(0, &address));
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &trial, call.caller.via(), command_id);
    dry_run(call, account, &trial, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    // ADR-007: the address is a sealed text under its own salt.
    let salt = crate::salted::draw().map_err(|e| call.refuse(e))?;
    let stored = call
        .ports
        .texts()
        .put(
            TextClass::Confidential,
            TextOwner::Proposal(p),
            &crate::salted::stored(&salt, address.as_bytes()),
        )
        .await
        .map_err(|e| call.refuse(port_failed(e, "text")))?;
    let contact = fstp_domain::id::TextRef::new(
        TextId::from_raw(stored.0),
        ContentDigest::from_bytes(crate::salted::digest(&salt, address.as_bytes())),
    );
    lock(&call.st.content).remember(contact, &address);
    let cmd = command(contact);
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    match call.ports.engine().execute(cmd, ctx, meta(call)).await {
        Ok(seq) => Ok(OpResult::Done {
            body: ReadModel::Accepted,
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// `proposal.withdraw_team_invitation` (module documentation).
pub(super) async fn withdraw<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let p = proposal_of(call, op)?;
    lead_only(call, account, p)?;
    let invitation = invitation_of(call, op)?;
    let cmd = Command::Core(fstp_domain::command::Command::WithdrawTeamInvitation {
        proposal: p,
        invitation,
    });
    run_command(call, account, &cmd.clone(), cmd).await
}

/// Whether `i` is addressed to `account`'s login email. An account with no
/// login email, or a store that cannot compare, matches nothing.
async fn addressed_to<P: Seams>(
    call: &Call<'_, P>,
    i: &TeamInvitation,
    account: AccountId,
) -> bool {
    let Ok(Some(login)) = call.ports.accounts().login_email(account).await else {
        return false;
    };
    let mine = normalised(&login);
    if let Some(known) = lock(&call.st.content).text(i.contact) {
        return known == mine;
    }
    call.ports
        .texts()
        .text_equals(crate::port::TextRef(i.contact.id().raw()), mine.as_bytes())
        .await
        .unwrap_or(false)
}

/// The open invitation of the route addressed to `account`, or the one
/// refusal of [`not_found`].
async fn mine<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<(TeamInvitationId, TeamInvitation), ApiError> {
    let id = invitation_of(call, op)?;
    let found = domain_team::team_invitation(&call.state.core, id)
        .copied()
        .filter(|i| i.open_at(call.now));
    match found {
        Some(i) if addressed_to(call, &i, account).await => Ok((id, i)),
        _ => Err(call.refuse(not_found())),
    }
}

/// `me.accept_team_invitation` and `me.decline_team_invitation` (module
/// documentation).
pub(super) async fn answer<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
    accept: bool,
) -> Result<OpResult, ApiError> {
    let (invitation, i) = mine(call, op, account).await?;
    let cmd = if accept {
        let binding =
            fstp_domain::id::BindingId::from_raw(call.draw().map_err(|e| call.refuse(e))?);
        fstp_domain::command::Command::AcceptTeamInvitation {
            proposal: i.proposal,
            invitation,
            binding,
        }
    } else {
        fstp_domain::command::Command::DeclineTeamInvitation {
            proposal: i.proposal,
            invitation,
        }
    };
    let cmd = Command::Core(cmd);
    run_command(call, account, &cmd.clone(), cmd).await
}

/// The role wire name of an invitation.
const fn role_name(guardian: bool) -> &'static str {
    if guardian { "guardian" } else { "team_member" }
}

/// One invitation as its lead sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeadRow {
    /// The invitation.
    pub invitation: TeamInvitationId,
    /// The address the lead typed, in its comparison form.
    pub email: String,
    /// Whether it is for the guardian.
    pub guardian: bool,
    /// `open`, `joined` or `not_joined`.
    pub state: &'static str,
    /// When it expires.
    pub expires: Timestamp,
}

/// One open invitation as its invitee sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnRow {
    /// The invitation.
    pub invitation: TeamInvitationId,
    /// The proposal it is for.
    pub proposal: ProposalId,
    /// Whether it is for the guardian.
    pub guardian: bool,
    /// When it expires.
    pub expires: Timestamp,
}

/// The two invitation reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeamInvitationsView {
    /// `proposal.team_invitations`.
    Lead(Vec<LeadRow>),
    /// `me.team_invitations`.
    Own(Vec<OwnRow>),
}

/// The state the lead reads: joined, open, or not joined for every other
/// end. A refused acceptance leaves an invitation open.
fn lead_state(i: &TeamInvitation, now: Timestamp) -> &'static str {
    match i.closed {
        Some(true) => "joined",
        None if now < i.expires => "open",
        _ => "not_joined",
    }
}

/// `proposal.team_invitations` (module documentation). The read rule
/// admitted the lead.
pub(super) async fn lead_list<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    clearance: &fstp_access::ReadClearance,
) -> Result<TeamInvitationsView, ApiError> {
    let p = proposal_of(call, op)?;
    let mut rows = Vec::new();
    for (id, i) in domain_team::team_invitations(&call.state.core) {
        if i.proposal != p {
            continue;
        }
        rows.push(LeadRow {
            invitation: id,
            email: salted_text(call, i.contact, clearance).await?,
            guardian: i.guardian,
            state: lead_state(i, call.now),
            expires: i.expires,
        });
    }
    Ok(TeamInvitationsView::Lead(rows))
}

/// `me.team_invitations` (module documentation). Each open invitation is
/// compared with the caller's login email, and only matches are listed.
pub(super) async fn own_list<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
) -> Result<TeamInvitationsView, ApiError> {
    let open: Vec<(TeamInvitationId, TeamInvitation)> =
        domain_team::team_invitations(&call.state.core)
            .filter(|(_, i)| i.open_at(call.now))
            .map(|(id, i)| (id, *i))
            .collect();
    let mut rows = Vec::new();
    for (id, i) in open {
        if addressed_to(call, &i, account).await {
            rows.push(OwnRow {
                invitation: id,
                proposal: i.proposal,
                guardian: i.guardian,
                expires: i.expires,
            });
        }
    }
    Ok(TeamInvitationsView::Own(rows))
}

impl ToJson for TeamInvitationsView {
    fn to_json(&self) -> Value {
        let id = |n: u128| Value::String(n.to_string());
        let micros = |t: Timestamp| Value::String(t.micros().to_string());
        let mut rows = Array::new();
        match self {
            TeamInvitationsView::Lead(v) => {
                for r in v {
                    let mut o = Object::new();
                    let _ = o.insert("invitation", id(r.invitation.raw()));
                    let _ = o.insert("email", Value::String(r.email.clone()));
                    let _ = o.insert("role", Value::from(role_name(r.guardian)));
                    let _ = o.insert("state", Value::from(r.state));
                    let _ = o.insert("expires", micros(r.expires));
                    rows.push(Value::Object(o));
                }
            }
            TeamInvitationsView::Own(v) => {
                for r in v {
                    let mut o = Object::new();
                    let _ = o.insert("invitation", id(r.invitation.raw()));
                    let _ = o.insert("proposal", id(r.proposal.raw()));
                    let _ = o.insert("role", Value::from(role_name(r.guardian)));
                    let _ = o.insert("expires", micros(r.expires));
                    rows.push(Value::Object(o));
                }
            }
        }
        let mut o = Object::new();
        let _ = o.insert("invitations", Value::Array(rows));
        Value::Object(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-038: addresses compare trimmed and in ASCII lower case.
    #[test]
    fn m10_f079_addresses_compare_trimmed_and_caseless() {
        assert_eq!(
            normalised("  Member@Example.INVALID "),
            "member@example.invalid"
        );
    }

    /// F-079, R-AN-01: the lead reads open, joined or not joined, and
    /// nothing tells a decline from a withdrawal or an expiry.
    #[test]
    fn m10_f079_the_lead_reads_three_states_only() {
        let at = Timestamp::from_micros(10);
        let i = |closed| TeamInvitation {
            proposal: ProposalId::from_raw(1),
            contact: forms::text_ref(1, "x@e2e.invalid"),
            guardian: false,
            by: AccountId::from_raw(2),
            expires: Timestamp::from_micros(20),
            closed,
        };
        assert_eq!(lead_state(&i(None), at), "open");
        assert_eq!(lead_state(&i(Some(true)), at), "joined");
        assert_eq!(lead_state(&i(Some(false)), at), "not_joined");
        assert_eq!(
            lead_state(&i(None), Timestamp::from_micros(20)),
            "not_joined"
        );
    }
}

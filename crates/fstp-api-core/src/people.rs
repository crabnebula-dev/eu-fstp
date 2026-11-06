//! The people operations of journey J2 (M4 design section 2.2 J1 and J2,
//! `roles-and-sod.md` SoD-09 and "Confidentiality on binding", lane inv).
//!
//! - `people.get_invitation` (`GET /invitations/{token}`): the landing.
//!   It names the invited role, the version of the confidentiality terms,
//!   the programme's P-75 and P-77 choices for the terms of a Judging role
//!   and the state. It names no account, no inviter, no address and no
//!   programme (I-86).
//! - `people.accept_invitation` (`POST /invitations/{token}/accept`, body
//!   `{terms_version}`): the enrolled invitee accepts the terms version
//!   the landing showed. The shell stores the terms as shown, and the
//!   engine records the core `TermsAccepted`, which the creator folds.
//! - `people.begin_verification` (`POST /invitations/{token}/verification`,
//!   body `{}`): the acceptor starts the identity verification of SoD-09
//!   through `VaultIntake::begin_verification`.
//! - `roles.grant` by `{invitation, approval?}`: the grant composed from
//!   the acceptance, of the accepting account in the invited role.
//!
//! The link token is the only capability. It names its invitation through
//! its digest (`creator::link_invitation`, ADR-007).
//!
//! # Interim readings, pending Daniel (design section 15.0)
//!
//! - **One refusal.** An unknown token, a withdrawn invitation and one
//!   another account accepted get the same refusal, `not_found` with rule
//!   `Input`, for every caller, so no answer tells the cases apart.
//! - **First acceptor.** No port says which account M3 bound to the
//!   address, so the first enrolled account that accepts with the token
//!   takes the invitation. From then on the token works for that account
//!   only. Its landing stays readable to it, for the verification step.
//! - **Terms.** The wording is approved text of the web catalogue, a
//!   `TODO(legal)` placeholder until Daniel supplies it. The server keeps
//!   its version, [`TERMS_VERSION`]. A choice of P-75 or P-77 that the
//!   draft does not hold yet reads as `null`, and the stored terms state it
//!   as undecided. The server does not refuse such an acceptance; the
//!   landing page offers none.
//! - **Grant.** A Drafting or Judging grant is composed only from a
//!   `TermsAccepted` of a live invitation of that role, accepted by that
//!   account (`fstp_engine::compose::terms_accepted`). Its confidentiality
//!   text is the stored terms. The refusal names the rule `J2`, since the
//!   spec section has no ID. Operations and oversight grants need none,
//!   as the spec names Drafting and Judging only.

use fstp_creator::{CreatorCommand, InvitationId, Invitee};
use fstp_domain::policy::AgentContentAccess;
use fstp_domain::roles::Group;

use super::*;
use crate::model::{InvitationLanding, InvitationState};

/// The version of the confidentiality terms that the landing shows and an
/// acceptance must name. TODO(legal): the wording behind it is placeholder
/// text in the web catalogue until Daniel supplies it.
pub(crate) const TERMS_VERSION: u32 = 1;

/// The rule a refusal of J2 names where the spec gives no ID.
const J2: &str = "J2";

/// The field keys of P-75 and P-77 in the draft spec.
const P75_KEY: &str = "evaluation.p75_agent_content_reads";
const P77_KEY: &str = "evaluation.p77_mcp_binding_actions";

/// The one refusal of a token that names no invitation the caller may use
/// (module documentation).
pub(crate) fn no_invitation() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

fn bad() -> ApiError {
    ApiError::bad_request(forms::REQUEST_RULE)
}

/// An invitation found by its token.
#[derive(Clone, Copy, Debug)]
struct Found {
    programme: ProgrammeId,
    id: InvitationId,
    invitation: fstp_creator::Invitation,
}

/// The live invitation by contact address that `token` names, if any.
fn find(state: &EngineState, token: &str) -> Option<Found> {
    let id = crate::creator::link_invitation(token);
    state.creator.drafts().find_map(|(programme, d)| {
        let i = d.invitations().get(&id)?;
        (!i.withdrawn && matches!(i.invitee, Invitee::Pending { .. })).then_some(Found {
            programme,
            id,
            invitation: *i,
        })
    })
}

/// The invitation of the route's token that `viewer` may use: live, and
/// not accepted by another account. Anything else is [`no_invitation`].
fn open_for(state: &EngineState, op: &Op, viewer: Option<AccountId>) -> Result<Found, ApiError> {
    let token = op
        .request
        .get("invitation_token")
        .and_then(Value::as_str)
        .ok_or_else(no_invitation)?;
    let found = find(state, token).ok_or_else(no_invitation)?;
    match found.invitation.accepted {
        Some(a) if Some(a) != viewer => Err(no_invitation()),
        _ => Ok(found),
    }
}

/// Whether the core holds a binding of `account` in `role` on `p`.
fn granted(state: &EngineState, account: AccountId, p: ProgrammeId, role: Role) -> bool {
    state
        .core
        .roster()
        .bindings()
        .any(|(_, b)| b.account == account && b.programme == p && b.role == role && b.held())
}

/// The state of `found`, as the invitation list reads it: `granted` once
/// a binding of the acceptor in the role is held, `verified` once the
/// vault verifies the acceptor, `accepted` before, and `invited` until an
/// account accepts. The vault answer is recorded (NOTE 5).
async fn state_of<P: Seams>(
    call: &Call<'_, P>,
    found: &Found,
) -> Result<InvitationState, ApiError> {
    let Some(a) = found.invitation.accepted else {
        return Ok(InvitationState::Invited);
    };
    if granted(&call.state, a, found.programme, found.invitation.role) {
        return Ok(InvitationState::Granted);
    }
    vault_read_admitted(call, a)?;
    let ans = ask_vault(call, &Query::IsVerified { account: a }).await?;
    Ok(if ans.holds {
        InvitationState::Verified
    } else {
        InvitationState::Accepted
    })
}

/// The programme's P-75 and P-77 choices that the terms of `role` state:
/// both `None` for a role outside Judging, and each `None` while the draft
/// holds no value for it.
fn choices(
    state: &EngineState,
    p: ProgrammeId,
    role: Role,
) -> (Option<bool>, Option<McpBindingActions>) {
    if role.group() != Group::Judging {
        return (None, None);
    }
    let Some(head) = fstp_domain::policy::head(&state.core, p) else {
        return (None, None);
    };
    let set = match state.creator.draft(p) {
        Some(d) => d.set_fields(),
        // A programme with no draft holds every value of its policy.
        None => {
            return (
                Some(head.frozen.p75 == AgentContentAccess::On),
                Some(head.frozen.p77),
            );
        }
    };
    let holds = |key: &str| set.iter().any(|f| f.key() == key);
    (
        holds(P75_KEY).then_some(head.frozen.p75 == AgentContentAccess::On),
        holds(P77_KEY).then_some(head.frozen.p77),
    )
}

/// `people.get_invitation` (module documentation).
pub(super) async fn landing<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
) -> Result<InvitationLanding, ApiError> {
    let found = open_for(&call.state, op, call.account()).map_err(|e| call.refuse(e))?;
    let state = state_of(call, &found).await?;
    let (p75, p77) = choices(&call.state, found.programme, found.invitation.role);
    let version = std::num::NonZeroU32::new(TERMS_VERSION).ok_or_else(|| call.refuse(bad()))?;
    InvitationLanding::new(found.invitation.role, version, p75, p77, state)
        .ok_or_else(|| call.refuse(no_invitation()))
}

/// The body of an acceptance: exactly `{terms_version}`, a positive JSON
/// integer that fits a `u32` (I-84).
fn terms_version(op: &Op) -> Result<u32, ApiError> {
    let members: Vec<&str> = op
        .request
        .keys()
        .filter(|k| *k != "invitation_token")
        .collect();
    if members != ["terms_version"] {
        return Err(bad());
    }
    op.request
        .get("terms_version")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= 1)
        .ok_or_else(bad)
}

/// The stored form of the terms as shown: their version, the role and
/// the bound P-75 and P-77 choices. It names no account and no address.
fn terms_text(found: &Found, p75: Option<bool>, p77: Option<McpBindingActions>) -> String {
    let p75 = match p75 {
        Some(true) => "on",
        Some(false) => "off",
        None => "undecided",
    };
    let p77 = match p77 {
        Some(McpBindingActions::Allowed) => "allowed",
        Some(McpBindingActions::DraftOnly) => "draft_only",
        None => "undecided",
    };
    let role = fstp_access::role_wire_name(found.invitation.role);
    if found.invitation.role.group() == Group::Judging {
        format!("confidentiality-terms;version={TERMS_VERSION};role={role};p75={p75};p77={p77}")
    } else {
        format!("confidentiality-terms;version={TERMS_VERSION};role={role}")
    }
}

/// `people.accept_invitation` (module documentation).
pub(super) async fn accept<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let version = terms_version(op).map_err(|e| call.refuse(e))?;
    let found = open_for(&call.state, op, Some(account)).map_err(|e| call.refuse(e))?;
    if found.invitation.accepted.is_some() {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, J2)));
    }
    if version != TERMS_VERSION {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, J2)));
    }
    let (p75, p77) = choices(&call.state, found.programme, found.invitation.role);
    let text = terms_text(&found, p75, p77);
    let command = |terms| {
        Command::Creator(CreatorCommand::AcceptInvitation {
            programme: found.programme,
            invitation: found.id,
            version,
            terms,
        })
    };
    let trial = command(forms::text_ref(0, &text));
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &trial, call.caller.via(), command_id);
    dry_run(call, account, &trial, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    let stored = call
        .ports
        .texts()
        .put(
            TextClass::Confidential,
            TextOwner::Programme(found.programme),
            text.as_bytes(),
        )
        .await
        .map_err(|e| call.refuse(port_failed(e, "text")))?;
    let terms = forms::text_ref(stored.0, &text);
    lock(&call.st.content).remember(terms, &text);
    let meta = ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    };
    match call.ports.engine().execute(command(terms), ctx, meta).await {
        Ok(seq) => Ok(OpResult::Done {
            body: ReadModel::Accepted,
            seq: Some(seq),
        }),
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// `people.begin_verification` (module documentation): the acceptor only.
pub(super) async fn begin_verification<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    if op.request.keys().any(|k| k != "invitation_token") {
        return Err(call.refuse(bad()));
    }
    let found = open_for(&call.state, op, Some(account)).map_err(|e| call.refuse(e))?;
    if found.invitation.accepted != Some(account) {
        // Not accepted yet: the verification follows the acceptance.
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, J2)));
    }
    match call
        .ports
        .vault()
        .begin_verification(VerificationPurpose::ProgrammeRole, account)
        .await
    {
        Ok(to) => {
            lock(&call.st.begun).begin(account, call.now);
            call.accept(ReadModel::Redirect(to.0))
        }
        Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
    }
}

/// The codec spelling of `role` in a core command, such as
/// `"ProgrammeManager"`.
fn role_json(role: Role) -> Option<Value> {
    let probe = fstp_domain::Command::GrantRole {
        binding: fstp_domain::id::BindingId::from_raw(0),
        account: AccountId::from_raw(0),
        programme: ProgrammeId::from_raw(0),
        role,
        start: Timestamp::from_micros(0),
        second_admin: None,
        confidentiality: None,
        organisation: None,
        end: None,
    };
    fstp_json::ToJson::to_json(&probe)
        .as_object()?
        .get("role")
        .cloned()
}

/// The text references a composed request supplies, by text path.
pub(super) type PresetTexts = BTreeMap<&'static str, TextRef>;

/// The strict check of a `roles.grant` body of the people admin page,
/// `{invitation, approval?}` (I-84, lane inv): the invitation a canonical
/// decimal id, an approval in its route form, and no other member. `None`
/// for a body of the M2 account form, which `forms.rs` checks.
///
/// Seam for the lead: `forms::check` refuses this body before dispatch,
/// since `roles.grant` has the account form only. Calling this check
/// there for `roles.grant` admits the page body.
pub(crate) fn check_grant_by_invitation(request: &Object) -> Option<Result<u128, ApiError>> {
    let raw = request.get("invitation")?;
    let members_ok = request
        .keys()
        .all(|k| matches!(k, "programme" | "invitation" | "approval"));
    let approval_ok = request
        .get("approval")
        .is_none_or(|v| v.is_null() || forms::param_ok("approval", v));
    Some(
        raw.as_str()
            .and_then(forms::canonical_id)
            .filter(|_| members_ok && approval_ok)
            .ok_or_else(bad),
    )
}

/// The grant request that a `roles.grant` by `{invitation, approval?}`
/// stands for (module documentation), with the text reference of its
/// confidentiality terms. `None` for a request of the account form.
pub(super) fn grant_request(
    state: &EngineState,
    op: &Op,
    now: Timestamp,
) -> Result<Option<(Op, PresetTexts)>, ApiError> {
    let Some(id) = check_grant_by_invitation(&op.request) else {
        return Ok(None);
    };
    let id = id?;
    let programme = forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or_else(bad)?;
    let invitation = state
        .creator
        .draft(programme)
        .and_then(|d| d.invitations().get(&InvitationId::from_raw(id)))
        .filter(|i| !i.withdrawn)
        .copied()
        .ok_or_else(|| ApiError::refused(ErrorCode::NotFound, "Input"))?;
    let (Some(account), Some((_, terms))) = (invitation.accepted, invitation.terms) else {
        return Err(ApiError::refused(ErrorCode::Refused, J2));
    };
    let mut request = Object::new();
    for (k, v) in op.request.iter() {
        if k != "invitation" {
            let _ = request.insert(k, v.clone());
        }
    }
    let _ = request.insert("account", Value::String(account.raw().to_string()));
    let _ = request.insert("role", role_json(invitation.role).ok_or_else(bad)?);
    let _ = request.insert("start", Value::String(now.micros().to_string()));
    if let Some(o) = invitation.organisation {
        let _ = request.insert("organisation", Value::String(o.raw().to_string()));
    }
    let mut texts = BTreeMap::new();
    texts.insert("confidentiality", terms);
    Ok(Some((
        Op {
            spec: op.spec,
            request,
            from_tool: op.from_tool,
        },
        texts,
    )))
}

/// The J2 guard of a composed grant: a Drafting or Judging grant needs a
/// `TermsAccepted` of that account and role (module documentation).
pub(super) fn grant_admitted(state: &EngineState, cmd: &Command) -> Result<(), ApiError> {
    let Command::Core(fstp_domain::Command::GrantRole {
        account,
        programme,
        role,
        ..
    }) = cmd
    else {
        return Ok(());
    };
    if !matches!(role.group(), Group::Drafting | Group::Judging) {
        return Ok(());
    }
    match fstp_engine::compose::terms_accepted(state, *account, *programme, *role) {
        Some(_) => Ok(()),
        None => Err(ApiError::refused(ErrorCode::Refused, J2)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-84, J2: the codec spelling of a role is the variant name the M2
    /// grant form takes.
    #[test]
    fn j2_role_json_is_the_m2_form_spelling() {
        assert_eq!(
            role_json(Role::ProgrammeManager),
            Some(Value::from("ProgrammeManager"))
        );
        assert_eq!(
            role_json(Role::CommitteeMember),
            Some(Value::from("CommitteeMember"))
        );
    }

    /// ADR-007, I-86, J2: the stored terms name the version, the role and
    /// the bound choices, and nothing about a person.
    #[test]
    fn j2_stored_terms_name_version_role_and_choices() {
        let found = Found {
            programme: ProgrammeId::from_raw(7),
            id: InvitationId::from_raw(9),
            invitation: fstp_creator::Invitation {
                role: Role::CommitteeMember,
                invitee: Invitee::Pending {
                    contact: forms::text_ref(3, "x@e2e.invalid"),
                },
                organisation: None,
                by: AccountId::from_raw(1),
                withdrawn: false,
                accepted: None,
                terms: None,
            },
        };
        let t = terms_text(&found, Some(true), None);
        assert_eq!(
            t,
            "confidentiality-terms;version=1;role=committee_member;p75=on;p77=undecided"
        );
        assert!(!t.contains('@'));
    }
}

//! The tenant arm of the one dispatch (M4 design sections 2.2 J0, 3.5
//! and 3.7; R-TN-01, R-LG-03, SoD-07, I-77, I-78, Q31; lane m4tenant).
//!
//! A tenant command runs the steps of design section 3.7 in order, after
//! the steps every call shares (principal, session strength, channel and
//! rate limits):
//!
//! 1. **Decode** with the strict decoder of `crate::tenant`.
//! 2. **Admin set.** The caller must be a tenant admin of the ledger's
//!    admin set (Q31 A). The ledger alone owns that set.
//! 3. **Facts.** Each prober check the command needs runs once, in this
//!    request (Q5). The outcome travels in the command.
//! 4. **Precheck** with `fstp_engine::tenant::precheck_tenant`, so a
//!    refusal names its tenant rule.
//! 5. **Dry run** with web semantics, its vault answers recorded.
//! 6. **Step-up** for a high-risk operation: a proof for this digest, or
//!    a challenge bound to it (I-78).
//! 7. **Execute.** The data protection contact goes to the cell's text
//!    store only now, so a refused call stores no text. A save of the
//!    Inference step carries a configuration id drawn from the id port,
//!    under which the engine records the inference configuration (design
//!    3.5).
//!
//! # The ledger governs the tenant
//!
//! Design 3.5: "Every change is a ledger record." Once the cell's ledger
//! holds the tenant part, dispatch reads from it alone: the admin set
//! ([`is_admin`], which also feeds the principal and the attested `Ctx`),
//! P-74 ([`mcp_settings`]) and the publication configuration
//! ([`inference`]).
//!
//! # Interim readings, pending Daniel and the lead
//!
//! - A cell whose ledger holds no tenant part yet keeps the M3 port's
//!   attested admin set, its P-74 and its inference record, as before M4.
//!   A production cell appends the provisioning record at first start,
//!   so this covers only cells and worlds from before the tenant part.
//! - The data protection contact goes to the cell's text store as a
//!   confidential text of the tenant (`TextOwner::Tenant`, Q22). As for
//!   every other text, this core caches it to show it again. The
//!   `TextStore` port has no read without a `ReadClearance` yet, so a
//!   restarted core that no longer caches the contact fails the
//!   Organisation read closed. That read path is a seam of the lead.
//! - P-70 to P-72 are recorded and shown here, but the M3 session and
//!   step-up ports enforce their own values. Those ports do not read the
//!   ledger yet, which is a seam of the lead.
//! - The P-74 `public_tools` flag has no place in `fstp_access`'s
//!   `McpSettings` yet. Public tools are not served in M4 (lane W2c).
//!   A P-74 role set that holds `Applicant` also admits an account that
//!   acts as an applicant with no binding yet.
//! - `tenant.invite_admin` draws the invitation, the invitee's account and
//!   a random invitation token, and records only the token's digest. No
//!   port hands the token and the email to M3 yet (`port::InviteKind` is
//!   a W0 placeholder), so the e2e cell's M3 emulation sends the
//!   invitation.
//! - `admin.approve_self_grant` needs the self-grant its approval names.
//!   No record or port lists pending self-grants yet (blocking seam of the
//!   lead). An approval id the ledger already holds is refused under
//!   SoD-07 as taken. Every other id names no known self-grant, so it is
//!   refused as not found under `Input`, before any step-up. The role
//!   grant does not consume a ledger approval yet either: `second_admin`
//!   still reads M3's recorded approvals.
//! - The port prober takes no domain and has no absent outcome. So the
//!   sending-domain check cannot name the domain of this save, and a cell
//!   with no prober shows `probe_failed`, not `prober_absent` (Q5). Both
//!   need a port change by the lead.

use fstp_access::{McpSettings, RoleOrApplicant};
use fstp_access::{ReadKind, TenantKind};
use fstp_domain::command::Via;
use fstp_domain::id::{AccountId, CommandId, LlmConfigId, TextRef};
use fstp_domain::oracle::Query;
use fstp_domain::policy::ModelRef;
use fstp_domain::roles::Role;
use fstp_engine::tenant::{PrecheckError, precheck_tenant};
use fstp_engine::{Command, EngineState, TenantRequest};
use fstp_tenant::{
    ActivationRequestId, ApprovalId, InvitationId, OnboardingStep, ProbeOutcome, StepValues,
    TenantCommand, TenantQuery, TenantRefusal, TenantState, TokenDigest,
};

use super::{
    Call, Seams, ask_vault, dry_run, exec_failed, label_of, lock, port_failed, step_up,
    vault_read_admitted,
};
use crate::model::{AdminRow, TenantAdmins};
use crate::port::{
    AsyncEngine, CellPorts, DisplayHandle, ExecMeta, OpName, Outcome, ProbeKind as PortProbe,
    ProbeOutcome as PortOutcome, Prober, TenantConfig, TextClass, TextOwner, TextStore,
};
use crate::tenant::{
    ActivationView, SaveRequest, SettingsView, SignatoryList, SignatoryRow, StepView, TenantView,
};
use crate::{ApiError, ErrorCode, Op, OpResult, ReadModel};

// ---------------------------------------------------------------------------
// What the ledger governs (module documentation)
// ---------------------------------------------------------------------------

/// Whether `account` is a tenant admin (Q31 A). Once the ledger holds the
/// tenant part, its admin set alone answers. Before that, the attested set
/// of the M3 port does (interim, module documentation).
pub(super) fn is_admin<P: CellPorts>(ports: &P, state: &EngineState, account: AccountId) -> bool {
    match state.tenant.state() {
        Some(ts) => ts.is_admin(account),
        None => ports.tenant().is_tenant_admin(account),
    }
}

/// Whether `account` holds a tenant-wide Operations role: tenant admin,
/// or Financial or Legal signatory (NOTE 5). Each acts in every programme
/// of the tenant, so each counts for SoD-03 against a Receiving binding.
/// Signatory bindings live only in the ledger's tenant part, so before
/// that part exists only the admin set answers.
pub(super) fn holds_tenant_operations<P: CellPorts>(
    ports: &P,
    state: &EngineState,
    account: AccountId,
) -> bool {
    match state.tenant.state() {
        Some(ts) => ts.is_admin(account) || ts.signatories().iter().any(|(_, a)| *a == account),
        None => ports.tenant().is_tenant_admin(account),
    }
}

/// P-74 as the channel policy reads it: the ledger's setting once the
/// ledger holds the tenant part, else the M3 port's (interim).
pub(super) fn mcp_settings<P: Seams>(ports: &P, state: &EngineState) -> McpSettings {
    match state.tenant.state() {
        Some(ts) => channel_settings(&ts.settings().p74),
        None => ports.mcp_settings(),
    }
}

/// The channel policy's form of a recorded P-74 value.
fn channel_settings(p74: &fstp_tenant::McpSettings) -> McpSettings {
    if !p74.enabled {
        return McpSettings::disabled();
    }
    let Some(roles) = &p74.roles else {
        return McpSettings::all_roles();
    };
    let mut allowed: Vec<RoleOrApplicant> =
        roles.iter().copied().map(RoleOrApplicant::Role).collect();
    if roles.contains(&Role::Applicant) {
        allowed.push(RoleOrApplicant::Applicant);
    }
    McpSettings::limited_to(allowed)
}

/// The configuration and primary model a publication names: the latest
/// `InferenceConfigRecorded` entry once the ledger holds the tenant part
/// (design 3.5), else the M3 port's record (interim). `None` before one
/// exists, so a publication is refused.
pub(super) fn inference<P: Seams>(
    ports: &P,
    state: &EngineState,
) -> Option<(LlmConfigId, ModelRef)> {
    match state.tenant.state() {
        Some(ts) => ts
            .publication_config()
            .map(|(config, model)| (config, ModelRef(model.as_str().to_owned()))),
        None => ports.inference(),
    }
}

/// The API error of a tenant refusal: the rule it names, never an account
/// (R-CF-03).
fn tenant_error(r: TenantRefusal) -> ApiError {
    let rule = match r {
        TenantRefusal::HighRiskViaMcp | TenantRefusal::WebOnlyViaMcp => "I-85",
        // Tenant configuration is the tenant admin's role (the
        // `roles-and-sod.md` roles table), so another caller is refused as
        // an actor. R-AC-01 governs proposal reads under P-10 only.
        TenantRefusal::NotTenantAdmin => "actor",
        TenantRefusal::StaleRevision
        | TenantRefusal::StepLocked
        | TenantRefusal::StepSkipped
        | TenantRefusal::StepsNotValidated
        | TenantRefusal::AlreadyCompleted => "R-TN-01",
        TenantRefusal::TooFewAdmins
        | TenantRefusal::AdminNotVerified
        | TenantRefusal::SelfApproval
        | TenantRefusal::GranteeNotAdmin
        | TenantRefusal::ApprovalTaken
        | TenantRefusal::ApprovalNotOpen
        | TenantRefusal::ApprovalExpired
        | TenantRefusal::AlreadyAdmin
        | TenantRefusal::InvitationTaken
        | TenantRefusal::InvitationNotOpen
        | TenantRefusal::InvitationMismatch => "SoD-07",
        TenantRefusal::HoldsReceiving => "SoD-03",
        TenantRefusal::InvalidSetting(p) => p.param_id().spec_id(),
        TenantRefusal::InvalidModels
        | TenantRefusal::NotDefaultModels
        | TenantRefusal::ConfigTaken => "P-21",
        TenantRefusal::AnswerMissing => "facts_incomplete",
        TenantRefusal::InvalidInstant | TenantRefusal::Inconsistent => "ledger",
        // NOTE 5: a grant to one's own account falls under SoD-07.
        TenantRefusal::SignatorySelfGrant => "SoD-07",
        // M4 design section 15.0: a role is granted again only after it
        // ends, and only a held binding ends.
        TenantRefusal::SignatoryHeld | TenantRefusal::SignatoryNotHeld => "Input",
        TenantRefusal::NoFinancialSignatory => "SoD-14",
        TenantRefusal::NoLegalSignatory => "SoD-15",
        TenantRefusal::LastSignatory => "SoD-17",
        // SoD-18 names the approver who requested the activation. A
        // request while one is open or the organisation is active is an
        // onboarding state, as a second completion is, and an approval of
        // no open request names an unknown request.
        TenantRefusal::SelfActivationApproval => "SoD-18",
        TenantRefusal::ActivationPending | TenantRefusal::AlreadyActive => "R-TN-01",
        TenantRefusal::ActivationNotOpen => "Input",
        // R-GA-01: only an https privacy statement address stands in
        // the Guide.
        TenantRefusal::InvalidAddress => "R-GA-01",
    };
    ApiError::refused(ErrorCode::Refused, rule)
}

/// The refusal of a tenant operation in a cell with no provisioning
/// record.
const fn unprovisioned() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

/// The port probe of a tenant prober check.
fn port_probe(kind: &fstp_tenant::ProbeKind) -> PortProbe {
    match kind {
        fstp_tenant::ProbeKind::SendingDomain(_) => PortProbe::SendingDomain,
        fstp_tenant::ProbeKind::Channels => PortProbe::Channel,
    }
}

/// The tenant state of the call's snapshot, and the caller's account,
/// once the ledger's admin set holds the caller (Q31 A). Refusals are
/// audited.
fn admin<'a, P: Seams>(call: &'a Call<'_, P>) -> Result<(AccountId, &'a TenantState), ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let Some(ts) = call.state.tenant.state() else {
        return Err(call.refuse(unprovisioned()));
    };
    if !ts.is_admin(account) {
        // An actor refusal, as in `tenant_error`.
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "actor")));
    }
    Ok((account, ts))
}

/// The tenant command of `op`, before its texts are stored.
fn build<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: TenantKind,
) -> Result<(TenantCommand, Option<SaveRequest>), ApiError> {
    match kind {
        TenantKind::SaveStep => {
            let s = crate::tenant::save_request(&op.request)?;
            let cmd = TenantCommand::SaveStep {
                values: s.values.clone(),
                base: s.base,
            };
            Ok((cmd, Some(s)))
        }
        TenantKind::Complete => Ok((TenantCommand::Complete, None)),
        TenantKind::GrantSignatory => {
            let (role, account) = crate::tenant::signatory_request(&op.request)?;
            Ok((TenantCommand::GrantSignatory { role, account }, None))
        }
        TenantKind::EndSignatory => {
            let (role, account) = crate::tenant::signatory_request(&op.request)?;
            Ok((TenantCommand::EndSignatory { role, account }, None))
        }
        TenantKind::RequestActivation => Ok((
            TenantCommand::RequestActivation {
                request: ActivationRequestId::from_raw(call.draw()?),
            },
            None,
        )),
        TenantKind::ApproveActivation => Ok((
            TenantCommand::ApproveActivation {
                request: crate::tenant::activation_request(&op.request)?,
            },
            None,
        )),
        TenantKind::InviteAdmin => {
            // The email is checked and goes to M3 with the token, once a
            // port takes them (module documentation).
            let _email = crate::tenant::invite_email(&op.request)?;
            let invitation = InvitationId::from_raw(call.draw()?);
            let invitee = AccountId::from_raw(call.draw()?);
            let token = fstp_crypto::random_array::<32>()
                .map_err(|_| ApiError::refused(ErrorCode::Unavailable, "ids"))?;
            let token_digest = TokenDigest::from_bytes(fstp_crypto::sha256(&token));
            Ok((
                TenantCommand::InviteAdmin {
                    invitation,
                    invitee,
                    token_digest,
                },
                None,
            ))
        }
        TenantKind::SetSetting(_) => Ok((
            TenantCommand::SetSetting {
                value: crate::tenant::setting_request(&op.request, kind)?,
            },
            None,
        )),
        TenantKind::ApproveSelfGrant => Err(unknown_self_grant(&call.state, op)),
        // The summary holds a placeholder reference with id 0 and the
        // text's digest until dispatch stores it ([`stored_notice`]).
        TenantKind::SetGuideNotice => {
            let n = crate::tenant::notice_request(&op.request)?;
            Ok((n.command(crate::forms::text_ref(0, &n.summary)), None))
        }
        // Recorded with a validated Inference save (design 3.5), never
        // through a route of its own.
        TenantKind::RecordInferenceConfig => Err(ApiError::refused(ErrorCode::NotFound, "route")),
    }
}

/// The refusal of a SoD-07 approval while no record or port lists the
/// pending self-grants (module documentation). An approval id the ledger
/// already holds is taken. Any other id names no self-grant this cell
/// knows of.
fn unknown_self_grant(state: &EngineState, op: &Op) -> ApiError {
    let Some(id) = crate::forms::id_param(&op.request, "approval") else {
        return ApiError::bad_request(crate::forms::REQUEST_RULE);
    };
    let taken = state
        .tenant
        .state()
        .is_some_and(|ts| ts.approvals().contains_key(&ApprovalId::from_raw(id)));
    if taken {
        tenant_error(TenantRefusal::ApprovalTaken)
    } else {
        ApiError::refused(ErrorCode::NotFound, "Input")
    }
}

/// Runs the prober checks `cmd` needs in `ts`, once, and returns the
/// request with their outcomes (Q5). A failed probe, or a prober that
/// reports none, fails the step.
async fn with_facts<P: Seams>(
    call: &Call<'_, P>,
    ts: &TenantState,
    cmd: TenantCommand,
) -> TenantRequest {
    let probes: Vec<fstp_tenant::ProbeKind> = fstp_tenant::queries(ts, &cmd)
        .into_iter()
        .filter_map(|q| match q {
            TenantQuery::Probe(k) => Some(k),
            _ => None,
        })
        .collect();
    let mut req = TenantRequest::new(cmd);
    for kind in probes {
        let outcome = match call.ports.prober().probe(port_probe(&kind)).await {
            PortOutcome::Pass => ProbeOutcome::Passed,
            PortOutcome::Fail => ProbeOutcome::Failed,
        };
        req.facts.probe(kind, outcome);
    }
    req
}

/// Stores the data protection contact `s` in the cell's text store, as a
/// confidential text of the tenant (Q22), and caches it as every stored
/// text is cached. The reference names the store's id and the text's
/// digest.
async fn stored_contact<P: Seams>(call: &Call<'_, P>, s: &str) -> Result<TextRef, ApiError> {
    let r = call
        .ports
        .texts()
        .put(TextClass::Confidential, TextOwner::Tenant, s.as_bytes())
        .await
        .map_err(|e| port_failed(e, "text"))?;
    let r = crate::forms::text_ref(r.0, s);
    lock(&call.st.content).remember(r, s);
    Ok(r)
}

/// The `SetGuideNotice` of `op` with its summary stored in the cell's
/// text store, as a public text of the tenant, since the published Guide
/// shows it (R-GA-01). It runs only once the command is admitted, so a
/// refused call stores no text.
async fn stored_notice<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<TenantCommand, ApiError> {
    let n = crate::tenant::notice_request(&op.request)?;
    let r = call
        .ports
        .texts()
        .put(TextClass::Public, TextOwner::Tenant, n.summary.as_bytes())
        .await
        .map_err(|e| port_failed(e, "text"))?;
    Ok(n.command(crate::forms::text_ref(r.0, &n.summary)))
}

/// The values of `save` with its data protection contact stored.
async fn stored_values<P: Seams>(
    call: &Call<'_, P>,
    save: &SaveRequest,
) -> Result<StepValues, ApiError> {
    match (&save.values, &save.contact) {
        (StepValues::Organisation { signatories, .. }, Some(text)) => {
            Ok(StepValues::Organisation {
                data_protection_contact: stored_contact(call, text).await?,
                signatories: signatories.clone(),
            })
        }
        (v, _) => Ok(v.clone()),
    }
}

/// The API error of a precheck refusal.
fn precheck_error(e: PrecheckError) -> ApiError {
    match e {
        PrecheckError::Unprovisioned => unprovisioned(),
        PrecheckError::Refused(r) => tenant_error(r),
    }
}

/// A tenant command operation (module documentation).
pub(super) async fn command<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: TenantKind,
) -> Result<OpResult, ApiError> {
    if call.caller.via() != Via::Web {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-85")));
    }
    let (account, ts) = admin(call)?;
    let (tenant_cmd, save) = build(call, op, kind).map_err(|e| call.refuse(e))?;
    let mut req = with_facts(call, ts, tenant_cmd).await;
    if matches!(
        req.command,
        TenantCommand::SaveStep {
            values: StepValues::Inference(_),
            ..
        }
    ) {
        // The engine records the inference configuration under this id
        // when the save validates (design 3.5).
        let id = call.draw().map_err(|e| call.refuse(e))?;
        req.inference_config = Some(LlmConfigId::from_raw(id));
    }
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let cmd = Command::Tenant(req);
    let ctx = call.ctx(account, &cmd, Via::Web, command_id);
    if let Command::Tenant(r) = &cmd {
        precheck_tenant(&call.state, r, account, &ctx)
            .map_err(|e| call.refuse(precheck_error(e)))?;
    }
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    let proof = if call.spec.high_risk {
        match step_up(call, call.digest)
            .await
            .map_err(|e| call.refuse(e))?
        {
            Ok(p) => Some(p),
            Err(ask) => {
                let _ = call.audit(Outcome::Refused("I-78"), None);
                return Ok(ask);
            }
        }
    } else {
        None
    };
    let cmd = match (cmd, &save) {
        (Command::Tenant(mut r), Some(s)) => {
            let values = stored_values(call, s).await.map_err(|e| call.refuse(e))?;
            r.command = TenantCommand::SaveStep {
                values,
                base: s.base,
            };
            Command::Tenant(r)
        }
        (c, _) => c,
    };
    let cmd = match cmd {
        Command::Tenant(mut r) if kind == TenantKind::SetGuideNotice => {
            r.command = stored_notice(call, op).await.map_err(|e| call.refuse(e))?;
            Command::Tenant(r)
        }
        c => c,
    };
    let meta = ExecMeta {
        via: Via::Web,
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: proof,
        pending: None,
        second_tenant_admin: None,
    };
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => {
            let body = match &save {
                Some(s) => {
                    let after = call.ports.engine().snapshot();
                    ReadModel::Tenant(TenantView::Step(
                        step_view(call, &after, s.values.step()).map_err(|e| call.refuse(e))?,
                    ))
                }
                None => ReadModel::Accepted,
            };
            Ok(OpResult::Done {
                body,
                seq: Some(seq),
            })
        }
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// The text of a stored data protection contact, if `values` hold one. A
/// contact this core does not hold, or whose text no longer matches its
/// digest, fails closed.
fn contact_text<P: Seams>(
    call: &Call<'_, P>,
    values: &StepValues,
) -> Result<Option<String>, ApiError> {
    let StepValues::Organisation {
        data_protection_contact: r,
        ..
    } = values
    else {
        return Ok(None);
    };
    let content = lock(&call.st.content);
    match content.text(*r) {
        Some(t) if crate::forms::text_digest(t) == r.digest() => Ok(Some(t.to_owned())),
        _ => Err(super::text_unknown()),
    }
}

/// The view of `step` in `state`.
fn step_view<P: Seams>(
    call: &Call<'_, P>,
    state: &EngineState,
    step: OnboardingStep,
) -> Result<StepView, ApiError> {
    let ts = state.tenant.state().ok_or_else(unprovisioned)?;
    let values = match ts.saved_values(step) {
        None => None,
        Some(v) => {
            let contact = contact_text(call, v)?;
            Some(
                crate::tenant::values_json(v, contact.as_deref())
                    .ok_or(ApiError::refused(ErrorCode::Unavailable, "ledger"))?,
            )
        }
    };
    let accepted = if step == OnboardingStep::Agreements {
        state.tenant.agreements()
    } else {
        None
    };
    Ok(StepView::new(
        step,
        ts.status(step),
        ts.revision(),
        values,
        ts.saved_outcome(step),
        accepted,
    ))
}

/// A tenant read: `tenant.get_step`, `tenant.settings`,
/// `tenant.list_admins`, `tenant.list_signatories` or
/// `tenant.get_activation`. `authorize_read` admitted the caller as a tenant
/// admin through [`is_admin`]. The tenant part must exist, and its admin
/// set holds the caller (Q31 A). Refusals are audited.
pub(super) async fn read<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: ReadKind,
) -> Result<ReadModel, ApiError> {
    let (account, ts) = admin(call)?;
    let view = match kind {
        ReadKind::GetOnboarding => {
            let step = op
                .request
                .get("step")
                .and_then(fstp_json::Value::as_str)
                .and_then(OnboardingStep::from_name)
                .ok_or_else(|| call.refuse(ApiError::bad_request(crate::forms::REQUEST_RULE)))?;
            TenantView::Step(step_view(call, &call.state, step).map_err(|e| call.refuse(e))?)
        }
        ReadKind::GetTenantSettings => TenantView::Settings(
            SettingsView::of(ts.settings())
                .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "ledger")))?,
        ),
        ReadKind::ListTenantAdmins => {
            // Each row shows a vault answer about another person, so the
            // read shares the H-07 limit of the dry runs.
            vault_read_admitted(call, account)?;
            let mut rows = Vec::new();
            for a in ts.admins() {
                let verified = ask_vault(call, &Query::IsVerified { account: *a })
                    .await?
                    .holds;
                rows.push(AdminRow {
                    account: *a,
                    handle: DisplayHandle(label_of(call, *a).await?),
                    verified,
                });
            }
            TenantView::Admins(TenantAdmins::new(rows))
        }
        ReadKind::ListSignatories => {
            // NOTE 5: each row names its account, role and handle, and no
            // programme. No vault answer is shown, since a signatory needs
            // no verified identity (SoD-09 covers Drafting and Judging).
            let mut rows = Vec::new();
            for (role, a) in ts.signatories() {
                rows.push(SignatoryRow {
                    account: *a,
                    role: *role,
                    handle: DisplayHandle(label_of(call, *a).await?),
                });
            }
            TenantView::Signatories(SignatoryList::new(rows))
        }
        ReadKind::GetActivation => TenantView::Activation(ActivationView(ts.activation())),
        _ => {
            return Err(call.refuse(ApiError::NotImplemented(
                "this tenant read: no tenant read model of this kind",
            )));
        }
    };
    Ok(ReadModel::Tenant(view))
}

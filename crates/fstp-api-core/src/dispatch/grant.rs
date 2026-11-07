//! The M5 operations that are not core commands, and the M5 reads (M5
//! design section 5, lane L-API).
//!
//! - The contract commands of the `Contract` envelope: draft, clause
//!   changes, send, sign, the advanced route approval and the decline.
//!   The cell renders every revision (R-CT-01) and keeps the bytes
//!   write-once by SHA-256 (I-30). A signature comes from the
//!   `SignaturePort` this core was built with ([`super::State`]). A core
//!   built without one refuses every signature with a typed error, so
//!   nothing falls back to a platform-made signature (12.1, Q2).
//! - The funder reports of the `Report` envelope (R-RP-01, R-RP-03,
//!   R-RP-04, I-44).
//! - The vault tickets for bank details and hardship evidence. The API
//!   only opens the vault origin page; no value passes through it (I-86).
//!
//! Every operation here is web only: none has a tool, so MCP refuses it
//! as not exposed before this module runs (I-85).
//!
//! Interim readings of lane L-API, pending Daniel:
//!
//! - The contract parties are the lead, the guardian of a minor-flagged
//!   proposal (R-CT-02) and the first Contract signatory of the
//!   programme. Team members do not sign yet.
//! - The terms list the amount and the agreed plan, then each accepted
//!   clause change. `TODO(legal)`: the clause texts come from the signed
//!   grant agreement and legal review (`contracts.md`, I-49).
//! - In test and demo cells the server prepares the signature increment
//!   that the signer's LibPDF Worker prepares in production (M5 design
//!   section 3.1). Both have the one shape the increment verifier takes.
//! - Terms, clause texts and revisions live in this core's memory, as the
//!   M4 workspaces do, until the `doc.blob` adapter reaches the API core.

use std::collections::BTreeMap;
use std::sync::Arc;

use fstp_access::{GrantKind, ReadKind, ReadOp, ReadTarget};
use fstp_contract::{
    BlobKind, BlobStore, ContractCommand, ContractStatus, ContractTerms, Digest, MemBlobStore,
    Party, PartyRole, Route, Side, SignaturePort, SignerRef, TermsBlock, VersionState,
};
use fstp_domain::assignment::{AssignmentKind, AssignmentStatus};
use fstp_domain::id::{AccountId, CallId, ContractId, ProgrammeId, ProposalId, RequestId};
use fstp_domain::payment::{RequestStatus, RequestSummary};
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState};
use fstp_json::Value;
use fstp_ledger::Seq;

use super::{Call, Seams, dry_run, exec_failed, lock, step_up};
use crate::forms;
use crate::grant::{
    ContractView, GrantModel, GrantOverview, LineRow, PartyRow, QueueRow, ReportRow, RequestRow,
    VersionRow,
};
use crate::port::{
    AsyncEngine, ExecMeta, OpName, Outcome, Vault, VerificationPurpose, VerificationRedirect,
};
use crate::{ApiError, ErrorCode, Op, OpResult, ReadModel};

/// The signature services of a test or demo cell (M5 design 3.2).
pub(crate) struct Signing {
    /// The fake wallet and QTSP.
    pub(crate) port: Box<dyn SignaturePort + Send + Sync>,
    /// The fake trusted list.
    pub(crate) trust: Box<dyn fstp_sigval::TrustedList + Send + Sync>,
}

impl std::fmt::Debug for Signing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signing(..)")
    }
}

/// A proposed clause change, kept until it is decided.
#[derive(Clone, Debug)]
struct Change {
    text: String,
    proposer: Side,
}

/// The contract terms and revisions this core rendered.
#[derive(Debug, Default)]
pub(crate) struct GrantMemory {
    terms: BTreeMap<(ContractId, u32), ContractTerms>,
    changes: BTreeMap<(ContractId, u32, u32), Change>,
    blobs: MemBlobStore,
}

/// The size of the `/Contents` placeholder of a prepared increment.
const CONTENTS_CAPACITY: usize = 8192;

fn actor() -> ApiError {
    ApiError::refused(ErrorCode::Refused, "actor")
}

fn not_found() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

fn wrong_state() -> ApiError {
    ApiError::refused(ErrorCode::Refused, "row")
}

fn bad() -> ApiError {
    ApiError::bad_request(forms::REQUEST_RULE)
}

// ---------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------

/// The programme of proposal `p`.
pub(crate) fn programme_of(state: &EngineState, p: ProposalId) -> Option<ProgrammeId> {
    forms::call_of_proposal(state, p).and_then(|c| forms::programme_of_call(state, c))
}

/// Whether `account` holds `role` in `programme` at `now`.
fn holds(
    state: &EngineState,
    account: AccountId,
    role: Role,
    programme: Option<ProgrammeId>,
    now: Timestamp,
) -> bool {
    let Some(programme) = programme else {
        return false;
    };
    state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.role == role
            && b.programme == programme
            && b.scope == BindingScope::Programme
            && b.active_at(now)
    })
}

/// The holders of an active Receiving binding of `role` on `p`.
fn receiving(state: &EngineState, p: ProposalId, role: Role, now: Timestamp) -> Vec<AccountId> {
    state
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| b.role == role && b.proposal() == Some(p) && b.active_at(now))
        .map(|(_, b)| b.account)
        .collect()
}

/// The first active holder of `role` in `programme`.
fn first_holder(
    state: &EngineState,
    role: Role,
    programme: ProgrammeId,
    now: Timestamp,
) -> Option<AccountId> {
    state
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| {
            b.role == role
                && b.programme == programme
                && b.scope == BindingScope::Programme
                && b.active_at(now)
        })
        .map(|(_, b)| b.account)
        .min()
}

/// The latest contract of `p`.
fn contract_of(
    state: &EngineState,
    p: ProposalId,
) -> Option<(ContractId, &fstp_contract::Contract)> {
    state
        .contracts
        .of_proposal(p)
        .max_by_key(|(id, _)| **id)
        .map(|(id, c)| (*id, c))
}

fn request_status(s: RequestStatus) -> &'static str {
    match s {
        RequestStatus::Submitted => "SUBMITTED",
        RequestStatus::ChecksFailed => "CHECKS_FAILED",
        RequestStatus::UnderReview => "UNDER_REVIEW",
        RequestStatus::ChangesRequested => "CHANGES_REQUESTED",
        RequestStatus::Accepted => "ACCEPTED",
        RequestStatus::PaymentApproved => "PAYMENT_APPROVED",
        RequestStatus::Released => "RELEASED",
        RequestStatus::Paid => "PAID",
        RequestStatus::Rejected => "REJECTED",
        RequestStatus::Withdrawn => "WITHDRAWN",
        RequestStatus::Closed => "CLOSED",
    }
}

fn version_state(s: VersionState) -> &'static str {
    match s {
        VersionState::Drafted => "drafted",
        VersionState::Sent => "sent",
        VersionState::SignedByGrantee => "signed_by_grantee",
        VersionState::Effective => "effective",
        VersionState::Superseded => "superseded",
        VersionState::Terminated => "terminated",
    }
}

fn contract_status(s: ContractStatus) -> &'static str {
    match s {
        ContractStatus::Drafted => "drafted",
        ContractStatus::Sent => "sent",
        ContractStatus::SignedByGrantee => "signed_by_grantee",
        ContractStatus::Effective => "effective",
        ContractStatus::AmendmentPending => "amendment_pending",
        ContractStatus::Terminated => "terminated",
    }
}

fn party_role(r: PartyRole) -> &'static str {
    match r {
        PartyRole::Lead => "lead",
        PartyRole::TeamMember => "team_member",
        PartyRole::Guardian => "guardian",
        PartyRole::Signatory => "signatory",
    }
}

fn request_row(s: &RequestSummary) -> RequestRow {
    RequestRow {
        request: s.request,
        proposal: s.grant,
        status: request_status(s.status),
        kind: if s.hardship { "hardship" } else { "milestone" },
        submission_checks: s.submission_passed,
        acceptance_checks: s.acceptance_passed,
        lines: s
            .lines
            .iter()
            .map(|l| LineRow {
                line: l.line,
                milestone: l.milestone,
                requested: l.requested.amount().to_string(),
                approved: l.decision.map(|(_, a)| a.amount().to_string()),
            })
            .collect(),
    }
}

/// The paid total of `p`: the approved amounts of its released and paid
/// requests (I-64).
fn paid_total(state: &EngineState, p: ProposalId) -> String {
    let mut total: Option<fstp_money::Amount> = None;
    for s in state.core.payments().summaries().filter(|s| s.grant == p) {
        if !s.status.paid() {
            continue;
        }
        for (_, a) in s.lines.iter().filter_map(|l| l.decision) {
            total = match total {
                None => Some(a.amount()),
                Some(t) => t.checked_add(a.amount()).ok(),
            };
        }
    }
    total.map_or_else(|| "0.00".to_owned(), |t| t.to_string())
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// `grant.overview`, `contract.view`, `payment.status` and
/// `payment.queue`, after `authorize_read` cleared them.
pub(super) fn read<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: ReadKind,
) -> Result<GrantModel, ApiError> {
    let state = &call.state;
    let account = call.account().ok_or_else(actor)?;
    if kind == ReadKind::ListMyPaymentQueue {
        return Ok(GrantModel::Queue(queue(state, account, call.now)));
    }
    let p = forms::id_param(&op.request, "proposal")
        .map(ProposalId::from_raw)
        .ok_or_else(bad)?;
    Ok(match kind {
        ReadKind::GetGrant => {
            let money = state.core.money();
            GrantModel::Overview(GrantOverview {
                proposal: p,
                state: fstp_domain::view::proposal_state(&state.core, p)
                    .map_or("UNKNOWN", fstp_domain::StateTag::spec_name),
                determination: money.determination(p).map(|d| d.raw()),
                amount: money
                    .granted(p)
                    .or_else(|| money.reserved(p))
                    .map(|a| a.amount().to_string()),
                paid: paid_total(state, p),
                contract: contract_of(state, p).map(|(id, _)| id),
                requests: u32::try_from(
                    state
                        .core
                        .payments()
                        .summaries()
                        .filter(|s| s.grant == p)
                        .count(),
                )
                .unwrap_or(u32::MAX),
            })
        }
        ReadKind::GetContract => {
            let found = contract_of(state, p);
            GrantModel::Contract(ContractView {
                proposal: p,
                contract: found.map(|(id, _)| id),
                status: found.map(|(_, c)| contract_status(c.status())),
                versions: found
                    .map(|(_, c)| {
                        c.versions()
                            .iter()
                            .map(|v| VersionRow {
                                version: v.number,
                                state: version_state(v.state()),
                                parties: v
                                    .parties()
                                    .iter()
                                    .map(|x| PartyRow {
                                        field: x.field.clone(),
                                        role: party_role(x.role),
                                        signed: v.signed(&x.field),
                                        mine: x.account == account,
                                    })
                                    .collect(),
                                revisions: u32::try_from(v.revisions().len()).unwrap_or(u32::MAX),
                                digest: v.revisions().last().map(Digest::hex),
                                open_changes: v
                                    .changes()
                                    .iter()
                                    .filter(|(_, s)| **s == fstp_contract::ChangeStatus::Proposed)
                                    .map(|(c, _)| *c)
                                    .collect(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        }
        ReadKind::GetPaymentStatus => GrantModel::Payments(
            state
                .core
                .payments()
                .summaries()
                .filter(|s| s.grant == p)
                .map(|s| request_row(&s))
                .collect(),
        ),
        _ => return Err(bad()),
    })
}

/// The caller's own payment work: line review on grants with an active
/// reviewer assignment, approval and confirmation as finance approver,
/// and release as payment releaser, each in the grant's programme.
fn queue(state: &EngineState, account: AccountId, now: Timestamp) -> Vec<QueueRow> {
    let reviews: Vec<ProposalId> = state
        .core
        .review()
        .assignments()
        .map(|(_, a)| a)
        .filter(|a| {
            a.reviewer == account
                && a.kind == AssignmentKind::Reviewer
                && a.status == AssignmentStatus::Active
        })
        .map(|a| a.proposal)
        .collect();
    let mut out = Vec::new();
    for s in state.core.payments().summaries() {
        let programme = programme_of(state, s.grant);
        let task = match s.status {
            RequestStatus::UnderReview if reviews.contains(&s.grant) => Some("review"),
            RequestStatus::Accepted
                if holds(state, account, Role::FinanceApprover, programme, now) =>
            {
                Some("approve")
            }
            RequestStatus::PaymentApproved
                if holds(state, account, Role::PaymentReleaser, programme, now) =>
            {
                Some("release")
            }
            RequestStatus::Released
                if holds(state, account, Role::FinanceApprover, programme, now) =>
            {
                Some("confirm")
            }
            _ => None,
        };
        if let Some(task) = task {
            out.push(QueueRow {
                task,
                request: request_row(&s),
            });
        }
    }
    out
}

/// `report.list`: the programme manager and the auditor through
/// `authorize_read`, and a Financial signatory of the tenant fold, who
/// approves (R-RP-03, Q3).
pub(super) async fn list_reports<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
) -> Result<OpResult, ApiError> {
    let programme = forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or_else(|| call.refuse(bad()))?;
    let account = call.account();
    let signatory =
        account.is_some_and(|a| fstp_engine::report::financial_signatory(&call.state, a));
    if !signatory {
        let rop = ReadOp {
            kind: ReadKind::ListReports,
            target: ReadTarget::Programme(programme),
        };
        if let Err(d) = fstp_access::authorize_read(&rop, &call.caller.p, &call.state, call.now) {
            return Err(call.refuse(super::read_denied(d.rule())));
        }
    }
    let state = &call.state;
    let rows = state
        .reports
        .reports()
        .filter(|(_, r)| match r.scope {
            fstp_report::Scope::Programme(p) => p == programme,
            fstp_report::Scope::Call(c) => forms::programme_of_call(state, c) == Some(programme),
        })
        .map(|(id, r)| ReportRow {
            report: id.raw(),
            kind: r.kind.name(),
            call: match r.scope {
                fstp_report::Scope::Call(c) => Some(c),
                fstp_report::Scope::Programme(_) => None,
            },
            programme: match r.scope {
                fstp_report::Scope::Programme(p) => Some(p),
                fstp_report::Scope::Call(_) => None,
            },
            document: crate::action::hex(&r.document.bytes()),
            template: r.template.clone(),
            generated_by_me: account == Some(r.generator),
            approved: r.approver.is_some(),
        })
        .collect();
    call.accept(ReadModel::Grant(GrantModel::Reports(rows)))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Decides and appends one engine command of the caller, as the core
/// command path does: the dry run with its vault answers, then the
/// execution with this call's digest.
async fn execute<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    cmd: Command,
) -> Result<Seq, ApiError> {
    let command_id = fstp_domain::id::CommandId::from_bytes(call.draw()?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    dry_run(call, account, &cmd, ctx).await?;
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
    call.ports
        .engine()
        .execute(cmd, ctx, meta)
        .await
        .map_err(exec_failed)
}

fn done(seq: Seq, body: ReadModel) -> OpResult {
    OpResult::Done {
        body,
        seq: Some(seq),
    }
}

fn str_member<'a>(op: &'a Op, name: &str) -> Result<&'a str, ApiError> {
    op.request
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= forms::TEXT_LIMIT)
        .ok_or_else(bad)
}

fn contract_param(call_state: &EngineState, op: &Op) -> Result<(ContractId, ProposalId), ApiError> {
    let id = forms::id_param(&op.request, "contract")
        .map(ContractId::from_raw)
        .ok_or_else(bad)?;
    let c = call_state.contracts.contract(id).ok_or_else(not_found)?;
    Ok((id, c.proposal()))
}

/// One M5 operation that is not a core command.
pub(super) async fn command<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: GrantKind,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let result = match kind {
        GrantKind::ContractDraft => draft(call, op, account).await,
        GrantKind::ContractProposeChange => propose_change(call, op, account).await,
        GrantKind::ContractDecideChange => decide_change(call, op, account).await,
        GrantKind::ContractSend => send(call, op, account).await,
        GrantKind::ContractSign => sign(call, op, account).await,
        GrantKind::ContractApproveAdvanced => approve_advanced(call, op, account).await,
        GrantKind::ContractDecline => decline(call, op, account).await,
        GrantKind::ReportGenerate => generate(call, op, account).await,
        GrantKind::ReportApprove => approve_report(call, op, account).await,
        GrantKind::BankDetails
        | GrantKind::BankVerify
        | GrantKind::BankDispute
        | GrantKind::BankView
        | GrantKind::HardshipEvidence
        | GrantKind::HardshipVerify => return ticket(call, op, account, kind).await,
    };
    result.map_err(|e| call.refuse(e))
}

/// The terms of version `version` of a contract for proposal `p`.
fn base_terms(
    state: &EngineState,
    p: ProposalId,
    version: u32,
    parties: &[Party],
) -> ContractTerms {
    let money = state.core.money();
    let amount = money
        .determined(p)
        .map(|(_, a)| a.amount().to_string())
        .unwrap_or_default();
    let plan = money
        .determined(p)
        .map(|(plan, _)| plan.raw().to_string())
        .unwrap_or_default();
    ContractTerms {
        title: format!(
            "Sub-grant agreement for proposal {}, version {version}",
            p.raw()
        ),
        blocks: vec![
            TermsBlock::Heading(format!("Sub-grant agreement for proposal {}", p.raw())),
            TermsBlock::Clause(format!("Granted amount: EUR {amount}.")),
            TermsBlock::Clause(format!("Agreed plan version: {plan}.")),
            // TODO(legal): the clause texts come from the signed grant
            // agreement and legal review (`contracts.md`, I-49).
            TermsBlock::Clause("Clause texts pending legal review.".to_owned()),
        ],
        parties: parties
            .iter()
            .map(|x| {
                let label = match x.role {
                    PartyRole::Lead => "Lead applicant",
                    PartyRole::TeamMember => "Team member",
                    PartyRole::Guardian => "Guardian",
                    PartyRole::Signatory => "Contract signatory",
                };
                (x.field.clone(), label.to_owned())
            })
            .collect(),
    }
}

fn render_digest(terms: &ContractTerms) -> Result<(Vec<u8>, Digest), ApiError> {
    fstp_contract::render::render_with_digest(terms)
        .map_err(|_| ApiError::refused(ErrorCode::Refused, "R-CT-01"))
}

/// `contract.draft`: version 1, or the next version after a sent one.
async fn draft<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let state = &call.state;
    let p = forms::id_param(&op.request, "proposal")
        .map(ProposalId::from_raw)
        .ok_or_else(bad)?;
    let programme = programme_of(state, p);
    if !holds(state, account, Role::ProgrammeManager, programme, call.now) {
        return Err(actor());
    }
    let programme = programme.ok_or_else(not_found)?;
    let (plan, _) = state.core.money().determined(p).ok_or_else(wrong_state)?;
    let determination = state
        .core
        .money()
        .determination(p)
        .ok_or_else(wrong_state)?;
    let lead = receiving(state, p, Role::Applicant, call.now)
        .into_iter()
        .next()
        .ok_or_else(wrong_state)?;
    let signatory = first_holder(state, Role::ContractSignatory, programme, call.now)
        .ok_or_else(wrong_state)?;
    let mut parties = vec![Party::new("lead", PartyRole::Lead, lead)];
    // R-CT-02: the guardian of a minor-flagged proposal signs too.
    let minor = fstp_domain::view::proposal_minor_flagged(&state.core, p);
    if let Some(g) = receiving(state, p, Role::Guardian, call.now)
        .into_iter()
        .next()
        .filter(|_| minor)
    {
        parties.push(Party::new("guardian", PartyRole::Guardian, g));
    }
    parties.push(Party::new("signatory", PartyRole::Signatory, signatory));
    let (contract, version) = match contract_of(state, p) {
        Some((id, c)) if !c.terminated() => {
            (id, c.latest().map_or(1, |v| v.number.saturating_add(1)))
        }
        _ => (ContractId::from_raw(call.draw()?), 1),
    };
    let terms = base_terms(state, p, version, &parties);
    let (_, base) = render_digest(&terms)?;
    let cmd = ContractCommand::Draft {
        contract,
        proposal: p,
        version,
        template: 1,
        plan,
        determination,
        parties,
        base,
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    lock(&call.st.grant)
        .terms
        .insert((contract, version), terms);
    Ok(done(
        seq,
        ReadModel::Created(vec![("contract", contract.raw())]),
    ))
}

/// The side of the caller on contract `c` of proposal `p`: the lead for
/// the grantee, a programme manager for the operator.
fn side_of<P: Seams>(call: &Call<'_, P>, p: ProposalId, account: AccountId) -> Option<Side> {
    if receiving(&call.state, p, Role::Applicant, call.now).contains(&account) {
        return Some(Side::Grantee);
    }
    holds(
        &call.state,
        account,
        Role::ProgrammeManager,
        programme_of(&call.state, p),
        call.now,
    )
    .then_some(Side::Operator)
}

fn latest_version(state: &EngineState, contract: ContractId) -> Result<u32, ApiError> {
    state
        .contracts
        .contract(contract)
        .and_then(fstp_contract::Contract::latest)
        .map(|v| v.number)
        .ok_or_else(not_found)
}

/// `contract.propose_change` (R-CT-04).
async fn propose_change<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, p) = contract_param(&call.state, op)?;
    let proposer = side_of(call, p, account).ok_or_else(actor)?;
    let clause = op
        .request
        .get("clause")
        .and_then(Value::as_u64)
        .and_then(|c| u32::try_from(c).ok())
        .ok_or_else(bad)?;
    let text = str_member(op, "text")?.to_owned();
    let version = latest_version(&call.state, contract)?;
    let cmd = ContractCommand::ProposeChange {
        contract,
        version,
        clause,
        diff: Digest::of(text.as_bytes()),
        proposer,
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    lock(&call.st.grant)
        .changes
        .insert((contract, version, clause), Change { text, proposer });
    Ok(done(seq, ReadModel::Accepted))
}

/// `contract.decide_change` by the other side (R-CT-04).
async fn decide_change<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, p) = contract_param(&call.state, op)?;
    let side = side_of(call, p, account).ok_or_else(actor)?;
    let clause = forms::id_param(&op.request, "clause")
        .and_then(|c| u32::try_from(c).ok())
        .ok_or_else(bad)?;
    let accept = op
        .request
        .get("accept")
        .and_then(Value::as_bool)
        .ok_or_else(bad)?;
    let version = latest_version(&call.state, contract)?;
    let (change, terms) = {
        let mem = lock(&call.st.grant);
        (
            mem.changes.get(&(contract, version, clause)).cloned(),
            mem.terms.get(&(contract, version)).cloned(),
        )
    };
    let change = change.ok_or_else(not_found)?;
    if change.proposer == side {
        return Err(actor());
    }
    let new_terms = if accept {
        let mut t = terms.ok_or_else(|| ApiError::refused(ErrorCode::Unavailable, "R-CT-01"))?;
        t.blocks.push(TermsBlock::Clause(format!(
            "Agreed change to clause {clause}: {}",
            change.text
        )));
        Some(t)
    } else {
        None
    };
    let base = match &new_terms {
        Some(t) => Some(render_digest(t)?.1),
        None => None,
    };
    let cmd = ContractCommand::DecideChange {
        contract,
        version,
        clause,
        accept,
        base,
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    let mut mem = lock(&call.st.grant);
    mem.changes.remove(&(contract, version, clause));
    if let Some(t) = new_terms {
        mem.terms.insert((contract, version), t);
    }
    Ok(done(seq, ReadModel::Accepted))
}

/// `contract.send`: renders revision 0 and freezes the version.
async fn send<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, p) = contract_param(&call.state, op)?;
    if !holds(
        &call.state,
        account,
        Role::ProgrammeManager,
        programme_of(&call.state, p),
        call.now,
    ) {
        return Err(actor());
    }
    let version = latest_version(&call.state, contract)?;
    let terms = lock(&call.st.grant)
        .terms
        .get(&(contract, version))
        .cloned()
        .ok_or_else(|| ApiError::refused(ErrorCode::Unavailable, "R-CT-01"))?;
    let (bytes, revision0) = render_digest(&terms)?;
    lock(&call.st.grant)
        .blobs
        .put(BlobKind::ContractRevision, &bytes)
        .map_err(|_| ApiError::refused(ErrorCode::Refused, "I-30"))?;
    let cmd = ContractCommand::Send {
        contract,
        version,
        revision0,
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    Ok(done(seq, ReadModel::Accepted))
}

fn route_of(s: &str) -> Option<Route> {
    match s {
        "wallet_qes" => Some(Route::WalletQes),
        "qtsp_remote_qes" => Some(Route::QtspRemoteQes),
        "advanced" => Some(Route::Advanced),
        _ => None,
    }
}

/// `contract.sign`: the caller's own field of the latest version, through
/// the signature port (I-30, M5 design section 3.1 steps 4 to 8).
async fn sign<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, _) = contract_param(&call.state, op)?;
    let route = str_member(op, "route")
        .ok()
        .and_then(route_of)
        .ok_or_else(bad)?;
    let c = call
        .state
        .contracts
        .contract(contract)
        .ok_or_else(not_found)?;
    let v = c.latest().ok_or_else(not_found)?;
    let party = v
        .parties()
        .iter()
        .find(|x| x.account == account)
        .ok_or_else(actor)?
        .field
        .clone();
    let base_digest = *v.revisions().last().ok_or_else(wrong_state)?;
    let version = v.number;
    let Some(signing) = call.st.signing.clone() else {
        // 12.1 Q2: no production adapter yet, and nothing falls back.
        return Err(ApiError::refused(ErrorCode::Unavailable, "signature_port"));
    };
    let base = lock(&call.st.grant)
        .blobs
        .get(&base_digest)
        .map_err(|_| ApiError::refused(ErrorCode::Unavailable, "I-30"))?;
    let increment =
        fstp_pdf::prepare_increment(&base, &party, CONTENTS_CAPACITY).map_err(|_| wrong_state())?;
    let at = call.now.micros().div_euclid(1_000_000);
    let signer = SignerRef {
        subject: format!("account {}", account.raw()),
    };
    let signed = fstp_contract::sign_increment(
        &base,
        &increment,
        &party,
        route,
        &signer,
        at,
        signing.port.as_ref(),
        signing.trust.as_ref(),
    )
    .map_err(|_| ApiError::refused(ErrorCode::Refused, "I-30"))?;
    lock(&call.st.grant)
        .blobs
        .put(BlobKind::ContractRevision, &signed.revision)
        .map_err(|_| ApiError::refused(ErrorCode::Refused, "I-30"))?;
    let cmd = ContractCommand::ApplySignature {
        contract,
        version,
        party,
        route,
        base_revision: base_digest,
        revision: signed.revision_digest,
        signer_certificate: signed.signer_certificate,
        report: signed.report_digest,
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    Ok(done(seq, ReadModel::Accepted))
}

/// `contract.approve_advanced` (P-30 step 3): a programme manager, with
/// a reason.
async fn approve_advanced<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, p) = contract_param(&call.state, op)?;
    if !holds(
        &call.state,
        account,
        Role::ProgrammeManager,
        programme_of(&call.state, p),
        call.now,
    ) {
        return Err(actor());
    }
    let party = str_member(op, "party")?.to_owned();
    let reason = str_member(op, "reason")?;
    let version = latest_version(&call.state, contract)?;
    let cmd = ContractCommand::ApproveAdvanced {
        contract,
        version,
        party,
        reason: Digest::of(reason.as_bytes()),
    };
    let seq = execute(call, account, Command::Contract(cmd)).await?;
    Ok(done(seq, ReadModel::Accepted))
}

/// `contract.decline` (reading 5, R-NG-04): before any signature, the
/// lead withdraws, and the contract ends with its unsigned draft sealed
/// and kept. Interim: the two records are two entries, the contract's
/// first.
async fn decline<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let (contract, p) = contract_param(&call.state, op)?;
    if !receiving(&call.state, p, Role::Applicant, call.now).contains(&account) {
        return Err(actor());
    }
    let reason = str_member(op, "reason")?;
    let c = call
        .state
        .contracts
        .contract(contract)
        .ok_or_else(not_found)?;
    if c.versions().iter().any(|v| !v.signatures().is_empty()) {
        return Err(wrong_state());
    }
    let version = c.latest().map(|v| v.number).ok_or_else(not_found)?;
    let terms = lock(&call.st.grant)
        .terms
        .get(&(contract, version))
        .cloned()
        .ok_or_else(|| ApiError::refused(ErrorCode::Unavailable, "R-CT-01"))?;
    let (bytes, _) = render_digest(&terms)?;
    let sealed = lock(&call.st.grant)
        .blobs
        .put(BlobKind::SealedDraft, &bytes)
        .map_err(|_| ApiError::refused(ErrorCode::Refused, "I-30"))?;
    let cmd = ContractCommand::Terminate {
        contract,
        reason: Digest::of(reason.as_bytes()),
        sealed_draft: Some(sealed),
    };
    let _ = execute(call, account, Command::Contract(cmd)).await?;
    let seq = execute(
        call,
        account,
        Command::Core(fstp_domain::Command::Withdraw { proposal: p }),
    )
    .await?;
    Ok(done(seq, ReadModel::Accepted))
}

/// The core ledger of this cell as a report snapshot (R-RP-01).
fn snapshot<P: Seams>(call: &Call<'_, P>) -> Result<fstp_report::Snapshot, ApiError> {
    let entries = call
        .ports
        .engine()
        .ledger()
        .ok_or_else(|| ApiError::refused(ErrorCode::Unavailable, "R-RP-01"))?;
    let core = entries
        .into_iter()
        .filter_map(|e| match e.record {
            fstp_engine::Record::Core(r) => Some(fstp_report::Entry {
                seq: e.seq,
                at: Timestamp::from_micros(e.at),
                record: r,
            }),
            _ => None,
        })
        .collect();
    fstp_report::Snapshot::new(core).map_err(|_| ApiError::refused(ErrorCode::Refused, "R-RP-01"))
}

fn instant(op: &Op, name: &str) -> Result<Timestamp, ApiError> {
    op.request
        .get(name)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .map(Timestamp::from_micros)
        .ok_or_else(bad)
}

/// `report.generate` (R-RP-04, I-44): one output of the Horizon Europe
/// profile from a snapshot of the core ledger. A mismatch fails
/// generation with I-44. Interim: the open call package waits for the
/// stored Guide bytes to reach this core.
async fn generate<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let programme = forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or_else(bad)?;
    if !holds(
        &call.state,
        account,
        Role::ProgrammeManager,
        Some(programme),
        call.now,
    ) {
        return Err(actor());
    }
    let kind = str_member(op, "kind")
        .ok()
        .and_then(fstp_report::ReportKind::from_name)
        .ok_or_else(bad)?;
    let call_id = || {
        forms::id_param(&op.request, "call")
            .map(CallId::from_raw)
            .filter(|c| forms::programme_of_call(&call.state, *c) == Some(programme))
            .ok_or_else(not_found)
    };
    let snap = snapshot(call)?;
    let identifier;
    let periods;
    let request = match kind {
        fstp_report::ReportKind::CallPublicationRecord => {
            let c = call_id()?;
            identifier = format!("FSTP-CALL-{}", c.raw());
            fstp_report::Request::CallPublicationRecord {
                call: c,
                identifier: &identifier,
            }
        }
        fstp_report::ReportKind::AuditFile => fstp_report::Request::AuditFile { call: call_id()? },
        fstp_report::ReportKind::DeliverableDraft => {
            fstp_report::Request::DeliverableDraft { call: call_id()? }
        }
        fstp_report::ReportKind::PeriodicReportingData => {
            periods = [fstp_report::Period {
                start: instant(op, "start")?,
                end: instant(op, "end")?,
            }];
            fstp_report::Request::PeriodicReportingData {
                programme,
                periods: &periods,
            }
        }
        fstp_report::ReportKind::OpenCallPackage => {
            return Err(ApiError::NotImplemented(
                "the open call package: the stored Guide bytes and package parts reach this core in a later lane",
            ));
        }
    };
    let output = fstp_report::generate(&snap, &request).map_err(|e| match e {
        fstp_report::ReportError::Reconciliation(_) => {
            ApiError::refused(ErrorCode::Refused, "I-44")
        }
        fstp_report::ReportError::UnknownCall => not_found(),
        _ => ApiError::refused(ErrorCode::Refused, "R-RP-04"),
    })?;
    lock(&call.st.grant)
        .blobs
        .put(BlobKind::Report, &output.bytes)
        .map_err(|_| ApiError::refused(ErrorCode::Refused, "I-30"))?;
    let report = fstp_report::ReportId::from_raw(call.draw()?);
    let record = fstp_report::generated(report, &output, account);
    let seq = execute(call, account, Command::Report(record)).await?;
    Ok(done(
        seq,
        ReadModel::Created(vec![("report", report.raw())]),
    ))
}

/// `report.approve`: a Financial signatory who did not generate the
/// document (R-RP-03, Q3). The engine decides it.
async fn approve_report<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let report = forms::id_param(&op.request, "report")
        .map(fstp_report::ReportId::from_raw)
        .ok_or_else(bad)?;
    let cmd = Command::Report(fstp_report::ReportRecord::Approved {
        report,
        approver: account,
    });
    let seq = execute(call, account, cmd).await?;
    Ok(done(seq, ReadModel::Accepted))
}

/// The vault ticket operations: the caller's relation to the grant, a
/// step-up for the high-risk ones (I-78), then the vault origin page.
async fn ticket<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
    kind: GrantKind,
) -> Result<OpResult, ApiError> {
    let state = &call.state;
    // The state guards run after the step-up, as the domain guards of a
    // high-risk command do (I-78).
    let in_state;
    let purpose = if kind == GrantKind::BankView {
        let r = forms::id_param(&op.request, "request")
            .map(RequestId::from_raw)
            .ok_or_else(|| call.refuse(bad()))?;
        let grant = state.core.payments().grant_of(r);
        let programme = grant.and_then(|g| programme_of(state, g));
        if !holds(state, account, Role::PaymentReleaser, programme, call.now) {
            return Err(call.refuse(actor()));
        }
        // Reading 6: the releaser of this one released request.
        in_state = state.core.payments().releaser(r) == Some(account);
        VerificationPurpose::BankView(r)
    } else {
        let p = forms::id_param(&op.request, "proposal")
            .map(ProposalId::from_raw)
            .ok_or_else(|| call.refuse(bad()))?;
        let lead = receiving(state, p, Role::Applicant, call.now).contains(&account);
        let finance = holds(
            state,
            account,
            Role::FinanceApprover,
            programme_of(state, p),
            call.now,
        );
        let admitted = match kind {
            GrantKind::BankVerify | GrantKind::HardshipVerify => finance,
            _ => lead,
        };
        if !admitted {
            return Err(call.refuse(actor()));
        }
        let granted = matches!(
            fstp_domain::view::proposal_state(&state.core, p),
            Some(fstp_domain::StateTag::Granted | fstp_domain::StateTag::InExecution)
        );
        in_state = granted;
        match kind {
            GrantKind::BankDetails => VerificationPurpose::BankDetails(p),
            GrantKind::BankVerify => VerificationPurpose::BankVerification(p),
            GrantKind::BankDispute => VerificationPurpose::BankDispute(p),
            GrantKind::HardshipEvidence => VerificationPurpose::HardshipEvidence(p),
            _ => VerificationPurpose::HardshipVerification(p),
        }
    };
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
    if !in_state {
        return Err(call.refuse(wrong_state()));
    }
    match call
        .ports
        .vault()
        .begin_verification(purpose, account)
        .await
    {
        Ok(VerificationRedirect(to)) => {
            call.accepted(proof)?;
            Ok(OpResult::Done {
                body: ReadModel::Redirect(to),
                seq: None,
            })
        }
        Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
    }
}

/// The signature services as `super::State` holds them.
pub(crate) type SharedSigning = Option<Arc<Signing>>;

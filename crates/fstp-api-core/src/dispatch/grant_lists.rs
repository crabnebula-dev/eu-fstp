//! The M5 reads follow-up (`docs/handoff/m5-ui.md`): the caller's grants
//! (`grant.list_mine`), the contract versions awaiting the caller's
//! signature (`contract.awaiting_me`), and the milestone rows of
//! `grant.overview`.
//!
//! Both lists are the caller's own reads (`ReadRule::Own`). Each row is
//! judged again with `authorize_read`, as `grant.overview` or
//! `contract.view` of that proposal would be. So a list holds exactly the
//! grants and contracts those reads serve the caller: the same rule, the
//! same states, the same programme scope and the same separation of
//! duties (R-AC-01, D11). Neither list widens a read.
//!
//! The signing list follows the order `fstp-contract-core` enforces
//! (P-30): a version waits on a grantee party once sent, and on the
//! signatory only once the grantee side signed. A signed party, a
//! terminated contract and a version no longer the latest wait on nobody.

use std::collections::BTreeMap;

use fstp_access::{ReadKind, ReadOp, ReadRule, ReadTarget, authorize_read};
use fstp_contract::{Digest, PartyRole, VersionState};
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::payment::MilestoneFunds;
use fstp_domain::roles::{BindingScope, Role};

use super::Call;
use super::Seams;
use super::grant::{contract_of, paid_total, party_role, version_state};
use crate::grant::GrantModel;
use crate::grant_lists::{GrantRow, MilestoneRow, SignRow};
use crate::{ApiError, ErrorCode};

/// The milestone row of `m`, every sum formatted by the cell (ADR-006).
pub(super) fn milestone_row(m: &MilestoneFunds) -> MilestoneRow {
    MilestoneRow {
        milestone: m.milestone,
        amount: m.amount.amount().to_string(),
        due: super::utc_day(m.due),
        paid: m.paid.amount().to_string(),
        pending: m.pending.amount().to_string(),
        available: m.available.amount().to_string(),
        closed: m.closed,
    }
}

/// The wire name of the `grant.overview` rule that admitted the caller.
/// `None` for a rule outside the grant readers, which never clears that
/// read, so the row is left out (fail closed).
fn via(rule: ReadRule) -> Option<&'static str> {
    Some(match rule {
        ReadRule::Team => "team",
        ReadRule::FormerTeam => "former_team",
        ReadRule::Holder(Role::ProgrammeManager) => "programme_manager",
        ReadRule::Holder(Role::FinanceApprover) => "finance_approver",
        ReadRule::Holder(Role::PaymentReleaser) => "payment_releaser",
        ReadRule::Holder(Role::ContractSignatory) => "contract_signatory",
        ReadRule::Auditor => "auditor",
        _ => return None,
    })
}

/// `grant.list_mine` and `contract.awaiting_me`, after `authorize_read`
/// cleared the list itself.
pub(super) fn read<P: Seams>(call: &Call<'_, P>, kind: ReadKind) -> Result<GrantModel, ApiError> {
    let account = call
        .account()
        .ok_or_else(|| ApiError::refused(ErrorCode::Refused, "actor"))?;
    Ok(match kind {
        ReadKind::ListMyGrants => GrantModel::Grants(grants(call)),
        ReadKind::ListMyContractsToSign => GrantModel::ToSign(to_sign(call, account)),
        _ => return Err(ApiError::bad_request(crate::forms::REQUEST_RULE)),
    })
}

/// The rule that clears `kind` of proposal `p` for the caller, if any.
fn cleared<P: Seams>(call: &Call<'_, P>, kind: ReadKind, p: ProposalId) -> Option<ReadRule> {
    let op = ReadOp {
        kind,
        target: ReadTarget::Proposal(p),
    };
    authorize_read(&op, &call.caller.p, &call.state, call.now)
        .ok()
        .map(|c| c.rule())
}

/// Every grant `grant.overview` serves the caller, oldest proposal first.
fn grants<P: Seams>(call: &Call<'_, P>) -> Vec<GrantRow> {
    let state = &call.state;
    // Every proposal holds a Receiving binding of its lead from its
    // draft on. A terminal state ends it, so the ended bindings count
    // too: together they name every proposal of the cell.
    let roster = state.core.roster();
    let mut home: BTreeMap<ProposalId, CallId> = BTreeMap::new();
    for b in roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
    {
        if let BindingScope::Proposal { proposal, call } = b.scope {
            home.insert(proposal, call);
        }
    }
    let money = state.core.money();
    home.into_iter()
        .filter_map(|(p, call_id)| {
            let via = via(cleared(call, ReadKind::GetGrant, p)?)?;
            Some(GrantRow {
                proposal: p,
                call: Some(call_id),
                state: fstp_domain::view::proposal_state(&state.core, p)
                    .map_or("UNKNOWN", fstp_domain::StateTag::spec_name),
                amount: money
                    .granted(p)
                    .or_else(|| money.reserved(p))
                    .map(|a| a.amount().to_string()),
                paid: paid_total(state, p),
                contract: contract_of(state, p).map(|(id, _)| id),
                via,
            })
        })
        .collect()
}

/// The latest version of each live contract that waits on `account`'s
/// signature now, where `contract.view` serves the caller.
fn to_sign<P: Seams>(call: &Call<'_, P>, account: AccountId) -> Vec<SignRow> {
    let mut out = Vec::new();
    for (id, c) in call.state.contracts.contracts() {
        if c.terminated() {
            continue;
        }
        let Some(v) = c.latest() else { continue };
        let state = v.state();
        if !matches!(state, VersionState::Sent | VersionState::SignedByGrantee) {
            continue;
        }
        for party in v.parties().iter().filter(|x| x.account == account) {
            if v.signed(&party.field) {
                continue;
            }
            // P-30: the signatory countersigns last.
            if party.role == PartyRole::Signatory && !v.signed_by_grantee() {
                continue;
            }
            if cleared(call, ReadKind::GetContract, c.proposal()).is_none() {
                continue;
            }
            out.push(SignRow {
                proposal: c.proposal(),
                contract: *id,
                version: v.number,
                field: party.field.clone(),
                role: party_role(party.role),
                state: version_state(state),
                digest: v.revisions().last().map(Digest::hex),
            });
        }
    }
    out
}

/// `grant.determination_view` of `p`, after `authorize_read` cleared it
/// for the assigned reviewer in NEGOTIATION (R-NG-03).
pub(super) fn determination<P: Seams>(call: &Call<'_, P>, p: ProposalId) -> GrantModel {
    let core = &call.state.core;
    let basis = fstp_domain::view::determination_plan(core, p);
    GrantModel::Determination(crate::grant_lists::DeterminationView {
        proposal: p,
        state: fstp_domain::view::proposal_state(core, p)
            .map_or("UNKNOWN", fstp_domain::StateTag::spec_name),
        determination: core.money().determination(p).map(|d| d.raw()),
        plan: basis.map(|(plan, _)| plan),
        plan_total: basis.and_then(|(_, t)| t).map(|t| t.amount().to_string()),
        granted: core
            .money()
            .determined(p)
            .map(|(_, g)| g.amount().to_string()),
    })
}

/// `payment.line_review_view` of request `{request}` of grant `p`, after
/// `authorize_read` cleared the caller as the declared, conflict-free
/// assigned reviewer of `p` while it is IN_EXECUTION (R-PR-08, lane
/// m5/polish-access). It serves only a request of `p` in UNDER_REVIEW,
/// the one status in which a line can be decided. Any other request,
/// whether it exists or not, is refused as the rule refuses (R-AC-01), so
/// the view reveals no other request.
pub(super) fn line_review<P: Seams>(
    call: &Call<'_, P>,
    op: &crate::Op,
    p: ProposalId,
) -> Result<GrantModel, ApiError> {
    use fstp_domain::payment::RequestStatus;
    let refused = || super::read_denied(fstp_access::DenyRule::Rac01);
    let r = crate::forms::id_param(&op.request, "request")
        .map(fstp_domain::id::RequestId::from_raw)
        .ok_or_else(|| ApiError::bad_request(crate::forms::REQUEST_RULE))?;
    let summary = call
        .state
        .core
        .payments()
        .summaries()
        .find(|s| s.request == r && s.grant == p && s.status == RequestStatus::UnderReview)
        .ok_or_else(refused)?;
    let content = super::lock(&call.st.content);
    let text =
        |t: Option<fstp_domain::id::TextRef>| t.and_then(|t| content.text(t).map(str::to_owned));
    let journal = super::lock(&call.st.journal);
    let given = journal.line_evidence(r).unwrap_or(&[]);
    let texts = summary
        .lines
        .iter()
        .map(|l| {
            given
                .iter()
                .find(|(id, _)| *id == l.line)
                .map(|(_, e)| crate::grant_lists::LineTexts {
                    location: text(e.location),
                    release: text(e.release),
                    licence: e.licence.as_ref().map(|s| s.0.clone()),
                    report: text(e.report),
                })
                .unwrap_or_default()
        })
        .collect();
    Ok(GrantModel::LineReview(Box::new(
        crate::grant_lists::LineReviewView {
            request: super::grant::request_row(&summary),
            texts,
        },
    )))
}

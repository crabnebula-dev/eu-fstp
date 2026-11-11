//! The pre-check of a draft (M7 design section 4; R-LA-06, R-LA-08,
//! I-21, TH-02, TH-29), and the coordinator's findings status (design
//! section 7). Lane L-DEMO built this slice of lane L-PRE.
//!
//! - `proposal.precheck` runs one check on the team's workspace as it
//!   stands. Only a member of the drafting team asks, and only on a draft
//!   of a published call, whose pinned configuration the run uses (I-11).
//!   The request counts against P-23 when it is made, before the port
//!   answers, so a failed run still counts.
//! - `proposal.precheck_runs` shows the runs and the remaining checks.
//!   The registry admits the team on a draft only, so no Operator or
//!   Judging role reads a run in any state (I-21).
//! - Neither reply carries a score, a band or a confidence (TH-02).
//! - `assess.findings_status` gives the coordinator, per submitted
//!   proposal of a call, "pending" or a count. Never a statement.
//!
//! Interim readings, pending Daniel:
//!
//! - "Per day" is a rolling 24 hours from each request, so the next
//!   available instant is exact without a zone.
//! - With `account_cap_across_drafts_in_call`, both P-23 limits also
//!   apply to the account's requests across every draft of the call.
//! - The request log lives in the content store, in memory of the cell
//!   process, as the workspace does until lane W6 seals both.
//! - A proposal with no recorded finding reads "pending". A trace record
//!   of a finished assessment (lane L-CELL) will tell "assessed, none"
//!   apart from "pending".

use fstp_domain::StateTag;
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::rules::ParamId;
use fstp_domain::time::Timestamp;
use fstp_findings::{FindingKind, Severity};
use fstp_json::Value;

use super::{Call, Seams, call_of, content_unknown, lock, proposal_param};
use crate::content::PrecheckRequest;
use crate::port::{
    CellPorts, InferenceProvider, Precheck, PrecheckPin, PrecheckRefusal, PrecheckRun,
    PrecheckRunState, PrecheckSection, PrecheckSnapshot, TenantConfig,
};
use crate::views::{
    FindingsStatusRow, PrecheckEvidenceRow, PrecheckFindingRow, PrecheckRunRow, PrecheckView,
};
use crate::{ApiError, ErrorCode, Op, OpResult, ReadModel};

/// One day, in microseconds.
pub(crate) const DAY_MICROS: i64 = 86_400_000_000;

/// The P-23 limits of a call (`fstp-programme` `Precheck`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Checks per rolling day per proposal.
    pub(crate) per_day: u32,
    /// Checks per call per proposal.
    pub(crate) per_call: u32,
    /// Whether the limits apply per account across drafts in the call.
    pub(crate) account_cap: bool,
}

/// The P-23 limits of a frozen policy, or `None` when the pre-check is
/// disabled or the value does not read. Fails closed.
pub(crate) fn limits(frozen: &fstp_domain::policy::FrozenValues) -> Option<Limits> {
    let v = fstp_json::parse(frozen.opaque.get(&ParamId::P23)?.as_str().as_bytes()).ok()?;
    if v.get("enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let n = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    Some(Limits {
        per_day: n("per_day_per_proposal")?,
        per_call: n("per_call_per_proposal")?,
        account_cap: v
            .get("account_cap_across_drafts_in_call")
            .and_then(Value::as_bool)?,
    })
}

/// The remaining checks of `account` on `proposal` of `call` at `now`,
/// from every counted request (P-23, TH-29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Remaining {
    /// Runs left in the rolling day.
    pub(crate) today: u32,
    /// Runs left in the call on this proposal.
    pub(crate) proposal_call: u32,
    /// Runs left for the account across its drafts in the call.
    pub(crate) account_call: u32,
    /// When the next run becomes available, if none is left now and one
    /// will be.
    pub(crate) next: Option<Timestamp>,
}

impl Remaining {
    /// Whether a run may be requested now.
    pub(crate) fn allows(&self) -> bool {
        self.today > 0 && self.proposal_call > 0 && self.account_call > 0
    }
}

/// The remaining checks (pure, TH-29).
pub(crate) fn remaining(
    l: Limits,
    requests: &[PrecheckRequest],
    call: CallId,
    proposal: ProposalId,
    account: AccountId,
    now: Timestamp,
) -> Remaining {
    let since = now.micros().saturating_sub(DAY_MICROS);
    let on_proposal: Vec<i64> = requests
        .iter()
        .filter(|r| r.proposal == proposal)
        .map(|r| r.at.micros())
        .collect();
    let by_account: Vec<i64> = requests
        .iter()
        .filter(|r| l.account_cap && r.call == call && r.account == account)
        .map(|r| r.at.micros())
        .collect();
    let in_day = |xs: &[i64]| -> Vec<i64> {
        let mut d: Vec<i64> = xs.iter().copied().filter(|t| *t > since).collect();
        d.sort_unstable();
        d
    };
    let left = |limit: u32, n: usize| limit.saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
    let day_proposal = in_day(&on_proposal);
    let day_account = in_day(&by_account);
    let today = left(l.per_day, day_proposal.len().max(day_account.len()));
    let proposal_call = left(l.per_call, on_proposal.len());
    let account_call = if l.account_cap {
        left(l.per_call, by_account.len())
    } else {
        proposal_call
    };
    // When the rolling day frees a run: the request whose expiry brings
    // the count below the limit. Only the daily limit frees up; a call
    // limit reached is final.
    let frees = |d: &[i64]| -> Option<i64> {
        let limit = usize::try_from(l.per_day).unwrap_or(usize::MAX);
        if d.len() < limit {
            return None;
        }
        d.get(d.len().saturating_sub(limit)).copied()
    };
    let next = if today == 0 && proposal_call > 0 && account_call > 0 {
        frees(&day_proposal)
            .into_iter()
            .chain(frees(&day_account))
            .max()
            .map(|t| Timestamp::from_micros(t.saturating_add(DAY_MICROS)))
    } else {
        None
    };
    Remaining {
        today,
        proposal_call,
        account_call,
        next,
    }
}

/// `synthetic` when the tenant's endpoint is the demo cell's synthetic
/// model, else `model` (M7 design section 7, R-LA-08).
pub(crate) fn assessor_name<P: Seams>(call: &Call<'_, P>) -> &'static str {
    let s = CellPorts::tenant(call.ports).settings();
    match s.inference.as_ref().and_then(|i| i.endpoint.as_ref()) {
        Some(e) if e.provider == InferenceProvider::Synthetic => "synthetic",
        _ => "model",
    }
}

/// The draft's call, its pin and its limits. Refuses a draft whose call
/// is unpublished or whose P-23 is off.
fn pin_of<P: Seams>(call: &Call<'_, P>, p: ProposalId) -> Result<(PrecheckPin, Limits), ApiError> {
    let c = call_of(&call.state, p)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let view = call.state.core.calls().get(c);
    let (Some(frozen), Some(config)) = (
        view.and_then(|v| v.frozen()),
        view.and_then(|v| v.llm_config()),
    ) else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")));
    };
    let values = frozen.values();
    let l =
        limits(values).ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Refused, "P-23")))?;
    let settings = CellPorts::tenant(call.ports).settings();
    Ok((
        PrecheckPin {
            call: c,
            config,
            model: values.p21.primary.clone(),
            criteria: values.p01.items().iter().map(|x| x.id).collect(),
            endpoint: settings.inference.as_ref().and_then(|i| i.endpoint.clone()),
        },
        l,
    ))
}

fn kind_name(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Completeness => "completeness",
        FindingKind::Quality => "quality",
        FindingKind::Accuracy => "accuracy",
        FindingKind::Integrity => "integrity",
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Minor => "minor",
        Severity::Major => "major",
    }
}

fn run_row(r: &PrecheckRun) -> PrecheckRunRow {
    PrecheckRunRow {
        run: r.run.raw(),
        requested: r.requested.micros(),
        state: match r.state {
            PrecheckRunState::Pending => "pending",
            PrecheckRunState::Done => "done",
            PrecheckRunState::Unavailable => "unavailable",
        },
        findings: r
            .findings
            .iter()
            .map(|f| PrecheckFindingRow {
                kind: kind_name(f.kind),
                criterion: f.criterion.map(|c| c.raw()),
                severity: severity_name(f.severity),
                statement: f.statement.as_data().to_owned(),
                evidence: f
                    .evidence
                    .iter()
                    .map(|e| PrecheckEvidenceRow {
                        section: match e.section {
                            PrecheckSection::Title => "title",
                            PrecheckSection::Summary => "summary",
                            PrecheckSection::Narrative => "narrative",
                        },
                        quote: e.quote.as_data().to_owned(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// The reply of both pre-check ops.
async fn view<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    account: AccountId,
) -> Result<PrecheckView, ApiError> {
    let (pin, l) = pin_of(call, p)?;
    let left = remaining(
        l,
        lock(&call.st.content).prechecks(),
        pin.call,
        p,
        account,
        call.now,
    );
    let runs = match call.ports.precheck() {
        Some(port) => port
            .runs(p)
            .await
            .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "R-LA-06")))?,
        None => Vec::new(),
    };
    Ok(PrecheckView {
        assessor: assessor_name(call),
        proposal_today: left.today,
        proposal_call: left.proposal_call,
        account_call: left.account_call,
        next: left.next.map(Timestamp::micros),
        runs: runs.iter().map(run_row).collect(),
    })
}

/// `proposal.precheck_runs`. `authorize_read` has admitted the team on a
/// draft only (I-21).
pub(crate) async fn runs<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: Option<AccountId>,
) -> Result<ReadModel, ApiError> {
    let Some(a) = account else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let p = proposal_param(call, op)?;
    Ok(ReadModel::Precheck(view(call, p, a).await?))
}

/// Whether `account` is on the team of draft `p` at `now`: its lead, a
/// team member or its guardian (the registry's team, I-21).
fn drafting_team_or_guardian(
    state: &fstp_engine::EngineState,
    account: AccountId,
    p: ProposalId,
    now: Timestamp,
) -> bool {
    use fstp_domain::roles::{BindingScope, Role};
    let member = state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.active_at(now)
            && matches!(
                b.role,
                Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
            )
            && matches!(b.scope, BindingScope::Proposal { proposal: x, .. } if x == p)
    });
    member && fstp_domain::view::proposal_state(&state.core, p) == Some(StateTag::Draft)
}

/// `proposal.precheck`: one run, counted at once (P-23, TH-29).
pub(crate) async fn request<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    account: AccountId,
) -> Result<OpResult, ApiError> {
    let p = proposal_param(call, op)?;
    if !drafting_team_or_guardian(&call.state, account, p, call.now) {
        // Anyone outside the drafting team is the wrong actor (I-21).
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "actor")));
    }
    let Some(port) = call.ports.precheck() else {
        // Q38: a cell without a provider has no pre-check.
        return Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "R-LA-06")));
    };
    let (pin, l) = pin_of(call, p)?;
    let w = lock(&call.st.content)
        .workspace(p)
        .ok_or_else(|| call.refuse(content_unknown()))?;
    {
        let mut content = lock(&call.st.content);
        let left = remaining(l, content.prechecks(), pin.call, p, account, call.now);
        if !left.allows() {
            drop(content);
            return Err(call.refuse(ApiError::refused(ErrorCode::RateLimited, "P-23")));
        }
        let counted = content.count_precheck(PrecheckRequest {
            call: pin.call,
            proposal: p,
            account,
            at: call.now,
        });
        if !counted {
            drop(content);
            return Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "P-23")));
        }
    }
    let snapshot = PrecheckSnapshot {
        pin,
        title: fstp_findings::UntrustedText::new(w.title),
        summary: fstp_findings::UntrustedText::new(w.summary),
        narrative: fstp_findings::UntrustedText::new(w.narrative),
    };
    match port.request(p, account, snapshot).await {
        Ok(_) | Err(PrecheckRefusal::Port(_)) => {}
        Err(PrecheckRefusal::QuotaExhausted(_)) => {
            return Err(call.refuse(ApiError::refused(ErrorCode::RateLimited, "P-23")));
        }
        Err(PrecheckRefusal::CallNotPublished) => {
            return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-11")));
        }
    }
    let v = view(call, p, account).await?;
    call.accept(ReadModel::Precheck(v))
}

/// The proposal states whose findings the coordinator's status lists:
/// every state after submission.
const SUBMITTED_ON: [StateTag; 14] = [
    StateTag::Submitted,
    StateTag::Ineligible,
    StateTag::Stage1,
    StateTag::NotSelected,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Declined,
    StateTag::Negotiation,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// `assess.findings_status`: per submitted proposal of the call, pending
/// or ready with a count (M7 design section 7). Never a statement.
pub(crate) fn findings_status<P: Seams>(call: &Call<'_, P>, c: CallId) -> Vec<FindingsStatusRow> {
    let findings = call.state.findings.findings_of(c);
    let mut proposals: Vec<ProposalId> = call
        .state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| *b)
        .chain(call.state.core.roster().ended().map(|(_, e)| e.binding))
        .filter_map(|b| match b.scope {
            fstp_domain::roles::BindingScope::Proposal { proposal, call: x } if x == c => {
                Some(proposal)
            }
            _ => None,
        })
        .collect();
    proposals.sort_unstable();
    proposals.dedup();
    proposals
        .into_iter()
        .filter(|p| {
            fstp_domain::view::proposal_state(&call.state.core, *p)
                .is_some_and(|s| SUBMITTED_ON.contains(&s))
        })
        .map(|p| {
            let n = findings.iter().filter(|f| f.proposal == p).count();
            FindingsStatusRow {
                proposal: p.raw(),
                status: if n == 0 { "pending" } else { "ready" },
                findings: u64::try_from(n).unwrap_or(u64::MAX),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: CallId = CallId::from_raw(1);
    const C2: CallId = CallId::from_raw(2);
    const P1: ProposalId = ProposalId::from_raw(11);
    const P2: ProposalId = ProposalId::from_raw(12);
    const A: AccountId = AccountId::from_raw(301);
    const B: AccountId = AccountId::from_raw(302);

    fn at(day: i64, hour: i64) -> Timestamp {
        Timestamp::from_micros(
            1_790_000_000_000_000_i64
                .saturating_add(day.saturating_mul(DAY_MICROS))
                .saturating_add(hour.saturating_mul(3_600_000_000)),
        )
    }

    fn req(
        call: CallId,
        proposal: ProposalId,
        account: AccountId,
        t: Timestamp,
    ) -> PrecheckRequest {
        PrecheckRequest {
            call,
            proposal,
            account,
            at: t,
        }
    }

    const SUPERSAFE: Limits = Limits {
        per_day: 1,
        per_call: 5,
        account_cap: true,
    };

    /// P-23: one run a rolling day per proposal; the next is exactly one
    /// day after the last.
    #[test]
    fn p23_daily_limit_and_next_instant() {
        let log = [req(C, P1, A, at(0, 9))];
        let r = remaining(SUPERSAFE, &log, C, P1, A, at(0, 10));
        assert_eq!(r.today, 0);
        assert!(!r.allows());
        assert_eq!(r.next, Some(at(1, 9)));
        assert_eq!(r.proposal_call, 4);
        let r = remaining(SUPERSAFE, &log, C, P1, A, at(1, 9));
        assert!(r.allows(), "a rolling day later the check is back");
    }

    /// P-23: the per-call limit per proposal is final; no next instant.
    #[test]
    fn p23_call_limit_is_final() {
        let log: Vec<PrecheckRequest> = (0..5).map(|d| req(C, P1, A, at(d, 9))).collect();
        let r = remaining(SUPERSAFE, &log, C, P1, A, at(9, 9));
        assert_eq!(r.proposal_call, 0);
        assert!(!r.allows());
        assert_eq!(r.next, None);
    }

    /// TH-29: one account's runs count across all its drafts in the same
    /// call, so a second draft opens no new allowance. Another account
    /// and another call are not counted.
    #[test]
    fn th29_account_cap_across_drafts() {
        let mut log: Vec<PrecheckRequest> = (0..3).map(|d| req(C, P1, A, at(d, 9))).collect();
        log.extend((3..5).map(|d| req(C, P2, A, at(d, 9))));
        let r = remaining(SUPERSAFE, &log, C, P2, A, at(9, 9));
        assert_eq!(r.proposal_call, 3, "P2 itself ran twice");
        assert_eq!(r.account_call, 0, "TH-29: A used all five in the call");
        assert!(!r.allows());
        assert_eq!(r.next, None);
        // The same day on another draft is refused too.
        let log = [req(C, P1, A, at(0, 9))];
        assert!(!remaining(SUPERSAFE, &log, C, P2, A, at(0, 10)).allows());
        // Another account on P2, and A in another call, are unaffected.
        assert!(remaining(SUPERSAFE, &log, C, P2, B, at(0, 10)).allows());
        let log = [req(C2, P1, A, at(0, 9))];
        assert!(remaining(SUPERSAFE, &log, C, P2, A, at(0, 10)).allows());
        // Without the cap, only the proposal limits apply.
        let free = Limits {
            account_cap: false,
            ..SUPERSAFE
        };
        let log = [req(C, P1, A, at(0, 9))];
        assert!(remaining(free, &log, C, P2, A, at(0, 10)).allows());
    }

    /// P-23: the SuperSAFE value reads; a disabled or absent value fails
    /// closed.
    #[test]
    fn p23_limits_read_from_the_frozen_value() {
        let fixture = fstp_programme::supersafe_fixture().unwrap();
        let compiled = fstp_programme::compile(
            &fixture.spec,
            &fstp_programme::FunderProfile::horizon_europe(),
            fstp_programme::CompileIds::new(
                fstp_domain::id::ProgrammeId::from_raw(1),
                fstp_domain::id::PolicyVersionId::from_raw(1),
                None,
            ),
        )
        .unwrap();
        assert_eq!(limits(&compiled.policy.frozen), Some(SUPERSAFE));
        let mut off = compiled.policy.frozen.clone();
        off.opaque.remove(&ParamId::P23);
        assert_eq!(limits(&off), None);
    }
}

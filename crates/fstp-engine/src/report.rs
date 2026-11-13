//! The `Report` envelope of the engine (M5 design section 4.3, lane
//! L-API, which wires what lane L-RPT left open).
//!
//! The shell generates an output from a ledger snapshot through
//! `fstp_report::generate` and submits its `ReportGenerated` record as the
//! command. The engine checks that the generator is the actor and holds
//! the programme manager role of the output's programme. `ReportApproved`
//! goes to `fstp_report_core::approve`: only a Financial signatory of the
//! tenant fold who did not generate the document approves it (R-RP-03,
//! Q3). The fold refuses a self-approval too (`ReportStore::apply`).
//!
//! The generated record must name the funder profile id and version that
//! P-53 pins for its scope (M9 design section 2.1, [`pinned_p53`]).

use fstp_domain::command::{Actor, Ctx};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::policy::FunderProfileRef;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::{BindingScope, Role};
use fstp_report_core::{ApprovalRefusal, ReportFoldError, ReportRecord, Scope};

use crate::{EngineState, Record};

pub use fstp_report_core::ReportStore;

fn actor_refusal() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)
}

fn programme_of(state: &EngineState, scope: Scope) -> Option<ProgrammeId> {
    match scope {
        Scope::Programme(p) => state.core.policy().programme(p).map(|_| p),
        Scope::Call(c) => state.core.calls().get(c).map(|v| v.programme()),
    }
}

fn manages(state: &EngineState, account: AccountId, programme: ProgrammeId, ctx: &Ctx) -> bool {
    state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.role == Role::ProgrammeManager
            && b.programme == programme
            && b.scope == BindingScope::Programme
            && b.active_at(ctx.now)
    })
}

/// The P-53 value that pins the funder profile of an output over `scope`
/// (M9 design section 2.5, R-RP-01): the frozen policy of a published
/// call, or the head policy version of a programme. An unpublished call
/// has none.
pub fn pinned_p53(state: &EngineState, scope: Scope) -> Option<&FunderProfileRef> {
    match scope {
        Scope::Call(c) => {
            fstp_domain::policy::frozen_policy(&state.core, c).map(|f| &f.values().p53)
        }
        Scope::Programme(p) => fstp_domain::policy::head(&state.core, p).map(|v| &v.frozen.p53),
    }
}

/// Whether `account` holds the Financial signatory role in the tenant
/// fold (NOTE 5, R-RP-03).
pub fn financial_signatory(state: &EngineState, account: AccountId) -> bool {
    state
        .tenant
        .state()
        .is_some_and(|ts| ts.holds_signatory(fstp_tenant::SignatoryRole::Financial, account))
}

/// The records of a report command.
pub(crate) fn decide_report(
    state: &EngineState,
    r: &ReportRecord,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    crate::ledger_clock(state, ctx)?;
    let Actor::Account(actor) = ctx.actor else {
        return Err(actor_refusal());
    };
    match r {
        ReportRecord::Generated {
            report,
            scope,
            by,
            profile,
            ..
        } => {
            if *by != actor {
                return Err(actor_refusal());
            }
            if state.reports.report(*report).is_some() {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            let programme = programme_of(state, *scope)
                .ok_or(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity))?;
            if !manages(state, actor, programme, ctx) {
                return Err(actor_refusal());
            }
            // R-RP-01: the document names the profile version P-53 pins.
            if !pinned_p53(state, *scope).is_some_and(|p| profile.matches_p53(p.0.as_str())) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
            }
        }
        ReportRecord::Approved { report, approver } => {
            if *approver != actor {
                return Err(actor_refusal());
            }
            fstp_report_core::approve(
                &state.reports,
                *report,
                actor,
                financial_signatory(state, actor),
            )
            .map_err(|e| match e {
                ApprovalRefusal::UnknownReport => {
                    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
                }
                ApprovalRefusal::AlreadyApproved => {
                    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
                }
                ApprovalRefusal::Generator | ApprovalRefusal::NotFinancialSignatory => {
                    actor_refusal()
                }
            })?;
        }
    }
    Ok(vec![Record::Report(r.clone())])
}

/// Folds a report record.
pub(crate) fn apply_report(state: &mut EngineState, r: &ReportRecord) -> Result<(), FoldError> {
    state.reports.apply(r).map_err(|e| match e {
        ReportFoldError::UnknownReport => FoldError::UnknownEntity,
        ReportFoldError::DuplicateReport
        | ReportFoldError::AlreadyApproved
        | ReportFoldError::SelfApproval => FoldError::Inconsistent,
    })
}

//! Routing of finding commands to `decide_finding` (design sections 2.13 and 3.1, I-10, I-11).
//!
//! A finding command reads the core projection and the finding store. It
//! returns only finding records, so it can never cause a state transition,
//! a score or a decision (I-10). Core `decide` never sees the finding
//! store, because `DomainDecider` passes it only the core part.
//!
//! - `Record` stores one finding under its call's pinned `config_id`
//!   (I-11, R-LA-05). The pin comes from the published call in the core,
//!   which `PublishCall` sets. After a replacement, the pin is the
//!   replacement configuration the store holds.
//! - `Regenerate` replaces every finding of a published call in one step
//!   (`SPEC/02-domain/policy-parameters.md` NOTE 10). Its model must be
//!   the frozen P-21 fallback at the call's next position. Its
//!   configuration must differ from the call's published pin on every
//!   regeneration, because the store cannot see a pin it never held.
//! - `Mark` records a reviewer's mark on a current finding. Marks feed
//!   calibration and never a decision (I-10).
//! - `ReadAssessmentInput` and `RecordClientAssessment` (ADR-033) are the
//!   FSTP coordinator's, through the connected agent that runs the
//!   assessment when the call's frozen P-21 names the client path. They
//!   are judged by the coordinator binding, the path, the state and P-10,
//!   the declaration, the absence of an assignment on the proposal, and a
//!   fresh vault answer (I-03). The run records its provenance, its
//!   findings under the call's pin (I-11) and its refusal list, all finding
//!   records only (I-10). The model the run reports must be the call's
//!   pinned model, and the input it names the one its account read last.
//! - Findings stay with the call that produced them, also after the
//!   proposal is deferred into a later call (state-machine NOTE 8). The
//!   store is keyed by call, and nothing here moves a finding.
//!
//! Every candidate batch is first checked as [`check_fold`] checks a
//! stored record, and folded into a copy of the store. So a command is
//! accepted exactly when its records fold, and a refused command changes
//! nothing.
//!
//! [`check_fold`] is the part of the fold that needs the core: a finding
//! record names a published call, a `Recorded` before any replacement
//! carries the published pin, and a `Regenerated` names a configuration
//! other than that pin and the frozen fallback at its position. A
//! `Marked` names an account that may mark the finding at the entry's
//! time, by the `Mark` rule below without the vault answer. So a replayed
//! log the engine could not have produced is refused, as the core refuses
//! forged publication records (I-03, I-11, I-12).
//!
//! Readings taken where the sources are silent:
//! - `Record` and `Regenerate` come from the assessment pipeline. `Actor`
//!   has no assessor variant (I-10), so they need a system actor.
//! - A finding command, like every core command, is refused when its time
//!   is before the latest recorded time of either side of the ledger
//!   ([`EngineState::now_floor`], design section 2.2), or when a system
//!   actor arrives through MCP.
//! - `Mark` is an assigned-reviewer act (`SPEC/02-domain/roles-and-sod.md`
//!   Conflict declarations, I-03, enforcement point 2). The account holds
//!   an active reviewer or IRC assignment on the finding's proposal, made
//!   in the call that produced the finding, over an active binding of the
//!   assignment's role. It has no conflict fact on the proposal, and the
//!   vault answers `HasConflict` false at the state's epoch.
//! - An unknown finding id and a finding the account may not mark give the
//!   same refusal, so a refusal never tells whether a finding id is taken.
//! - Whether a finding's proposal must belong to the producing call is not
//!   checked. The core projection has no public read of a proposal's call
//!   history, so this lane cannot check it.
//! - A `Mark` is not refused when the finding's proposal is in a terminal
//!   state. `SPEC/04-llm-assessment/assessment.md` keeps marking open after
//!   a terminal state, and a mark never changes the proposal (I-10, decided
//!   2026-10-26).
//!
//! Status: lane L-FIND-B of milestone M2.

use fstp_domain::assignment::{Assignment, AssignmentStatus, ReleaseCause};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::policy::FrozenPolicy;
use fstp_domain::programme::CallView;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_findings::{
    Finding, FindingCommand, FindingId, FindingRecord, FindingRefusal, FindingStore, Mark,
};

use crate::EngineState;

/// The vault questions a finding command needs. `Record` and `Regenerate`
/// ask none. A `Mark` by an account that may mark the finding asks
/// `HasConflict` for that account and the proposal's team (I-03). The
/// answers never reach core `decide` (I-10).
pub fn finding_queries(
    state: &EngineState,
    cmd: &FindingCommand,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    shared_checks(state, ctx)?;
    match cmd {
        FindingCommand::Mark { finding, .. } => Ok(mark_basis(state, *finding, ctx)
            .ok()
            .map(|(by, f)| conflict_query(&state.core, by, f.proposal))
            .into_iter()
            .collect()),
        FindingCommand::ReadAssessmentInput { call, proposal, .. }
        | FindingCommand::RecordClientAssessment { call, proposal, .. } => {
            let Actor::Account(by) = ctx.actor else {
                return Ok(Vec::new());
            };
            Ok(client_basis(&state.core, by, *call, *proposal, ctx.now)
                .ok()
                .map(|()| conflict_query(&state.core, by, *proposal))
                .into_iter()
                .collect())
        }
        // ADR-035: the release asks the vault for a conflict, as every
        // read of content does (I-03).
        FindingCommand::ReleaseIntegrityHold { call, proposal } => {
            let Actor::Account(by) = ctx.actor else {
                return Ok(Vec::new());
            };
            Ok(
                check_release_basis(&state.core, by, *call, *proposal, ctx.now)
                    .ok()
                    .map(|()| conflict_query(&state.core, by, *proposal))
                    .into_iter()
                    .collect(),
            )
        }
        FindingCommand::Record(_)
        | FindingCommand::Regenerate { .. }
        | FindingCommand::RequestRerun { .. }
        | FindingCommand::AbandonRerun { .. }
        | FindingCommand::RecordRefusals { .. } => Ok(Vec::new()),
    }
}

/// The finding records `cmd` produces, or the refusal (I-10, I-11).
///
/// It reads the core projection only for the call's pin, its frozen P-21
/// list and the marking reviewer's assignments, bindings and conflict
/// facts. It returns only finding records, so no finding can drive a
/// core transition.
pub fn decide_finding(
    state: &EngineState,
    cmd: &FindingCommand,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<FindingRecord>, Refusal> {
    shared_checks(state, ctx)?;
    let core = &state.core;
    let store = &state.findings;
    let records = match cmd {
        FindingCommand::ReadAssessmentInput {
            call,
            proposal,
            input,
        } => {
            let by = client_actor(state, *call, *proposal, ctx, answers)?;
            // ADR-035: no AI assessment reads a held proposal.
            store.check_not_held(*proposal).map_err(store_refusal)?;
            vec![FindingRecord::AssessmentInputRead {
                call: *call,
                proposal: *proposal,
                by,
                input: *input,
            }]
        }
        FindingCommand::RecordClientAssessment {
            call,
            proposal,
            run,
            findings,
            refused,
        } => {
            let by = client_actor(state, *call, *proposal, ctx, answers)?;
            store.check_not_held(*proposal).map_err(store_refusal)?;
            client_records(store, *call, *proposal, by, run, findings, refused)?
        }
        other => vec![decide_one(state, other, ctx, answers)?],
    };
    let mut trial = store.clone();
    for record in &records {
        check_fold(core, &trial, record, ctx.now)
            .map_err(|_| Refusal::new(RuleRef::I11, RefusalReason::GuardFailed))?;
        trial.apply_at(record, ctx.now).map_err(store_refusal)?;
    }
    Ok(records)
}

/// The one record of every finding command but the two of ADR-033.
fn decide_one(
    state: &EngineState,
    cmd: &FindingCommand,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<FindingRecord, Refusal> {
    let core = &state.core;
    let store = &state.findings;
    let record = match cmd {
        FindingCommand::ReadAssessmentInput { .. }
        | FindingCommand::RecordClientAssessment { .. } => {
            return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
        }
        FindingCommand::Record(f) => {
            let record = decide_record(core, store, f, ctx)?;
            // ADR-035: the assessor records nothing on a held proposal.
            store.check_not_held(f.proposal).map_err(store_refusal)?;
            record
        }
        FindingCommand::ReleaseIntegrityHold { call, proposal } => {
            // ADR-035: the call's FSTP coordinator, as for a re-run, with
            // no conflict on the proposal (I-03, lead reading 2026-11-22).
            let Actor::Account(by) = ctx.actor else {
                return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
            };
            check_release_basis(core, by, *call, *proposal, ctx.now)?;
            match answers.get(&conflict_query(core, by, *proposal)) {
                None => {
                    return Err(Refusal::new(
                        RuleRef::FactsIncomplete,
                        RefusalReason::AnswerMissing,
                    ));
                }
                Some(a) if a.epoch != core.epoch() => {
                    return Err(Refusal::new(
                        RuleRef::StaleFacts,
                        RefusalReason::AnswerStale,
                    ));
                }
                Some(a) if a.holds => {
                    return Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused));
                }
                Some(_) => {}
            }
            if !store.held(*proposal) {
                return Err(store_refusal(FindingRefusal::NotHeld {
                    proposal: *proposal,
                }));
            }
            FindingRecord::IntegrityReleased {
                call: *call,
                proposal: *proposal,
                by,
            }
        }
        FindingCommand::Mark { finding, mark } => {
            decide_mark(state, *finding, *mark, ctx, answers)?
        }
        FindingCommand::RequestRerun { call, proposal } => {
            // Issue 6 M3, I-10: the call's FSTP coordinator asks, once at
            // a time and at most MAX_RERUNS times. The bounds are the
            // store's, which the trial fold below applies.
            let Actor::Account(by) = ctx.actor else {
                return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
            };
            check_rerun_basis(core, by, *call, *proposal, ctx.now)?;
            FindingRecord::RerunRequested {
                call: *call,
                proposal: *proposal,
                by,
            }
        }
        FindingCommand::AbandonRerun {
            call,
            proposal,
            reason,
        } => {
            // Issue 6 M3: the cell, as the system, ends a re-run whose run
            // died. The store checks that one is in flight, and for the
            // timeout that it is old enough, in the trial fold below.
            system_actor(ctx)?;
            published(core, *call)?;
            if !proposal_in_call(core, *proposal, *call) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity));
            }
            FindingRecord::RerunAbandoned {
                call: *call,
                proposal: *proposal,
                reason: *reason,
            }
        }
        FindingCommand::RecordRefusals {
            call,
            proposal,
            refused,
        } => {
            system_actor(ctx)?;
            published(core, *call)?;
            if !proposal_in_call(core, *proposal, *call) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity));
            }
            FindingRecord::RefusalsRecorded {
                call: *call,
                proposal: *proposal,
                refused: refused.clone(),
            }
        }
        FindingCommand::Regenerate {
            call,
            config,
            config_model,
            findings,
        } => {
            system_actor(ctx)?;
            let (view, frozen) = published(core, *call)?;
            if view.llm_config() == Some(*config) {
                // The store never saw the pin of a call that held no
                // findings, so the pin is refused here on every
                // regeneration (P-21 NOTE 10, I-11).
                return Err(Refusal::new(RuleRef::I11, RefusalReason::GuardFailed));
            }
            let Some(next) = store.next_fallback(*call) else {
                return Err(store_refusal(FindingRefusal::FallbackExhausted {
                    call: *call,
                }));
            };
            if fallback_model(frozen, next) != Some(config_model) {
                // A replacement takes the next model on the frozen list,
                // as `PublishCall` takes the primary (I-12).
                return Err(Refusal::new(RuleRef::I12, RefusalReason::GuardFailed));
            }
            FindingRecord::Regenerated {
                call: *call,
                fallback: next,
                config_model: config_model.clone(),
                config: *config,
                findings: findings.clone(),
            }
        }
    };
    Ok(record)
}

/// The coordinator of an ADR-033 command, after [`client_basis`] and a
/// fresh `HasConflict` answer of false at the state's epoch (I-03), as
/// every read of content asks.
fn client_actor(
    state: &EngineState,
    call: CallId,
    proposal: ProposalId,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<AccountId, Refusal> {
    let Actor::Account(by) = ctx.actor else {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    };
    client_basis(&state.core, by, call, proposal, ctx.now)?;
    match answers.get(&conflict_query(&state.core, by, proposal)) {
        None => Err(Refusal::new(
            RuleRef::FactsIncomplete,
            RefusalReason::AnswerMissing,
        )),
        Some(a) if a.epoch != state.core.epoch() => Err(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )),
        Some(a) if a.holds => Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused)),
        Some(_) => Ok(by),
    }
}

/// The records of one client assessment (ADR-033): the provenance, one
/// `Recorded` per finding and the refusal list, which also ends a re-run
/// in flight. Each finding names the run's call, proposal and trace, and
/// the call's pin, which the trial fold checks (I-11).
fn client_records(
    store: &FindingStore,
    call: CallId,
    proposal: ProposalId,
    by: AccountId,
    run: &fstp_findings::ClientRun,
    findings: &[Finding],
    refused: &[fstp_findings::RefusedStage],
) -> Result<Vec<FindingRecord>, Refusal> {
    let invalid = || Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    if findings.len() > fstp_findings::MAX_CLIENT_FINDINGS
        || refused.len() > fstp_findings::MAX_REFUSED
    {
        return Err(invalid());
    }
    if findings
        .iter()
        .any(|f| f.call != call || f.proposal != proposal || f.trace != run.trace)
    {
        return Err(invalid());
    }
    store.check_client_run(proposal).map_err(store_refusal)?;
    let mut out = Vec::with_capacity(findings.len().saturating_add(2));
    out.push(FindingRecord::ClientAssessed {
        call,
        proposal,
        by,
        run: run.clone(),
    });
    out.extend(findings.iter().cloned().map(FindingRecord::Recorded));
    out.push(FindingRecord::RefusalsRecorded {
        call,
        proposal,
        refused: refused.to_vec(),
    });
    Ok(out)
}

/// What an ADR-033 command needs from the core, also when its record is
/// folded (without the vault answer):
///
/// - `by` holds an active FSTP coordinator binding in its programme, and
///   the call is published;
/// - the proposal is a proposal of the call in a state where the
///   coordinator reads its content: SUBMITTED, or STAGE1 and STAGE2 under
///   P-10 "operator staff only" (R-AC-01);
/// - `by` declared no conflict on it and holds no conflict fact (I-03,
///   R-CF-02);
/// - the call's frozen P-21 names the client path;
/// - `by` holds no reviewer or IRC assignment on it, in any status, so no
///   scorer of the proposal produces its findings (ADR-033).
fn client_basis(
    core: &State,
    by: AccountId,
    call: CallId,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<(), Refusal> {
    use fstp_domain::policy::ReadAccess;
    use fstp_domain::roles::Role;
    use fstp_domain::rules::ParamId;
    // The actor, the state and the declaration first, as for every read of
    // content, then the path: the authorisation classes do not depend on
    // P-21, and a call off the path ends in the `P-21` guard.
    let Some(programme) = core.calls().get(call).map(CallView::programme) else {
        return Err(Refusal::new(RuleRef::I11, RefusalReason::UnknownEntity));
    };
    if !core.roster().bindings().any(|(_, b)| {
        b.account == by
            && b.role == Role::FstpCoordinator
            && b.programme == programme
            && b.active_at(now)
    }) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    let (_, frozen) = published(core, call)?;
    if !proposal_in_call(core, proposal, call) {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity));
    }
    let open = match fstp_domain::view::proposal_state(core, proposal) {
        Some(fstp_domain::StateTag::Submitted) => true,
        Some(fstp_domain::StateTag::Stage1 | fstp_domain::StateTag::Stage2) => {
            frozen.values().p10 == ReadAccess::OperatorStaffOnly
        }
        _ => false,
    };
    if !open {
        return Err(Refusal::new(RuleRef::Rac01, RefusalReason::WrongState));
    }
    let review = core.review();
    if review.conflict_fact(by, proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    if !review.cleared(by, proposal) {
        return Err(Refusal::new(RuleRef::Rcf02, RefusalReason::GuardFailed));
    }
    if !fstp_findings::client_run(&frozen.values().p21) {
        return Err(Refusal::new(
            RuleRef::Param(ParamId::P21),
            RefusalReason::GuardFailed,
        ));
    }
    if review
        .assignments()
        .any(|(_, a)| a.reviewer == by && a.proposal == proposal)
    {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    Ok(())
}

/// The model a client run must report (ADR-033, I-11): the frozen P-21
/// primary, or the fallback at the call's current position.
fn client_model<'a>(
    frozen: &'a FrozenPolicy,
    store: &FindingStore,
    call: CallId,
) -> Option<&'a fstp_domain::policy::ModelRef> {
    match store.fallback_of(call) {
        None => Some(&frozen.values().p21.primary),
        Some(k) => fallback_model(frozen, k),
    }
}

/// The checks of a stored finding record that need the core (I-11, I-12).
///
/// A `Recorded` or `Regenerated` names a published call. A `Recorded`
/// before the call's first replacement carries the published pin. A
/// `Regenerated` names a configuration other than the published pin, and
/// its model is the frozen P-21 fallback at its position. A `Marked` names
/// a stored finding that its account may mark at `at`, as [`mark_basis`]
/// judges without the vault answer (I-03). The store checks the rest when
/// it folds.
pub fn check_fold(
    core: &State,
    store: &FindingStore,
    record: &FindingRecord,
    at: Timestamp,
) -> Result<(), FoldError> {
    match record {
        FindingRecord::Recorded(f) => {
            let (view, _) = published(core, f.call).map_err(|_| FoldError::Inconsistent)?;
            if store.fallback_of(f.call).is_none() && view.llm_config() != Some(f.config) {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        FindingRecord::Regenerated {
            call,
            fallback,
            config_model,
            config,
            ..
        } => {
            let (view, frozen) = published(core, *call).map_err(|_| FoldError::Inconsistent)?;
            if view.llm_config() == Some(*config)
                || fallback_model(frozen, *fallback) != Some(config_model)
            {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        FindingRecord::AssessmentInputRead {
            call, proposal, by, ..
        } => client_basis(core, *by, *call, *proposal, at).map_err(|_| FoldError::Inconsistent),
        FindingRecord::ClientAssessed {
            call,
            proposal,
            by,
            run,
        } => {
            client_basis(core, *by, *call, *proposal, at).map_err(|_| FoldError::Inconsistent)?;
            let (_, frozen) = published(core, *call).map_err(|_| FoldError::Inconsistent)?;
            // I-11: the run reports the model the call pins.
            if client_model(frozen, store, *call) == Some(&run.model) {
                Ok(())
            } else {
                Err(FoldError::Inconsistent)
            }
        }
        FindingRecord::RerunRequested { call, proposal, by } => {
            check_rerun_basis(core, *by, *call, *proposal, at).map_err(|_| FoldError::Inconsistent)
        }
        FindingRecord::IntegrityReleased { call, proposal, by } => {
            check_release_basis(core, *by, *call, *proposal, at)
                .map_err(|_| FoldError::Inconsistent)
        }
        FindingRecord::IntegrityHeld {
            call,
            proposal,
            reasons,
        } => {
            published(core, *call).map_err(|_| FoldError::Inconsistent)?;
            let ordered = reasons.windows(2).all(|w| matches!(w, [a, b] if a < b));
            if proposal_in_call(core, *proposal, *call) && !reasons.is_empty() && ordered {
                Ok(())
            } else {
                Err(FoldError::Inconsistent)
            }
        }
        FindingRecord::RefusalsRecorded { call, proposal, .. }
        | FindingRecord::RerunAbandoned { call, proposal, .. } => {
            published(core, *call).map_err(|_| FoldError::Inconsistent)?;
            if proposal_in_call(core, *proposal, *call) {
                Ok(())
            } else {
                Err(FoldError::Inconsistent)
            }
        }
        FindingRecord::Marked { finding, by, .. } => {
            // An unknown finding is the store's refusal, as before.
            match store.finding(*finding) {
                Some(f) if !may_mark(core, *by, f, at) => Err(FoldError::Inconsistent),
                _ => Ok(()),
            }
        }
    }
}

/// Folds one finding record into the finding store only, after
/// [`check_fold`] at the entry's time `at`. It never touches the core
/// (I-10). A refused record leaves the store unchanged.
pub fn apply_finding(
    core: &State,
    store: &mut FindingStore,
    record: &FindingRecord,
    at: Timestamp,
) -> Result<(), FoldError> {
    check_fold(core, store, record, at)?;
    store.apply_at(record, at).map_err(fold_error)
}

/// The `AbandonRerun` commands the cell issues at `now` (issue 6 M3, I-10):
/// one `Timeout` for each re-run that has been in flight for
/// `RERUN_TIMEOUT_US`. It reads the finding store only. A dead run never
/// records its result, so without this its slot would stay taken.
pub fn stale_reruns(state: &EngineState, now: Timestamp) -> Vec<FindingCommand> {
    abandon(
        state.findings.stale_reruns(now),
        fstp_findings::RerunEnd::Timeout,
    )
}

/// The `AbandonRerun` commands of a cell start (issue 6 M3, I-10): one
/// `CellStart` for each re-run in flight. A run lives in the cell process,
/// so none of an earlier process is alive when the cell starts.
pub fn reruns_at_start(state: &EngineState) -> Vec<FindingCommand> {
    abandon(
        state.findings.in_flight_reruns(),
        fstp_findings::RerunEnd::CellStart,
    )
}

fn abandon(
    runs: Vec<(ProposalId, CallId)>,
    reason: fstp_findings::RerunEnd,
) -> Vec<FindingCommand> {
    runs.into_iter()
        .map(|(proposal, call)| FindingCommand::AbandonRerun {
            call,
            proposal,
            reason,
        })
        .collect()
}

/// The checks every command shares with the core (design section 3.4).
/// The time floor covers the entries of both sides (design section 2.2).
fn shared_checks(state: &EngineState, ctx: &Ctx) -> Result<(), Refusal> {
    crate::ledger_clock(state, ctx)?;
    if ctx.via == Via::Mcp && matches!(ctx.actor, Actor::System(_)) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    Ok(())
}

/// Whether the actor is the assessment pipeline, which runs as a system
/// actor because `Actor` has no assessor variant (I-10).
fn system_actor(ctx: &Ctx) -> Result<(), Refusal> {
    match ctx.actor {
        Actor::System(_) => Ok(()),
        Actor::Account(_) => Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)),
    }
}

/// The published call `call` and its frozen policy. A call that is
/// unknown or not yet published has no pin, so it stores no finding (I-11).
fn published(core: &State, call: CallId) -> Result<(&CallView, &FrozenPolicy), Refusal> {
    let Some(view) = core.calls().get(call) else {
        return Err(Refusal::new(RuleRef::I11, RefusalReason::UnknownEntity));
    };
    match (view.llm_config(), view.frozen()) {
        (Some(_), Some(frozen)) => Ok((view, frozen)),
        _ => Err(Refusal::new(RuleRef::I11, RefusalReason::WrongState)),
    }
}

/// The frozen P-21 fallback at position `k`, counted from 0.
fn fallback_model(frozen: &FrozenPolicy, k: u32) -> Option<&fstp_domain::policy::ModelRef> {
    usize::try_from(k)
        .ok()
        .and_then(|k| frozen.values().p21.fallbacks.get(k))
}

/// The `Recorded` record for `f`, checked against the call's pin (I-11).
fn decide_record(
    core: &State,
    store: &FindingStore,
    f: &Finding,
    ctx: &Ctx,
) -> Result<FindingRecord, Refusal> {
    system_actor(ctx)?;
    let (view, _) = published(core, f.call)?;
    let Some(pin) = view.llm_config() else {
        return Err(Refusal::new(RuleRef::I11, RefusalReason::WrongState));
    };
    // After a replacement the call's pin is the replacement configuration.
    // Before one, it is the configuration the call was published with.
    let pinned = match store.fallback_of(f.call) {
        Some(_) => store.config_of(f.call).unwrap_or(pin),
        None => pin,
    };
    if f.config != pinned {
        return Err(store_refusal(FindingRefusal::ForeignConfig {
            call: f.call,
            expected: pinned,
            found: f.config,
        }));
    }
    // The trial fold in `decide_finding` checks the rest, as
    // `FindingStore::insert` would with this pin.
    Ok(FindingRecord::Recorded(f.clone()))
}

/// Whether `proposal` has its latest binding scope in `call`.
fn proposal_in_call(core: &State, proposal: ProposalId, call: CallId) -> bool {
    current_call(core, proposal) == Some(call)
}

/// The call of `proposal`: the call of its latest proposal binding.
fn current_call(core: &State, proposal: ProposalId) -> Option<CallId> {
    use fstp_domain::roles::BindingScope;
    let roster = core.roster();
    roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
        .filter_map(|b| match b.scope {
            BindingScope::Proposal { proposal: p, call } if p == proposal => {
                Some((b.opened, b.start, call))
            }
            _ => None,
        })
        .max()
        .map(|(_, _, c)| c)
}

/// What a re-run request needs from the core (issue 6 M3, I-10): the
/// call is published, the proposal is a submitted proposal of that call,
/// and `by` holds an active FSTP coordinator binding in the call's
/// programme, as `review.assign` requires. The store's bounds are
/// checked by the fold.
/// What a release of an integrity hold needs from the core (ADR-035):
/// the basis of a re-run, and no conflict of `by` on the proposal, as
/// for every content read (I-03). Another coordinator releases a proposal
/// its own coordinator is conflicted on. Lead reading, 2026-11-22.
fn check_release_basis(
    core: &State,
    by: AccountId,
    call: CallId,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<(), Refusal> {
    check_rerun_basis(core, by, call, proposal, now)?;
    if core.review().conflict_fact(by, proposal) {
        return Err(Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    Ok(())
}

fn check_rerun_basis(
    core: &State,
    by: AccountId,
    call: CallId,
    proposal: ProposalId,
    now: Timestamp,
) -> Result<(), Refusal> {
    use fstp_domain::roles::Role;
    let (view, _) = published(core, call)?;
    let programme = view.programme();
    if !core.roster().bindings().any(|(_, b)| {
        b.account == by
            && b.role == Role::FstpCoordinator
            && b.programme == programme
            && b.active_at(now)
    }) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    if !proposal_in_call(core, proposal, call) {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity));
    }
    match fstp_domain::view::proposal_state(core, proposal) {
        Some(fstp_domain::StateTag::Draft) | None => {
            Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState))
        }
        Some(_) => Ok(()),
    }
}

/// The refusal of a `Mark` before the account is shown to be allowed. It
/// is the same for an unknown finding, so it never tells whether an id is
/// taken.
const fn mark_refused() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)
}

/// Whether `a` lets `by` mark `f` at `now`: an active reviewer or IRC
/// assignment of `by` on the finding's proposal, made in the finding's
/// call, over an active binding of its role in the call's programme
/// (enforcement point 2). An active binding is started, not ended, not
/// suspended and not voided.
fn assignment_qualifies(
    core: &State,
    by: AccountId,
    f: &Finding,
    a: &Assignment,
    now: Timestamp,
) -> bool {
    let Some(view) = core.calls().get(f.call) else {
        return false;
    };
    let programme = view.programme();
    a.reviewer == by
        && a.proposal == f.proposal
        && a.call == f.call
        && a.kind.reviews_proposal()
        && a.active()
        && core.roster().bindings().any(|(_, b)| {
            b.account == by
                && b.role == a.kind.role()
                && b.programme == programme
                && b.active_at(now)
        })
}

/// Whether `by` may mark `f` at `now` before the vault is asked: a
/// qualifying assignment and no conflict fact on the finding's proposal
/// (I-03). The decision and the fold both judge a mark by this rule.
fn may_mark(core: &State, by: AccountId, f: &Finding, now: Timestamp) -> bool {
    let review = core.review();
    review
        .assignments()
        .any(|(_, a)| assignment_qualifies(core, by, f, a, now))
        && !review.conflict_fact(by, f.proposal)
}

/// The account and the finding of a `Mark` that may proceed to its fresh
/// vault check, or the one refusal of every other `Mark`.
fn mark_basis<'s>(
    state: &'s EngineState,
    finding: FindingId,
    ctx: &Ctx,
) -> Result<(AccountId, &'s Finding), Refusal> {
    let Actor::Account(by) = ctx.actor else {
        return Err(mark_refused());
    };
    let Some(f) = state.findings.finding(finding) else {
        return Err(mark_refused());
    };
    if !may_mark(&state.core, by, f, ctx.now) {
        return Err(assignee_refusal(&state.core, by, f, ctx.now).unwrap_or(mark_refused()));
    }
    Ok((by, f))
}

/// The conflict refusal of a `Mark` by an assignee of the finding's
/// proposal in the finding's call, over an active binding of its role:
/// I-03 for a conflict the assignee declared, R-CF-02 for an assignment
/// still awaiting its declaration (`roles-and-sod.md` Conflict
/// declarations). It names only what the assignee already knows, since
/// its own assignment is on that proposal. `None` for anyone else, who
/// gets [`mark_refused`].
///
/// Interim, pending Daniel: a conflict only the vault detected gets
/// [`mark_refused`] too (I-03, I-10). The vault returns only a boolean to
/// the platform, and the assignee never stated that conflict. So a mark
/// refusal neither confirms the detection nor tells whether the finding
/// id is taken.
fn assignee_refusal(core: &State, by: AccountId, f: &Finding, now: Timestamp) -> Option<Refusal> {
    let review = core.review();
    let programme = core.calls().get(f.call)?.programme();
    let own = review.assignments().filter(|(_, a)| {
        a.reviewer == by
            && a.proposal == f.proposal
            && a.call == f.call
            && a.kind.reviews_proposal()
            && core.roster().bindings().any(|(_, b)| {
                b.account == by
                    && b.role == a.kind.role()
                    && b.programme == programme
                    && b.active_at(now)
            })
    });
    let own: Vec<&Assignment> = own.map(|(_, a)| a).collect();
    if review.conflict_fact(by, f.proposal) {
        let declared = own
            .iter()
            .any(|a| a.status == AssignmentStatus::Released(ReleaseCause::DeclaredConflict));
        return declared.then(|| Refusal::new(RuleRef::I03, RefusalReason::GuardFailed));
    }
    own.iter()
        .any(|a| a.status == AssignmentStatus::AwaitingDeclaration)
        .then(|| Refusal::new(RuleRef::Rcf02, RefusalReason::GuardFailed))
}

/// The `HasConflict` question for `account` and the team of `proposal`:
/// every account with a held Receiving binding on it (design 4.2). It is
/// the question the core asks for every reviewer act.
fn conflict_query(core: &State, account: AccountId, proposal: ProposalId) -> Query {
    Query::HasConflict {
        reviewer: account,
        team: core
            .roster()
            .bindings()
            .filter(|(_, b)| b.held() && b.proposal() == Some(proposal))
            .map(|(_, b)| b.account)
            .collect(),
    }
}

/// The `Marked` record for the acting reviewer's mark on `finding`
/// (I-03): [`mark_basis`], then a `HasConflict` answer of false at the
/// state's epoch. A missing answer or one at another epoch refuses.
fn decide_mark(
    state: &EngineState,
    finding: FindingId,
    mark: Mark,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<FindingRecord, Refusal> {
    let (by, f) = mark_basis(state, finding, ctx)?;
    match answers.get(&conflict_query(&state.core, by, f.proposal)) {
        None => Err(Refusal::new(
            RuleRef::FactsIncomplete,
            RefusalReason::AnswerMissing,
        )),
        Some(a) if a.epoch != state.core.epoch() => Err(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )),
        Some(a) if a.holds => Err(Refusal::new(RuleRef::I03, RefusalReason::VaultRefused)),
        Some(_) => Ok(FindingRecord::Marked { finding, by, mark }),
    }
}

/// The refusal for a store refusal. It keeps the store's rule and names
/// no account and no statement (R-CF-03).
fn store_refusal(r: FindingRefusal) -> Refusal {
    let reason = match r {
        FindingRefusal::ForeignConfig { .. }
        | FindingRefusal::RetiredConfig { .. }
        | FindingRefusal::FallbackOutOfOrder { .. }
        | FindingRefusal::FallbackExhausted { .. } => RefusalReason::GuardFailed,
        FindingRefusal::DuplicateFinding { .. } => RefusalReason::IdReused,
        FindingRefusal::RerunInFlight { .. }
        | FindingRefusal::RerunLimit { .. }
        | FindingRefusal::NoRerunInFlight { .. }
        | FindingRefusal::RerunNotStale { .. }
        | FindingRefusal::ClientRunTaken { .. }
        | FindingRefusal::IntegrityHeld { .. }
        | FindingRefusal::NotHeld { .. }
        | FindingRefusal::InputNotRead { .. } => RefusalReason::GuardFailed,
        FindingRefusal::TooManyRefused { .. } => RefusalReason::InvalidValue,
        FindingRefusal::UnknownFinding { .. } => RefusalReason::UnknownEntity,
        FindingRefusal::WrongCall { .. } | FindingRefusal::MalformedEvidence { .. } => {
            RefusalReason::InvalidValue
        }
    };
    Refusal::new(r.rule(), reason)
}

/// The fold error for a finding record the store refuses: a log the
/// engine could not have produced.
fn fold_error(r: FindingRefusal) -> FoldError {
    match r {
        FindingRefusal::DuplicateFinding { .. } => FoldError::DuplicateId,
        FindingRefusal::RerunInFlight { .. }
        | FindingRefusal::RerunLimit { .. }
        | FindingRefusal::TooManyRefused { .. }
        | FindingRefusal::NoRerunInFlight { .. }
        | FindingRefusal::RerunNotStale { .. }
        | FindingRefusal::ClientRunTaken { .. }
        | FindingRefusal::IntegrityHeld { .. }
        | FindingRefusal::NotHeld { .. }
        | FindingRefusal::InputNotRead { .. } => FoldError::Inconsistent,
        FindingRefusal::UnknownFinding { .. } => FoldError::UnknownEntity,
        FindingRefusal::ForeignConfig { .. }
        | FindingRefusal::RetiredConfig { .. }
        | FindingRefusal::FallbackOutOfOrder { .. }
        | FindingRefusal::FallbackExhausted { .. }
        | FindingRefusal::WrongCall { .. }
        | FindingRefusal::MalformedEvidence { .. } => FoldError::Inconsistent,
    }
}

/// The records of a flagged submission (ADR-035): the core records of its
/// `Submit`, then one `Recorded` per integrity finding of the scan and
/// the `IntegrityHeld`, all in one entry. Each finding names the
/// submitted proposal and its call, and carries the call's pin (I-11),
/// which the trial fold checks. A finding record never changes the core
/// (I-10).
pub fn decide_scanned_submit(
    state: &EngineState,
    s: &crate::ScannedSubmit,
    core: Vec<crate::Record>,
    ctx: &Ctx,
) -> Result<Vec<crate::Record>, Refusal> {
    let invalid = || Refusal::new(RuleRef::Input, RefusalReason::InvalidValue);
    let fstp_domain::Command::Submit { proposal, .. } = s.submit() else {
        return Err(invalid());
    };
    let call = current_call(&state.core, *proposal).ok_or_else(invalid)?;
    if s.findings().iter().any(|f| f.call != call) {
        return Err(invalid());
    }
    let mut records: Vec<FindingRecord> = s
        .findings()
        .iter()
        .cloned()
        .map(FindingRecord::Recorded)
        .collect();
    records.push(FindingRecord::IntegrityHeld {
        call,
        proposal: *proposal,
        reasons: s.reasons().to_vec(),
    });
    let mut trial = state.findings.clone();
    for record in &records {
        check_fold(&state.core, &trial, record, ctx.now)
            .map_err(|_| Refusal::new(RuleRef::I11, RefusalReason::GuardFailed))?;
        trial.apply_at(record, ctx.now).map_err(store_refusal)?;
    }
    let mut out = core;
    out.extend(records.into_iter().map(crate::Record::Finding));
    Ok(out)
}

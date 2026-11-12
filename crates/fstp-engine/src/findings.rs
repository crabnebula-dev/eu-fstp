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
        FindingCommand::Record(_) | FindingCommand::Regenerate { .. } => Ok(Vec::new()),
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
    let record = match cmd {
        FindingCommand::Record(f) => decide_record(core, store, f, ctx)?,
        FindingCommand::Mark { finding, mark } => {
            decide_mark(state, *finding, *mark, ctx, answers)?
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
    check_fold(core, store, &record, ctx.now)
        .map_err(|_| Refusal::new(RuleRef::I11, RefusalReason::GuardFailed))?;
    let mut trial = store.clone();
    trial.apply(&record).map_err(store_refusal)?;
    Ok(vec![record])
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
    store.apply(record).map_err(fold_error)
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
        FindingRefusal::UnknownFinding { .. } => FoldError::UnknownEntity,
        FindingRefusal::ForeignConfig { .. }
        | FindingRefusal::RetiredConfig { .. }
        | FindingRefusal::FallbackOutOfOrder { .. }
        | FindingRefusal::FallbackExhausted { .. }
        | FindingRefusal::WrongCall { .. }
        | FindingRefusal::MalformedEvidence { .. } => FoldError::Inconsistent,
    }
}

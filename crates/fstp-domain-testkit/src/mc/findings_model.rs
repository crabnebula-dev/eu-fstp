//! The findings model for fstp-mc, the I-10 twin machine and the I-11 machine (design sections 6.2 and 6.3).
//!
//! Owned by lane L-FIND-B (docs/handoff/m2-design.md section 10).
//!
//! - The envelope adapter ([`engine_command`], [`engine_record`],
//!   [`finding_record`], [`store_of`]) carries `fstp_findings` values
//!   across the `fstp_engine` envelope. It goes through `Any`, so it
//!   compiles before and after the engine's placeholder finding types
//!   become re-exports of `fstp_findings` (lane L-FIND-B seam). While the
//!   placeholders remain, every crossing fails with [`SEAM`].
//! - [`decide_on`] runs one finding command through the engine's
//!   `DomainDecider` and `fstp_engine::apply` on a model world. The world
//!   holds no ledger, so two histories that reach the same situation give
//!   equal states.
//! - [`FindingSide`] is the findings part of a life model state: the
//!   production store, the reference store with its ghost pins, and the
//!   offer budget. `LifeAction::AddFinding` uses it in M-LIFE-S1 and M-FIND.
//! - M-FIND ([`m_find_config`], [`m_find_offers`], [`m_find_properties`]):
//!   two calls, two configurations and one proposal deferred between them
//!   (design 6.3). [`fault_foreign_config`] is its teeth fault.
//! - [`TwinMachine`] is the I-10 twin machine: twin B also receives every
//!   finding command, twin A never does. Twin B decides its core commands
//!   through the engine's `Decider` on an engine state that holds its
//!   finding store ([`engine_exec`]). [`FindingReadingDecider`] is the
//!   teeth decider whose core branch reads the finding store.
//! - [`mark_scenario`] is the reference driver scenario of the mark tests,
//!   and `reference::findings::mark_verdict` judges who may mark (I-03).
//! - [`PinMachine`] is the I-11 machine over the reference driver, with
//!   findings of random configurations, pre-check origin included.
//!
//! Predicates read the reference store, the ghost pins taken from the
//! commands that published each call, and the production finding store.
//! They never read production guard code.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, Ctx, DeclarationSubject};
use fstp_domain::id::{
    AccountId, CallId, CommandId, LlmConfigId, ProgrammeId, ProposalId, VaultEpoch,
};
use fstp_domain::oracle::Answers;
use fstp_domain::policy::{ModelRef, OpaqueValue, ReadAccess};
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::rules::{ParamId, Row, StateTag};
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_engine::{Decider, DomainDecider, EngineState, ExecError};
use fstp_findings::{Finding, FindingCommand, FindingKind, FindingRecord, FindingStore};
use fstp_ledger::{Entry, Seq};
use fstp_mc::{Model, Property};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::findings::{
    ASSESSOR, INJECTION_PHRASES, MARKS, MODEL_C, actor_ctx, assessor_ctx, finding,
    finding_command_id, gen_finding, model as model_ref,
};
use crate::r#gen::policy::{MODEL_A, MODEL_B};
use crate::r#gen::review::{
    COORDINATOR, DraftSpec, L1, L2, PR1, PR2, R1, R2, R3, ReviewSetup, ReviewWorld, StepResult,
    after, plan_of, read, review_truth, run_on, scenario_from, submit, tag, withdraw,
};
use crate::r#gen::roster::{Backend, SodSetup, Step, T0, call, publish};
use crate::harness::prop::{ledger_step, two_way_exec};
use crate::mc::life_model::{
    LifeAction, LifeConfig, LifeModel, LifeSetup, LifeState, LifeWorld, Phases, Start, T_EVAL, Who,
    admit, agree, answer, ask, assign_declared, assignment_of, close, correct, expire, knock_out,
    life_judges, no_questions, rank, reenter, s1_even, s1_vectors, score,
};
use crate::reference::findings::{MarkFacts, RefFindings, check_i11, mark_verdict, same_findings};
use crate::scenario::Scenario;
use crate::vault::Relation;

// ---------------------------------------------------------------------------
// The envelope adapter
// ---------------------------------------------------------------------------

/// The failure of every crossing while `fstp_engine` still holds its
/// placeholder finding types.
pub const SEAM: &str = "L-FIND-B seam: fstp_engine still holds its placeholder finding types, \
     so a fstp_findings value cannot cross the engine envelope (re-export \
     fstp_findings::{FindingStore, FindingCommand, FindingRecord} and route decide_finding)";

/// The engine command for the finding command `cmd`.
pub fn engine_command(cmd: FindingCommand) -> Result<fstp_engine::Command, String> {
    let boxed: Box<dyn Any> = Box::new(cmd);
    boxed
        .downcast::<fstp_engine::FindingCommand>()
        .map(|c| fstp_engine::Command::Finding(*c))
        .map_err(|_| SEAM.to_owned())
}

/// The engine record for the finding record `rec`.
pub fn engine_record(rec: FindingRecord) -> Result<fstp_engine::Record, String> {
    let boxed: Box<dyn Any> = Box::new(rec);
    boxed
        .downcast::<fstp_engine::FindingRecord>()
        .map(|r| fstp_engine::Record::Finding(*r))
        .map_err(|_| SEAM.to_owned())
}

/// The finding record inside `r`, or `None` for a core record.
pub fn finding_record(r: &fstp_engine::Record) -> Option<&FindingRecord> {
    match r {
        fstp_engine::Record::Finding(f) => (f as &dyn Any).downcast_ref::<FindingRecord>(),
        fstp_engine::Record::Core(_)
        | fstp_engine::Record::Creator(_)
        | fstp_engine::Record::Import(_)
        | fstp_engine::Record::Tenant(_) => None,
    }
}

/// The `fstp_findings` store inside the engine's finding store.
pub fn store_of(store: &fstp_engine::FindingStore) -> Result<&FindingStore, String> {
    (store as &dyn Any)
        .downcast_ref::<FindingStore>()
        .ok_or_else(|| SEAM.to_owned())
}

// ---------------------------------------------------------------------------
// Finding commands on a model world
// ---------------------------------------------------------------------------

/// What an accepted finding command left: the core, the store and the records.
#[derive(Clone, Debug)]
pub struct Decided {
    /// The core projection after folding the records.
    pub core: State,
    /// The finding store after folding the records.
    pub store: fstp_engine::FindingStore,
    /// The records `decide` returned, in order.
    pub records: Vec<fstp_engine::Record>,
    /// The finding floor after folding the records.
    pub floor: Timestamp,
}

/// Runs the finding command `cmd` by `ctx` on `rev`'s core and `store`
/// through the engine's `DomainDecider`, answering vault questions from
/// `rev`, and folds the records with `fstp_engine::apply`.
///
/// `Ok(Err)` is a refusal. `Err` is the seam or a batch the fold refuses.
pub fn decide_on(
    rev: &ReviewWorld,
    store: &fstp_engine::FindingStore,
    cmd: FindingCommand,
    ctx: &Ctx,
) -> Result<Result<Decided, Refusal>, String> {
    decide_in(
        rev,
        EngineState::new(rev.sod.state.clone(), store.clone()),
        cmd,
        ctx,
    )
}

/// [`decide_on`] over the engine state `es`, whose core is `rev`'s and
/// whose finding floor the caller keeps.
pub fn decide_in(
    rev: &ReviewWorld,
    mut es: EngineState,
    cmd: FindingCommand,
    ctx: &Ctx,
) -> Result<Result<Decided, Refusal>, String> {
    let cmd = engine_command(cmd)?;
    let questions = match DomainDecider.queries(&es, &cmd, ctx) {
        Ok(q) => q,
        Err(r) => return Ok(Err(r)),
    };
    let mut answers = Answers::new();
    for q in questions {
        let a = rev.answer(&q);
        answers.insert(q, a);
    }
    let records = match DomainDecider.decide(&es, &cmd, ctx, &answers) {
        Ok(r) => r,
        Err(r) => return Ok(Err(r)),
    };
    for r in &records {
        fstp_engine::apply(&mut es, Seq::from_raw(1), ctx.now, r)
            .map_err(|e| format!("the engine refused to fold its own record {r:?}: {e}"))?;
    }
    Ok(Ok(Decided {
        core: es.core,
        store: es.findings,
        records,
        floor: es.finding_floor,
    }))
}

/// Runs the finding command `cmd` by `actor` at `now` through the
/// reference driver of `s`. `Err` is the seam.
pub fn exec_finding(
    s: &mut Scenario,
    cmd: FindingCommand,
    actor: Actor,
    now: Timestamp,
) -> Result<Result<Seq, ExecError>, String> {
    let cmd = engine_command(cmd)?;
    let ctx = s.ctx(now, actor);
    Ok(s.execute(cmd, ctx))
}

// ---------------------------------------------------------------------------
// Ghost pins
// ---------------------------------------------------------------------------

/// What the ghost needs to pin a call: each programme's frozen P-21
/// fallback list at its head, and each call's programme.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PinGhost {
    /// The P-21 fallback list of each programme's head version.
    pub fallbacks: BTreeMap<ProgrammeId, Vec<ModelRef>>,
    /// The programme of each drafted call.
    pub programme_of: BTreeMap<CallId, ProgrammeId>,
}

impl PinGhost {
    /// Follows the accepted `step`. A `PublishCall` pins its call in
    /// `reference` with the configuration the command named and the
    /// fallback list its programme's head holds.
    pub fn observe(&mut self, step: &Step, reference: &mut RefFindings) {
        match &step.cmd {
            Command::CreateProgramme { policy } => {
                self.fallbacks
                    .insert(policy.programme, policy.frozen.p21.fallbacks.clone());
            }
            Command::EditPolicy { version, .. } => {
                self.fallbacks
                    .insert(version.programme, version.frozen.p21.fallbacks.clone());
            }
            Command::DraftCall {
                call, programme, ..
            } => {
                self.programme_of.insert(*call, *programme);
            }
            Command::PublishCall { call, config, .. } => {
                let fallbacks = self
                    .programme_of
                    .get(call)
                    .and_then(|p| self.fallbacks.get(p))
                    .cloned()
                    .unwrap_or_default();
                reference.publish(*call, *config, fallbacks);
            }
            _ => {}
        }
    }
}

/// The reference store and pin ghost after the accepted `steps`.
pub fn ghost_from_steps(steps: &[Step]) -> (PinGhost, RefFindings) {
    let mut pins = PinGhost::default();
    let mut reference = RefFindings::new();
    for s in steps {
        pins.observe(s, &mut reference);
    }
    (pins, reference)
}

// ---------------------------------------------------------------------------
// The findings part of a life model state
// ---------------------------------------------------------------------------

/// The findings part of a life model state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindingSide {
    /// The production finding store. Genesis on the references alone.
    pub store: fstp_engine::FindingStore,
    /// The reference store, with the ghost pins.
    pub reference: RefFindings,
    /// What the ghost needs to pin a later call.
    pub pins: PinGhost,
    /// How many `AddFinding` actions are left.
    pub left: u8,
    /// The offers already stored.
    pub added: BTreeSet<usize>,
}

impl FindingSide {
    /// The side of a model whose start ran the accepted `steps`, with
    /// `budget` findings to add.
    pub fn new(steps: &[Step], budget: u8) -> FindingSide {
        let (pins, reference) = ghost_from_steps(steps);
        FindingSide {
            store: fstp_engine::FindingStore::genesis(),
            reference,
            pins,
            left: budget,
            added: BTreeSet::new(),
        }
    }

    /// Follows an accepted core step, so a later publication is pinned.
    pub fn observe(&mut self, step: &Step) {
        self.pins.observe(step, &mut self.reference);
    }

    /// The same side with every finding removed and every pin kept: the
    /// `strip` of design 6.2 I-10.
    pub fn stripped(&self) -> FindingSide {
        FindingSide {
            store: fstp_engine::FindingStore::genesis(),
            reference: self.reference.stripped(),
            pins: self.pins.clone(),
            left: self.left,
            added: self.added.clone(),
        }
    }
}

/// The current call of `proposal` in the lifecycle reference view.
fn current_call(s: &LifeState, proposal: ProposalId) -> Option<CallId> {
    s.world
        .life
        .proposals
        .get(&proposal)
        .map(|p| p.current_call)
}

/// Pushes `AddFinding(i)` for every offer not yet stored whose call is
/// its proposal's current call, while the budget lasts. A finding is
/// produced by the call the proposal is in (NOTE 8).
pub fn offer_findings(model: &LifeModel, s: &LifeState, actions: &mut Vec<LifeAction>) {
    if s.findings.left == 0 {
        return;
    }
    for (i, f) in model.offers.iter().enumerate() {
        if !s.findings.added.contains(&i) && current_call(s, f.proposal) == Some(f.call) {
            actions.push(LifeAction::AddFinding(i));
        }
    }
}

fn diverge(s: &LifeState, why: String) -> LifeState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

/// The state after `AddFinding(i)`: the offer goes to the reference store
/// and, on production, through the engine's finding decider. Production
/// and the reference are compared in both directions. `None` when both
/// refuse.
pub fn add_finding(model: &LifeModel, s: &LifeState, i: usize) -> Option<LifeState> {
    let f = model.offers.get(i)?.clone();
    let verdict = s.findings.reference.record_verdict(&f);
    let mut next = s.clone();
    match s.world.backend() {
        Backend::Reference => {
            verdict.ok()?;
        }
        Backend::Production => {
            let n = u64::try_from(i).unwrap_or(u64::MAX);
            let ctx = assessor_ctx(s.world.now(), finding_command_id(n));
            match (
                verdict,
                decide_on(
                    &s.world.rev,
                    &s.findings.store,
                    FindingCommand::Record(f.clone()),
                    &ctx,
                ),
            ) {
                (_, Err(e)) => return Some(diverge(s, format!("AddFinding({i}): {e}"))),
                (Err(_), Ok(Err(_))) => return None,
                (Ok(()), Ok(Err(r))) => {
                    return Some(diverge(
                        s,
                        format!(
                            "AddFinding({i}): over-denial, the reference stores {:?}, production refuses with {r}",
                            f.id
                        ),
                    ));
                }
                (Err(why), Ok(Ok(d))) => {
                    return Some(diverge(
                        s,
                        format!(
                            "AddFinding({i}): over-permission, the reference refuses ({why}), production records {:?}",
                            d.records
                        ),
                    ));
                }
                (Ok(()), Ok(Ok(d))) => {
                    next.world.rev.sod.state = d.core;
                    next.findings.store = d.store;
                }
            }
        }
    }
    if let Err(e) = next.findings.reference.record(f) {
        return Some(diverge(s, format!("AddFinding({i}): {e}")));
    }
    next.findings.added.insert(i);
    next.findings.left = next.findings.left.saturating_sub(1);
    Some(next)
}

/// `s` with every finding removed: the `strip` of design 6.2 I-10.
pub fn strip(s: &LifeState) -> LifeState {
    let mut out = s.clone();
    out.findings = s.findings.stripped();
    out
}

/// transition("I-10"): `AddFinding` leaves the core world unchanged, and
/// every other action reaches the same core world from `before` as from
/// `before` with its findings stripped. The predicate captures `model`.
pub fn transition_i10(
    model: &LifeModel,
    before: &LifeState,
    action: &LifeAction,
    after: &LifeState,
) -> Result<(), String> {
    if let LifeAction::AddFinding(i) = action {
        if before.world == after.world {
            return Ok(());
        }
        return Err(format!(
            "I-10: AddFinding({i}) changed the core: PR1 {:?} to {:?}",
            before.state(),
            after.state()
        ));
    }
    match model.step(&strip(before), action) {
        Some(t) if t.world == after.world && t.divergence == after.divergence => Ok(()),
        Some(t) => Err(format!(
            "I-10: {action:?} reached a different core with the findings stripped: PR1 {:?}, not {:?}",
            t.state(),
            after.state()
        )),
        None => Err(format!(
            "I-10: {action:?} is enabled only while findings are stored"
        )),
    }
}

/// always("I-11") on a life model state over `calls`: the reference store
/// and, on production, the production store hold for each call only
/// findings under the configuration the ghost pinned, and production
/// holds exactly the reference's findings.
pub fn side_i11(s: &LifeState, calls: &[CallId]) -> Result<(), String> {
    let side = &s.findings;
    check_i11(&side.reference, calls, |c| side.reference.findings_of(c))?;
    if s.world.backend() == Backend::Production {
        let store = store_of(&side.store)?;
        check_i11(&side.reference, calls, |c| store.findings_of(c))?;
        same_findings(&side.reference, calls, |c| store.findings_of(c))?;
    }
    Ok(())
}

/// Whether the reference store holds a finding of `call`.
pub fn holds_finding(s: &LifeState, call: CallId) -> bool {
    !s.findings.reference.findings_of(call).is_empty()
}

// ---------------------------------------------------------------------------
// M-LIFE-S1 with findings (I-10)
// ---------------------------------------------------------------------------

/// The two findings M-LIFE-S1 offers beside every action (design 6.3):
/// an integrity finding that holds an injection phrase, and a quality
/// finding on criterion 1 whose statement is a JSON command. Both carry
/// call 1's pinned configuration.
pub fn s1_finding_offers() -> Vec<Finding> {
    let pin = LlmConfigId::from_raw(call(1).raw());
    vec![
        finding(
            11,
            call(1),
            PR1,
            pin,
            FindingKind::Integrity,
            INJECTION_PHRASES[0],
        ),
        finding(
            12,
            call(1),
            PR1,
            pin,
            FindingKind::Quality,
            INJECTION_PHRASES[3],
        ),
    ]
}

/// At most two `AddFinding` actions in M-LIFE-S1 (design 6.2 I-10).
pub const S1_FINDING_BUDGET: u8 = 2;

/// M-LIFE-S1 with weights (1, 1) at P-02 50.00 and the two finding offers.
pub fn s1_findings_model(backend: Backend) -> Result<LifeModel, String> {
    LifeModel::with_findings(s1_even(), backend, s1_finding_offers(), S1_FINDING_BUDGET)
}

/// The state count of M-LIFE-S1 with findings, measured on production in
/// step W6. The references store 22_792.
pub const M_LIFE_S1_FINDINGS_STATES: usize = 27_064;
/// The state count of M-LIFE-S1 with findings on the references, the
/// tripwire of its `_reference` twin (design 6.1).
pub const M_LIFE_S1_FINDINGS_REFERENCE_STATES: usize = 22_792;

/// The I-10 properties of M-LIFE-S1 with findings: every M-LIFE-S1
/// property, transition("I-10"), always("I-11"), and witnesses of stored
/// findings beside both stage 1 exits.
pub fn s1_findings_properties(model: &LifeModel) -> Vec<Property<'_, LifeModel>> {
    let mut out = crate::mc::life_model::s1_properties::<LifeModel>();
    out.push(Property::transition_with(
        "I-10",
        move |b: &LifeState, a: &LifeAction, t: &LifeState| transition_i10(model, b, a, t),
    ));
    out.push(Property::always_with("I-11", |s: &LifeState| {
        side_i11(s, &[call(1), call(2)])
    }));
    out.push(Property::reachable(
        "I-10 witness: two findings stored and PR1 in STAGE2",
        |s: &LifeState| {
            s.findings.added.len() == 2 && s.state() == Some(StateTag::Stage2) && agree(s).is_ok()
        },
    ));
    out.push(Property::reachable(
        "I-10 witness: a finding stored and PR1 NOT_SELECTED",
        |s: &LifeState| {
            !s.findings.added.is_empty()
                && s.state() == Some(StateTag::NotSelected)
                && agree(s).is_ok()
        },
    ));
    out
}

// ---------------------------------------------------------------------------
// M-FIND (I-11)
// ---------------------------------------------------------------------------

/// The pin of `call` in the life setups: `publish` names the
/// configuration with the call's raw id.
pub fn pin_of(c: CallId) -> LlmConfigId {
    LlmConfigId::from_raw(c.raw())
}

/// The three findings M-FIND offers: one of call 1 under its pin, one of
/// call 2 under its pin, and one of call 2 under call 1's configuration,
/// which I-11 refuses.
pub fn m_find_offers() -> Vec<Finding> {
    vec![
        finding(
            21,
            call(1),
            PR1,
            pin_of(call(1)),
            FindingKind::Integrity,
            INJECTION_PHRASES[1],
        ),
        finding(
            22,
            call(2),
            PR1,
            pin_of(call(2)),
            FindingKind::Completeness,
            INJECTION_PHRASES[4],
        ),
        finding(
            23,
            call(2),
            PR1,
            pin_of(call(1)),
            FindingKind::Accuracy,
            INJECTION_PHRASES[5],
        ),
    ]
}

/// M-FIND offers three findings (design 6.3).
pub const M_FIND_BUDGET: u8 = 3;

/// M-FIND (design 6.3): PR1 in STAGE2 of call 1 from genesis with two
/// reviewers. Actions: the reduced clock, expiry to DEFERRED, publication
/// of call 2, re-entry into call 2, fresh assignments there, and the three
/// finding offers, each while its call is PR1's current call.
pub fn m_find_config() -> LifeConfig {
    LifeConfig {
        setup: LifeSetup {
            scale_max: 2,
            weights: vec![1, 1],
            p02_bp: 5_000,
            p03: 2,
            p07_days: 28,
            p15: 2,
            judges: life_judges(),
            proposals: vec![(L1, PR1, false)],
            reviewers: vec![R1, R2],
            start_scores: vec![vec![2, 1], vec![2, 1]],
            revision_scores: Vec::new(),
            start: Start::Stage2,
        },
        reviewers: vec![R1, R2],
        vectors: Vec::new(),
        vectors2: Vec::new(),
        corrections: 0,
        conflicts: Vec::new(),
        havoc: Vec::new(),
        revisions: 0,
        spares: Vec::new(),
        phases: Phases {
            intake: false,
            stage1: false,
            stage2: false,
            revisions: false,
            deferral: true,
            after: false,
            withdraw: false,
        },
    }
}

/// M-FIND over `backend`, with its start built from genesis.
pub fn m_find_model(backend: Backend) -> Result<LifeModel, String> {
    LifeModel::with_findings(m_find_config(), backend, m_find_offers(), M_FIND_BUDGET)
}

/// The state count of M-FIND, measured on production in step W6. The
/// references store 74.
pub const M_FIND_STATES: usize = 110;
/// The state count of M-FIND on the references, the tripwire of its
/// `_reference` twin (design 6.1).
pub const M_FIND_REFERENCE_STATES: usize = 74;

/// The calls of M-FIND.
pub const M_FIND_CALLS: [CallId; 2] = [call(1), call(2)];

/// Whether PR1 sits in call 2 after re-entry while call 1 still holds the
/// finding it produced (NOTE 8).
pub fn finding_stayed_with_call_1(s: &LifeState) -> bool {
    current_call(s, PR1) == Some(call(2))
        && s.findings
            .reference
            .findings_of(call(1))
            .iter()
            .any(|f| f.proposal == PR1)
}

/// The M-FIND properties that need no model: always("I-11") and the
/// witness of a stored finding in call 1. The teeth runs use them.
pub fn m_find_core_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LifeState> + 'a,
{
    vec![
        Property::always_with("I-11", |s: &LifeState| side_i11(s, &M_FIND_CALLS)),
        Property::reachable(
            "I-11 witness: a finding stored in call 1",
            |s: &LifeState| holds_finding(s, call(1)),
        ),
    ]
}

/// The M-FIND properties: two-way, always("I-11"), transition("I-10"),
/// and witnesses of a stored finding in each call and of call 1 keeping
/// its finding after re-entry.
pub fn m_find_properties(model: &LifeModel) -> Vec<Property<'_, LifeModel>> {
    let mut out = vec![Property::always_with("two-way", agree)];
    out.extend(m_find_core_properties::<LifeModel>());
    out.push(Property::transition_with(
        "I-10",
        move |b: &LifeState, a: &LifeAction, t: &LifeState| transition_i10(model, b, a, t),
    ));
    out.push(Property::reachable(
        "I-11 witness: a finding stored in call 2",
        |s: &LifeState| holds_finding(s, call(2)) && agree(s).is_ok(),
    ));
    out.push(Property::reachable(
        "NOTE 8 witness: call 1 keeps its finding after re-entry",
        |s: &LifeState| finding_stayed_with_call_1(s) && agree(s).is_ok(),
    ));
    out
}

/// The id of the finding [`fault_foreign_config`] injects.
pub const FOREIGN_FINDING: u128 = 999;

/// The I-11 fault: an engine that stores a finding of PR1's current call
/// under a configuration no call pinned. On production it folds the
/// finding record into the finding store with `FindingStore::apply`,
/// past the engine's check against the published pin. On the references
/// it forces the finding into the reference store.
pub fn fault_foreign_config(s: &LifeState) -> Option<LifeState> {
    if s.divergence.is_some() {
        return None;
    }
    let c = current_call(s, PR1)?;
    s.findings.reference.expected(c)?;
    let f = finding(
        FOREIGN_FINDING,
        c,
        PR1,
        LlmConfigId::from_raw(99),
        FindingKind::Quality,
        INJECTION_PHRASES[2],
    );
    let mut next = s.clone();
    match s.world.backend() {
        Backend::Production => {
            if store_of(&s.findings.store).ok()?.is_taken(f.id) {
                return None;
            }
            // The public `fstp_engine::apply` checks a record against the
            // call's published pin, so the fault folds at the store level.
            next.findings
                .store
                .apply(&FindingRecord::Recorded(f))
                .ok()?;
        }
        Backend::Reference => {
            if s.findings.reference.taken.contains(&f.id) {
                return None;
            }
            if !next.findings.reference.force_insert(f) {
                return None;
            }
        }
    }
    Some(next)
}

// ---------------------------------------------------------------------------
// The I-10 twin machine
// ---------------------------------------------------------------------------

/// The command id of twin B's core steps. It equals the id that
/// `ReviewWorld::exec` gives twin A's steps, so both twins decide under
/// the same context.
const TWIN_CORE_COMMAND: CommandId = CommandId::from_bytes(*b"model:rev:steps!");

/// Runs the core step `step` on `w` through `decider`, over the engine
/// state of `w`'s core, the finding store `store` and the finding floor
/// `floor`. Vault questions are answered from `w`. Nothing is committed.
///
/// `Err` is a finding record in the batch of a core command (I-10).
pub fn engine_core<D: Decider>(
    decider: &D,
    w: &ReviewWorld,
    store: &fstp_engine::FindingStore,
    floor: Timestamp,
    step: &Step,
) -> Result<Result<Vec<Record>, Refusal>, String> {
    let mut es = EngineState::new(w.sod.state.clone(), store.clone());
    es.finding_floor = floor;
    let ctx = step.ctx(w.sod.now, TWIN_CORE_COMMAND);
    let cmd = fstp_engine::Command::Core(step.cmd.clone());
    let questions = match decider.queries(&es, &cmd, &ctx) {
        Ok(q) => q,
        Err(r) => return Ok(Err(r)),
    };
    let mut answers = Answers::new();
    for q in questions {
        let a = w.answer(&q);
        answers.insert(q, a);
    }
    let batch = match decider.decide(&es, &cmd, &ctx, &answers) {
        Ok(b) => b,
        Err(r) => return Ok(Err(r)),
    };
    let mut out = Vec::with_capacity(batch.len());
    for r in batch {
        match r {
            fstp_engine::Record::Core(c) => out.push(c),
            fstp_engine::Record::Finding(f) => {
                return Err(format!(
                    "I-10: the core command {:?} emitted the finding record {f:?}",
                    step.cmd.kind()
                ));
            }
            other @ (fstp_engine::Record::Creator(_)
            | fstp_engine::Record::Import(_)
            | fstp_engine::Record::Tenant(_)) => {
                return Err(format!(
                    "the core command {:?} emitted the non-core record {other:?}",
                    step.cmd.kind()
                ));
            }
        }
    }
    Ok(Ok(out))
}

/// `ReviewWorld::sync` through `decider` on the engine state of `w`,
/// `store` and `floor`: processes a newer vault epoch with `VaultChanged`.
pub fn engine_sync<D: Decider>(
    decider: &D,
    w: &mut ReviewWorld,
    store: &fstp_engine::FindingStore,
    floor: Timestamp,
) -> StepResult {
    if w.vault_epoch() <= w.processed() {
        return Ok(Ok(Vec::new()));
    }
    let step = w.vault_step();
    let records = match engine_core(decider, w, store, floor, &step)? {
        Ok(r) => r,
        Err(r) => return Ok(Err(r)),
    };
    w.commit(&records)?;
    Ok(Ok(records))
}

/// `ReviewWorld::exec` on production through `decider` on the engine
/// state of `w`, `store` and `floor`: the vault change first, then `step`.
/// The finding store is in the path, so a decider that lets findings
/// reach a core outcome is visible to the twin comparison.
pub fn engine_exec<D: Decider>(
    decider: &D,
    w: &mut ReviewWorld,
    store: &fstp_engine::FindingStore,
    floor: Timestamp,
    step: &Step,
) -> StepResult {
    if let Err(r) = engine_sync(decider, w, store, floor)? {
        return Ok(Err(r));
    }
    let records = match engine_core(decider, w, store, floor, step)? {
        Ok(r) => r,
        Err(r) => return Ok(Err(r)),
    };
    w.commit(&records)?;
    Ok(Ok(records))
}

/// A broken engine decider for the I-10 teeth: its core branch reads the
/// finding store and refuses every core command while call 1 holds a
/// finding. Finding commands go to the production decider.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FindingReadingDecider;

impl Decider for FindingReadingDecider {
    fn queries(
        &self,
        state: &EngineState,
        cmd: &fstp_engine::Command,
        ctx: &Ctx,
    ) -> Result<Vec<fstp_domain::oracle::Query>, Refusal> {
        DomainDecider.queries(state, cmd, ctx)
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &fstp_engine::Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<fstp_engine::Record>, Refusal> {
        if matches!(cmd, fstp_engine::Command::Core(_))
            && !state.findings.findings_of(call(1)).is_empty()
        {
            return Err(Refusal::new(RuleRef::I10, RefusalReason::GuardFailed));
        }
        DomainDecider.decide(state, cmd, ctx, answers)
    }
}

/// The value of P-28 "on".
pub fn p28_on() -> Result<OpaqueValue, String> {
    OpaqueValue::from_value(&fstp_json::Value::Bool(true)).map_err(|e| format!("P-28: {e:?}"))
}

/// Where the twins start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TwinStart {
    /// PR1 admitted to STAGE1.
    Stage1,
    /// PR1 in STAGE2 after every reviewer scored 75.00 and the close.
    Stage2,
}

/// The world of the twins: M-LIFE-S1's setup with P-28 on, PR1 admitted
/// to STAGE1 with R1, R2 and R3 assigned and declared, from genesis. For
/// [`TwinStart::Stage2`], every reviewer then scores (2, 1) and the
/// coordinator closes stage 1, so PR1 is in STAGE2.
pub fn twin_start(from: TwinStart) -> Result<ReviewWorld, String> {
    let setup = s1_even().setup;
    let on = p28_on()?;
    let mut steps = setup.draft_steps()?;
    for s in &mut steps {
        if let Command::CreateProgramme { policy } = &mut s.cmd {
            policy.frozen.opaque.insert(ParamId::P28, on.clone());
        }
    }
    let mut w = LifeWorld::from_steps(Backend::Production, setup.truth(), &steps)?;
    w = w.must(&submit(L1, PR1, plan_of(PR1), false))?;
    w.set_now(T_EVAL);
    for r in &setup.reviewers {
        for s in assign_declared(*r, PR1, call(1), AssignmentKind::Reviewer) {
            w = w.must(&s)?;
        }
    }
    w = w.must(&crate::r#gen::review::declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ))?;
    w = w.must(&knock_out(PR1, true))?;
    w = w.must(&admit(PR1))?;
    if from == TwinStart::Stage2 {
        for r in &setup.reviewers {
            let key = ScoreKey {
                assignment: assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer),
                stage: Stage::One,
                plan: plan_of(PR1),
            };
            w = w.must(&score(*r, key, &[2, 1]))?;
        }
        w = w.must(&close(Actor::Account(COORDINATOR), PR1))?;
    }
    Ok(w.rev)
}

/// One command of the twin machine.
#[derive(Clone, Debug)]
pub enum TwinCmd {
    /// A core command, run on both twins.
    Core(Step),
    /// `now` moves on by this many microseconds on both twins.
    Tick(i64),
    /// The vault relates the reviewer to the lead on both twins, and both
    /// process the change.
    Conflict(AccountId),
    /// A finding command by `actor`, run on twin B only.
    Finding {
        /// The command.
        cmd: FindingCommand,
        /// The actor.
        actor: Actor,
    },
}

/// The twin machine's model: the finding ids drawn so far.
#[derive(Clone, Debug, Default)]
pub struct TwinModel {
    /// Every finding id a command named.
    pub ids: Vec<u128>,
    /// The next fresh finding id.
    pub next_id: u128,
}

/// The twins: A never sees a finding, B sees every finding command.
#[derive(Clone, Debug)]
pub struct TwinSut {
    /// Twin A.
    pub a: ReviewWorld,
    /// Twin B.
    pub b: ReviewWorld,
    /// Twin B's finding store.
    pub b_store: fstp_engine::FindingStore,
    /// Every core record twin A committed, in order.
    pub a_log: Vec<Record>,
    /// Every core record twin B committed, in order, finding records removed.
    pub b_log: Vec<Record>,
    /// The first seam failure, reported after the I-10 comparisons.
    pub seam: Option<String>,
    /// The finding commands run so far.
    pub n: u64,
    /// The time of twin B's latest finding entry, the engine's finding floor.
    pub b_floor: Timestamp,
}

/// What one twin command did.
#[derive(Debug)]
pub enum TwinOutput {
    /// A core command's results on A and B.
    Core {
        /// Twin A.
        a: crate::r#gen::review::StepResult,
        /// Twin B.
        b: crate::r#gen::review::StepResult,
    },
    /// The vault reaction on A and B.
    Vault {
        /// Twin A.
        a: crate::r#gen::review::StepResult,
        /// Twin B.
        b: crate::r#gen::review::StepResult,
    },
    /// The clock moved.
    Tick,
    /// A finding command's result on B, and for a `Mark` the reference
    /// verdict on twin B before it.
    Finding {
        /// The records, a refusal, or the seam.
        out: Result<Result<Vec<fstp_engine::Record>, Refusal>, String>,
        /// The reference verdict of a `Mark`, `None` for other commands.
        mark: Option<Result<(), String>>,
    },
}

/// The I-10 twin machine (design 6.2): random lifecycle commands from
/// STAGE1 on both twins, and finding commands of every kind, severity,
/// criterion and confidence, with generated strings and injection
/// phrases, on twin B only. P-28 is on.
///
/// Twin B runs its core commands and vault changes through the engine's
/// `DomainDecider` on an engine state that holds its finding store, so a
/// decider that lets findings reach a core outcome is in the path.
///
/// Postconditions: each core command gives identical records or identical
/// refusals on both twins, a finding command emits only finding records,
/// and a `Mark` is accepted exactly when the reference allows it (I-03).
/// Invariant: identical core projections, and identical core
/// ledgers after removing finding records. A seam failure is reported
/// after these checks.
///
/// With `fault`, the adapter folds a core transition into twin B whenever
/// B receives a finding command: the teeth of
/// `i10_teeth_finding_driven_transition_is_caught`. With `reading`, twin B
/// decides core commands with [`FindingReadingDecider`]: the teeth of
/// `i10_teeth_core_decider_reading_findings_is_caught`.
pub struct TwinMachine {
    /// The start world of both twins.
    pub start: ReviewWorld,
    /// Whether the adapter injects the fault.
    pub fault: bool,
    /// Where the twins start. It also sets the command weights.
    pub from: TwinStart,
    /// Whether twin B decides with [`FindingReadingDecider`].
    pub reading: bool,
}

impl TwinMachine {
    /// The machine from [`twin_start`] at `from`.
    pub fn new(from: TwinStart, fault: bool) -> Result<TwinMachine, String> {
        Ok(TwinMachine {
            start: twin_start(from)?,
            fault,
            from,
            reading: false,
        })
    }

    /// The machine from [`twin_start`] at `from` whose twin B decides core
    /// commands with [`FindingReadingDecider`].
    pub fn reading(from: TwinStart) -> Result<TwinMachine, String> {
        Ok(TwinMachine {
            start: twin_start(from)?,
            fault: false,
            from,
            reading: true,
        })
    }

    /// Runs `step` on twin B through the decider this machine names.
    fn exec_b(&self, sut: &mut TwinSut, step: &Step) -> StepResult {
        let (store, floor) = (&sut.b_store, sut.b_floor);
        if self.reading {
            engine_exec(&FindingReadingDecider, &mut sut.b, store, floor, step)
        } else {
            engine_exec(&DomainDecider, &mut sut.b, store, floor, step)
        }
    }

    /// Processes twin B's vault change through the decider this machine names.
    fn sync_b(&self, sut: &mut TwinSut) -> StepResult {
        let (store, floor) = (&sut.b_store, sut.b_floor);
        if self.reading {
            engine_sync(&FindingReadingDecider, &mut sut.b, store, floor)
        } else {
            engine_sync(&DomainDecider, &mut sut.b, store, floor)
        }
    }
}

/// The reference verdict on twin B of a `Mark` of `finding` by `actor`
/// (I-03). The finding's call and proposal come from twin B's store.
fn twin_mark_verdict(
    sut: &TwinSut,
    finding: fstp_findings::FindingId,
    actor: Actor,
) -> Result<(), String> {
    let at = sut.b_store.finding(finding).map(|f| (f.call, f.proposal));
    let conflicts = sut.b.facts();
    let facts = MarkFacts {
        review: &sut.b.view,
        roles: &sut.b.sod.view,
        conflicts: &conflicts,
        vault_current: sut.b.vault_epoch() <= sut.b.processed(),
        now: sut.b.sod.now,
    };
    mark_verdict(at, actor, &facts)
}

/// One day in microseconds.
pub const DAY: i64 = 86_400_000_000;

fn twin_core(g: &mut Gen, from: TwinStart) -> TwinCmd {
    let r = *g.pick(&[R1, R2, R3]);
    let assignment = assignment_of(r, PR1, call(1), AssignmentKind::Reviewer);
    let key = ScoreKey {
        assignment,
        stage: Stage::One,
        plan: plan_of(PR1),
    };
    let vectors = s1_vectors();
    // Score, correct, close, ask, no questions, answer, rank, expire,
    // publish, re-enter, withdraw, read, tick, conflict.
    let weights: [u32; 14] = match from {
        TwinStart::Stage1 => [10, 1, 3, 2, 4, 1, 3, 1, 1, 1, 1, 1, 2, 1],
        TwinStart::Stage2 => [1, 1, 1, 3, 6, 2, 4, 2, 2, 2, 1, 1, 3, 1],
    };
    match g.weighted(&weights) {
        0 => TwinCmd::Core(score(r, key, g.pick(&vectors))),
        1 => TwinCmd::Core(correct(r, key, g.pick(&vectors))),
        2 => {
            let who = *g.pick(&[Who::Named, Who::Other, Who::System]);
            let actor = match who {
                Who::Named => Actor::Account(COORDINATOR),
                Who::Other => Actor::Account(R1),
                Who::System => ASSESSOR,
            };
            TwinCmd::Core(close(actor, PR1))
        }
        3 => TwinCmd::Core(ask(r, PR1, assignment)),
        4 => TwinCmd::Core(no_questions(r, PR1, assignment)),
        5 => TwinCmd::Core(answer(L1, PR1)),
        6 => TwinCmd::Core(rank(r, PR1)),
        7 => TwinCmd::Core(expire(PR1)),
        8 => TwinCmd::Core(publish(call(2))),
        9 => TwinCmd::Core(reenter(PR1, call(2))),
        10 => TwinCmd::Core(withdraw(L1, PR1)),
        11 => TwinCmd::Core(read(r, PR1)),
        12 => TwinCmd::Tick(*g.pick(&[1, DAY, DAY.saturating_mul(29)])),
        _ => TwinCmd::Conflict(r),
    }
}

fn twin_id(g: &mut Gen, model: &TwinModel, k: u128) -> u128 {
    if !model.ids.is_empty() && g.weighted(&[4, 1]) == 1 {
        *g.pick(&model.ids)
    } else {
        model.next_id.saturating_add(k)
    }
}

fn twin_finding(g: &mut Gen, model: &TwinModel) -> TwinCmd {
    match g.weighted(&[5, 2, 1]) {
        0 => {
            let id = twin_id(g, model, 0);
            let c = *g.pick(&[call(1), call(1), call(2), call(9)]);
            let config = LlmConfigId::from_raw(*g.pick(&[1, 1, 1, 2, 7]));
            TwinCmd::Finding {
                cmd: FindingCommand::Record(gen_finding(g, id, c, PR1, config, true)),
                actor: ASSESSOR,
            }
        }
        1 => {
            let id = if model.ids.is_empty() || g.weighted(&[4, 1]) == 1 {
                u128::from(g.u8_in(1..=5))
            } else {
                *g.pick(&model.ids)
            };
            let actor = if g.weighted(&[5, 1]) == 0 {
                Actor::Account(*g.pick(&[R1, R2, R3, L1, COORDINATOR]))
            } else {
                ASSESSOR
            };
            TwinCmd::Finding {
                cmd: FindingCommand::Mark {
                    finding: fstp_findings::FindingId::from_raw(id),
                    mark: *g.pick(&MARKS),
                },
                actor,
            }
        }
        _ => {
            let config = LlmConfigId::from_raw(*g.pick(&[3, 4, 1]));
            let config_model = model_ref(g.pick(&[MODEL_B, MODEL_A, MODEL_C]));
            let n = g.usize_in(0..=2);
            let mut findings = Vec::new();
            for k in 0..n {
                let id = twin_id(g, model, u128::try_from(k).unwrap_or(0));
                findings.push(gen_finding(g, id, call(1), PR1, config, true));
            }
            TwinCmd::Finding {
                cmd: FindingCommand::Regenerate {
                    call: call(1),
                    config,
                    config_model,
                    findings,
                },
                actor: ASSESSOR,
            }
        }
    }
}

/// The finding ids `cmd` names.
fn named_ids(cmd: &FindingCommand) -> Vec<u128> {
    match cmd {
        FindingCommand::Record(f) => vec![f.id.raw()],
        FindingCommand::Mark { finding, .. } => vec![finding.raw()],
        FindingCommand::Regenerate { findings, .. } => {
            findings.iter().map(|f| f.id.raw()).collect()
        }
    }
}

/// Folds a core transition into `b` as a broken engine would: PR1 is
/// withdrawn from whatever state allows it, or else the vault epoch
/// moves. Returns the record, or `None` when no candidate folds.
fn inject_core(b: &mut ReviewWorld) -> Option<Record> {
    let mut candidates: Vec<Record> = [
        StateTag::Stage1,
        StateTag::Stage2,
        StateTag::Deferred,
        StateTag::Ranked,
    ]
    .into_iter()
    .map(|from| {
        Record::Transitioned(Transitioned {
            proposal: PR1,
            from,
            to: StateTag::Withdrawn,
            row: Row::Withdraw,
            actor: Actor::Account(L1),
            decision: None,
        })
    })
    .collect();
    candidates.push(Record::VaultEpochProcessed {
        epoch: VaultEpoch::from_raw(b.processed().raw().saturating_add(1)),
    });
    for rec in candidates {
        let mut w = b.clone();
        if w.commit(std::slice::from_ref(&rec)).is_ok() {
            *b = w;
            return Some(rec);
        }
    }
    None
}

fn log(out: &crate::r#gen::review::StepResult, to: &mut Vec<Record>) {
    if let Ok(Ok(records)) = out {
        to.extend(records.iter().cloned());
    }
}

impl StateMachine for TwinMachine {
    type Model = TwinModel;
    type Sut = TwinSut;
    type Command = TwinCmd;
    type Output = TwinOutput;

    fn init_model(&self) -> TwinModel {
        TwinModel {
            ids: Vec::new(),
            next_id: 1,
        }
    }

    fn init_sut(&self) -> TwinSut {
        TwinSut {
            a: self.start.clone(),
            b: self.start.clone(),
            b_store: fstp_engine::FindingStore::genesis(),
            a_log: Vec::new(),
            b_log: Vec::new(),
            seam: None,
            n: 0,
            b_floor: Timestamp::from_micros(0),
        }
    }

    fn command(&self, g: &mut Gen, model: &TwinModel) -> TwinCmd {
        if g.weighted(&[3, 2]) == 0 {
            twin_core(g, self.from)
        } else {
            twin_finding(g, model)
        }
    }

    fn run(&self, sut: &mut TwinSut, cmd: &TwinCmd) -> TwinOutput {
        match cmd {
            TwinCmd::Core(step) => {
                let a = sut.a.exec(step);
                let b = self.exec_b(sut, step);
                log(&a, &mut sut.a_log);
                log(&b, &mut sut.b_log);
                TwinOutput::Core { a, b }
            }
            TwinCmd::Tick(d) => {
                sut.a.sod.now = after(sut.a.sod.now, *d);
                sut.b.sod.now = after(sut.b.sod.now, *d);
                TwinOutput::Tick
            }
            TwinCmd::Conflict(r) => {
                for w in [&mut sut.a, &mut sut.b] {
                    w.sod.truth.relate(tag(*r), tag(L1), Relation::CoWorker);
                }
                let a = sut.a.sync();
                let b = self.sync_b(sut);
                log(&a, &mut sut.a_log);
                log(&b, &mut sut.b_log);
                TwinOutput::Vault { a, b }
            }
            TwinCmd::Finding { cmd, actor } => {
                if self.fault
                    && let Some(rec) = inject_core(&mut sut.b)
                {
                    sut.b_log.push(rec);
                }
                sut.n = sut.n.saturating_add(1);
                let ctx = actor_ctx(sut.b.sod.now, *actor, finding_command_id(sut.n));
                let mark = match cmd {
                    FindingCommand::Mark { finding, .. } => {
                        Some(twin_mark_verdict(sut, *finding, *actor))
                    }
                    FindingCommand::Record(_) | FindingCommand::Regenerate { .. } => None,
                };
                let mut es = EngineState::new(sut.b.sod.state.clone(), sut.b_store.clone());
                es.finding_floor = sut.b_floor;
                let out = decide_in(&sut.b, es, cmd.clone(), &ctx);
                match &out {
                    Err(e) => {
                        if sut.seam.is_none() {
                            sut.seam = Some(e.clone());
                        }
                    }
                    Ok(Ok(d)) => {
                        sut.b.sod.state = d.core.clone();
                        sut.b_store = d.store.clone();
                        sut.b_floor = d.floor;
                        for r in &d.records {
                            if let fstp_engine::Record::Core(c) = r {
                                sut.b_log.push(c.clone());
                            }
                        }
                    }
                    Ok(Err(_)) => {}
                }
                TwinOutput::Finding {
                    out: out.map(|r| r.map(|d| d.records)),
                    mark,
                }
            }
        }
    }

    fn next_state(&self, model: &mut TwinModel, cmd: &TwinCmd) {
        if let TwinCmd::Finding { cmd, .. } = cmd {
            for id in named_ids(cmd) {
                if !model.ids.contains(&id) {
                    model.ids.push(id);
                }
                if id >= model.next_id {
                    model.next_id = id.saturating_add(1);
                }
            }
        }
    }

    fn postcondition(
        &self,
        _model: &TwinModel,
        _cmd: &TwinCmd,
        output: &TwinOutput,
    ) -> Result<(), String> {
        match output {
            TwinOutput::Core { a, b } | TwinOutput::Vault { a, b } => {
                if let Err(e) = a {
                    return Err(format!("harness: twin A failed: {e}"));
                }
                if a != b {
                    return Err(format!(
                        "I-10: the twins answered a core command differently: A {a:?}, B {b:?}"
                    ));
                }
                Ok(())
            }
            TwinOutput::Finding { out, mark } => {
                if let Ok(Ok(records)) = out
                    && let Some(r) = records
                        .iter()
                        .find(|r| matches!(r, fstp_engine::Record::Core(_)))
                {
                    return Err(format!(
                        "I-10: a finding command emitted the core record {r:?}"
                    ));
                }
                match (mark, out) {
                    (Some(Ok(())), Ok(Err(r))) => Err(format!(
                        "I-03 two-way: over-denial, the reference allows the mark, production refuses with {r}"
                    )),
                    (Some(Err(why)), Ok(Ok(records))) => Err(format!(
                        "I-03 two-way: over-permission, the reference refuses the mark ({why}), production records {records:?}"
                    )),
                    _ => Ok(()),
                }
            }
            TwinOutput::Tick => Ok(()),
        }
    }

    fn invariant(&self, _model: &TwinModel, sut: &TwinSut) -> Result<(), String> {
        if sut.a.sod.state != sut.b.sod.state {
            return Err(format!(
                "I-10: twin B's core projection differs from twin A's ({} core records in A, {} in B)",
                sut.a_log.len(),
                sut.b_log.len()
            ));
        }
        if sut.a_log != sut.b_log {
            return Err(format!(
                "I-10: the core ledgers differ after removing finding records: A {:?}, B {:?}",
                sut.a_log.last(),
                sut.b_log.last()
            ));
        }
        match &sut.seam {
            Some(s) => Err(s.clone()),
            None => Ok(()),
        }
    }

    fn max_commands(&self) -> usize {
        48
    }
}

// ---------------------------------------------------------------------------
// The I-11 machine over the reference driver
// ---------------------------------------------------------------------------

/// The setup of the I-11 machine: calls 1, 2 and 3 drafted and approved,
/// calls 1 and 2 published with configurations 1 and 2, PR1 in DRAFT in
/// call 1 by L1 and PR2 in DRAFT in call 2 by L2. Call 3 has no pin.
pub fn pin_setup() -> ReviewSetup {
    let mut base = SodSetup::one(0, &[1, 2, 3]);
    base.published = vec![call(1), call(2)];
    let draft = |lead, proposal, c| DraftSpec {
        lead,
        proposal,
        call: c,
        team: Vec::new(),
        minor: false,
        submit: false,
    };
    ReviewSetup {
        base,
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: vec![(COORDINATOR, Role::FstpCoordinator, None)],
        drafts: vec![draft(L1, PR1, call(1)), draft(L2, PR2, call(2))],
    }
}

/// A scenario of [`pin_setup`] from genesis through the reference driver,
/// with the reference store and pin ghost of its publications.
pub fn pin_scenario() -> Result<(Scenario, RefFindings), String> {
    let setup = pin_setup();
    let s = scenario_from(&setup, review_truth(setup.accounts()))?;
    let (_, ghost) = ghost_from_steps(&setup.steps()?);
    Ok((s, ghost))
}

/// [`pin_scenario`] with `fallbacks` as the frozen P-21 fallback list of
/// the programme, so every call publishes with it.
pub fn pin_scenario_with_fallbacks(
    fallbacks: Vec<ModelRef>,
) -> Result<(Scenario, RefFindings), String> {
    let setup = pin_setup();
    let mut steps = setup.steps()?;
    for s in &mut steps {
        if let Command::CreateProgramme { policy } = &mut s.cmd {
            policy.frozen.p21.fallbacks = fallbacks.clone();
        }
    }
    let mut s =
        Scenario::new(review_truth(setup.accounts())).map_err(|e| format!("open: {e:?}"))?;
    for step in &steps {
        match run_on(&mut s, step, T0) {
            Ok(_) => {}
            Err(e) => return Err(format!("setup step {:?}: {e:?}", step.cmd.kind())),
        }
    }
    let (_, ghost) = ghost_from_steps(&steps);
    Ok((s, ghost))
}

/// The finding [`mark_scenario`] stores: a quality finding of call 1 on PR1.
pub const MARKED_FINDING: u128 = 1;

/// A scenario through the reference driver for the mark tests:
/// M-LIFE-S1's setup from genesis, PR1 submitted at `T0` and admitted to
/// STAGE1 at `T_EVAL`, with R1, R2 and R3 assigned and declared, and
/// [`MARKED_FINDING`] stored under call 1's pin at `T_EVAL`.
pub fn mark_scenario() -> Result<Scenario, String> {
    let setup = s1_even().setup;
    let mut s = Scenario::new(setup.truth()).map_err(|e| format!("open: {e:?}"))?;
    let mut early = setup.draft_steps()?;
    early.push(submit(L1, PR1, plan_of(PR1), false));
    let mut late = Vec::new();
    for r in &setup.reviewers {
        late.extend(assign_declared(*r, PR1, call(1), AssignmentKind::Reviewer));
    }
    late.push(crate::r#gen::review::declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ));
    late.push(knock_out(PR1, true));
    late.push(admit(PR1));
    for (steps, now) in [(&early, T0), (&late, T_EVAL)] {
        for st in steps {
            run_on(&mut s, st, now)
                .map_err(|e| format!("setup step {:?}: {e:?}", st.cmd.kind()))?;
        }
    }
    let f = finding(
        MARKED_FINDING,
        call(1),
        PR1,
        pin_of(call(1)),
        FindingKind::Quality,
        INJECTION_PHRASES[0],
    );
    exec_finding(&mut s, FindingCommand::Record(f), ASSESSOR, T_EVAL)?
        .map_err(|e| format!("storing the finding: {e:?}"))?;
    Ok(s)
}

/// Every call the I-11 machine names: two pinned, one unpublished, one unknown.
pub const PIN_CALLS: [CallId; 4] = [call(1), call(2), call(3), call(9)];

/// One command of the I-11 machine.
#[derive(Clone, Debug)]
pub enum PinCmd {
    /// The assessor stores a finding.
    Record(Finding),
    /// The assessor replaces every finding of a call (P-21 NOTE 10).
    Regenerate {
        /// The call.
        call: CallId,
        /// The replacement configuration.
        config: LlmConfigId,
        /// The model the configuration pins.
        config_model: ModelRef,
        /// The new set.
        findings: Vec<Finding>,
    },
    /// The lead submits the proposal, which ends its pre-check phase.
    Submit(AccountId, ProposalId),
}

/// The I-11 machine's model: the reference store and the ids drawn.
#[derive(Clone, Debug)]
pub struct PinModel {
    /// The reference store with the ghost pins.
    pub ghost: RefFindings,
    /// Every finding id a command named.
    pub ids: Vec<u128>,
    /// The next fresh finding id.
    pub next_id: u128,
    /// The proposals submitted.
    pub submitted: BTreeSet<ProposalId>,
}

/// The reference driver and the ledger around the latest command.
#[derive(Clone, Debug)]
pub struct PinSut {
    /// The scenario.
    pub s: Scenario,
    /// The ledger before the latest command.
    pub before: Vec<Entry<fstp_engine::Record>>,
    /// The ledger after it.
    pub after: Vec<Entry<fstp_engine::Record>>,
    /// A store read failure, reported by the invariant.
    pub read_error: Option<String>,
}

/// What one I-11 command did: the driver's result, or the seam, and the
/// records it appended.
#[derive(Debug)]
pub struct PinOutput {
    /// The driver's result, or the seam.
    pub result: Result<Result<Seq, ExecError>, String>,
    /// The records appended.
    pub appended: Vec<fstp_engine::Record>,
}

/// The I-11 machine (design 6.2): findings with random configuration ids,
/// of proposals in DRAFT (pre-check origin) and submitted, in pinned,
/// unpublished and unknown calls, and replacements with random models and
/// sets. Each finding command is compared with the reference in both
/// directions and appends only finding records (I-10). After every step
/// each call holds only findings under the configuration the ghost
/// expects, production holds exactly the reference's findings, and the
/// ledger extends and replays to the state (I-23).
pub struct PinMachine {
    /// The start scenario.
    pub start: Scenario,
    /// The reference store at the start.
    pub ghost: RefFindings,
}

impl PinMachine {
    /// The machine from [`pin_scenario`].
    pub fn new() -> Result<PinMachine, String> {
        let (start, ghost) = pin_scenario()?;
        Ok(PinMachine { start, ghost })
    }
}

fn pin_id(g: &mut Gen, model: &PinModel, k: u128) -> u128 {
    if !model.ids.is_empty() && g.weighted(&[5, 1]) == 1 {
        *g.pick(&model.ids)
    } else {
        model.next_id.saturating_add(k)
    }
}

fn pin_config(g: &mut Gen, model: &PinModel, c: CallId) -> LlmConfigId {
    let expected = model.ghost.expected(c).map_or(1, LlmConfigId::raw);
    LlmConfigId::from_raw(match g.weighted(&[6, 2, 2, 1]) {
        0 => expected,
        1 => *g.pick(&[1, 2]),
        2 => u128::from(g.u8_in(1..=12)),
        _ => u128::from(g.u64()),
    })
}

fn entries(s: &Scenario) -> Result<Vec<Entry<fstp_engine::Record>>, String> {
    s.entries().map_err(|e| format!("store read: {e:?}"))
}

impl StateMachine for PinMachine {
    type Model = PinModel;
    type Sut = PinSut;
    type Command = PinCmd;
    type Output = PinOutput;

    fn init_model(&self) -> PinModel {
        PinModel {
            ghost: self.ghost.clone(),
            ids: Vec::new(),
            next_id: 1,
            submitted: BTreeSet::new(),
        }
    }

    fn init_sut(&self) -> PinSut {
        let (now, read_error) = match entries(&self.start) {
            Ok(e) => (e, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        PinSut {
            s: self.start.clone(),
            before: now.clone(),
            after: now,
            read_error,
        }
    }

    fn command(&self, g: &mut Gen, model: &PinModel) -> PinCmd {
        match g.weighted(&[6, 2, 1]) {
            0 => {
                let (c, p) = *g.pick(&[
                    (call(1), PR1),
                    (call(1), PR1),
                    (call(2), PR2),
                    (call(3), PR1),
                    (call(9), PR2),
                ]);
                let id = pin_id(g, model, 0);
                let config = pin_config(g, model, c);
                PinCmd::Record(gen_finding(g, id, c, p, config, true))
            }
            1 => {
                let (c, p) = *g.pick(&[(call(1), PR1), (call(2), PR2), (call(3), PR1)]);
                let config = match g.weighted(&[4, 1, 1, 1]) {
                    0 => LlmConfigId::from_raw(model.next_id.saturating_add(100)),
                    1 => model.ghost.expected(c).unwrap_or(LlmConfigId::from_raw(1)),
                    2 => LlmConfigId::from_raw(*g.pick(&[1, 2])),
                    _ => LlmConfigId::from_raw(u128::from(g.u8_in(1..=12))),
                };
                let config_model = model_ref(g.pick(&[MODEL_B, MODEL_B, MODEL_A, MODEL_C]));
                let n = g.usize_in(0..=2);
                let mut findings = Vec::new();
                for k in 0..n {
                    let id = pin_id(g, model, u128::try_from(k).unwrap_or(0));
                    let (fc, fconfig) = match g.weighted(&[6, 1, 1]) {
                        0 => (c, config),
                        1 => (c, pin_config(g, model, c)),
                        _ => (*g.pick(&[call(1), call(2)]), config),
                    };
                    findings.push(gen_finding(g, id, fc, p, fconfig, true));
                }
                PinCmd::Regenerate {
                    call: c,
                    config,
                    config_model,
                    findings,
                }
            }
            _ => {
                let (lead, p) = *g.pick(&[(L1, PR1), (L2, PR2)]);
                PinCmd::Submit(lead, p)
            }
        }
    }

    fn precondition(&self, model: &PinModel, cmd: &PinCmd) -> bool {
        match cmd {
            PinCmd::Submit(_, p) => !model.submitted.contains(p),
            PinCmd::Record(_) | PinCmd::Regenerate { .. } => true,
        }
    }

    fn run(&self, sut: &mut PinSut, cmd: &PinCmd) -> PinOutput {
        sut.before = sut.after.clone();
        let result = match cmd {
            PinCmd::Record(f) => {
                exec_finding(&mut sut.s, FindingCommand::Record(f.clone()), ASSESSOR, T0)
            }
            PinCmd::Regenerate {
                call,
                config,
                config_model,
                findings,
            } => exec_finding(
                &mut sut.s,
                FindingCommand::Regenerate {
                    call: *call,
                    config: *config,
                    config_model: config_model.clone(),
                    findings: findings.clone(),
                },
                ASSESSOR,
                T0,
            ),
            PinCmd::Submit(lead, p) => Ok(run_on(
                &mut sut.s,
                &submit(*lead, *p, plan_of(*p), false),
                T0,
            )),
        };
        match entries(&sut.s) {
            Ok(e) => sut.after = e,
            Err(e) => sut.read_error = Some(e),
        }
        let appended = sut
            .after
            .get(sut.before.len()..)
            .unwrap_or_default()
            .iter()
            .map(|e| e.record.clone())
            .collect();
        PinOutput { result, appended }
    }

    fn next_state(&self, model: &mut PinModel, cmd: &PinCmd) {
        let mut named = Vec::new();
        match cmd {
            PinCmd::Record(f) => {
                named.push(f.id.raw());
                let _ = model.ghost.record(f.clone());
            }
            PinCmd::Regenerate {
                call,
                config,
                config_model,
                findings,
            } => {
                named.extend(findings.iter().map(|f| f.id.raw()));
                let _ = model
                    .ghost
                    .replace(*call, *config, config_model, findings.clone());
            }
            PinCmd::Submit(_, p) => {
                model.submitted.insert(*p);
            }
        }
        for id in named {
            if !model.ids.contains(&id) {
                model.ids.push(id);
            }
            if id >= model.next_id {
                model.next_id = id.saturating_add(1);
            }
        }
    }

    fn postcondition(
        &self,
        model: &PinModel,
        cmd: &PinCmd,
        output: &PinOutput,
    ) -> Result<(), String> {
        let result = output.result.as_ref().map_err(Clone::clone)?;
        let (context, accepts) = match cmd {
            PinCmd::Record(f) => {
                let v = model.ghost.record_verdict(f);
                (
                    format!(
                        "Record({:?} in {:?} by {:?}): {v:?}",
                        f.id, f.call, f.config
                    ),
                    v.is_ok(),
                )
            }
            PinCmd::Regenerate {
                call,
                config,
                config_model,
                findings,
            } => {
                let v = model
                    .ghost
                    .replace_verdict(*call, *config, config_model, findings);
                (
                    format!("Regenerate({call:?} to {config:?} on {config_model:?}): {v:?}"),
                    v.is_ok(),
                )
            }
            PinCmd::Submit(_, p) => (format!("Submit({p:?})"), true),
        };
        two_way_exec(&context, accepts, result)?;
        if !matches!(cmd, PinCmd::Submit(..))
            && let Some(r) = output
                .appended
                .iter()
                .find(|r| matches!(r, fstp_engine::Record::Core(_)))
        {
            return Err(format!("I-10: {context} appended the core record {r:?}"));
        }
        Ok(())
    }

    fn invariant(&self, model: &PinModel, sut: &PinSut) -> Result<(), String> {
        if let Some(e) = &sut.read_error {
            return Err(e.clone());
        }
        ledger_step(&sut.before, &sut.after, sut.s.state())?;
        let store = store_of(&sut.s.state().findings)?;
        check_i11(&model.ghost, &PIN_CALLS, |c| store.findings_of(c))?;
        same_findings(&model.ghost, &PIN_CALLS, |c| store.findings_of(c))?;
        for c in PIN_CALLS {
            if !store.findings_of(c).is_empty() && store.config_of(c) != model.ghost.expected(c) {
                return Err(format!(
                    "I-11: {c:?} holds {:?}, the ghost expects {:?}",
                    store.config_of(c),
                    model.ghost.expected(c)
                ));
            }
        }
        Ok(())
    }
}

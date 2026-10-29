//! I-23 over the full engine: the ledger checks, the corrections reference, the
//! ledger machine and M-LEDGER (design sections 5.1, 6.1, 6.2 and 6.3).
//!
//! Owned by lane L-LEDGER (docs/handoff/m2-design.md section 10).
//!
//! I-23: role bindings, conflict declarations, policy versions, scores and
//! decisions are append-only, and corrections are new records
//! (`SPEC/02-domain/invariants.md`). ADR-007 adds that a correction names
//! the record it supersedes, that ending a binding is a new record, and
//! that a policy change is a new policy version.
//!
//! - [`Canon`] gives an engine record its RFC 8785 bytes, so the ledger
//!   crate's own verifier [`fstp_ledger::verify_append_only`] runs over
//!   engine ledgers. [`stored_round_trip`] checks that the stored bytes of
//!   each entry decode to the entry again.
//! - [`CorrectionView`] is the independent reference for corrections,
//!   written from the spec text. It reads only ledger entries and
//!   [`check_corrections`] reports the first correction whose target is
//!   missing or of another kind.
//! - [`LedgerRun`] drives the full engine over [`fstp_ledger::MemStore`]
//!   through a [`Scenario`] from genesis. [`check_step`] runs every I-23
//!   check of one step.
//! - [`LedgerMachine`] is the fstp-prop machine over commands of every
//!   lane that exists: policy, calls, roles, drafts, intake, assignments
//!   and the lifecycle with vault changes. Its stage 2 paths include a
//!   revision with its scores and their corrections. Past NEGOTIATION,
//!   PR1 runs the money commands: the amount, the grant facts, the start
//!   of execution, one payment and the termination. Its
//!   postcondition compares the I-23 correction commands with
//!   [`LedgerGhost::reference`] in both directions.
//! - [`LedgerModel`] is M-LEDGER: one proposal, two reviewers, a small
//!   alphabet with corrections and at most six I-23 records after the
//!   start. Its state carries the ledger.
//!
//! Readings taken where the design is silent:
//! - The money machines decide on the domain state alone and keep no
//!   ledger. So this machine runs the money commands, under a P-04
//!   minimum below the submitted plan total. Amendments are left out: no
//!   command records an amendment plan in M2 (I-15 repeat model).
//! - Finding records have no canonical form in the testkit. The engine's
//!   finding record is a placeholder with no value yet. Their bytes fall
//!   back to their debug text, and the stored round trip skips them.
//! - The fstp-engine `Canonical` impl for its `Record` is a seam of lane
//!   L-CODEC that has not landed. [`Canon`] stands in for it here, built
//!   from the codec's own `ToJson` and the envelope form.
//! - The M-LEDGER budget of six records counts I-23 records only:
//!   bindings and their ends, suspensions, voids and reinstatements,
//!   conflict facts, policy versions, scores and their voids, and
//!   decisions. Vault answers, outbox events, reads and transition records
//!   are audit records around them.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, ClassId, LineId, PlanVersionId, PolicyVersionId,
    ProgrammeId, ProposalId, RequestId,
};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::{Declared, Record as CoreRecord};
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::{MICROS_PER_DAY, Timestamp};
use fstp_engine::{Engine, EnvelopeKind, ExecError, Record, envelope_from_json, envelope_to_json};
use fstp_json::{FromJson, ToJson, Value};
use fstp_ledger::{Canonical, Entry, Seq, verify_append_only};
use fstp_mc::{Model, Property};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::money;
use crate::r#gen::review::{
    COORDINATOR, IRC, L1, L2, PR1, PR2, R1, R2, R3, R4, assign, declare, handle, plan_of, read,
    submit, tag, unassign, withdraw,
};
use crate::r#gen::roster::{
    P1, STAFF_DRAFTER, STAFF_PM, Step, T0, call, edit_policy, end, grant, is_staff_binding,
    publish, reinstate,
};
use crate::harness::prop::{append_only, ledger_step, replay_matches};
use crate::mc::life_model::{
    IRC2, LifeSetup, Start, T_EVAL, admit, answer, ask, assign_declared, assignment_of, ballots,
    close, correct, cut_off, cut_off_decision, decline, irc_review, knock_out, life_judges,
    no_questions, rank, reenter, revision_milestone, revision_of, revision_plan, score,
    submit_revision, system,
};
use crate::scenario::Scenario;
use crate::vault::{GroundTruth, Relation};

// ---------------------------------------------------------------------------
// Canonical bytes and the stored form
// ---------------------------------------------------------------------------

/// The stored JSON form of an engine record: the envelope around the core
/// record's codec form. `None` for a finding record, which has no codec in
/// the testkit.
pub fn stored_json(record: &Record) -> Option<Value> {
    match record {
        Record::Core(r) => Some(envelope_to_json(EnvelopeKind::Core, r.to_json())),
        Record::Finding(_) => None,
    }
}

/// An engine record with its RFC 8785 bytes (ADR-007), so that
/// [`fstp_ledger::verify_append_only`] can compare engine ledgers.
///
/// A record without a canonical form falls back to its debug text, which
/// still differs between different records.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Canon(pub Record);

impl Canonical for Canon {
    fn canonical(&self) -> Vec<u8> {
        match stored_json(&self.0).map(|v| fstp_json::to_canonical(&v)) {
            Some(Ok(text)) => text.into_bytes(),
            _ => format!("not canonical: {:?}", self.0).into_bytes(),
        }
    }
}

impl ToJson for Canon {
    fn to_json(&self) -> Value {
        stored_json(&self.0).unwrap_or(Value::Null)
    }
}

/// The entries with their records wrapped in [`Canon`].
pub fn canon_entries(entries: &[Entry<Record>]) -> Vec<Entry<Canon>> {
    entries
        .iter()
        .cloned()
        .map(|e| e.map_record(Canon))
        .collect()
}

/// I-23 with the ledger crate's own verifier: `current` extends `previous`
/// without a changed, dropped, inserted or reordered entry, compared by
/// canonical bytes.
pub fn verify_canonical(
    previous: &[Entry<Record>],
    current: &[Entry<Record>],
) -> Result<(), String> {
    verify_append_only(&canon_entries(previous), &canon_entries(current))
        .map_err(|d| format!("I-23: the ledger verifier reports {d:?}"))
}

/// Decodes a stored record of schema version `schema`.
fn decode_record(schema: u16, value: &Value) -> Result<Record, String> {
    let (kind, inner) =
        envelope_from_json(value).map_err(|e| format!("the envelope does not decode: {e:?}"))?;
    match kind {
        EnvelopeKind::Core => fstp_domain::codec::record_from_json_at(schema, inner)
            .map(Record::Core)
            .map_err(|e| format!("the core record does not decode: {e:?}")),
        EnvelopeKind::Finding => Err("the testkit has no finding decoder".to_owned()),
    }
}

/// I-23 and ADR-007: the stored text of each core entry decodes to the
/// same entry, so a replay from the stored bytes is the replay of the
/// ledger. Finding entries are skipped.
pub fn stored_round_trip(entries: &[Entry<Record>]) -> Result<(), String> {
    for e in entries {
        if matches!(e.record, Record::Finding(_)) {
            continue;
        }
        let n = e.seq.raw();
        let text = e
            .clone()
            .map_record(Canon)
            .canonical_text()
            .map_err(|err| format!("I-23: entry {n} has no stored form: {err}"))?;
        let value = fstp_json::parse(text.as_bytes())
            .map_err(|err| format!("I-23: the stored text of entry {n} does not parse: {err:?}"))?;
        let raw = Entry::<Value>::from_json(&value)
            .map_err(|err| format!("I-23: the stored entry {n} does not decode: {err:?}"))?;
        let decoded = raw
            .try_map_record(|schema, v| decode_record(schema, &v))
            .map_err(|err| format!("I-23: stored entry {n}: {err}"))?;
        if decoded != *e {
            return Err(format!(
                "I-23: the stored text of entry {n} decodes to another entry\n  entry: {e:?}\ndecoded: {decoded:?}"
            ));
        }
    }
    Ok(())
}

/// The stored form of an entry, used as a template. Only a store or the
/// decoder builds entries, so [`make_entry`] decodes this and sets the fields.
const TEMPLATE: &[u8] =
    br#"{"at":0,"command":"00000000000000000000000000000000","record":null,"schema":1,"seq":"1"}"#;

/// An entry numbered `seq` at `at` under `command` holding `record`, schema
/// version 1, for a test that extends a ledger by hand.
pub fn make_entry(
    seq: Seq,
    at: Timestamp,
    command: [u8; 16],
    record: Record,
) -> Result<Entry<Record>, String> {
    let value = fstp_json::parse(TEMPLATE).map_err(|e| format!("template: {e:?}"))?;
    let template = Entry::<Value>::from_json(&value).map_err(|e| format!("template: {e:?}"))?;
    let mut e = template.map_record(|_| record);
    e.seq = seq;
    e.at = at.micros();
    e.command = command;
    Ok(e)
}

// ---------------------------------------------------------------------------
// The corrections reference
// ---------------------------------------------------------------------------

/// What the reference knows of one binding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BindingFacts {
    /// The account.
    pub account: Option<AccountId>,
    /// The role.
    pub role: Option<Role>,
    /// Whether a `BindingEnded` names it.
    pub ended: bool,
    /// Whether a `BindingVoided` names it.
    pub voided: bool,
    /// The `BindingSuspended` records that name it.
    pub suspensions: u32,
    /// The `BindingReinstated` records that name it.
    pub reinstatements: u32,
}

impl BindingFacts {
    /// Whether the binding is granted, not ended, not voided and not under a
    /// suspension that no reinstatement lifted.
    pub fn open(&self) -> bool {
        !self.ended && !self.voided && self.suspensions <= self.reinstatements
    }
}

/// The independent reference for I-23 corrections, folded from ledger
/// entries alone (design 5.1, ADR-007).
///
/// Every correction must target an earlier record of the same kind:
/// - a score correction names the entry of the current value of its key,
///   and a score without `supersedes` finds no current value of its key;
/// - a score void names a key with a current value;
/// - a score correction or void names a key whose stage has not sealed:
///   the proposal is in that stage and has not left it since the key's
///   scores began (design 5.1, NOTE 3);
/// - a policy version names the latest earlier version of its programme as
///   its parent, or none when it is the first, and its programme exists;
/// - a binding end, suspension or void names a granted binding that is not
///   voided, a binding ends at most once and is voided at most once;
/// - a reinstatement names a binding that has not ended, with a suspension
///   not yet lifted;
/// - a release names an assignment that was made and not yet released;
/// - a plan that supersedes names an earlier plan of the same proposal
///   that no other plan superseded;
/// - a call edit names a drafted call.
///
/// A record never reuses the id of an earlier binding, policy version,
/// assignment or plan, since that would overwrite it without naming it.
///
/// No complaint remedy exists in M2, so no record reopens a sealed stage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorrectionView {
    /// The sequence number of the last entry folded.
    pub head: u64,
    /// The created programmes.
    pub programmes: BTreeSet<ProgrammeId>,
    /// Every policy version id recorded.
    pub policy_ids: BTreeSet<PolicyVersionId>,
    /// The latest policy version of each programme.
    pub policy_heads: BTreeMap<ProgrammeId, PolicyVersionId>,
    /// The granted bindings.
    pub bindings: BTreeMap<BindingId, BindingFacts>,
    /// The key of every score entry, by sequence number.
    pub score_entries: BTreeMap<u64, ScoreKey>,
    /// The entry of the current value of each key.
    pub live: BTreeMap<ScoreKey, u64>,
    /// The assignments made, with their proposal.
    pub assignments: BTreeMap<AssignmentId, ProposalId>,
    /// The released assignments.
    pub released: BTreeSet<AssignmentId>,
    /// The plans recorded, with their proposal.
    pub plans: BTreeMap<PlanVersionId, ProposalId>,
    /// The plans a later plan superseded.
    pub superseded: BTreeSet<PlanVersionId>,
    /// The state of each proposal, from its latest transition.
    pub states: BTreeMap<ProposalId, StateTag>,
    /// The keys whose stage the proposal left: they are sealed (NOTE 3).
    pub sealed: BTreeSet<ScoreKey>,
    /// The drafted calls.
    pub calls: BTreeSet<CallId>,
    /// A short name of the record at each sequence number.
    pub kinds: BTreeMap<u64, &'static str>,
}

/// A short name of `r` for messages and for the "another kind" check.
pub fn kind_name(r: &CoreRecord) -> &'static str {
    match r {
        CoreRecord::ProgrammeCreated { .. } => "ProgrammeCreated",
        CoreRecord::PolicyVersionRecorded { .. } => "PolicyVersionRecorded",
        CoreRecord::CallDrafted { .. } => "CallDrafted",
        CoreRecord::CallEdited { .. } => "CallEdited",
        CoreRecord::CallPublished { .. } => "CallPublished",
        CoreRecord::BindingGranted(_) => "BindingGranted",
        CoreRecord::BindingEnded(_) => "BindingEnded",
        CoreRecord::BindingSuspended(_) => "BindingSuspended",
        CoreRecord::BindingVoided(_) => "BindingVoided",
        CoreRecord::BindingReinstated(_) => "BindingReinstated",
        CoreRecord::Assigned(_) => "Assigned",
        CoreRecord::AssignmentReleased(_) => "AssignmentReleased",
        CoreRecord::ConflictDeclared(_) => "ConflictDeclared",
        CoreRecord::ConflictDetected(_) => "ConflictDetected",
        CoreRecord::PlanVersionRecorded(_) => "PlanVersionRecorded",
        CoreRecord::ScoreRecorded(_) => "ScoreRecorded",
        CoreRecord::ScoreVoided(_) => "ScoreVoided",
        CoreRecord::Transitioned(_) => "Transitioned",
        CoreRecord::VaultOutcome { .. } => "VaultOutcome",
        CoreRecord::OutboxEnqueued(_) => "OutboxEnqueued",
        _ => "another record",
    }
}

/// Whether `r` is of a kind I-23 names: role bindings, conflict facts,
/// policy versions, scores and decisions, with their corrections.
pub fn is_i23_record(r: &CoreRecord) -> bool {
    matches!(
        r,
        CoreRecord::PolicyVersionRecorded { .. }
            | CoreRecord::CallApproved { .. }
            | CoreRecord::BindingGranted(_)
            | CoreRecord::BindingEnded(_)
            | CoreRecord::BindingSuspended(_)
            | CoreRecord::BindingVoided(_)
            | CoreRecord::BindingReinstated(_)
            | CoreRecord::ConflictDeclared(_)
            | CoreRecord::ConflictDetected(_)
            | CoreRecord::ScoreRecorded(_)
            | CoreRecord::ScoreVoided(_)
            | CoreRecord::KnockOutRecorded { .. }
            | CoreRecord::Stage1Closed(_)
            | CoreRecord::EffectiveScoreSet(_)
            | CoreRecord::CutOffRecorded(_)
            | CoreRecord::IrcReviewRecorded { .. }
            | CoreRecord::AmountDetermined { .. }
            | CoreRecord::GrantDecided(_)
            | CoreRecord::NegotiationDeclined { .. }
            | CoreRecord::TerminationRecorded { .. }
    )
}

impl CorrectionView {
    /// The view of `entries`, or the first correction that breaks I-23.
    pub fn of(entries: &[Entry<Record>]) -> Result<CorrectionView, String> {
        let mut v = CorrectionView::default();
        for e in entries {
            v.fold(e)?;
        }
        Ok(v)
    }

    /// The name of the record at `seq`, if any.
    pub fn kind_at(&self, seq: u64) -> &'static str {
        self.kinds.get(&seq).copied().unwrap_or("no record")
    }

    /// Folds one entry, or reports why its correction breaks I-23.
    pub fn fold(&mut self, e: &Entry<Record>) -> Result<(), String> {
        let n = e.seq.raw();
        if let Record::Core(r) = &e.record {
            self.fold_core(n, r)
                .map_err(|why| format!("I-23: entry {n} ({}): {why}", kind_name(r)))?;
            self.kinds.insert(n, kind_name(r));
        } else {
            self.kinds.insert(n, "finding");
        }
        self.head = n;
        Ok(())
    }

    fn binding(&mut self, b: BindingId, what: &str) -> Result<&mut BindingFacts, String> {
        self.bindings.get_mut(&b).ok_or_else(|| {
            format!(
                "the {what} names binding {} that was never granted",
                b.raw()
            )
        })
    }

    /// The state tag of the stage that `stage` scores.
    pub fn stage_state(stage: Stage) -> StateTag {
        match stage {
            Stage::One => StateTag::Stage1,
            Stage::Two => StateTag::Stage2,
        }
    }

    /// Refuses a correction or void of `key` once its stage has sealed:
    /// the proposal left the stage, or is not in it (NOTE 3).
    fn require_unsealed(&self, key: &ScoreKey) -> Result<(), String> {
        if self.sealed.contains(key) {
            return Err(format!(
                "the {:?} stage of the key sealed when the proposal left it",
                key.stage
            ));
        }
        let proposal = self.assignments.get(&key.assignment);
        let state = proposal.and_then(|p| self.states.get(p)).copied();
        if state != Some(Self::stage_state(key.stage)) {
            return Err(format!(
                "the key is on the {:?} stage, but its proposal is in {state:?}",
                key.stage
            ));
        }
        Ok(())
    }

    /// Folds a transition: leaving a stage seals every key of the proposal
    /// on that stage.
    fn fold_transition(&mut self, t: &fstp_domain::record::Transitioned) {
        for stage in [Stage::One, Stage::Two] {
            let tag = Self::stage_state(stage);
            if t.from == tag && t.to != tag {
                let keys: Vec<ScoreKey> = self
                    .score_entries
                    .values()
                    .filter(|k| {
                        k.stage == stage && self.assignments.get(&k.assignment) == Some(&t.proposal)
                    })
                    .copied()
                    .collect();
                self.sealed.extend(keys);
            }
        }
        self.states.insert(t.proposal, t.to);
    }

    fn fold_core(&mut self, n: u64, r: &CoreRecord) -> Result<(), String> {
        match r {
            CoreRecord::Transitioned(t) => self.fold_transition(t),
            CoreRecord::ProgrammeCreated { programme, .. } => {
                if !self.programmes.insert(*programme) {
                    return Err("the programme already exists".to_owned());
                }
            }
            CoreRecord::PolicyVersionRecorded { version, .. } => {
                if !self.programmes.contains(&version.programme) {
                    return Err("the policy version names no created programme".to_owned());
                }
                let head = self.policy_heads.get(&version.programme).copied();
                if version.parent != head {
                    return Err(format!(
                        "the policy version names parent {:?}, the latest version of its programme is {head:?}",
                        version.parent
                    ));
                }
                if !self.policy_ids.insert(version.id) {
                    return Err("the policy version reuses an earlier version id".to_owned());
                }
                self.policy_heads.insert(version.programme, version.id);
            }
            CoreRecord::CallDrafted { call, .. } => {
                if !self.calls.insert(*call) {
                    return Err("the call was already drafted".to_owned());
                }
            }
            CoreRecord::CallEdited { call, .. } => {
                if !self.calls.contains(call) {
                    return Err("the call edit names no drafted call".to_owned());
                }
            }
            CoreRecord::BindingGranted(g) => {
                if self.bindings.contains_key(&g.binding) {
                    return Err("the grant reuses an earlier binding id".to_owned());
                }
                self.bindings.insert(
                    g.binding,
                    BindingFacts {
                        account: Some(g.account),
                        role: Some(g.role),
                        ..BindingFacts::default()
                    },
                );
            }
            CoreRecord::BindingEnded(x) => {
                let b = self.binding(x.binding, "end")?;
                if b.ended {
                    return Err("the binding already ended".to_owned());
                }
                if b.voided {
                    return Err("the end names a voided binding".to_owned());
                }
                b.ended = true;
            }
            CoreRecord::BindingSuspended(x) => {
                let b = self.binding(x.binding, "suspension")?;
                if b.voided {
                    return Err("the suspension names a voided binding".to_owned());
                }
                b.suspensions = b.suspensions.saturating_add(1);
            }
            CoreRecord::BindingVoided(x) => {
                let b = self.binding(x.binding, "void")?;
                if b.voided {
                    return Err("the binding was already voided".to_owned());
                }
                b.voided = true;
            }
            CoreRecord::BindingReinstated(x) => {
                let b = self.binding(x.binding, "reinstatement")?;
                if b.ended {
                    return Err("the reinstatement names an ended binding".to_owned());
                }
                if b.suspensions <= b.reinstatements {
                    return Err("the reinstatement names no suspension still in force".to_owned());
                }
                b.reinstatements = b.reinstatements.saturating_add(1);
            }
            CoreRecord::Assigned(a) => {
                if self.assignments.contains_key(&a.assignment) {
                    return Err("the assignment reuses an earlier assignment id".to_owned());
                }
                self.assignments.insert(a.assignment, a.proposal);
            }
            CoreRecord::AssignmentReleased(x) => {
                if !self.assignments.contains_key(&x.assignment) {
                    return Err("the release names an assignment that was never made".to_owned());
                }
                if !self.released.insert(x.assignment) {
                    return Err("the assignment was already released".to_owned());
                }
            }
            CoreRecord::PlanVersionRecorded(p) => {
                if let Some(old) = p.supersedes {
                    match self.plans.get(&old) {
                        Some(_) if self.superseded.contains(&old) => {
                            return Err("the plan supersedes a plan already superseded".to_owned());
                        }
                        Some(owner) if *owner == p.proposal => {}
                        Some(_) => {
                            return Err("the plan supersedes a plan of another proposal".to_owned());
                        }
                        None => return Err("the plan supersedes no recorded plan".to_owned()),
                    }
                }
                if self.plans.contains_key(&p.plan) {
                    return Err("the plan reuses an earlier plan id".to_owned());
                }
                self.plans.insert(p.plan, p.proposal);
                if let Some(old) = p.supersedes {
                    self.superseded.insert(old);
                }
            }
            CoreRecord::ScoreRecorded(s) => {
                let current = self.live.get(&s.key).copied();
                match s.supersedes {
                    None => {
                        if let Some(c) = current {
                            return Err(format!(
                                "the score names no target, yet entry {c} holds the current value of its key"
                            ));
                        }
                    }
                    Some(t) => {
                        let t = t.raw();
                        if t >= n {
                            return Err(format!(
                                "the correction names entry {t}, which is not earlier"
                            ));
                        }
                        let Some(key) = self.score_entries.get(&t) else {
                            return Err(format!(
                                "the correction names entry {t}, a {} and not a score",
                                self.kind_at(t)
                            ));
                        };
                        if *key != s.key {
                            return Err(format!(
                                "the correction names entry {t}, a score of another key"
                            ));
                        }
                        if current != Some(t) {
                            return Err(format!(
                                "the correction names entry {t}, the current value is {current:?}"
                            ));
                        }
                        self.require_unsealed(&s.key)?;
                    }
                }
                self.score_entries.insert(n, s.key);
                self.live.insert(s.key, n);
            }
            CoreRecord::ScoreVoided(x) => {
                if !self.live.contains_key(&x.key) {
                    return Err("the void names a key with no current score".to_owned());
                }
                self.require_unsealed(&x.key)?;
                self.live.remove(&x.key);
            }
            _ => {}
        }
        Ok(())
    }
}

/// I-23: every correction in `entries` targets an existing record of the
/// same kind, and no record overwrites an earlier one (see [`CorrectionView`]).
pub fn check_corrections(entries: &[Entry<Record>]) -> Result<(), String> {
    CorrectionView::of(entries).map(|_| ())
}

/// Every I-23 check of one step from `previous` to the ledger and state of `run`:
/// - `run.ledger` extends `previous`, compared field by field and by
///   canonical bytes with the ledger crate's verifier;
/// - the state is the replay of the ledger, and a driver opened over a
///   copy of the store holds the same state;
/// - every correction targets an existing record of the same kind;
/// - the stored bytes of each new entry decode to that entry.
pub fn check_step(previous: &[Entry<Record>], run: &LedgerRun) -> Result<(), String> {
    let current = &run.ledger;
    ledger_step(previous, current, run.scenario.state())?;
    verify_canonical(previous, current)?;
    check_corrections(current)?;
    stored_round_trip(current.get(previous.len()..).unwrap_or_default())?;
    let engine = run.scenario.engine();
    match Engine::open(engine.store().clone(), engine.oracle().clone()) {
        Ok(reopened) if reopened.state() == run.scenario.state() => Ok(()),
        Ok(_) => Err("I-23: a driver opened over the same store holds another state".to_owned()),
        Err(e) => Err(format!(
            "I-23: a driver cannot open over the same store: {e}"
        )),
    }
}

// ---------------------------------------------------------------------------
// Setup and the run over the full engine
// ---------------------------------------------------------------------------

/// The parameters of the ledger runs: scale 0 to 2, weights (1, 1), P-02
/// 50.00, P-03 = 2, P-07 = 28 days, `p15`, the life judges and the
/// proposals with their leads, all in call 1. Calls 1 and 2 are drafted
/// and approved, and call 1 is published.
pub fn ledger_setup(
    judges: Vec<(AccountId, Role, Option<fstp_domain::id::OrganisationId>)>,
    proposals: &[(AccountId, ProposalId)],
    p15: u8,
) -> LifeSetup {
    LifeSetup {
        scale_max: 2,
        weights: vec![1, 1],
        p02_bp: 5_000,
        p03: 2,
        p07_days: 28,
        p15,
        judges,
        proposals: proposals.iter().map(|(l, p)| (*l, *p, false)).collect(),
        reviewers: Vec::new(),
        start_scores: Vec::new(),
        revision_scores: Vec::new(),
        start: Start::Draft,
    }
}

/// The vault of a setup, with the spare committee account [`R4`] verified.
pub fn ledger_truth(setup: &LifeSetup) -> GroundTruth {
    let mut truth = setup.truth();
    truth.set_identity(R4, tag(R4));
    truth.verify(R4);
    truth
}

/// The commands from genesis: the setup at [`T0`], then the submission of
/// every proposal at [`T0`], before the call deadline.
pub fn genesis_steps(setup: &LifeSetup) -> Result<Vec<(Timestamp, Step)>, String> {
    let mut out: Vec<(Timestamp, Step)> =
        setup.draft_steps()?.into_iter().map(|s| (T0, s)).collect();
    for (lead, proposal, _) in &setup.proposals {
        out.push((T0, submit(*lead, *proposal, plan_of(*proposal), false)));
    }
    Ok(out)
}

/// What one command did to the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// Whether the command appended a batch.
    pub accepted: bool,
    /// The core records it appended.
    pub appended: Vec<CoreRecord>,
    /// The refusal of a refused command.
    pub refusal: Option<fstp_domain::refusal::Refusal>,
}

/// The full engine over a [`fstp_ledger::MemStore`], with the ledger read
/// back after every command.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LedgerRun {
    /// The reference driver over the store and the synthetic vault.
    pub scenario: Scenario,
    /// Every entry of the store, read after the latest command.
    pub ledger: Vec<Entry<Record>>,
}

/// The core records of `entries`.
fn core_of(entries: &[Entry<Record>]) -> Vec<CoreRecord> {
    entries
        .iter()
        .filter_map(|e| match &e.record {
            Record::Core(r) => Some(r.clone()),
            Record::Finding(_) => None,
        })
        .collect()
}

impl LedgerRun {
    /// An empty ledger over `truth`, then `steps`, each of which must be
    /// accepted. Every I-23 check of [`check_step`] runs after each step.
    pub fn new(truth: GroundTruth, steps: &[(Timestamp, Step)]) -> Result<LedgerRun, String> {
        let scenario = Scenario::new(truth).map_err(|e| format!("open: {e}"))?;
        let mut run = LedgerRun {
            scenario,
            ledger: Vec::new(),
        };
        for (now, step) in steps {
            run.checked(*now, step)?;
        }
        Ok(run)
    }

    /// Runs `step` at `now`, which must be accepted, then every I-23 check
    /// of the step (design 6.1, "Replay and append-only every step").
    pub fn checked(&mut self, now: Timestamp, step: &Step) -> Result<Vec<CoreRecord>, String> {
        let previous = self.ledger.clone();
        let records = self.must(now, step)?;
        check_step(&previous, self)?;
        Ok(records)
    }

    /// Reads the store and returns the entries after the first `before`.
    fn advance(&mut self, before: usize) -> Result<Vec<Entry<Record>>, String> {
        self.ledger = self
            .scenario
            .entries()
            .map_err(|e| format!("store read: {e}"))?;
        Ok(self.ledger.get(before..).unwrap_or_default().to_vec())
    }

    /// Runs `step` at `now` through the driver and checks the batch (ADR-007).
    /// An accepted command appends one non-empty batch under its own command
    /// id and instant, ending at the head it returns. A refused one appends
    /// nothing. Any other driver result is an error.
    pub fn core(&mut self, now: Timestamp, step: &Step) -> Result<Applied, String> {
        let before = self.ledger.len();
        let mut ctx = self.scenario.ctx(now, step.actor);
        ctx.tenant_admin = step.flags.tenant_admin;
        ctx.second_tenant_admin = step.flags.second_admin;
        ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
        let command = ctx.command.bytes();
        let result = self
            .scenario
            .execute(fstp_engine::Command::Core(step.cmd.clone()), ctx);
        let tail = self.advance(before)?;
        let kind = step.cmd.kind();
        match result {
            Ok(head) => {
                let own: Vec<&Entry<Record>> = tail
                    .iter()
                    .filter(|e| {
                        !fstp_engine::is_reserved_command_id(
                            fstp_domain::id::CommandId::from_bytes(e.command),
                        )
                    })
                    .collect();
                if own.is_empty() {
                    return Err(format!("I-23: the accepted {kind:?} appended no entry"));
                }
                if tail.last().map(|e| e.seq) != Some(head) {
                    return Err(format!(
                        "I-23: the accepted {kind:?} returned head {} but the ledger ends at {:?}",
                        head.raw(),
                        tail.last().map(|e| e.seq.raw())
                    ));
                }
                if let Some(e) = own
                    .iter()
                    .find(|e| e.command != command || e.at != now.micros())
                {
                    return Err(format!(
                        "I-23: entry {} of the batch of {kind:?} carries another command id or time",
                        e.seq.raw()
                    ));
                }
                Ok(Applied {
                    accepted: true,
                    appended: core_of(&tail),
                    refusal: None,
                })
            }
            Err(ExecError::Refused(r)) if tail.is_empty() => Ok(Applied {
                accepted: false,
                appended: Vec::new(),
                refusal: Some(r),
            }),
            Err(ExecError::Refused(r)) => Err(format!(
                "I-23: the refused {kind:?} ({r}) appended {} entries",
                tail.len()
            )),
            Err(e) => Err(format!("I-23: the driver failed on {kind:?} with {e:?}")),
        }
    }

    /// Runs `step` at `now`, which must be accepted, and returns its records.
    pub fn must(&mut self, now: Timestamp, step: &Step) -> Result<Vec<CoreRecord>, String> {
        let applied = self.core(now, step)?;
        if applied.accepted {
            Ok(applied.appended)
        } else {
            Err(format!(
                "{:?} by {:?} at {} was refused: {:?}",
                step.cmd,
                step.actor,
                now.micros(),
                applied.refusal
            ))
        }
    }

    /// Changes the vault facts with `change` at `now` and processes the
    /// change in the same step. A refusal or an unchanged epoch appends
    /// nothing. Any other driver result is an error.
    pub fn vault(
        &mut self,
        now: Timestamp,
        change: impl FnOnce(&mut GroundTruth),
    ) -> Result<Applied, String> {
        let before = self.ledger.len();
        let ctx = self.scenario.ctx(now, Actor::System(SystemCause::Vault));
        let result = self.scenario.change_vault(change, ctx);
        let tail = self.advance(before)?;
        match result {
            Ok(Some(head)) => {
                if tail.is_empty() || tail.last().map(|e| e.seq) != Some(head) {
                    return Err(format!(
                        "I-23: the vault change returned head {} but appended {} entries",
                        head.raw(),
                        tail.len()
                    ));
                }
                if let Some(e) = tail.iter().find(|e| e.at != now.micros()) {
                    return Err(format!(
                        "I-23: entry {} of the vault reaction carries another time",
                        e.seq.raw()
                    ));
                }
                Ok(Applied {
                    accepted: true,
                    appended: core_of(&tail),
                    refusal: None,
                })
            }
            Ok(None) | Err(ExecError::Refused(_)) if tail.is_empty() => Ok(Applied {
                accepted: false,
                appended: Vec::new(),
                refusal: None,
            }),
            Ok(None) | Err(ExecError::Refused(_)) => Err(format!(
                "I-23: a vault change that appended no batch left {} new entries",
                tail.len()
            )),
            Err(e) => Err(format!(
                "I-23: the driver failed on a vault change with {e:?}"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// The witness script
// ---------------------------------------------------------------------------

/// The judges of the machine and the witness: the life judges.
pub fn ledger_judges() -> Vec<(AccountId, Role, Option<fstp_domain::id::OrganisationId>)> {
    life_judges()
}

/// The setup of the machine and the witness: [`PR1`] led by [`L1`] and
/// [`PR2`] led by [`L2`], both in call 1, P-15 = 1.
pub fn ledger_machine_setup() -> LifeSetup {
    let mut judges = ledger_judges();
    judges.extend([
        (money::FINREL, Role::FinanceApprover, None),
        (money::REL, Role::PaymentReleaser, None),
    ]);
    ledger_setup(judges, &[(L1, PR1), (L2, PR2)], 1)
}

/// The P-04 minimum of the ledger machine, in cents. It lies below the
/// submitted plan total of [`MILESTONE_CENTS`], so the money acts of
/// [`script`] can grant that plan (I-13).
pub const MACHINE_P04_MIN_CENTS: i64 = 50_000;

/// The commands from genesis of the ledger machine and its witness:
/// [`genesis_steps`] with the P-04 minimum at [`MACHINE_P04_MIN_CENTS`].
pub fn machine_genesis_steps(setup: &LifeSetup) -> Result<Vec<(Timestamp, Step)>, String> {
    let mut steps = genesis_steps(setup)?;
    for (_, s) in &mut steps {
        if let Command::CreateProgramme { policy } = &mut s.cmd {
            let max = policy.frozen.p04.max();
            policy.frozen.p04 =
                fstp_money::AmountRange::new(money::nonneg(MACHINE_P04_MIN_CENTS)?, max)
                    .map_err(|e| format!("P-04: {e:?}"))?;
        }
    }
    Ok(steps)
}

/// The binding of the `i`-th judge of [`ledger_judges`].
pub fn judge(i: usize) -> BindingId {
    crate::r#gen::review::judge_binding(i)
}

/// The binding of [`IRC2`], the sixth judge.
pub const IRC2_BINDING: BindingId = BindingId::from_raw(205);

/// The Receiving binding of the lead of [`PR2`], the second draft.
pub const L2_BINDING: BindingId = BindingId::from_raw(310);

/// The excluded class of P-13 in the setup.
pub const EXCLUDED: ClassId = ClassId::from_raw(1);

/// The assignment of `reviewer` on `proposal` in call 1.
pub fn reviewer_assignment(reviewer: AccountId, proposal: ProposalId) -> AssignmentId {
    assignment_of(reviewer, proposal, call(1), AssignmentKind::Reviewer)
}

/// The stage 1 key of `reviewer` on `proposal` and its submitted plan.
pub fn stage1_key(reviewer: AccountId, proposal: ProposalId) -> ScoreKey {
    ScoreKey {
        assignment: reviewer_assignment(reviewer, proposal),
        stage: Stage::One,
        plan: plan_of(proposal),
    }
}

/// The committee ballots of the witness cut-off: R1, R2 and R3 for.
pub fn witness_ballots() -> Vec<fstp_domain::decision::Ballot> {
    ballots(&[R1, R2, R3], Vote::For)
}

/// The stage 2 key of `reviewer` on the first revision of `proposal`.
pub fn stage2_key(reviewer: AccountId, proposal: ProposalId) -> ScoreKey {
    ScoreKey {
        assignment: reviewer_assignment(reviewer, proposal),
        stage: Stage::Two,
        plan: revision_of(proposal, 1),
    }
}

/// The first stage 2 revision of `proposal` by its lead, superseding `live`.
pub fn first_revision(proposal: ProposalId, live: PlanVersionId) -> Result<Step, String> {
    revision_plan(
        lead_of(proposal),
        proposal,
        revision_of(proposal, 1),
        Some(live),
        revision_milestone(proposal, 1),
    )
}

/// The deterministic run behind the machine's non-vacuity witness and the
/// corrections property. From genesis it takes [`PR1`] to NEGOTIATION with
/// a score correction and a policy edit on the way. In STAGE2 the lead
/// answers a question and submits a revision that supersedes the submitted
/// plan. The reviewers score it, R1 corrects that score, and R1 ranks.
/// [`PR2`] stays in STAGE1 with a corrected current score of R1, while R3
/// is released by a vault conflict. No command emits a score void in M2,
/// because only a complaint remedy voids a score. A vault merge suspends
/// [`IRC2`]. Once the vault splits the identity again, the binding is
/// reinstated and then ended. A vault exclusion of [`L2`] voids L2's
/// Receiving binding. [`check_step`] holds after every step.
pub fn witness_run() -> Result<LedgerRun, String> {
    let setup = ledger_machine_setup();
    let mut run = LedgerRun::new(ledger_truth(&setup), &machine_genesis_steps(&setup)?)?;
    let t = T_EVAL;
    let mut steps: Vec<Step> = Vec::new();
    for r in [R1, R2] {
        steps.extend(assign_declared(r, PR1, call(1), AssignmentKind::Reviewer));
    }
    steps.push(declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ));
    steps.push(knock_out(PR1, true));
    steps.push(admit(PR1));
    steps.push(score(R1, stage1_key(R1, PR1), &[2, 1]));
    steps.push(score(R2, stage1_key(R2, PR1), &[2, 2]));
    steps.push(correct(R1, stage1_key(R1, PR1), &[2, 2]));
    for s in &steps {
        run.checked(t, s)?;
    }
    let head = fstp_domain::policy::head(&run.scenario.state().core, P1)
        .cloned()
        .ok_or("no policy head")?;
    let mut later: Vec<Step> = vec![edit_policy(&head, PolicyVersionId::from_raw(900), |v| {
        v.live.p12 = CoolingOff(2);
    })];
    later.push(close(Actor::Account(COORDINATOR), PR1));
    later.push(ask(R1, PR1, reviewer_assignment(R1, PR1)));
    later.push(answer(L1, PR1));
    later.push(first_revision(PR1, plan_of(PR1))?);
    later.push(submit_revision(L1, PR1, revision_of(PR1, 1)));
    later.push(score(R1, stage2_key(R1, PR1), &[1, 1]));
    later.push(score(R2, stage2_key(R2, PR1), &[2, 2]));
    later.push(correct(R1, stage2_key(R1, PR1), &[2, 1]));
    later.push(rank(R1, PR1));
    later.extend(cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        witness_ballots(),
    ));
    later.extend(assign_declared(IRC, PR1, call(1), AssignmentKind::Irc));
    later.push(irc_review(
        IRC,
        assignment_of(IRC, PR1, call(1), AssignmentKind::Irc),
        true,
    ));
    for r in [R1, R3] {
        later.extend(assign_declared(r, PR2, call(1), AssignmentKind::Reviewer));
    }
    later.push(declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR2),
        false,
        false,
    ));
    later.push(knock_out(PR2, true));
    later.push(admit(PR2));
    later.push(score(R1, stage1_key(R1, PR2), &[1, 1]));
    later.push(score(R3, stage1_key(R3, PR2), &[0, 1]));
    later.push(correct(R1, stage1_key(R1, PR2), &[1, 2]));
    for s in &later {
        run.checked(t, s)?;
    }
    let ops = [
        LedgerVaultOp::Relate(R3, L2),
        LedgerVaultOp::Merge(IRC2, STAFF_DRAFTER),
        LedgerVaultOp::Split(IRC2),
        LedgerVaultOp::Exclude(L2),
    ];
    for op in ops {
        let previous = run.ledger.clone();
        let applied = run.vault(t, |truth| op.apply(truth))?;
        if !applied.accepted {
            return Err(format!("the witness vault change {op:?} appended nothing"));
        }
        check_step(&previous, &run)?;
        if op == LedgerVaultOp::Split(IRC2) {
            for s in [reinstate(IRC2_BINDING), end(IRC2_BINDING, t)] {
                run.checked(t, &s)?;
            }
        }
    }
    Ok(run)
}

/// The correction kinds the witness ledger must hold, by name, with
/// whether the ledger holds one.
pub fn correction_kinds(entries: &[Entry<Record>]) -> Vec<(&'static str, bool)> {
    let cores = core_of(entries);
    let any = |f: &dyn Fn(&CoreRecord) -> bool| cores.iter().any(f);
    vec![
        (
            "score correction",
            any(&|r| matches!(r, CoreRecord::ScoreRecorded(s) if s.supersedes.is_some())),
        ),
        (
            "stage 2 score correction",
            any(
                &|r| matches!(r, CoreRecord::ScoreRecorded(s) if s.supersedes.is_some() && s.key.stage == Stage::Two),
            ),
        ),
        (
            "superseding plan",
            any(&|r| matches!(r, CoreRecord::PlanVersionRecorded(p) if p.supersedes.is_some())),
        ),
        (
            "policy version with a parent",
            any(
                &|r| matches!(r, CoreRecord::PolicyVersionRecorded { version, .. } if version.parent.is_some()),
            ),
        ),
        (
            "binding end",
            any(&|r| matches!(r, CoreRecord::BindingEnded(_))),
        ),
        (
            "binding suspension",
            any(&|r| matches!(r, CoreRecord::BindingSuspended(_))),
        ),
        (
            "reinstatement",
            any(&|r| matches!(r, CoreRecord::BindingReinstated(_))),
        ),
        (
            "binding void",
            any(&|r| matches!(r, CoreRecord::BindingVoided(_))),
        ),
        (
            "release",
            any(&|r| matches!(r, CoreRecord::AssignmentReleased(_))),
        ),
        (
            "entry into NEGOTIATION",
            any(&|r| matches!(r, CoreRecord::Transitioned(t) if t.to == StateTag::Negotiation)),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The ledger machine
// ---------------------------------------------------------------------------

/// One scripted lifecycle act of a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Act {
    /// The coordinator assigns the account with this kind.
    Assign(AccountId, AssignmentKind),
    /// The assignee declares no conflict.
    Declare(AccountId, AssignmentKind),
    /// The coordinator declares no conflict on the proposal.
    CoordinatorDeclare,
    /// The coordinator records a passed knock-out check.
    KnockOut,
    /// The coordinator admits the proposal to stage 1.
    Admit,
    /// A stage 1 score.
    Score(AccountId, [u8; 2]),
    /// The coordinator closes stage 1.
    Close,
    /// A "no questions" record.
    NoQuestions(AccountId),
    /// A committee member records the cut-off of call 1.
    CutOff,
    /// An IRC validation.
    Irc(AccountId),
    /// A stage 2 question by the reviewer.
    Ask(AccountId),
    /// The System expires the stage 2 window, 29 days later.
    Expire,
    /// The programme manager publishes call 2.
    PublishNext,
    /// The System re-enters the deferred proposal into call 2.
    ReEnter,
    /// The lead answers the questions.
    Answer,
    /// The lead records the first stage 2 revision, superseding the live plan.
    Revise,
    /// The lead submits the first stage 2 revision.
    SubmitRevision,
    /// A stage 2 score on the first revision.
    Score2(AccountId, [u8; 2]),
    /// A correction of the reviewer's stage 2 score on the first revision.
    Correct2(AccountId, [u8; 2]),
    /// `RankAfterStage2` by the reviewer.
    Rank(AccountId),
    /// R1 determines the amount on the submitted plan (R-NG-03).
    Determine,
    /// The lead accepts the grant.
    Accept,
    /// The programme manager approves the grant.
    Approve,
    /// The contract port reports the contract EFFECTIVE.
    Contract,
    /// The System starts execution at the milestone start date.
    Start,
    /// The lead records an amendment plan that supersedes the submitted plan.
    AmendPlan,
    /// The lead proposes the amendment.
    ProposeAmendment,
    /// The programme manager routes it through a P-14 exemption.
    RouteAmendment,
    /// The contract port activates it.
    ActivateAmendment,
    /// The lead requests the payment of the amended milestone.
    Request,
    /// R1 accepts the payment line in full.
    AcceptLine,
    /// The finance approver approves the payment.
    ApprovePay,
    /// The payment releaser releases it (SoD-04).
    Release,
    /// The payment port confirms it paid.
    Confirm,
    /// The programme manager terminates the grant.
    Terminate,
}

/// The scripted path of `proposal`. [`PR1`] reaches NEGOTIATION through
/// "no questions". Every other proposal reaches STAGE2 and gets a question.
/// Without `revise`, the question is never answered, the proposal is
/// deferred when the window expires and it re-enters call 2. With
/// `revise`, the lead answers and submits a revision that supersedes the
/// submitted plan. Both reviewers score it, one corrects that score, and
/// the proposal is ranked after stage 2.
pub fn script(proposal: ProposalId, revise: bool) -> Vec<Act> {
    use AssignmentKind::{Irc, Reviewer};
    if proposal != PR1 && revise {
        return vec![
            Act::Assign(R1, Reviewer),
            Act::Declare(R1, Reviewer),
            Act::Assign(R3, Reviewer),
            Act::Declare(R3, Reviewer),
            Act::CoordinatorDeclare,
            Act::KnockOut,
            Act::Admit,
            Act::Score(R1, [2, 2]),
            Act::Score(R3, [2, 1]),
            Act::Close,
            Act::Ask(R1),
            Act::Answer,
            Act::Revise,
            Act::SubmitRevision,
            Act::Score2(R1, [2, 2]),
            Act::Score2(R3, [1, 1]),
            Act::Correct2(R1, [1, 2]),
            Act::Rank(R1),
        ];
    }
    if proposal == PR1 {
        vec![
            Act::Assign(R1, Reviewer),
            Act::Declare(R1, Reviewer),
            Act::Assign(R2, Reviewer),
            Act::Declare(R2, Reviewer),
            Act::CoordinatorDeclare,
            Act::KnockOut,
            Act::Admit,
            Act::Score(R1, [2, 1]),
            Act::Score(R2, [2, 2]),
            Act::Close,
            Act::NoQuestions(R1),
            Act::NoQuestions(R2),
            Act::CutOff,
            Act::Assign(IRC, Irc),
            Act::Declare(IRC, Irc),
            Act::Irc(IRC),
            Act::Determine,
            Act::Accept,
            Act::Approve,
            Act::Contract,
            Act::Start,
            Act::AmendPlan,
            Act::ProposeAmendment,
            Act::RouteAmendment,
            Act::ActivateAmendment,
            Act::Request,
            Act::AcceptLine,
            Act::ApprovePay,
            Act::Release,
            Act::Confirm,
            Act::Terminate,
        ]
    } else {
        vec![
            Act::Assign(R1, Reviewer),
            Act::Declare(R1, Reviewer),
            Act::Assign(R3, Reviewer),
            Act::Declare(R3, Reviewer),
            Act::CoordinatorDeclare,
            Act::KnockOut,
            Act::Admit,
            Act::Score(R1, [2, 2]),
            Act::Score(R3, [2, 1]),
            Act::Close,
            Act::Ask(R1),
            Act::Expire,
            Act::PublishNext,
            Act::ReEnter,
        ]
    }
}

/// What the machine knows of the ledger, folded from the records production appended.
#[derive(Clone, Debug, Default)]
pub struct LedgerGhost {
    /// Whether the setup ran.
    pub ready: bool,
    /// The latest instant.
    pub now: Option<Timestamp>,
    /// The next scripted act of each proposal.
    pub cursors: BTreeMap<ProposalId, usize>,
    /// The state of each proposal.
    pub states: BTreeMap<ProposalId, StateTag>,
    /// The bindings, open or not, with their facts.
    pub bindings: BTreeMap<BindingId, BindingFacts>,
    /// The head policy version of the programme.
    pub head: Option<PolicyVersion>,
    /// The assignments: reviewer and proposal.
    pub assignments: BTreeMap<AssignmentId, (AccountId, ProposalId)>,
    /// The keys with a current score.
    pub keys: BTreeSet<ScoreKey>,
    /// The accounts with a conflict fact on a proposal.
    pub conflicts: BTreeSet<(AccountId, ProposalId)>,
    /// The next fresh id.
    pub next_id: u128,
    /// Whether [`PR2`] takes the stage 2 revision path of [`script`].
    pub revise: bool,
    /// The call each assignment was made in.
    pub assignment_calls: BTreeMap<AssignmentId, CallId>,
    /// The released assignments.
    pub released: BTreeSet<AssignmentId>,
    /// The call of each proposal's latest re-entry.
    pub reentered: BTreeMap<ProposalId, CallId>,
    /// The latest plan recorded for each proposal.
    pub latest_plan: BTreeMap<ProposalId, PlanVersionId>,
    /// The vault relations made: the reviewer and the lead.
    pub relations: BTreeSet<(AccountId, AccountId)>,
    /// The accounts the vault merged into another identity and has not split.
    pub merged: BTreeSet<AccountId>,
    /// Every policy version id recorded.
    pub policy_ids: BTreeSet<PolicyVersionId>,
}

impl LedgerGhost {
    /// The current call of `proposal`: its latest re-entry, else call 1.
    pub fn current_call(&self, proposal: ProposalId) -> CallId {
        self.reentered.get(&proposal).copied().unwrap_or(call(1))
    }

    /// Whether the vault knows a conflict of `reviewer` on `proposal`: a
    /// recorded conflict fact, or a relation to its lead while the
    /// reviewer is not merged into another identity.
    pub fn conflicted(&self, reviewer: AccountId, proposal: ProposalId) -> bool {
        self.conflicts.contains(&(reviewer, proposal))
            || (self.relations.contains(&(reviewer, lead_of(proposal)))
                && !self.merged.contains(&reviewer))
    }

    /// Whether `account` holds an open binding of `role`.
    pub fn holds(&self, account: AccountId, role: Role) -> bool {
        self.bindings
            .values()
            .any(|b| b.account == Some(account) && b.role == Some(role) && b.open())
    }

    /// Applies a vault change to what the ghost knows of the vault. The
    /// ground truth changes whether or not the reaction appends a batch.
    pub fn vault(&mut self, op: LedgerVaultOp) {
        match op {
            LedgerVaultOp::Relate(a, b) => {
                self.relations.insert((a, b));
            }
            LedgerVaultOp::Merge(a, _) => {
                self.merged.insert(a);
            }
            LedgerVaultOp::Split(a) => {
                self.merged.remove(&a);
            }
            LedgerVaultOp::Exclude(_) => {}
        }
    }

    /// The reference verdict of an I-23 correction command, or `None` for
    /// any other command. It reads the ghost alone (design 6.1).
    /// - `CorrectScore`: the key has a current value, its proposal is in
    ///   the key's stage, and the assignee may act. The assignment is
    ///   unreleased and of the proposal's current call. The assignee holds
    ///   an open committee binding and has no known conflict.
    /// - `EditPolicy`: the base is the head and the version id is fresh.
    /// - `EndRole`: the binding was granted, is not ended or voided, and is
    ///   not a Receiving binding, which ends with its proposal (Q11 A).
    /// - `ReinstateBinding`: the binding is granted, not ended or voided,
    ///   under a suspension not yet lifted, and its account is no longer
    ///   merged into another identity.
    pub fn reference(&self, step: &Step) -> Option<(bool, String)> {
        match &step.cmd {
            Command::CorrectScore { key, .. } => Some(self.correct_verdict(key)),
            Command::EditPolicy { base, version } => {
                let head = self.head.as_ref().map(|h| h.id);
                let fresh = !self.policy_ids.contains(&version.id);
                Some((
                    head == Some(*base) && fresh,
                    format!("base {base:?}, head {head:?}, fresh id {fresh}"),
                ))
            }
            Command::EndRole { binding, .. } => {
                let b = self.bindings.get(binding);
                let ok = b.is_some_and(|f| {
                    !f.ended
                        && !f.voided
                        && f.role
                            .is_some_and(|r| r.group() != fstp_domain::roles::Group::Receiving)
                });
                Some((ok, format!("binding facts {b:?}")))
            }
            Command::ReinstateBinding { binding, .. } => {
                let b = self.bindings.get(binding);
                let ok = b.is_some_and(|f| {
                    !f.ended
                        && !f.voided
                        && f.suspensions > f.reinstatements
                        && f.account.is_some_and(|a| !self.merged.contains(&a))
                });
                Some((ok, format!("binding facts {b:?}, merged {:?}", self.merged)))
            }
            _ => None,
        }
    }

    fn correct_verdict(&self, key: &ScoreKey) -> (bool, String) {
        let Some((reviewer, proposal)) = self.assignments.get(&key.assignment).copied() else {
            return (false, "no such assignment".to_owned());
        };
        let state = self.states.get(&proposal).copied();
        let checks = [
            ("a current value", self.keys.contains(key)),
            (
                "the proposal in the key's stage",
                state == Some(CorrectionView::stage_state(key.stage)),
            ),
            (
                "an unreleased assignment",
                !self.released.contains(&key.assignment),
            ),
            (
                "an assignment of the current call",
                self.assignment_calls.get(&key.assignment) == Some(&self.current_call(proposal)),
            ),
            (
                "an open committee binding",
                self.holds(reviewer, Role::CommitteeMember),
            ),
            ("no known conflict", !self.conflicted(reviewer, proposal)),
        ];
        match checks.iter().find(|(_, ok)| !ok) {
            Some((what, _)) => (false, format!("no {what}, proposal in {state:?}")),
            None => (
                true,
                format!("every condition holds, proposal in {state:?}"),
            ),
        }
    }

    fn fold(&mut self, records: &[CoreRecord]) {
        for r in records {
            match r {
                CoreRecord::Transitioned(t) => {
                    self.states.insert(t.proposal, t.to);
                }
                CoreRecord::ReEntered {
                    proposal, to_call, ..
                } => {
                    self.reentered.insert(*proposal, *to_call);
                }
                CoreRecord::PlanVersionRecorded(p) => {
                    self.latest_plan.insert(p.proposal, p.plan);
                }
                CoreRecord::AssignmentReleased(x) => {
                    self.released.insert(x.assignment);
                }
                CoreRecord::PolicyVersionRecorded { version, .. } => {
                    self.policy_ids.insert(version.id);
                    self.head = Some((**version).clone());
                }
                CoreRecord::BindingGranted(g) => {
                    self.bindings.insert(
                        g.binding,
                        BindingFacts {
                            account: Some(g.account),
                            role: Some(g.role),
                            ..BindingFacts::default()
                        },
                    );
                }
                CoreRecord::BindingEnded(x) => {
                    if let Some(b) = self.bindings.get_mut(&x.binding) {
                        b.ended = true;
                    }
                }
                CoreRecord::BindingVoided(x) => {
                    if let Some(b) = self.bindings.get_mut(&x.binding) {
                        b.voided = true;
                    }
                }
                CoreRecord::BindingSuspended(x) => {
                    if let Some(b) = self.bindings.get_mut(&x.binding) {
                        b.suspensions = b.suspensions.saturating_add(1);
                    }
                }
                CoreRecord::BindingReinstated(x) => {
                    if let Some(b) = self.bindings.get_mut(&x.binding) {
                        b.reinstatements = b.reinstatements.saturating_add(1);
                    }
                }
                CoreRecord::Assigned(a) => {
                    self.assignments
                        .insert(a.assignment, (a.reviewer, a.proposal));
                    self.assignment_calls.insert(a.assignment, a.call);
                }
                CoreRecord::ScoreRecorded(s) => {
                    self.keys.insert(s.key);
                }
                CoreRecord::ScoreVoided(x) => {
                    self.keys.remove(&x.key);
                }
                CoreRecord::ConflictDetected(c) => {
                    self.conflicts.insert((c.account, c.proposal));
                }
                CoreRecord::ConflictDeclared(c) if c.conflicted => match c.subject {
                    Declared::Assignment(a) => {
                        if let Some(pair) = self.assignments.get(&a).copied() {
                            self.conflicts.insert(pair);
                        }
                    }
                    Declared::Proposal { proposal, account } => {
                        self.conflicts.insert((account, proposal));
                    }
                },
                _ => {}
            }
        }
    }

    /// The proposals in RANKED.
    fn ranked(&self) -> Vec<ProposalId> {
        self.states
            .iter()
            .filter(|(_, s)| **s == StateTag::Ranked)
            .map(|(p, _)| *p)
            .collect()
    }

    /// The committee members with an open binding and no conflict on any of `ranked`.
    fn voters(&self, ranked: &[ProposalId]) -> Vec<AccountId> {
        let members: BTreeSet<AccountId> = self
            .bindings
            .values()
            .filter(|b| b.role == Some(Role::CommitteeMember) && b.open())
            .filter_map(|b| b.account)
            .filter(|a| !ranked.iter().any(|p| self.conflicts.contains(&(*a, *p))))
            .collect();
        members.into_iter().collect()
    }
}

/// The lead of a machine proposal.
pub fn lead_of(proposal: ProposalId) -> AccountId {
    if proposal == PR1 { L1 } else { L2 }
}

/// The steps of `act` on `proposal`, given what the ghost knows, or why
/// they cannot be built. Every act is one step, except the cut-off, which
/// since M4 change D5 is the steps of a whole round.
pub fn act_step(ghost: &LedgerGhost, proposal: ProposalId, act: Act) -> Result<Vec<Step>, String> {
    let lead = lead_of(proposal);
    let one = match act {
        Act::Assign(a, kind) => {
            let id = assignment_of(a, proposal, call(1), kind);
            assign(COORDINATOR, id, proposal, a, kind, Some(handle(id.raw())))
        }
        Act::Declare(a, kind) => declare(
            a,
            DeclarationSubject::Assignment(assignment_of(a, proposal, call(1), kind)),
            false,
            false,
        ),
        Act::CoordinatorDeclare => declare(
            COORDINATOR,
            DeclarationSubject::Proposal(proposal),
            false,
            false,
        ),
        Act::KnockOut => knock_out(proposal, true),
        Act::Admit => admit(proposal),
        Act::Score(r, v) => score(r, stage1_key(r, proposal), &v),
        Act::Close => close(Actor::Account(COORDINATOR), proposal),
        Act::NoQuestions(r) => no_questions(r, proposal, reviewer_assignment(r, proposal)),
        Act::CutOff => {
            let ranked = ghost.ranked();
            let voters = ghost.voters(&ranked);
            let nominated = u32::try_from(ranked.len()).unwrap_or(0);
            return Ok(cut_off(
                R1,
                cut_off_decision(ghost.next_id),
                call(1),
                ranked,
                nominated,
                false,
                ballots(&voters, Vote::For),
            ));
        }
        Act::Irc(i) => irc_review(
            i,
            assignment_of(i, proposal, call(1), AssignmentKind::Irc),
            true,
        ),
        Act::Ask(r) => ask(r, proposal, reviewer_assignment(r, proposal)),
        Act::Expire => system(Command::ExpireStage2 { proposal }),
        Act::PublishNext => publish(call(2)),
        Act::ReEnter => reenter(proposal, call(2)),
        Act::Answer => answer(lead, proposal),
        Act::Revise => {
            let live = ghost
                .latest_plan
                .get(&proposal)
                .copied()
                .unwrap_or(plan_of(proposal));
            first_revision(proposal, live)?
        }
        Act::SubmitRevision => submit_revision(lead, proposal, revision_of(proposal, 1)),
        Act::Score2(r, v) => score(r, stage2_key(r, proposal), &v),
        Act::Correct2(r, v) => correct(r, stage2_key(r, proposal), &v),
        Act::Rank(r) => rank(r, proposal),
        Act::Determine => money::determine(
            R1,
            proposal,
            money::amount_decision(proposal, 1),
            plan_of(proposal),
            &[],
        )?,
        Act::Accept => money::accept_grant(lead, proposal),
        Act::Approve => money::approve_grant(STAFF_PM, proposal),
        Act::Contract => money::contract_effective(proposal),
        Act::Start => money::start_execution(proposal),
        Act::AmendPlan => money::money_plan(
            lead,
            proposal,
            amended_plan(proposal),
            fstp_domain::proposal::PlanOrigin::Amendment,
            Some(plan_of(proposal)),
            &[(amended_milestone(proposal), AMENDED_CENTS, T0)],
        )?,
        Act::ProposeAmendment => money::propose_amendment(
            lead,
            amendment_of(proposal),
            proposal,
            amended_plan(proposal),
        ),
        Act::RouteAmendment => money::route_amendment(
            STAFF_PM,
            amendment_of(proposal),
            fstp_domain::amendment::AmendmentRoute::Exempt,
        ),
        Act::ActivateAmendment => {
            money::activate_amendment(amendment_of(proposal), amended_contract(proposal))
        }
        Act::Request => money::request_payment(
            lead,
            payment_request(proposal),
            proposal,
            &[(
                payment_line(proposal),
                amended_milestone(proposal),
                AMENDED_CENTS,
            )],
        )?,
        Act::AcceptLine => money::accept_line(
            R1,
            payment_request(proposal),
            payment_line(proposal),
            AMENDED_CENTS,
            false,
        )?,
        Act::ApprovePay => money::approve_payment(money::FINREL, payment_request(proposal)),
        Act::Release => money::release_payment(money::REL, payment_request(proposal)),
        Act::Confirm => money::confirm_paid(payment_request(proposal)),
        Act::Terminate => money::terminate(STAFF_PM, proposal),
    };
    Ok(vec![one])
}

/// The amount of the single milestone of a machine proposal's submitted
/// plan, in cents (`crate::gen::review::milestone`).
pub const MILESTONE_CENTS: i64 = 100_000;

/// The amount of the single milestone of the amendment plan, in cents.
/// It lies within the machine's P-04 and under P-05 (I-13, I-14).
pub const AMENDED_CENTS: i64 = 120_000;

/// The amendment plan of `proposal` in the ledger machine.
pub fn amended_plan(proposal: ProposalId) -> PlanVersionId {
    PlanVersionId::from_raw(4_500u128.saturating_add(proposal.raw()))
}

/// The milestone of [`amended_plan`].
pub fn amended_milestone(proposal: ProposalId) -> fstp_domain::id::MilestoneId {
    money::milestone_n(proposal, 10)
}

/// The amendment of `proposal` in the ledger machine.
pub fn amendment_of(proposal: ProposalId) -> fstp_domain::id::AmendmentId {
    fstp_domain::id::AmendmentId::from_raw(600u128.saturating_add(proposal.raw()))
}

/// The contract version that activates [`amendment_of`].
pub fn amended_contract(proposal: ProposalId) -> fstp_domain::id::ContractId {
    fstp_domain::id::ContractId::from_raw(54_100u128.saturating_add(proposal.raw()))
}

/// The payment request of `proposal` in the ledger machine.
pub fn payment_request(proposal: ProposalId) -> RequestId {
    RequestId::from_raw(30_000u128.saturating_add(proposal.raw()))
}

/// The line of [`payment_request`].
pub fn payment_line(proposal: ProposalId) -> LineId {
    LineId::from_raw(31_000u128.saturating_add(proposal.raw()))
}

/// A vault change of the ledger machine, processed in the same step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LedgerVaultOp {
    /// The vault relates the reviewer to the lead: a conflict of interest.
    Relate(AccountId, AccountId),
    /// The vault merges the account into the identity of another account.
    Merge(AccountId, AccountId),
    /// The vault learns that the account's identity is in the excluded class.
    Exclude(AccountId),
    /// The vault splits the account back to its own identity.
    Split(AccountId),
}

impl LedgerVaultOp {
    /// Applies the change to `truth`.
    pub fn apply(self, truth: &mut GroundTruth) {
        match self {
            LedgerVaultOp::Relate(a, b) => truth.relate(tag(a), tag(b), Relation::CoWorker),
            LedgerVaultOp::Merge(a, into) => {
                if let Some(t) = truth.identity_of(into) {
                    truth.set_identity(a, t);
                }
            }
            LedgerVaultOp::Exclude(a) => truth.exclude(tag(a), EXCLUDED),
            LedgerVaultOp::Split(a) => truth.set_identity(a, tag(a)),
        }
    }
}

/// One command of the ledger machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerCmd {
    /// Builds the start state from genesis. `revise` picks the path of
    /// [`PR2`] in [`script`].
    Setup {
        /// Whether PR2 takes the stage 2 revision path.
        revise: bool,
    },
    /// A core command at `now`. `scripted` names the proposal whose
    /// cursor moves on when the command is accepted.
    Core {
        /// The instant.
        now: Timestamp,
        /// The command, or since M4 change D5 the steps of a cut-off
        /// round. They run in order and stop at the first refusal.
        step: Box<Vec<Step>>,
        /// The proposal whose script this step comes from.
        scripted: Option<ProposalId>,
    },
    /// A vault change at `now`, with its reaction.
    Vault {
        /// The instant.
        now: Timestamp,
        /// The change.
        op: LedgerVaultOp,
    },
}

/// The system under test of the ledger machine.
#[derive(Debug, Default)]
pub struct LedgerSut {
    /// The run, once the setup ran.
    pub run: Option<LedgerRun>,
    /// The ledger before the latest command.
    pub previous: Vec<Entry<Record>>,
    /// For the teeth only: the ledger as the store holds it after the
    /// latest command, kept apart from the tampered read.
    pub honest: Vec<Entry<Record>>,
}

/// What one command of the ledger machine did.
#[derive(Debug)]
pub struct LedgerOutput {
    /// What the command is.
    pub context: String,
    /// What it did to the ledger, or why the batch checks failed.
    pub applied: Result<Applied, String>,
}

/// The fstp-prop machine of I-23 over the full engine.
///
/// Commands come from every lane that exists. They are policy edits, calls,
/// role grants, ends and reinstatements, drafts and submissions from
/// genesis, assignments, unassignments, declarations and reads. The
/// lifecycle runs with score corrections, withdrawals, expiry, re-entry
/// and declines. On one of two stage 2 paths the lead submits a revision
/// that supersedes the submitted plan, which is scored, corrected and
/// ranked. Past NEGOTIATION, PR1 runs the amount, the grant facts, the
/// start of execution, one payment and the termination. Vault changes
/// suspend, void and release.
///
/// The postcondition checks the batch of every command. For `CorrectScore`,
/// `EditPolicy`, `EndRole` and `ReinstateBinding` it also compares accept
/// and refuse with [`LedgerGhost::reference`] in both directions. The
/// invariant runs [`check_step`] after every command: the ledger only
/// grows, the state is its replay, and every correction targets an earlier
/// record of the same kind.
#[derive(Debug, Default)]
pub struct LedgerMachine {
    /// Commands per case.
    pub max_commands: usize,
    /// Teeth: after every command, the read of the ledger shows entry 1
    /// under other command bytes. The ledger kept for the next step stays
    /// the store's own, so only the prefix checks of the invariant see it.
    pub tamper: bool,
    /// The records of the latest command and whether it was accepted, for `next_state`.
    last: RefCell<Option<Applied>>,
}

impl LedgerMachine {
    /// The machine with `max_commands` commands per case.
    pub fn new(max_commands: usize) -> LedgerMachine {
        LedgerMachine {
            max_commands,
            tamper: false,
            last: RefCell::new(None),
        }
    }

    /// The same machine whose ledger reads show a changed past entry.
    pub fn tampering(max_commands: usize) -> LedgerMachine {
        LedgerMachine {
            tamper: true,
            ..LedgerMachine::new(max_commands)
        }
    }

    fn core(now: Timestamp, step: Step, scripted: Option<ProposalId>) -> LedgerCmd {
        LedgerMachine::core_steps(now, vec![step], scripted)
    }

    fn core_steps(now: Timestamp, steps: Vec<Step>, scripted: Option<ProposalId>) -> LedgerCmd {
        LedgerCmd::Core {
            now,
            step: Box::new(steps),
            scripted,
        }
    }

    fn gen_scripted(&self, g: &mut Gen, model: &LedgerGhost, now: Timestamp) -> LedgerCmd {
        let open: Vec<(ProposalId, Act)> = [PR1, PR2]
            .into_iter()
            .filter_map(|p| {
                let at = model.cursors.get(&p).copied().unwrap_or(0);
                script(p, model.revise).get(at).map(|a| (p, *a))
            })
            .collect();
        if open.is_empty() {
            return self.gen_noise(g, model, now);
        }
        let (p, act) = *g.pick(&open);
        let at = if act == Act::Expire {
            Timestamp::from_micros(
                now.micros()
                    .saturating_add(MICROS_PER_DAY.saturating_mul(29)),
            )
        } else {
            now
        };
        match act_step(model, p, act) {
            Ok(steps) => LedgerMachine::core_steps(at, steps, Some(p)),
            // Only a revision with a malformed milestone fails to build.
            Err(_) => LedgerMachine::core(now, read(R1, p), None),
        }
    }

    /// A command for a proposal's current situation: a question, the
    /// lead's answers or the expiry of a stage 2 window, and the
    /// publication of call 2 or the re-entry of a deferred proposal.
    fn gen_situational(&self, g: &mut Gen, model: &LedgerGhost, now: Timestamp) -> LedgerCmd {
        let in_state = |tag: StateTag| -> Vec<ProposalId> {
            model
                .states
                .iter()
                .filter(|(_, s)| **s == tag)
                .map(|(p, _)| *p)
                .collect()
        };
        let stage2 = in_state(StateTag::Stage2);
        let deferred = in_state(StateTag::Deferred);
        if let Some(p) = (!stage2.is_empty()).then(|| *g.pick(&stage2)) {
            let reviewers: Vec<AccountId> = model
                .assignments
                .values()
                .filter(|(_, q)| *q == p)
                .map(|(r, _)| *r)
                .collect();
            return match g.weighted(&[3, 1, 2]) {
                0 if !reviewers.is_empty() => {
                    let r = *g.pick(&reviewers);
                    LedgerMachine::core(now, ask(r, p, reviewer_assignment(r, p)), None)
                }
                1 => LedgerMachine::core(now, answer(lead_of(p), p), None),
                _ => {
                    let later = now
                        .micros()
                        .saturating_add(MICROS_PER_DAY.saturating_mul(29));
                    LedgerMachine::core(
                        Timestamp::from_micros(later),
                        system(Command::ExpireStage2 { proposal: p }),
                        None,
                    )
                }
            };
        }
        if let Some(p) = (!deferred.is_empty()).then(|| *g.pick(&deferred)) {
            return if g.bool() {
                LedgerMachine::core(now, publish(call(2)), None)
            } else {
                LedgerMachine::core(now, reenter(p, call(2)), None)
            };
        }
        // The programme manager's decline of a negotiation. It is refused
        // unless a NOTE 9 failure holds, for example after a vault change.
        let negotiating = in_state(StateTag::Negotiation);
        if let Some(p) = (!negotiating.is_empty() && g.bool()).then(|| *g.pick(&negotiating)) {
            return LedgerMachine::core(
                now,
                money::decline_negotiation(Actor::Account(STAFF_PM), p),
                None,
            );
        }
        self.gen_noise(g, model, now)
    }

    fn gen_noise(&self, g: &mut Gen, model: &LedgerGhost, now: Timestamp) -> LedgerCmd {
        let proposal = *g.pick(&[PR1, PR2]);
        let open_bindings: Vec<BindingId> = model
            .bindings
            .keys()
            .copied()
            .filter(|b| !is_staff_binding(*b))
            .collect();
        let fresh = model.next_id;
        match g.weighted(&[16, 8, 4, 6, 6, 4, 1, 6, 6, 3, 4, 4, 8, 4, 2, 1]) {
            0 => {
                let keys: Vec<ScoreKey> = model.keys.iter().copied().collect();
                if keys.is_empty() {
                    return self.gen_scripted(g, model, now);
                }
                let key = *g.pick(&keys);
                let reviewer = model
                    .assignments
                    .get(&key.assignment)
                    .map_or(R1, |(r, _)| *r);
                let v = *g.pick(&[[0u8, 0], [1, 1], [2, 2], [2, 1], [0, 2]]);
                LedgerMachine::core(now, correct(reviewer, key, &v), None)
            }
            1 => match &model.head {
                Some(head) => {
                    let p12 = g.u8_in(0..=2);
                    // Sometimes reuse a recorded version id, which I-23
                    // refuses: a correction is a new record.
                    let used: Vec<PolicyVersionId> = model.policy_ids.iter().copied().collect();
                    let id = if !used.is_empty() && g.weighted(&[5, 1]) == 1 {
                        *g.pick(&used)
                    } else {
                        PolicyVersionId::from_raw(fresh)
                    };
                    let mut step = edit_policy(head, id, |v| {
                        v.live.p12 = CoolingOff(p12);
                    });
                    // Sometimes base the edit on a superseded version, which
                    // I-23 refuses: a version names the latest as its parent.
                    let stale: Vec<PolicyVersionId> = model
                        .policy_ids
                        .iter()
                        .copied()
                        .filter(|v| *v != head.id)
                        .collect();
                    if !stale.is_empty() && g.weighted(&[4, 1]) == 1 {
                        let old = *g.pick(&stale);
                        if let Command::EditPolicy { base, version } = &mut step.cmd {
                            *base = old;
                            version.parent = Some(old);
                        }
                    }
                    LedgerMachine::core(now, step, None)
                }
                None => self.gen_scripted(g, model, now),
            },
            2 => {
                let role = *g.pick(&[Role::CommitteeMember, Role::Auditor, Role::IrcMember]);
                LedgerMachine::core(
                    now,
                    grant(BindingId::from_raw(fresh), R4, P1, role, now),
                    None,
                )
            }
            3 => {
                if open_bindings.is_empty() {
                    return self.gen_scripted(g, model, now);
                }
                let b = *g.pick(&open_bindings);
                LedgerMachine::core(now, end(b, now), None)
            }
            4 => {
                let suspended: Vec<BindingId> = model
                    .bindings
                    .iter()
                    .filter(|(_, f)| f.suspensions > f.reinstatements)
                    .map(|(b, _)| *b)
                    .collect();
                let pool = if suspended.is_empty() || g.weighted(&[4, 1]) == 1 {
                    open_bindings
                } else {
                    suspended
                };
                if pool.is_empty() {
                    return self.gen_scripted(g, model, now);
                }
                LedgerMachine::core(now, reinstate(*g.pick(&pool)), None)
            }
            5 => {
                let reader = *g.pick(&[R1, R2, R3, COORDINATOR, IRC]);
                LedgerMachine::core(now, read(reader, proposal), None)
            }
            6 => LedgerMachine::core(now, withdraw(lead_of(proposal), proposal), None),
            7 => {
                let reviewer = *g.pick(&[R1, R2, R3]);
                LedgerCmd::Vault {
                    now,
                    op: LedgerVaultOp::Relate(reviewer, lead_of(proposal)),
                }
            }
            8 => {
                // Mostly split a suspended account back, so that its
                // reinstatement can follow; otherwise merge a judge into
                // the call drafter's identity, which suspends it.
                let suspended: Vec<AccountId> = model
                    .bindings
                    .values()
                    .filter(|f| f.suspensions > f.reinstatements)
                    .filter_map(|f| f.account)
                    .collect();
                let op = if !suspended.is_empty() && g.weighted(&[1, 3]) == 1 {
                    LedgerVaultOp::Split(*g.pick(&suspended))
                } else {
                    LedgerVaultOp::Merge(*g.pick(&[IRC2, R3, IRC]), STAFF_DRAFTER)
                };
                LedgerCmd::Vault { now, op }
            }
            9 => LedgerCmd::Vault {
                now,
                op: LedgerVaultOp::Exclude(lead_of(proposal)),
            },
            10 => {
                let later = now
                    .micros()
                    .saturating_add(MICROS_PER_DAY.saturating_mul(29));
                let in_stage2: Vec<ProposalId> = model
                    .states
                    .iter()
                    .filter(|(_, s)| **s == StateTag::Stage2)
                    .map(|(p, _)| *p)
                    .collect();
                let target = if in_stage2.is_empty() {
                    proposal
                } else {
                    *g.pick(&in_stage2)
                };
                LedgerMachine::core(
                    Timestamp::from_micros(later),
                    system(Command::ExpireStage2 { proposal: target }),
                    None,
                )
            }
            11 => {
                if g.bool() {
                    LedgerMachine::core(now, publish(call(2)), None)
                } else {
                    let deferred: Vec<ProposalId> = model
                        .states
                        .iter()
                        .filter(|(_, s)| **s == StateTag::Deferred)
                        .map(|(p, _)| *p)
                        .collect();
                    let target = if deferred.is_empty() {
                        proposal
                    } else {
                        *g.pick(&deferred)
                    };
                    LedgerMachine::core(now, reenter(target, call(2)), None)
                }
            }
            12 => {
                // Mostly a reviewer of a proposal in STAGE2, so that the
                // window can expire without answers.
                let in_stage2: Vec<(AccountId, ProposalId)> = model
                    .assignments
                    .values()
                    .copied()
                    .filter(|(_, p)| model.states.get(p) == Some(&StateTag::Stage2))
                    .collect();
                let (reviewer, target) = if in_stage2.is_empty() {
                    (*g.pick(&[R1, R2, R3]), proposal)
                } else {
                    *g.pick(&in_stage2)
                };
                let assignment = reviewer_assignment(reviewer, target);
                LedgerMachine::core(now, ask(reviewer, target, assignment), None)
            }
            13 => {
                let at = model.cursors.get(&proposal).copied().unwrap_or(0);
                let back = at.saturating_sub(1);
                let again = script(proposal, model.revise)
                    .get(back)
                    .and_then(|act| act_step(model, proposal, *act).ok());
                match again {
                    Some(steps) => LedgerMachine::core_steps(now, steps, None),
                    None => LedgerMachine::core(now, publish(call(1)), None),
                }
            }
            14 => {
                let made: Vec<AssignmentId> = model.assignments.keys().copied().collect();
                if made.is_empty() {
                    return self.gen_scripted(g, model, now);
                }
                LedgerMachine::core(now, unassign(COORDINATOR, *g.pick(&made)), None)
            }
            _ => LedgerMachine::core(now, decline(Actor::Account(STAFF_PM), proposal), None),
        }
    }
}

impl StateMachine for LedgerMachine {
    type Model = LedgerGhost;
    type Sut = LedgerSut;
    type Command = LedgerCmd;
    type Output = LedgerOutput;

    fn init_model(&self) -> LedgerGhost {
        LedgerGhost {
            next_id: 10_000,
            ..LedgerGhost::default()
        }
    }

    fn init_sut(&self) -> LedgerSut {
        LedgerSut::default()
    }

    fn command(&self, g: &mut Gen, model: &LedgerGhost) -> LedgerCmd {
        if !model.ready {
            return LedgerCmd::Setup { revise: g.bool() };
        }
        let now = model.now.unwrap_or(T_EVAL);
        match g.weighted(&[6, 2, 1]) {
            0 => self.gen_scripted(g, model, now),
            1 => self.gen_noise(g, model, now),
            _ => self.gen_situational(g, model, now),
        }
    }

    fn precondition(&self, model: &LedgerGhost, cmd: &LedgerCmd) -> bool {
        match cmd {
            LedgerCmd::Setup { .. } => !model.ready,
            LedgerCmd::Core { now, .. } | LedgerCmd::Vault { now, .. } => {
                model.ready && model.now.is_none_or(|t| *now >= t)
            }
        }
    }

    fn run(&self, sut: &mut LedgerSut, cmd: &LedgerCmd) -> LedgerOutput {
        self.last.replace(None);
        let (context, applied) = match cmd {
            LedgerCmd::Setup { .. } => {
                let setup = ledger_machine_setup();
                let built = machine_genesis_steps(&setup)
                    .and_then(|steps| LedgerRun::new(ledger_truth(&setup), &steps));
                let applied = built.map(|run| {
                    let records = core_of(&run.ledger);
                    sut.previous = Vec::new();
                    sut.run = Some(run);
                    Applied {
                        accepted: true,
                        appended: records,
                        refusal: None,
                    }
                });
                ("setup from genesis".to_owned(), applied)
            }
            LedgerCmd::Core { now, step, .. } => {
                let context = step
                    .iter()
                    .map(|s| format!("{:?} by {:?}", s.cmd, s.actor))
                    .collect::<Vec<_>>()
                    .join(", then ");
                match sut.run.as_mut() {
                    Some(run) => {
                        sut.previous = if self.tamper {
                            core::mem::take(&mut sut.honest)
                        } else {
                            run.ledger.clone()
                        };
                        (context, run_steps(run, *now, step))
                    }
                    None => (context, Err("no run".to_owned())),
                }
            }
            LedgerCmd::Vault { now, op } => {
                let context = format!("vault change {op:?}");
                match sut.run.as_mut() {
                    Some(run) => {
                        sut.previous = if self.tamper {
                            core::mem::take(&mut sut.honest)
                        } else {
                            run.ledger.clone()
                        };
                        (context, run.vault(*now, |t| op.apply(t)))
                    }
                    None => (context, Err("no run".to_owned())),
                }
            }
        };
        // Teeth: the read of the ledger shows entry 1 under other command
        // bytes. Replay ignores them, so only the prefix checks can see
        // it. The ledger kept as the next `previous` stays the store's own.
        if self.tamper
            && let Some(run) = sut.run.as_mut()
        {
            sut.honest = run.ledger.clone();
            if let Some(first) = run.ledger.first_mut() {
                for b in &mut first.command {
                    *b ^= 0xff;
                }
            }
        }
        if let Ok(a) = &applied {
            self.last.replace(Some(a.clone()));
        }
        LedgerOutput { context, applied }
    }

    /// The batch checks of every command, and for the I-23 correction
    /// commands the verdict of [`LedgerGhost::reference`] in both
    /// directions (design 6.1, "Two-way postconditions").
    fn postcondition(
        &self,
        model: &LedgerGhost,
        cmd: &LedgerCmd,
        out: &LedgerOutput,
    ) -> Result<(), String> {
        let applied = out
            .applied
            .as_ref()
            .map_err(|e| format!("{}: {e}", out.context))?;
        let LedgerCmd::Core { step, .. } = cmd else {
            return Ok(());
        };
        // The I-23 reference judges single correction commands. A cut-off
        // round is a sequence of steps, and no correction is among them.
        let [step] = step.as_slice() else {
            return Ok(());
        };
        let Some((expected, why)) = model.reference(step) else {
            return Ok(());
        };
        match (expected, applied.accepted) {
            (true, true) | (false, false) => Ok(()),
            (false, true) => Err(format!(
                "I-23: {}: over-permission, the engine accepted what the reference refuses ({why})",
                out.context
            )),
            (true, false) => Err(format!(
                "I-23: {}: over-denial, the engine refused ({:?}) what the reference accepts ({why})",
                out.context, applied.refusal
            )),
        }
    }

    fn next_state(&self, model: &mut LedgerGhost, cmd: &LedgerCmd) {
        let applied = self.last.borrow().clone();
        let accepted = applied.as_ref().is_some_and(|a| a.accepted);
        // Time moves only with an accepted command, as the ledger's latest
        // time does, so a refused late command never closes a window.
        match cmd {
            LedgerCmd::Setup { revise } => {
                model.ready = true;
                model.revise = *revise;
                model.now = Some(T_EVAL);
            }
            LedgerCmd::Core { now, scripted, .. } if accepted => {
                model.now = Some(*now);
                if let Some(p) = scripted {
                    let at = model.cursors.entry(*p).or_insert(0);
                    *at = at.saturating_add(1);
                }
            }
            LedgerCmd::Vault { now, op } => {
                model.vault(*op);
                if accepted {
                    model.now = Some(*now);
                }
            }
            LedgerCmd::Core { .. } => {}
        }
        if let Some(a) = applied {
            model.fold(&a.appended);
        }
        model.next_id = model.next_id.saturating_add(1);
    }

    fn invariant(&self, _model: &LedgerGhost, sut: &LedgerSut) -> Result<(), String> {
        match &sut.run {
            Some(run) => check_step(&sut.previous, run),
            None => Ok(()),
        }
    }

    fn max_commands(&self) -> usize {
        self.max_commands
    }
}

// ---------------------------------------------------------------------------
// M-LEDGER
// ---------------------------------------------------------------------------

/// The I-23 record budget of M-LEDGER after the start (design 6.3).
pub const M_LEDGER_BUDGET: usize = 6;

/// The state count of M-LEDGER, measured on production in step W6.
pub const M_LEDGER_STATES: usize = 1_422;

/// The binding of the IRC member, the fourth judge of [`m_ledger_judges`].
pub const M_LEDGER_IRC_BINDING: BindingId = BindingId::from_raw(203);

/// The judges of M-LEDGER: the coordinator, the two reviewers and an IRC member.
pub fn m_ledger_judges() -> Vec<(AccountId, Role, Option<fstp_domain::id::OrganisationId>)> {
    ledger_judges()
        .into_iter()
        .filter(|(a, _, _)| [COORDINATOR, R1, R2, IRC].contains(a))
        .collect()
}

/// One action of M-LEDGER on [`PR1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LedgerAction {
    /// The reviewer scores (2, 1).
    Score(AccountId),
    /// The reviewer corrects the score to (2, 2). One correction per run.
    Correct(AccountId),
    /// The programme manager edits P-12: a new policy version.
    EditPolicy,
    /// The tenant admin ends the IRC member's binding.
    EndIrc,
    /// The vault relates the reviewer to the lead, and the reaction runs.
    Conflict(AccountId),
    /// The coordinator closes stage 1.
    Close,
}

/// One M-LEDGER state: the engine with its store, and the ledger it carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LedgerState {
    /// The engine over its store, and the ledger read after the latest step.
    pub run: LedgerRun,
    /// The I-23 records appended since the start.
    pub used: usize,
    /// The actions taken, each at most once. A correction counts for both reviewers.
    pub done: BTreeSet<LedgerAction>,
    /// Set when a step broke a batch check or the driver failed.
    pub failure: Option<String>,
}

/// M-LEDGER (design 6.3): one proposal in STAGE1 from genesis, two
/// reviewers, P-03 = 2 and a budget of six I-23 records.
pub struct LedgerModel {
    /// The start state.
    pub start: LedgerState,
}

/// The start of M-LEDGER: [`PR1`] in STAGE1 with R1 and R2 assigned and declared.
pub fn m_ledger_start() -> Result<LedgerState, String> {
    let setup = ledger_setup(m_ledger_judges(), &[(L1, PR1)], 1);
    let mut steps = genesis_steps(&setup)?;
    for r in [R1, R2] {
        for s in assign_declared(r, PR1, call(1), AssignmentKind::Reviewer) {
            steps.push((T_EVAL, s));
        }
    }
    steps.push((
        T_EVAL,
        declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false),
    ));
    steps.push((T_EVAL, knock_out(PR1, true)));
    steps.push((T_EVAL, admit(PR1)));
    Ok(LedgerState {
        run: LedgerRun::new(ledger_truth(&setup), &steps)?,
        used: 0,
        done: BTreeSet::new(),
        failure: None,
    })
}

/// The M-LEDGER actions, in exploration order.
pub const M_LEDGER_ACTIONS: [LedgerAction; 8] = [
    LedgerAction::Score(R1),
    LedgerAction::Score(R2),
    LedgerAction::Correct(R1),
    LedgerAction::Correct(R2),
    LedgerAction::EditPolicy,
    LedgerAction::EndIrc,
    LedgerAction::Conflict(R2),
    LedgerAction::Close,
];

impl LedgerModel {
    /// M-LEDGER from genesis.
    pub fn new() -> Result<LedgerModel, String> {
        Ok(LedgerModel {
            start: m_ledger_start()?,
        })
    }
}

/// Runs `steps` on `run` at `now`, in order, stopping at the first
/// refusal. The result is accepted when every step is, appends every
/// record the accepted steps appended, and names the first refusal.
fn run_steps(run: &mut LedgerRun, now: Timestamp, steps: &[Step]) -> Result<Applied, String> {
    let mut out = Applied {
        accepted: true,
        appended: Vec::new(),
        refusal: None,
    };
    for s in steps {
        let a = run.core(now, s)?;
        out.appended.extend(a.appended);
        if !a.accepted {
            out.accepted = false;
            out.refusal = a.refusal;
            break;
        }
    }
    Ok(out)
}

/// Runs `action` of M-LEDGER on `run`.
fn apply_action(run: &mut LedgerRun, action: LedgerAction) -> Result<Applied, String> {
    match action {
        LedgerAction::Score(r) => run.core(T_EVAL, &score(r, stage1_key(r, PR1), &[2, 1])),
        LedgerAction::Correct(r) => run.core(T_EVAL, &correct(r, stage1_key(r, PR1), &[2, 2])),
        LedgerAction::EditPolicy => {
            let head = fstp_domain::policy::head(&run.scenario.state().core, P1)
                .cloned()
                .ok_or("no policy head")?;
            let step = edit_policy(&head, PolicyVersionId::from_raw(900), |v| {
                v.live.p12 = CoolingOff(2);
            });
            run.core(T_EVAL, &step)
        }
        LedgerAction::EndIrc => run.core(T_EVAL, &end(M_LEDGER_IRC_BINDING, T_EVAL)),
        LedgerAction::Conflict(r) => {
            run.vault(T_EVAL, |t| t.relate(tag(r), tag(L1), Relation::CoWorker))
        }
        LedgerAction::Close => run.core(T_EVAL, &close(Actor::Account(COORDINATOR), PR1)),
    }
}

/// Whether `done` already holds `action`: each action runs once, and one
/// correction runs per model run.
fn taken(done: &BTreeSet<LedgerAction>, action: LedgerAction) -> bool {
    match action {
        LedgerAction::Correct(_) => done.iter().any(|a| matches!(a, LedgerAction::Correct(_))),
        a => done.contains(&a),
    }
}

/// One M-LEDGER step: `None` when the action was taken before, was
/// refused, or would pass the budget.
fn step_state(state: &LedgerState, action: LedgerAction) -> Option<LedgerState> {
    if state.failure.is_some() || taken(&state.done, action) {
        return None;
    }
    let mut next = state.clone();
    match apply_action(&mut next.run, action) {
        Ok(a) if !a.accepted => None,
        Ok(a) => {
            let counted = a.appended.iter().filter(|r| is_i23_record(r)).count();
            next.used = next.used.saturating_add(counted);
            if next.used > M_LEDGER_BUDGET {
                return None;
            }
            next.done.insert(action);
            Some(next)
        }
        Err(e) => {
            next.failure = Some(e);
            Some(next)
        }
    }
}

impl Model for LedgerModel {
    type State = LedgerState;
    type Action = LedgerAction;

    fn init(&self) -> Vec<LedgerState> {
        vec![self.start.clone()]
    }

    fn actions(&self, state: &LedgerState, actions: &mut Vec<LedgerAction>) {
        if state.failure.is_some() {
            return;
        }
        actions.extend(M_LEDGER_ACTIONS);
    }

    fn step(&self, state: &LedgerState, action: &LedgerAction) -> Option<LedgerState> {
        step_state(state, *action)
    }

    fn is_terminal(&self, _state: &LedgerState) -> bool {
        true
    }
}

/// `transition("I-23")` of M-LEDGER: the step did not fail, `before.ledger`
/// is a strict prefix of `after.ledger`, field by field and by canonical
/// bytes, and `replay(after.ledger) == after.state`.
pub fn transition_i23(before: &LedgerState, after: &LedgerState) -> Result<(), String> {
    if let Some(f) = &after.failure {
        return Err(f.clone());
    }
    let (old, new) = (&before.run.ledger, &after.run.ledger);
    if new.len() <= old.len() {
        return Err(format!(
            "I-23: an accepted step left the ledger at {} entries from {}",
            new.len(),
            old.len()
        ));
    }
    append_only(old, new)?;
    verify_canonical(old, new)?;
    replay_matches(new, after.run.scenario.state())
}

/// Whether the ledger of `s` holds a core record that `f` selects after the start.
fn holds(s: &LedgerState, f: impl Fn(&CoreRecord) -> bool) -> bool {
    s.run.ledger.iter().any(|e| match &e.record {
        Record::Core(r) => f(r),
        Record::Finding(_) => false,
    })
}

/// The M-LEDGER properties: `transition("I-23")`, the corrections
/// reference in every state, and witnesses of each correction kind.
pub fn m_ledger_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = LedgerState> + 'a,
{
    vec![
        Property::transition_with("I-23", |b: &LedgerState, _, a: &LedgerState| {
            transition_i23(b, a)
        }),
        Property::always_with("I-23 corrections", |s: &LedgerState| {
            check_corrections(&s.run.ledger)
        }),
        Property::reachable("I-23 witness: a score correction", |s: &LedgerState| {
            holds(
                s,
                |r| matches!(r, CoreRecord::ScoreRecorded(x) if x.supersedes.is_some()),
            )
        }),
        Property::reachable(
            "I-23 witness: a second policy version",
            |s: &LedgerState| {
                holds(
                    s,
                    |r| matches!(r, CoreRecord::PolicyVersionRecorded { version, .. } if version.parent.is_some()),
                )
            },
        ),
        Property::reachable("I-23 witness: a binding end", |s: &LedgerState| {
            holds(s, |r| matches!(r, CoreRecord::BindingEnded(_)))
        }),
        Property::reachable(
            "I-23 witness: a release by a vault conflict",
            |s: &LedgerState| holds(s, |r| matches!(r, CoreRecord::AssignmentReleased(_))),
        ),
        Property::reachable(
            "I-23 witness: stage 1 closed after a correction",
            |s: &LedgerState| {
                s.done.contains(&LedgerAction::Close)
                    && holds(
                        s,
                        |r| matches!(r, CoreRecord::ScoreRecorded(x) if x.supersedes.is_some()),
                    )
            },
        ),
    ]
}

/// The teeth fault of M-LEDGER. An honest action runs first, so the
/// ledger grows and the state is still its replay. The read of the ledger
/// then shows the latest earlier score entry under other command bytes,
/// which replay never reads. A store that rewrote a past entry during an
/// honest append would look like this. Only the prefix checks of
/// [`transition_i23`] can catch it.
pub fn change_past_score(s: &LedgerState) -> Option<LedgerState> {
    let seq = s
        .run
        .ledger
        .iter()
        .rev()
        .find(|e| matches!(&e.record, Record::Core(CoreRecord::ScoreRecorded(_))))?
        .seq;
    let mut next = M_LEDGER_ACTIONS
        .iter()
        .filter_map(|a| step_state(s, *a))
        .find(|n| n.failure.is_none())?;
    let entry = next.run.ledger.iter_mut().find(|e| e.seq == seq)?;
    for b in &mut entry.command {
        *b ^= 0xff;
    }
    Some(next)
}

//! Teeth helpers that inject records through the public apply (design section 6.1).
//!
//! - [`inject`] and [`inject_envelope`] fold a record that a broken engine
//!   would emit, through the public structural `apply`. No production hook
//!   exists. They change the state only, which suits models whose state
//!   has no ledger.
//! - [`inject_entry`] appends the injected record to a model ledger with
//!   the next sequence number and folds it into the state in the same call.
//!   So `replay(ledger) == state` still holds after the injection, and only
//!   the target property can catch the fault.
//! - [`replace_record`] changes the record of a past ledger entry and keeps
//!   its envelope: the "changed past entry" fault.
//! - [`Injecting`] adds a fault action to a model, beside its own actions.
//!   [`expect_violation`] then asserts that the property catches the fault.
//! - [`Dropping`] is an over-denial mutant: it drops legal actions.
//!   [`expect_unreachable`] asserts that a `reachable` witness disappears.
//! - [`expect_prop_failure`] asserts that an fstp-prop run fails with a
//!   counterexample that names the target property.
//!
//! Each assertion returns an error when the fault goes undetected, so a
//! broken property cannot pass its teeth test.
//!
//! A teeth property has its own id, apart from the I-23 ledger checks of
//! `harness::prop`. Its failure message starts with that id and a colon,
//! for example `"I-14: grant above the cap"`, as the ledger checks start
//! with `"I-23:"`. A failure that names only another id, such as I-23, is
//! reported as an undetected fault.

use fstp_domain::engine::{FoldError, apply};
use fstp_domain::record::Record;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;
use fstp_json::FromJson;
use fstp_ledger::{Entry, Seq};
use fstp_mc::{Model, Outcome, Verdict};
use fstp_prop::FailureKind;

/// Folds `record` into `state` through the public structural `apply`.
/// When the fold refuses, the state is left unchanged and the refusal returned.
pub fn inject(
    state: &mut State,
    seq: Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let mut next = state.clone();
    apply(&mut next, seq, at, record)?;
    *state = next;
    Ok(())
}

/// Folds an envelope record into an engine state through `fstp_engine::apply`.
/// When the fold refuses, the state is left unchanged and the refusal returned.
pub fn inject_envelope(
    state: &mut EngineState,
    seq: Seq,
    at: Timestamp,
    record: &fstp_engine::Record,
) -> Result<(), FoldError> {
    let mut next = state.clone();
    fstp_engine::apply(&mut next, seq, at, record)?;
    *state = next;
    Ok(())
}

/// Why [`inject_entry`] injected nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InjectError {
    /// The ledger already holds `u64::MAX` entries.
    Full,
    /// The entry could not be built from the ledger's stored form.
    Entry(String),
    /// The fold refused the record.
    Fold(FoldError),
}

impl core::fmt::Display for InjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InjectError::Full => f.write_str("the ledger is full"),
            InjectError::Entry(e) => write!(f, "no entry: {e}"),
            InjectError::Fold(e) => write!(f, "{e}"),
        }
    }
}

/// The stored form of an entry, used as a template. Only a store or the
/// decoder builds entries, so injection decodes this and sets the fields.
const TEMPLATE: &[u8] =
    br#"{"at":0,"command":"00000000000000000000000000000000","record":null,"schema":1,"seq":"1"}"#;

/// An entry with these envelope fields and `record`, schema version 1.
fn entry(
    seq: Seq,
    at: Timestamp,
    command: [u8; 16],
    record: fstp_engine::Record,
) -> Result<Entry<fstp_engine::Record>, InjectError> {
    let value = fstp_json::parse(TEMPLATE).map_err(|e| InjectError::Entry(format!("{e:?}")))?;
    let template: Entry<fstp_json::Value> =
        Entry::from_json(&value).map_err(|e| InjectError::Entry(format!("{e:?}")))?;
    let mut e = template.map_record(|_| record);
    e.seq = seq;
    e.at = at.micros();
    e.command = command;
    Ok(e)
}

/// Appends `record` to `ledger` as the next entry, under `command` at
/// `at`, and folds it into `state` in the same call. Returns the new
/// entry's sequence number.
///
/// When the fold refuses, neither the ledger nor the state changes. So
/// `replay(ledger) == state` holds after the call whenever it held before.
pub fn inject_entry(
    ledger: &mut Vec<Entry<fstp_engine::Record>>,
    state: &mut EngineState,
    at: Timestamp,
    command: [u8; 16],
    record: fstp_engine::Record,
) -> Result<Seq, InjectError> {
    let last = ledger.last().map_or(0, |e| e.seq.raw());
    let seq = Seq::from_raw(last.checked_add(1).ok_or(InjectError::Full)?);
    let mut next = state.clone();
    fstp_engine::apply(&mut next, seq, at, &record).map_err(InjectError::Fold)?;
    ledger.push(entry(seq, at, command, record)?);
    *state = next;
    Ok(seq)
}

/// Replaces the record of the entry numbered `seq` in `ledger`, keeping its
/// envelope: the "changed past entry" fault. Returns the old record, or
/// `None` when no entry has that number.
pub fn replace_record(
    ledger: &mut [Entry<fstp_engine::Record>],
    seq: Seq,
    record: fstp_engine::Record,
) -> Option<fstp_engine::Record> {
    let e = ledger.iter_mut().find(|e| e.seq == seq)?;
    Some(core::mem::replace(&mut e.record, record))
}

/// Passes when the property `id` was violated in `outcome`.
pub fn expect_violation<S, A>(outcome: &Outcome<S, A>, id: &str) -> Result<(), String> {
    match outcome.verdict(id) {
        Some(Verdict::Violated(_)) => Ok(()),
        Some(v) => Err(format!(
            "teeth: the injected fault went undetected, {id} is {}",
            v.label()
        )),
        None => Err(format!("teeth: no property {id} was checked")),
    }
}

/// Passes when the `reachable` property `id` was found unreachable by an
/// exhaustive run, as an over-denial mutant should make it.
pub fn expect_unreachable<S, A>(outcome: &Outcome<S, A>, id: &str) -> Result<(), String> {
    match outcome.verdict(id) {
        Some(Verdict::Unreachable) => Ok(()),
        Some(v) => Err(format!(
            "teeth: the over-denial mutant went undetected, {id} is {}",
            v.label()
        )),
        None => Err(format!("teeth: no property {id} was checked")),
    }
}

/// Whether `message` names the property `id`: it holds `id` followed by a
/// colon, at the start or after a character that cannot be part of an id.
/// So `"I-2"` is not named by `"I-23: ..."`.
pub fn names_property(message: &str, id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let needle = format!("{id}:");
    message.match_indices(&needle).any(|(i, _)| {
        message
            .get(..i)
            .and_then(|before| before.chars().next_back())
            .is_none_or(|c| !(c.is_alphanumeric() || c == '-' || c == '_'))
    })
}

/// Passes when an fstp-prop run failed with a counterexample that fails
/// again on replay and whose message names the property `id`, see
/// [`names_property`]. A passing run, a flaky failure, too many discards,
/// or a failure of another property such as the I-23 ledger check mean
/// the fault was not reliably detected by `id`.
pub fn expect_prop_failure(outcome: &fstp_prop::Outcome, id: &str) -> Result<(), String> {
    match outcome.failure() {
        Some(f) if f.kind == FailureKind::Counterexample && names_property(&f.message, id) => {
            Ok(())
        }
        Some(f) if f.kind == FailureKind::Counterexample => Err(format!(
            "teeth: the injected fault went undetected by {id}; the run failed on another property: {}",
            f.message
        )),
        Some(f) => Err(format!(
            "teeth: the property failed only as {:?}, not with a counterexample",
            f.kind
        )),
        None => Err(format!(
            "teeth: the injected fault went undetected, {id} passed"
        )),
    }
}

/// An action of a mutant model: one of the model's own, or the injected fault.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Mutant<A> {
    /// An action of the model.
    Model(A),
    /// The injected fault.
    Fault,
}

/// `M` with one extra action, the fault. The fault maps a state to the
/// state a broken engine would reach, or `None` where it does not apply.
/// Faults usually build that state with [`inject`].
pub struct Injecting<'a, M, F> {
    model: &'a M,
    fault: F,
}

impl<'a, M: Model, F: Fn(&M::State) -> Option<M::State>> Injecting<'a, M, F> {
    /// `model` with the fault `fault`.
    pub fn new(model: &'a M, fault: F) -> Injecting<'a, M, F> {
        Injecting { model, fault }
    }
}

impl<M: Model, F: Fn(&M::State) -> Option<M::State>> Model for Injecting<'_, M, F> {
    type State = M::State;
    type Action = Mutant<M::Action>;

    fn init(&self) -> Vec<M::State> {
        self.model.init()
    }

    fn actions(&self, state: &M::State, actions: &mut Vec<Mutant<M::Action>>) {
        let mut own = Vec::new();
        self.model.actions(state, &mut own);
        actions.extend(own.into_iter().map(Mutant::Model));
        actions.push(Mutant::Fault);
    }

    fn step(&self, state: &M::State, action: &Mutant<M::Action>) -> Option<M::State> {
        match action {
            Mutant::Model(a) => self.model.step(state, a),
            Mutant::Fault => (self.fault)(state),
        }
    }

    fn is_terminal(&self, state: &M::State) -> bool {
        self.model.is_terminal(state)
    }

    fn canonicalize(&self, state: &M::State) -> M::State {
        self.model.canonicalize(state)
    }
}

/// `M` without the actions that `drop` selects: an over-denial mutant.
pub struct Dropping<'a, M, D> {
    model: &'a M,
    drop: D,
}

impl<'a, M: Model, D: Fn(&M::Action) -> bool> Dropping<'a, M, D> {
    /// `model` without every action for which `drop` is true.
    pub fn new(model: &'a M, drop: D) -> Dropping<'a, M, D> {
        Dropping { model, drop }
    }
}

impl<M: Model, D: Fn(&M::Action) -> bool> Model for Dropping<'_, M, D> {
    type State = M::State;
    type Action = M::Action;

    fn init(&self) -> Vec<M::State> {
        self.model.init()
    }

    fn actions(&self, state: &M::State, actions: &mut Vec<M::Action>) {
        self.model.actions(state, actions);
        actions.retain(|a| !(self.drop)(a));
    }

    fn step(&self, state: &M::State, action: &M::Action) -> Option<M::State> {
        if (self.drop)(action) {
            None
        } else {
            self.model.step(state, action)
        }
    }

    fn is_terminal(&self, state: &M::State) -> bool {
        self.model.is_terminal(state)
    }

    fn canonicalize(&self, state: &M::State) -> M::State {
        self.model.canonicalize(state)
    }
}

//! Composition of the domain core and findings.
//!
//! The crate holds `EngineState`, the `Command` and `Record` envelopes over
//! core and finding values, the synchronous `IdentityOracle` trait and the
//! synchronous reference driver (`docs/handoff/m2-design.md` section 3.1).
//! Core commands go to `fstp_domain::decide`, which never sees the finding
//! store. Finding commands go to `decide_finding`, which returns only finding
//! records (I-10).
//!
//! - [`apply`] folds one envelope record into an [`EngineState`]. A core
//!   record goes to `fstp_domain::apply` on the core part only.
//! - [`replay`] folds a whole ledger from genesis and checks that sequence
//!   numbers run from 1 without gaps.
//! - [`envelope_to_json`] and [`envelope_from_json`] give the stored JSON
//!   shape of an envelope around the inner record's own JSON value.
//!
//! # Finding placeholder
//!
//! `fstp-findings` is still an empty skeleton owned by lane L-FIND-A. Until
//! it lands, [`FindingStore`], [`FindingCommand`] and [`FindingRecord`] are
//! placeholders in this crate. The command and record placeholders are
//! uninhabited, so no finding command or record can exist yet. When
//! L-FIND-A lands, the three names are re-exported from `fstp_findings`
//! instead and `decide_finding` routing goes into `findings` (lane L-FIND-B).
//!
//! # Handover seams
//!
//! Lane W2 owns this file and `driver`, and lane L-FIND-B owns `findings`.
//! Design section 10 gives no later lane these files. So each line that a
//! later lane must change is listed here with its owner, and nothing else
//! in W2 files needs to change for them:
//!
//! - L-FIND-A: the three placeholder types under "Finding seam" below
//!   become `pub use fstp_findings::{FindingStore, FindingCommand, FindingRecord};`.
//! - L-FIND-B: the bodies of `finding_queries`, `decide_finding` and
//!   `apply_finding` under "Finding seam" become calls into `findings`.
//! - L-CODEC: a `fstp_ledger::Canonical` impl for [`Record`] in this file,
//!   the inner decode in the `envelope_decode` fuzz target, the
//!   `check_decodes` hook of the `decide_sequence` fuzz target, and the
//!   switch of the testkit's `harness::prop::append_only` to
//!   `fstp_ledger::verify_append_only`.
//!
//! Status: harness lane W2.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod driver;
pub mod findings;

use fstp_domain::command::Ctx;
use fstp_domain::engine::FoldError;
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query};
use fstp_domain::refusal::Refusal;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_json::typed::expect_object;
use fstp_json::{FromJsonError, Object, Value};
use fstp_ledger::{Entry, Seq};

pub use driver::{
    CatchUpError, Decider, DomainDecider, Engine, ExecError, MAX_ATTEMPTS, OpenError,
    RESERVED_COMMAND_PREFIX, is_reserved_command_id,
};

// ---------------------------------------------------------------------------
// Finding seam. L-FIND-A owns the three type definitions below, and L-FIND-B
// owns the bodies of the three functions after them (see "Handover seams").
// ---------------------------------------------------------------------------

/// The finding store of the engine state.
///
/// Placeholder until lane L-FIND-A lands `fstp_findings::FindingStore`. It
/// holds nothing, so two engine states differ only in their core part.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindingStore {
    _empty: (),
}

impl FindingStore {
    /// The store before any finding record.
    pub const fn genesis() -> FindingStore {
        FindingStore { _empty: () }
    }
}

/// A finding command.
///
/// Placeholder until lane L-FIND-A lands `fstp_findings::FindingCommand`.
/// It has no variant, so no finding command can be built yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FindingCommand {}

/// A finding record.
///
/// Placeholder until lane L-FIND-A lands `fstp_findings::FindingRecord`.
/// It has no variant, so no finding record can be built yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FindingRecord {}

/// The vault questions a finding command needs. L-FIND-B routes it to
/// `findings`. A finding command never sees the core's answers (I-10).
pub(crate) fn finding_queries(
    _state: &EngineState,
    cmd: &FindingCommand,
    _ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    match *cmd {}
}

/// The finding records a finding command produces. L-FIND-B routes it to
/// `findings::decide_finding`, which returns only finding records (I-10).
pub(crate) fn decide_finding(
    _state: &EngineState,
    cmd: &FindingCommand,
    _ctx: &Ctx,
    _answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match *cmd {}
}

/// Folds a finding record into the finding store only. L-FIND-B routes it
/// to `findings`. It never touches the core (I-10).
fn apply_finding(
    _findings: &mut FindingStore,
    _seq: Seq,
    _at: Timestamp,
    record: &FindingRecord,
) -> Result<(), FoldError> {
    match *record {}
}

// ---------------------------------------------------------------------------
// End of the finding seam.
// ---------------------------------------------------------------------------

/// The state the engine folds records into: the domain core and the
/// finding store, kept apart (I-10).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EngineState {
    /// The domain projection. Core `decide` reads only this part.
    pub core: State,
    /// The finding store. Core `decide` never reads it.
    pub findings: FindingStore,
}

impl EngineState {
    /// The state before any record.
    pub fn genesis() -> EngineState {
        EngineState {
            core: State::genesis(),
            findings: FindingStore::genesis(),
        }
    }

    /// The last vault epoch the core has processed.
    pub fn epoch(&self) -> VaultEpoch {
        self.core.epoch()
    }

    /// The latest recorded time.
    pub fn now_floor(&self) -> Timestamp {
        self.core.now_floor()
    }
}

/// A command for the engine: a core command or a finding command.
#[allow(
    clippy::large_enum_variant,
    reason = "the finding side is an empty placeholder until L-FIND-A; boxing would change the envelope API"
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// A core command, decided by `fstp_domain::decide`.
    Core(fstp_domain::Command),
    /// A finding command, decided by `decide_finding` (lane L-FIND-B).
    Finding(FindingCommand),
}

/// A ledger record of the engine: a core record or a finding record.
#[allow(
    clippy::large_enum_variant,
    reason = "the finding side is an empty placeholder until L-FIND-A; boxing would change the envelope API"
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Record {
    /// A core record, folded by `fstp_domain::apply`.
    Core(fstp_domain::Record),
    /// A finding record, folded into the finding store.
    Finding(FindingRecord),
}

/// The identity vault as the engine sees it (design section 3.1).
///
/// Every answer carries the vault epoch it was given at. When the vault
/// cannot answer, the driver refuses the command and appends nothing
/// (`SPEC/03-architecture/overview.md` NOTE 2).
pub trait IdentityOracle {
    /// The answer to `q`, or [`OracleDown`] when the vault cannot answer.
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown>;

    /// The vault's current epoch, or [`OracleDown`] when the vault cannot answer.
    fn epoch(&self) -> Result<VaultEpoch, OracleDown>;
}

impl<O: IdentityOracle + ?Sized> IdentityOracle for &O {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        (**self).ask(q)
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        (**self).epoch()
    }
}

/// Folds one ledger record into `state`. `seq` and `at` come from the entry.
///
/// A core record goes to `fstp_domain::apply` on the core part. The fold is
/// structural and never re-runs guards. On a refusal the state may be
/// partly folded, so callers fold into a copy (as [`replay`] and the driver do).
pub fn apply(
    state: &mut EngineState,
    seq: Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    match record {
        Record::Core(r) => fstp_domain::apply(&mut state.core, seq, at, r),
        Record::Finding(f) => apply_finding(&mut state.findings, seq, at, f),
    }
}

/// The state after folding `entries` from genesis, in order (I-23).
///
/// Each entry's `seq` must be one more than the previous entry's, starting
/// at 1. Any other sequence fails with [`FoldError::OutOfOrder`].
pub fn replay(entries: &[Entry<Record>]) -> Result<EngineState, FoldError> {
    let mut state = EngineState::genesis();
    let mut previous = Seq::ZERO;
    for entry in entries {
        let expected = previous.raw().checked_add(1).ok_or(FoldError::OutOfOrder)?;
        if entry.seq.raw() != expected {
            return Err(FoldError::OutOfOrder);
        }
        previous = entry.seq;
        apply(
            &mut state,
            entry.seq,
            Timestamp::from_micros(entry.at),
            &entry.record,
        )?;
    }
    Ok(state)
}

/// Which side of the envelope a stored record is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnvelopeKind {
    /// A core record, stored under the member `core`.
    Core,
    /// A finding record, stored under the member `finding`.
    Finding,
}

impl EnvelopeKind {
    /// The member name of this side in the stored form.
    pub const fn member(self) -> &'static str {
        match self {
            EnvelopeKind::Core => "core",
            EnvelopeKind::Finding => "finding",
        }
    }
}

/// The stored JSON form of an envelope: an object with exactly one member,
/// `core` or `finding`, whose value is the inner record's own JSON form.
///
/// The inner record codecs land with lanes L-CODEC and L-FIND-A. Until
/// then the envelope layer works on the inner value as JSON.
pub fn envelope_to_json(kind: EnvelopeKind, inner: Value) -> Value {
    let mut o = Object::with_capacity(1);
    o.insert(kind.member(), inner);
    Value::Object(o)
}

/// Splits the stored JSON form of an envelope into its side and the inner
/// record's JSON value. Anything other than an object with exactly one
/// member, `core` or `finding`, is refused.
pub fn envelope_from_json(value: &Value) -> Result<(EnvelopeKind, &Value), FromJsonError> {
    let o = expect_object(value)?;
    let mut found: Option<(EnvelopeKind, &Value)> = None;
    for (key, v) in o.iter() {
        let kind = match key {
            "core" => EnvelopeKind::Core,
            "finding" => EnvelopeKind::Finding,
            _ => return Err(FromJsonError::invalid("unknown envelope member")),
        };
        if found.is_some() {
            return Err(FromJsonError::invalid("an envelope has exactly one member"));
        }
        found = Some((kind, v));
    }
    found.ok_or_else(|| FromJsonError::invalid("an envelope has exactly one member"))
}

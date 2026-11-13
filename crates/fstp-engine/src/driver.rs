//! The synchronous reference driver over a RecordStore and an IdentityOracle (design section 3.1).
//!
//! [`Engine::execute`] runs these steps for one command:
//!
//! 1. Fold every stored entry the engine has not seen yet, so the decision
//!    starts from a fresh state.
//! 2. If the vault epoch is ahead of the state's, ask which accounts changed
//!    since the state's epoch, and process `VaultChanged` first
//!    (`SPEC/03-architecture/overview.md` NOTE 3). Then start again. The
//!    vault epoch is the newer of the `epoch` reading and the newest epoch
//!    an answer carried earlier in the same call.
//! 3. Ask the vault every question the command needs. When the vault cannot
//!    answer, refuse with `OracleDown` and append nothing (NOTE 2). When an
//!    answer carries an epoch newer than the one the command must be
//!    decided at, the vault moved during the questions. The driver keeps
//!    that epoch and starts again, so step 2 processes it.
//! 4. Decide, fold the batch on a copy of the state, append against the
//!    expected head, then fold what the store holds. On a stale head, start
//!    again from step 1.
//!
//! After every call, accepted or not, the state equals the replay of the
//! store, unless the store holds a log the fold refuses. Every fold groups
//! the records of one command id into one entry (`apply_in`, `finish`), so
//! the entry pairings of the crate root hold on the trial fold of a batch,
//! on catch-up and on replay alike.
//!
//! # Held values
//!
//! A ledger body keeps the digest of a saved or proposed value, never the
//! value (ADR-007). So after an entry is appended, the driver holds the
//! values the later checks read, outside the ledger:
//!
//! - a `RecordProposals` batch: each proposal value, in the import store;
//! - a creator `SaveFields`: each saved value, in the creator
//!   (`CreatorState::hold_saved`);
//! - a confirmed or edited `ResolveImport`: the saved value, in the
//!   creator (`CreatorState::hold_import`). It is the value
//!   `bridge::applied_edit` gives on the state the command was decided
//!   in, never a value of the client's command itself.
//!
//! A save is held only for a field and digest that the appended entry's
//! `FieldsSaved` names, and the creator holds a value only under the
//! digest of the field's latest save. An `ApplyStart` and an
//! `AcceptNarrative` need no hold: a start from a shipped template, and
//! the narrative it offers, read the template, which ships with the
//! platform. A clone start copies the source's policy, which the core
//! holds. Its free texts read back empty, so the Guide checks that read
//! them fail closed until they are saved again.
//!
//! After every catch-up, and after [`Engine::hold_import`], the driver
//! holds again every confirmed import value whose proposal value the
//! import store holds (`bridge::rehold_confirmed`). Nothing else can be
//! recovered from the ledger, which keeps only digests. A client save or
//! an edited import value that this engine did not append, such as one it
//! replayed at [`Engine::open_with`], stays unheld. Every check that reads
//! such a value fails closed until the shell holds it from its value
//! store, through [`Engine::hold_value`] or [`Engine::hold_import`].
//!
//! A finding command skips step 2, so it never appends a core record
//! (I-10). When it has vault questions and the vault is ahead, it is
//! refused with `StaleFacts` instead.
//!
//! Readings taken where the design is silent:
//! - Retries are bounded by [`MAX_ATTEMPTS`]. A driver that gives up still
//!   holds the replay of the store and reports [`ExecError::Contended`].
//! - `VaultChanged` has a `System(Vault)` actor, the caller's instant, the
//!   web channel and a command id derived from the new epoch. A System
//!   actor never arrives through MCP, so an MCP caller cannot block it.
//! - Command ids that start with the bytes `fstp:vc:` are reserved for the
//!   driver. A caller command with such an id fails with
//!   [`ExecError::ReservedCommandId`] before anything is asked or appended.
//!   So no caller can hold the id of a later `VaultChanged`.
//! - A `ChangedSince` answer without its list of accounts is no answer.
//!   Design section 4.1 sets the list on every such answer. The command
//!   is refused with `OracleDown` before anything is decided.
//! - The new epoch of `VaultChanged` is the epoch of its `ChangedSince`
//!   answer, so the changed set and the epoch always agree. An answer older
//!   than the epoch the vault reported is refused with `StaleFacts`.
//! - Two drivers that process the same epoch append it once. The second
//!   one meets the store's duplicate check, folds the store and treats the
//!   change as processed only when the state's epoch reached it. Otherwise
//!   it fails with [`ExecError::CommandIdTaken`].
//! - A refused `VaultChanged` is passed back unchanged, and the command
//!   itself is never decided.
//! - When an appended `VaultChanged` leaves the state's epoch behind the
//!   vault's, the command is refused with `StaleFacts`.
//! - A batch that `decide` returns but `apply` refuses is never appended.
//!   It fails with [`ExecError::Unfoldable`].
//!
//! [`Decider`] is a seam added by the harness lane. It stands for
//! `fstp_domain::queries` and `decide`, so the driver steps can be tested
//! while the domain lanes are stubs. The default, [`DomainDecider`], is the
//! domain core. Answer digests are taken from the oracle as they come. The
//! M3 driver computes them with `fstp-crypto` over the canonical query
//! encoding of lane L-CODEC.

use fstp_creator::{
    CreatorCommand, CreatorRecord, FieldEdit, ImportFieldEdit, Provenance, ValueDigest,
};
use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{CommandId, ProgrammeId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_import::{ImportCommand, ImportProposal};
use fstp_ledger::{AppendError, Entry, RecordStore, Seq, StoreError};
use fstp_programme::FieldId;

use crate::compose::{CreatorEnvironment, NoEnvironment};
use crate::{Command, EngineState, IdentityOracle, Record, apply_in, finish};

/// How many times [`Engine::execute`] decides before it gives up under
/// contention. Each stale head, moving vault or processed vault change
/// uses one attempt.
pub const MAX_ATTEMPTS: usize = 16;

/// How many entries the driver reads from the store at a time.
const READ_CHUNK: usize = 256;

/// The first bytes of every command id the driver issues itself. The id of
/// a driver-issued `VaultChanged` is this prefix followed by the new epoch,
/// big-endian. Caller commands may not use the prefix.
pub const RESERVED_COMMAND_PREFIX: [u8; 8] = *b"fstp:vc:";

/// Whether `id` is in the driver's reserved namespace.
pub fn is_reserved_command_id(id: CommandId) -> bool {
    id.bytes().starts_with(&RESERVED_COMMAND_PREFIX)
}

/// The pure decision functions the driver calls.
///
/// [`DomainDecider`] is the production one. Tests may substitute a scripted
/// decider to reach driver paths that the domain stubs cannot reach yet.
pub trait Decider {
    /// The vault questions `cmd` needs in `state`, or the refusal.
    fn queries(&self, state: &EngineState, cmd: &Command, ctx: &Ctx)
    -> Result<Vec<Query>, Refusal>;

    /// The records `cmd` produces in `state` given `answers`, or the refusal.
    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal>;
}

/// The production decision functions, with no shell facts for the
/// creator ([`NoEnvironment`]).
///
/// - A core command goes to `fstp_domain::queries` and `decide`, which see
///   only the core part of the state, never the finding store, the creator
///   or the import store (I-10, I-65). Every core `ActivateProgramme` is
///   refused with `RuleRef::I66`, drafted or not: only the creator's
///   approval composes it (D2e, strict since 2026-10-30).
/// - A finding command goes through the finding seam in the crate root,
///   which lane L-FIND-B routes to `decide_finding`.
/// - A creator command goes to `compose::creator_queries` and
///   `compose::decide_creator_command`.
/// - A bridge command goes to `bridge::bridge_queries` and
///   `bridge::resolve_import`, and an import command to
///   `bridge::decide_import_command`, which asks no vault question.
/// - A tenant command goes to `tenant::tenant_queries` and
///   `tenant::decide_tenant`, which see only the tenant part, the core
///   roster for the Receiving check, and the vault answers.
///
/// Before any of them but a finding command, the engine refuses a time
/// before the latest entry of any part, so the ledger stays time-monotone
/// (design section 2.2). That check reads the time of the latest entry,
/// never a finding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DomainDecider;

/// The production decision functions of [`DomainDecider`], with the
/// shell's creator facts from `E` (design 3.2, `CreatorInputs`). A shell
/// that serves creator commands opens its engine with this decider and
/// updates the environment, such as the probe results of the request,
/// through [`Engine::decider_mut`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CreatorDecider<E>(pub E);

/// The refusal of a core `ActivateProgramme` that did not come from the
/// creator's approval (D2e, I-66).
fn outside_activation(c: &fstp_domain::Command, ctx: &Ctx) -> Result<(), Refusal> {
    match c {
        // The channel guard first, as `compose::mcp_guard` runs it first
        // for the creator's approval (I-85).
        fstp_domain::Command::ActivateProgramme { .. } if ctx.via == Via::Mcp => {
            Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp))
        }
        fstp_domain::Command::ActivateProgramme { .. } => {
            Err(Refusal::new(RuleRef::I66, RefusalReason::GuardFailed))
        }
        _ => Ok(()),
    }
}

/// The vault questions of `cmd`, with the creator facts of `env`.
fn route_queries(
    state: &EngineState,
    cmd: &Command,
    ctx: &Ctx,
    env: &dyn CreatorEnvironment,
) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::Core(c) => {
            crate::ledger_clock(state, ctx)?;
            outside_activation(c, ctx)?;
            fstp_domain::queries(&state.core, c, ctx)
        }
        Command::Finding(f) => crate::finding_queries(state, f, ctx),
        Command::Creator(c) => {
            crate::ledger_clock(state, ctx)?;
            crate::compose::creator_queries(state, c, ctx, env)
        }
        Command::Bridge(b) => {
            crate::ledger_clock(state, ctx)?;
            Ok(crate::bridge::bridge_queries(state, b, ctx))
        }
        Command::Import(_) => {
            crate::ledger_clock(state, ctx)?;
            Ok(Vec::new())
        }
        Command::Tenant(t) => {
            crate::ledger_clock(state, ctx)?;
            crate::tenant::tenant_queries(state, t, ctx)
        }
        Command::Stage2Revision(r) => {
            crate::ledger_clock(state, ctx)?;
            crate::compose::revision_queries(state, r, ctx)
        }
        Command::Contract(c) => crate::contract::contract_queries(state, c, ctx),
        Command::Report(_) => {
            crate::ledger_clock(state, ctx)?;
            Ok(Vec::new())
        }
    }
}

/// The records of `cmd`, with the creator facts of `env`.
fn route_decide(
    state: &EngineState,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    env: &dyn CreatorEnvironment,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::Core(c) => {
            crate::ledger_clock(state, ctx)?;
            outside_activation(c, ctx)?;
            let records = fstp_domain::decide(&state.core, c, ctx, answers)?
                .into_iter()
                .map(Record::Core)
                .collect();
            // R-GA-01, I-52: a publication carries its Guide.
            crate::compose::with_guide(state, c, ctx.now, records, env)
        }
        Command::Finding(f) => crate::decide_finding(state, f, ctx, answers),
        Command::Creator(c) => {
            crate::ledger_clock(state, ctx)?;
            crate::compose::decide_creator_command(state, c, ctx, answers, env)
                .map_err(crate::compose::CreatorFailure::refusal)
        }
        Command::Bridge(b) => {
            crate::ledger_clock(state, ctx)?;
            crate::bridge::resolve_import(state, b, ctx, answers)
        }
        Command::Import(i) => {
            crate::ledger_clock(state, ctx)?;
            crate::bridge::decide_import_command(state, i, ctx)
        }
        Command::Tenant(t) => {
            crate::ledger_clock(state, ctx)?;
            crate::tenant::decide_tenant(state, t, ctx, answers)
        }
        Command::Stage2Revision(r) => {
            crate::ledger_clock(state, ctx)?;
            crate::compose::decide_revision(state, r, ctx, answers)
        }
        Command::Contract(c) => crate::contract::decide_contract(state, c, ctx, answers),
        Command::Report(r) => crate::report::decide_report(state, r, ctx),
    }
}

impl Decider for DomainDecider {
    fn queries(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
    ) -> Result<Vec<Query>, Refusal> {
        route_queries(state, cmd, ctx, &NoEnvironment)
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        route_decide(state, cmd, ctx, answers, &NoEnvironment)
    }
}

impl<E: CreatorEnvironment> Decider for CreatorDecider<E> {
    fn queries(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
    ) -> Result<Vec<Query>, Refusal> {
        route_queries(state, cmd, ctx, &self.0)
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        route_decide(state, cmd, ctx, answers, &self.0)
    }
}

/// Why [`Engine::open`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpenError {
    /// The store could not be read.
    Store(StoreError),
    /// The store holds a log the fold refuses (I-23).
    Fold(FoldError),
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OpenError::Store(e) => write!(f, "open: {e}"),
            OpenError::Fold(e) => write!(f, "open: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// Why folding the stored entries failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CatchUpError {
    /// The store could not be read.
    Store(StoreError),
    /// The store holds a log the fold refuses (I-23).
    Fold(FoldError),
}

impl core::fmt::Display for CatchUpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CatchUpError::Store(e) => write!(f, "store: {e}"),
            CatchUpError::Fold(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CatchUpError {}

/// Why [`Engine::execute`] did not append a batch for a command, or why
/// it could not fold the batch it appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecError {
    /// The command, or the `VaultChanged` processed before it, was refused.
    /// A vault that cannot answer gives `OracleDown` here.
    Refused(Refusal),
    /// The command id was already appended, at this entry. The command was
    /// applied earlier, so nothing new is appended.
    Duplicate {
        /// The first entry of the earlier append.
        at: Seq,
    },
    /// The caller's command id starts with [`RESERVED_COMMAND_PREFIX`],
    /// which only the driver may use. Nothing was asked or appended.
    ReservedCommandId,
    /// The id of the driver's `VaultChanged` is held by an entry that did
    /// not process that epoch. Nothing was appended.
    CommandIdTaken {
        /// The first entry under the id.
        at: Seq,
        /// The epoch the `VaultChanged` was for.
        epoch: VaultEpoch,
    },
    /// Other writers moved the head on every one of [`MAX_ATTEMPTS`] attempts.
    Contended,
    /// The store failed or refused the batch. Nothing was appended.
    Store(StoreError),
    /// The store holds a log the fold refuses (I-23). The engine keeps the
    /// state it had and fails the same way on every later call.
    Fold(FoldError),
    /// `decide` returned a batch that `apply` refuses. Nothing was appended.
    Unfoldable(FoldError),
    /// The batch was appended, with `head` as the new head, but reading or
    /// folding the store afterwards failed. The engine keeps the state it
    /// had before the append.
    AppendedUnfolded {
        /// The head after the append.
        head: Seq,
        /// Why the follow-up fold failed.
        cause: CatchUpError,
    },
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecError::Refused(r) => write!(f, "{r}"),
            ExecError::Duplicate { at } => {
                write!(f, "command already appended at entry {}", at.raw())
            }
            ExecError::ReservedCommandId => {
                f.write_str("the command id is in the driver's reserved namespace")
            }
            ExecError::CommandIdTaken { at, epoch } => write!(
                f,
                "the id of VaultChanged for epoch {} is held by entry {}, which did not process it",
                epoch.raw(),
                at.raw()
            ),
            ExecError::Contended => f.write_str("gave up after repeated stale heads"),
            ExecError::Store(e) => write!(f, "store: {e}"),
            ExecError::Fold(e) => write!(f, "{e}"),
            ExecError::Unfoldable(e) => write!(f, "the decided batch does not fold: {e}"),
            ExecError::AppendedUnfolded { head, cause } => write!(
                f,
                "appended up to entry {}, then the fold failed: {cause}",
                head.raw()
            ),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<CatchUpError> for OpenError {
    fn from(e: CatchUpError) -> OpenError {
        match e {
            CatchUpError::Store(s) => OpenError::Store(s),
            CatchUpError::Fold(f) => OpenError::Fold(f),
        }
    }
}

impl From<CatchUpError> for ExecError {
    fn from(e: CatchUpError) -> ExecError {
        match e {
            CatchUpError::Store(s) => ExecError::Store(s),
            CatchUpError::Fold(f) => ExecError::Fold(f),
        }
    }
}

/// What one decide-and-append attempt gave.
enum Attempt {
    /// The batch was appended. The new head, and the values to hold.
    Appended(Seq, Vec<Hold>),
    /// Another writer moved the head first, or the vault moved during the
    /// questions. Start again from a fresh state. When the vault moved, the
    /// newer epoch the answer carried.
    Again(Option<VaultEpoch>),
    /// The command id was already appended, at this entry.
    Duplicate(Seq),
}

/// The refusal of a command whose vault questions went unanswered (NOTE 2).
const fn oracle_down() -> Refusal {
    Refusal::new(RuleRef::OracleDown, RefusalReason::OracleUnavailable)
}

/// The refusal of a command whose answers are older than required (NOTE 3).
const fn stale_facts() -> Refusal {
    Refusal::new(RuleRef::StaleFacts, RefusalReason::AnswerStale)
}

/// The command id of the driver-issued `VaultChanged` for `epoch`.
fn vault_changed_id(epoch: VaultEpoch) -> CommandId {
    let mut id = [0u8; 16];
    let (head, tail) = id.split_at_mut(RESERVED_COMMAND_PREFIX.len());
    head.copy_from_slice(&RESERVED_COMMAND_PREFIX);
    tail.copy_from_slice(&epoch.raw().to_be_bytes());
    CommandId::from_bytes(id)
}

/// The epoch the answers to `cmd` must carry: the new epoch for
/// `VaultChanged`, and the state's epoch for every other command.
fn expected_epoch(state: &EngineState, cmd: &Command) -> VaultEpoch {
    match cmd {
        Command::Core(fstp_domain::Command::VaultChanged { epoch, .. }) => *epoch,
        _ => state.epoch(),
    }
}

/// The synchronous reference driver for tests. M3 writes an async driver
/// over the same pure functions.
///
/// It derives `Clone`, `PartialEq`, `Eq` and `Hash` when its parts do, so
/// a model state can hold a whole engine.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Engine<S, O, D = DomainDecider> {
    store: S,
    oracle: O,
    decider: D,
    state: EngineState,
    /// The sequence number of the last entry folded into `state`.
    head: Seq,
}

impl<S: RecordStore<Record>, O: IdentityOracle> Engine<S, O, DomainDecider> {
    /// Opens the engine over `store` with the domain core as decider. It
    /// replays the store from genesis and appends nothing.
    pub fn open(store: S, oracle: O) -> Result<Self, OpenError> {
        Engine::open_with(store, oracle, DomainDecider)
    }
}

impl<S, O, D> Engine<S, O, D> {
    /// The state: the replay of every entry folded so far.
    pub fn state(&self) -> &EngineState {
        &self.state
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The oracle.
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// The oracle, for test doubles whose facts a test changes.
    pub fn oracle_mut(&mut self) -> &mut O {
        &mut self.oracle
    }

    /// The decider.
    pub fn decider(&self) -> &D {
        &self.decider
    }

    /// The decider, for a shell that updates its creator environment
    /// before a command, such as the probe results of the request.
    pub fn decider_mut(&mut self) -> &mut D {
        &mut self.decider
    }

    /// The sequence number of the last entry folded into the state.
    pub fn head(&self) -> Seq {
        self.head
    }

    /// The store, the oracle and the decider, giving up the engine.
    /// [`Engine::open_with`] rebuilds an engine from them.
    pub fn into_parts(self) -> (S, O, D) {
        (self.store, self.oracle, self.decider)
    }
}

impl<S: RecordStore<Record>, O: IdentityOracle, D: Decider> Engine<S, O, D> {
    /// Opens the engine over `store` with `decider`. It replays the store
    /// from genesis and appends nothing.
    pub fn open_with(store: S, oracle: O, decider: D) -> Result<Self, OpenError> {
        let mut engine = Engine {
            store,
            oracle,
            decider,
            state: EngineState::genesis(),
            head: Seq::ZERO,
        };
        engine.catch_up()?;
        Ok(engine)
    }

    /// Runs `cmd` and returns the new head, or why nothing was appended for it.
    ///
    /// See the module documentation for the steps. A `VaultChanged`
    /// processed first stays appended even when the command is then refused.
    pub fn execute(&mut self, cmd: Command, ctx: Ctx) -> Result<Seq, ExecError> {
        self.catch_up()?;
        if is_reserved_command_id(ctx.command) {
            return Err(ExecError::ReservedCommandId);
        }
        if matches!(cmd, Command::Finding(_)) {
            return self.execute_finding(&cmd, &ctx);
        }
        let mut progress = Progress::default();
        for _ in 0..MAX_ATTEMPTS {
            self.catch_up()?;
            match self.vault_step(&ctx, &mut progress)? {
                VaultStep::Current => {}
                VaultStep::Again => continue,
            }
            match self.attempt(&cmd, &ctx)? {
                Attempt::Appended(seq, holds) => {
                    self.hold_recorded(holds);
                    return Ok(seq);
                }
                Attempt::Duplicate(at) => return Err(ExecError::Duplicate { at }),
                Attempt::Again(answered) => progress.saw(answered),
            }
        }
        self.catch_up()?;
        Err(ExecError::Contended)
    }

    /// Holds the values of an appended entry (module documentation, "Held
    /// values"). Returns whether every value is held. A value that is not
    /// held fails closed: a proposal can only be dismissed until
    /// [`Engine::hold_import`] holds it, and a creator check that reads a
    /// saved value refuses to pass.
    fn hold_recorded(&mut self, holds: Vec<Hold>) -> bool {
        hold_in(&mut self.state, holds)
    }

    /// Holds `value` under `text` in the import store, as the shell
    /// resolved it from the text store after a replay (design 3.3). The
    /// held values are a cache of the text store and take no part in the
    /// state's equality. A confirmed resolution of a proposal that names
    /// `text` then has its value held in the creator again (module
    /// documentation, "Held values").
    pub fn hold_import(
        &mut self,
        text: fstp_import::ValueTextRef,
        value: fstp_import::UntrustedValue,
    ) -> Result<(), fstp_import::HoldError> {
        self.state.import.hold(text, value)?;
        crate::bridge::rehold_confirmed(&mut self.state);
        Ok(())
    }

    /// Holds `value` as the value of `field` on the draft of `programme`,
    /// saved under `digest`, as the shell resolved it from its value store
    /// after a replay (module documentation, "Held values"). Returns
    /// whether it is held. The field's latest save must carry `digest`,
    /// and `value` must be a value of `field`, so a value is held only for
    /// the save that recorded it.
    pub fn hold_value(
        &mut self,
        programme: ProgrammeId,
        field: FieldId,
        digest: ValueDigest,
        value: fstp_programme::FieldValue,
    ) -> bool {
        self.state.creator.hold(programme, field, digest, value)
    }

    /// [`Engine::execute`] for a finding command, without step 2. It never
    /// processes `VaultChanged`, so a finding command appends only its own
    /// finding records and never a core record (I-10). A command with vault
    /// questions is refused with `StaleFacts` while the vault is ahead of
    /// the state's epoch. The next core command or [`Engine::sync_vault`]
    /// processes the change first (NOTE 3). A command without questions
    /// never reads the vault.
    fn execute_finding(&mut self, cmd: &Command, ctx: &Ctx) -> Result<Seq, ExecError> {
        for _ in 0..MAX_ATTEMPTS {
            self.catch_up()?;
            let asks = !self
                .decider
                .queries(&self.state, cmd, ctx)
                .map_err(ExecError::Refused)?
                .is_empty();
            if asks {
                let vault = self
                    .oracle
                    .epoch()
                    .map_err(|_| ExecError::Refused(oracle_down()))?;
                if vault > self.state.epoch() {
                    return Err(ExecError::Refused(stale_facts()));
                }
            }
            match self.attempt(cmd, ctx)? {
                Attempt::Appended(seq, _) => return Ok(seq),
                Attempt::Duplicate(at) => return Err(ExecError::Duplicate { at }),
                Attempt::Again(Some(_)) => return Err(ExecError::Refused(stale_facts())),
                Attempt::Again(None) => {}
            }
        }
        self.catch_up()?;
        Err(ExecError::Contended)
    }

    /// Processes `VaultChanged` when the vault epoch is ahead of the state's
    /// (enforcement point 3). Returns the new head, or `None` when the
    /// state's epoch is current. Models use it to run a vault change and its
    /// reaction in one step.
    pub fn sync_vault(&mut self, ctx: Ctx) -> Result<Option<Seq>, ExecError> {
        let mut progress = Progress::default();
        for _ in 0..MAX_ATTEMPTS {
            self.catch_up()?;
            match self.vault_step(&ctx, &mut progress)? {
                VaultStep::Current => return Ok(progress.processed.map(|_| self.head)),
                VaultStep::Again => {}
            }
        }
        self.catch_up()?;
        Err(ExecError::Contended)
    }

    /// Step 2: checks the vault epoch and processes `VaultChanged` when the
    /// vault is ahead. `progress` holds what this call saw of the vault.
    fn vault_step(&mut self, ctx: &Ctx, progress: &mut Progress) -> Result<VaultStep, ExecError> {
        let reported = self
            .oracle
            .epoch()
            .map_err(|_| ExecError::Refused(oracle_down()))?;
        // An answer at a newer epoch is the vault reporting that epoch
        // (NOTE 3), even when the `epoch` reading lags behind it.
        let vault = match progress.answered {
            Some(answered) if answered > reported => answered,
            _ => reported,
        };
        let ours = self.state.epoch();
        if vault <= ours {
            return Ok(VaultStep::Current);
        }
        if progress.processed.is_some_and(|p| p >= vault) {
            // The change was processed, yet the state's epoch did not move.
            return Err(ExecError::Refused(stale_facts()));
        }
        let answer = self
            .oracle
            .ask(&Query::ChangedSince { epoch: ours })
            .map_err(|_| ExecError::Refused(oracle_down()))?;
        if answer.epoch < vault {
            // The vault answered at an epoch older than the one it reported.
            return Err(ExecError::Refused(stale_facts()));
        }
        // The answer may be newer than the reading. Its epoch is the one its
        // changed set belongs to.
        let target = answer.epoch;
        // Design 4.1 sets the list on every `ChangedSince` answer. Without
        // it the vault did not say which accounts changed, so fail closed
        // (NOTE 2) rather than record an empty change set.
        let Some(changed) = answer.accounts else {
            return Err(ExecError::Refused(oracle_down()));
        };
        progress.saw(Some(target));
        let cmd = Command::Core(fstp_domain::Command::VaultChanged {
            epoch: target,
            changed,
        });
        let vctx = Ctx {
            actor: Actor::System(SystemCause::Vault),
            command: vault_changed_id(target),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
            ..*ctx
        };
        match self.attempt(&cmd, &vctx)? {
            Attempt::Appended(_, _) => progress.processed = Some(target),
            Attempt::Duplicate(at) => {
                // Another driver may have processed this epoch. Fold what it
                // appended and check that the epoch was reached.
                self.catch_up()?;
                if self.state.epoch() < target {
                    return Err(ExecError::CommandIdTaken { at, epoch: target });
                }
                progress.processed = Some(target);
            }
            Attempt::Again(answered) => progress.saw(answered),
        }
        Ok(VaultStep::Again)
    }

    /// Steps 3 and 4 for one command on the current state.
    fn attempt(&mut self, cmd: &Command, ctx: &Ctx) -> Result<Attempt, ExecError> {
        let questions = self
            .decider
            .queries(&self.state, cmd, ctx)
            .map_err(ExecError::Refused)?;
        let expected = expected_epoch(&self.state, cmd);
        let mut answers = Answers::new();
        for q in questions {
            let a = self
                .oracle
                .ask(&q)
                .map_err(|_| ExecError::Refused(oracle_down()))?;
            if a.epoch > expected {
                // The vault moved during the questions (NOTE 3). Start again,
                // so the change is processed first and the questions asked anew.
                return Ok(Attempt::Again(Some(a.epoch)));
            }
            answers.insert(q, a);
        }
        let batch = self
            .decider
            .decide(&self.state, cmd, ctx, &answers)
            .map_err(ExecError::Refused)?;
        self.trial_fold(ctx.now, ctx.command.bytes(), &batch)?;
        // The values to hold are read on the state the batch was decided
        // in, before the append moves it.
        let holds = holds_of(&self.state, cmd, ctx, &batch);
        match self
            .store
            .append(self.head, ctx.now.micros(), ctx.command.bytes(), batch)
        {
            Ok(seq) => {
                self.catch_up()
                    .map_err(|cause| ExecError::AppendedUnfolded { head: seq, cause })?;
                Ok(Attempt::Appended(seq, holds))
            }
            Err(AppendError::StaleHead { .. }) => Ok(Attempt::Again(None)),
            Err(AppendError::DuplicateCommand { at }) => Ok(Attempt::Duplicate(at)),
            Err(AppendError::Store(e)) => Err(ExecError::Store(e)),
        }
    }

    /// Folds `batch` on a copy of the state, as the entries after the head
    /// at `now`. A batch the fold refuses is never appended. A batch that
    /// would number past `u64::MAX` is left to the store, which refuses it.
    fn trial_fold(
        &self,
        now: Timestamp,
        command: [u8; 16],
        batch: &[Record],
    ) -> Result<(), ExecError> {
        let mut next = self.state.clone();
        let mut seq = self.head;
        for record in batch {
            let Some(raw) = seq.raw().checked_add(1) else {
                return Ok(());
            };
            seq = Seq::from_raw(raw);
            apply_in(&mut next, seq, now, Some(command), record).map_err(ExecError::Unfoldable)?;
        }
        finish(&mut next).map_err(ExecError::Unfoldable)
    }

    /// Step 1: folds every stored entry after `head`, in order.
    ///
    /// The fold runs on a copy, so a refused entry leaves the engine state
    /// and head as they were before the call. Entries must continue the
    /// sequence numbers without a gap, or the fold fails with [`FoldError::OutOfOrder`].
    fn catch_up(&mut self) -> Result<(), CatchUpError> {
        let mut next = self.state.clone();
        let mut head = self.head;
        let mut chunk: Vec<Entry<Record>> = Vec::new();
        while let Some(from) = head.raw().checked_add(1) {
            chunk.clear();
            self.store
                .read(Seq::from_raw(from), READ_CHUNK, &mut chunk)
                .map_err(CatchUpError::Store)?;
            if chunk.is_empty() {
                break;
            }
            for entry in &chunk {
                let expected = head.raw().checked_add(1);
                if Some(entry.seq.raw()) != expected {
                    return Err(CatchUpError::Fold(FoldError::OutOfOrder));
                }
                apply_in(
                    &mut next,
                    entry.seq,
                    Timestamp::from_micros(entry.at),
                    Some(entry.command),
                    &entry.record,
                )
                .map_err(CatchUpError::Fold)?;
                head = entry.seq;
            }
        }
        finish(&mut next).map_err(CatchUpError::Fold)?;
        crate::bridge::rehold_confirmed(&mut next);
        self.state = next;
        self.head = head;
        Ok(())
    }
}

/// A value an appended entry saved or proposed, which the driver holds
/// outside the ledger (module documentation, "Held values").
#[derive(Clone, Debug)]
enum Hold {
    /// The proposals of a `RecordProposals` batch, for the import store.
    Proposals(Vec<ImportProposal>),
    /// The fields of a creator `SaveFields` that the entry recorded.
    Saved {
        /// The draft.
        programme: ProgrammeId,
        /// The saved fields.
        fields: Vec<FieldEdit>,
    },
    /// The field edit of a confirmed or edited import resolution that the
    /// entry recorded.
    Import {
        /// The draft.
        programme: ProgrammeId,
        /// The edit.
        edit: ImportFieldEdit,
    },
}

/// Whether `batch` holds a creator `FieldsSaved` on `programme` that saves
/// `field` under `digest` with `provenance`.
fn saves(
    batch: &[Record],
    programme: ProgrammeId,
    field: FieldId,
    digest: ValueDigest,
    provenance: &Provenance,
) -> bool {
    batch.iter().any(|r| match r {
        Record::Creator(CreatorRecord::FieldsSaved {
            programme: p,
            fields,
            ..
        }) => {
            *p == programme
                && fields
                    .iter()
                    .any(|(f, d, pr)| *f == field && *d == digest && pr == provenance)
        }
        _ => false,
    })
}

/// The values to hold once `batch`, decided for `cmd` in `state`, is
/// appended (module documentation, "Held values").
fn holds_of(state: &EngineState, cmd: &Command, ctx: &Ctx, batch: &[Record]) -> Vec<Hold> {
    match cmd {
        Command::Import(ImportCommand::RecordProposals { proposals, .. }) => {
            vec![Hold::Proposals(proposals.clone())]
        }
        Command::Creator(CreatorCommand::SaveFields {
            programme, fields, ..
        }) => vec![Hold::Saved {
            programme: *programme,
            fields: fields
                .iter()
                .filter(|f| saves(batch, *programme, f.field, f.digest, &f.provenance))
                .cloned()
                .collect(),
        }],
        Command::Bridge(b) => match crate::bridge::applied_edit(state, b, ctx) {
            Some((programme, edit))
                if saves(
                    batch,
                    programme,
                    edit.field,
                    edit.digest,
                    &edit.provenance(),
                ) =>
            {
                vec![Hold::Import { programme, edit }]
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// What one call of [`Engine::execute`] or [`Engine::sync_vault`] saw of
/// the vault so far.
#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    /// The epoch of the `VaultChanged` processed in this call, if any.
    processed: Option<VaultEpoch>,
    /// The newest epoch an answer carried in this call, if any.
    answered: Option<VaultEpoch>,
}

impl Progress {
    /// Remembers `epoch`, an epoch an answer carried, when it is the newest.
    fn saw(&mut self, epoch: Option<VaultEpoch>) {
        if let Some(e) = epoch
            && self.answered.is_none_or(|a| e > a)
        {
            self.answered = Some(e);
        }
    }
}

/// What the vault step decided.
enum VaultStep {
    /// The state's epoch is current, so the command may be decided.
    Current,
    /// A vault change was handled or raced, so start again from a fresh state.
    Again,
}

/// Holds `holds` in `state` ([`Engine::hold_recorded`]).
fn hold_in(state: &mut EngineState, holds: Vec<Hold>) -> bool {
    let mut all = true;
    for hold in holds {
        all &= match hold {
            Hold::Proposals(proposals) => state.import.hold_recorded(&proposals).is_ok(),
            Hold::Saved { programme, fields } => state.creator.hold_saved(programme, &fields),
            Hold::Import { programme, edit } => state.creator.hold_import(programme, &edit),
        };
    }
    crate::bridge::rehold_confirmed(state);
    all
}

/// Holds the values of the entry `batch`, decided for `cmd` by `ctx` on
/// `before` and now folded into `after` (module documentation, "Held
/// values"). A shell that runs its own driver over the engine's decider
/// calls it once the entry is appended, as [`Engine::execute`] does.
/// Returns whether every value is held. A value that is not held fails
/// its checks closed.
pub fn hold_appended(
    before: &EngineState,
    after: &mut EngineState,
    cmd: &Command,
    ctx: &Ctx,
    batch: &[Record],
) -> bool {
    hold_in(after, holds_of(before, cmd, ctx, batch))
}

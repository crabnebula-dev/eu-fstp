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
//! store, unless the store holds a log the fold refuses.
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

use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{CommandId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_ledger::{AppendError, Entry, RecordStore, Seq, StoreError};

use crate::{Command, EngineState, IdentityOracle, Record, apply};

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

/// The domain core: `fstp_domain::queries` and `decide` for core commands.
///
/// A core command sees only the core part of the state, never the finding
/// store (I-10). Finding commands go through the finding seam in the crate
/// root, which lane L-FIND-B routes to `decide_finding`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DomainDecider;

impl Decider for DomainDecider {
    fn queries(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
    ) -> Result<Vec<Query>, Refusal> {
        match cmd {
            Command::Core(c) => fstp_domain::queries(&state.core, c, ctx),
            Command::Finding(f) => crate::finding_queries(state, f, ctx),
        }
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        match cmd {
            Command::Core(c) => fstp_domain::decide(&state.core, c, ctx, answers)
                .map(|records| records.into_iter().map(Record::Core).collect()),
            Command::Finding(f) => crate::decide_finding(state, f, ctx, answers),
        }
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
    /// The batch was appended. The new head.
    Appended(Seq),
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
        let mut progress = Progress::default();
        for _ in 0..MAX_ATTEMPTS {
            self.catch_up()?;
            match self.vault_step(&ctx, &mut progress)? {
                VaultStep::Current => {}
                VaultStep::Again => continue,
            }
            match self.attempt(&cmd, &ctx)? {
                Attempt::Appended(seq) => return Ok(seq),
                Attempt::Duplicate(at) => return Err(ExecError::Duplicate { at }),
                Attempt::Again(answered) => progress.saw(answered),
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
            Attempt::Appended(_) => progress.processed = Some(target),
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
        self.trial_fold(ctx.now, &batch)?;
        match self
            .store
            .append(self.head, ctx.now.micros(), ctx.command.bytes(), batch)
        {
            Ok(seq) => {
                self.catch_up()
                    .map_err(|cause| ExecError::AppendedUnfolded { head: seq, cause })?;
                Ok(Attempt::Appended(seq))
            }
            Err(AppendError::StaleHead { .. }) => Ok(Attempt::Again(None)),
            Err(AppendError::DuplicateCommand { at }) => Ok(Attempt::Duplicate(at)),
            Err(AppendError::Store(e)) => Err(ExecError::Store(e)),
        }
    }

    /// Folds `batch` on a copy of the state, as the entries after the head
    /// at `now`. A batch the fold refuses is never appended. A batch that
    /// would number past `u64::MAX` is left to the store, which refuses it.
    fn trial_fold(&self, now: Timestamp, batch: &[Record]) -> Result<(), ExecError> {
        let mut next = self.state.clone();
        let mut seq = self.head;
        for record in batch {
            let Some(raw) = seq.raw().checked_add(1) else {
                return Ok(());
            };
            seq = Seq::from_raw(raw);
            apply(&mut next, seq, now, record).map_err(ExecError::Unfoldable)?;
        }
        Ok(())
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
                apply(
                    &mut next,
                    entry.seq,
                    Timestamp::from_micros(entry.at),
                    &entry.record,
                )
                .map_err(CatchUpError::Fold)?;
                head = entry.seq;
            }
        }
        self.state = next;
        self.head = head;
        Ok(())
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

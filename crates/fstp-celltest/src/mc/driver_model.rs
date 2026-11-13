//! M-DRIVER (design section 14.2): `DriverCore` over a store and a vault,
//! with I-23 and the driver's NOTE 4 duties. Lane W1c owns this file.
//!
//! The universe: two caller commands and one vault fact, so one
//! `VaultChanged` reaction. Faults: a crash after an append commits and
//! before its reply, one lost acknowledgement, and one stale head from a
//! second writer. ADR-007 allows a second process that contends through
//! the expected head.
//!
//! The driver runs over a [`DriverBackend`]. [`Reference`] is this lane's
//! own transcription of design section 5.2 ([`RefDriver`]). [`Production`]
//! steps `fstp_cell_core::driver::DriverCore` and answers its needs from
//! the model's store and vault. [`Mutant`] seeds the teeth defect: a crash
//! retry under a fresh command id.
//!
//! The store and the vault belong to the model, so every backend meets the
//! same environment: the store checks the command id before the head
//! (ADR-007), and the vault is `reference::vault::RefVault` with its NOTE 4
//! protocol.
//!
//! The model state keeps the backend's live objects in [`Live`], which
//! compares equal to every other `Live`. The abstract part of the state
//! (the ledger, the vault, the run's history of replies) determines them,
//! since every backend is deterministic. So the explorer may merge states
//! by the abstract part alone.
//!
//! This file also holds [`Shell`], the production shell that the seam
//! tests of design section 14.6 drive.

use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};

use fstp_auth::{AuthCommand, AuthRecord};
use fstp_cell_core::driver::{DriverCore, Event, ExecError, Need, Step, VaultFault};
use fstp_cell_core::gate::{self, Action, Admitted, Deny, LoginPolicy, Principal, StepUpView};
use fstp_cell_core::text::TextCommand;
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellRefusal, CellState, FoldError};
use fstp_domain::id::{AccountId, ContentDigest, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::mc::auth_model::STEPUP_STALE_AT_COMMIT;
use crate::reference::vault::{
    self as rv, RefAnswer, RefVault, RefWrite, is_reaction_command_id, reaction_command_id,
};

// ---------------------------------------------------------------------------
// Seams.

/// Not a seam since lane m3/seams-custody. A model read reply ([`LEntry`])
/// carries a sequence and a command id but no records. [`Production`] now
/// keeps the records each run asked to append, by command id, and the
/// second writer's own record. Each run mirrors the ledger it saw in an
/// `fstp_ledger::MemStore`, one production sequence per record, and maps
/// the model's sequences to the mirror's. The constant names a mapping
/// that failed: a model entry whose records no run appended, or a
/// sequence the run never saw. Either stops the run as a backend that did
/// not answer.
///
/// [`Shell`] keeps its ledger in an `fstp_ledger::MemStore` and answers
/// every read with the stored entries, so the seam tests never meet it.
pub const LEDGER_SEAM: &str = "fstp_celltest::mc::driver_model: a model entry or sequence has no production entry (no run appended its records, or the run never saw it)";

/// The seam of the caller's command id, closed by lane W2c:
/// `DriverCore::start_with_id` takes the caller's command id, and
/// `gate::admit_command` binds the step-up digest to it (design section
/// 5.2). [`Production::start`] passes `retry_id` or `Cmd::id`, so the
/// crash retry runs under the caller's id. `DriverCore` refuses an id with
/// the reserved prefix `fstp:vc:` before it reads anything. The constant
/// stays as the refusal of a command index outside the universe.
///
/// Still open for lane W1c: M-DRIVER can gain a third command whose id has
/// the reserved prefix, whose run must finish refused and append nothing
/// (`seam_driver_core_refuses_reserved_command_id`).
pub const COMMAND_ID_SEAM: &str =
    "DriverCore::start takes no caller command id (design section 5.2, lane W2c)";

// ---------------------------------------------------------------------------
// The universe.

/// The two caller commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cmd {
    /// The first command.
    One,
    /// The second command.
    Two,
}

impl Cmd {
    /// Both commands.
    pub const ALL: [Cmd; 2] = [Cmd::One, Cmd::Two];

    /// The caller's command id.
    pub const fn id(self) -> [u8; 16] {
        match self {
            Cmd::One => [0xC1; 16],
            Cmd::Two => [0xC2; 16],
        }
    }

    const fn index(self) -> usize {
        match self {
            Cmd::One => 0,
            Cmd::Two => 1,
        }
    }
}

/// The command id of the second writer's entry.
pub const FOREIGN_ID: [u8; 16] = [0xF0; 16];
/// The command id the mutant uses for its retry.
pub const FRESH_ID: [u8; 16] = [0xEE; 16];
/// The instant of every command.
pub const AT: Timestamp = Timestamp::from_micros(2_000_000);
/// The account that issues both commands.
pub const ACTOR: AccountId = AccountId::from_raw(1);
/// The account the vault fact verifies.
pub const SUBJECT: AccountId = AccountId::from_raw(101);
/// The most decide attempts of one run (`fstp_engine::MAX_ATTEMPTS`).
pub const MAX_ATTEMPTS: u8 = 16;

/// The vault fact of the run.
pub fn fact() -> RefWrite {
    RefWrite::VerificationRecorded {
        account: SUBJECT,
        person: rv::Person(7),
    }
}

/// What an entry of the model's ledger is, by its command id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A caller command.
    Command(Cmd),
    /// The reaction to a vault epoch.
    Reaction(u64),
    /// The second writer's entry.
    Foreign,
    /// Any other id: a defect.
    Other([u8; 16]),
}

/// The kind of command id `id`.
pub fn kind_of(id: [u8; 16]) -> EntryKind {
    if id == FOREIGN_ID {
        return EntryKind::Foreign;
    }
    if is_reaction_command_id(id) {
        let mut be = [0u8; 8];
        for (slot, b) in be.iter_mut().zip(id.iter().skip(8)) {
            *slot = *b;
        }
        return EntryKind::Reaction(u64::from_be_bytes(be));
    }
    for c in Cmd::ALL {
        if id == c.id() {
            return EntryKind::Command(c);
        }
    }
    EntryKind::Other(id)
}

/// One entry of the model's ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LEntry {
    /// The sequence, from 1.
    pub seq: u64,
    /// The command id.
    pub command: [u8; 16],
}

/// What a driver needs, as the model sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNeed {
    /// The entries after this sequence.
    ReadFrom(u64),
    /// The vault epoch.
    Epoch,
    /// Answers.
    Ask {
        /// The reaction epoch, if a reaction asks.
        reaction_for: Option<u64>,
        /// The queries.
        queries: Vec<Query>,
    },
    /// An append.
    Append {
        /// The expected head.
        expected: u64,
        /// The command id.
        command: [u8; 16],
    },
    /// An acknowledgement.
    Ack {
        /// The epoch.
        epoch: u64,
        /// The sequence of the reaction.
        seq: u64,
    },
    /// The run finished.
    Done(DDone),
}

/// How a run finished.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DDone {
    /// Committed, or found committed as a duplicate. The head after it.
    Ok {
        /// The head.
        head: u64,
    },
    /// The vault failed, so the command failed closed (NOTE 2).
    VaultFault,
    /// Too many stale heads.
    Contended,
    /// Any other refusal, as text.
    Refused(String),
}

/// The shell's reply to a need, as the model sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reply {
    /// The ledger read: every entry after the need's sequence.
    Read(Vec<LEntry>),
    /// The vault epoch, or a fault.
    Epoch(Option<u64>),
    /// The answers in query order, or a fault.
    Answers(Option<Vec<RefAnswer>>),
    /// The append result.
    Appended(AppendReply),
    /// Whether the vault took the acknowledgement.
    Acked(bool),
}

/// The store's answer to an append (ADR-007 order: duplicate first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppendReply {
    /// Appended at this sequence.
    Ok(u64),
    /// The command id is in the ledger.
    Duplicate,
    /// The head moved to this sequence.
    Stale(u64),
}

// ---------------------------------------------------------------------------
// Backends.

/// A driver under M-DRIVER.
pub trait DriverBackend {
    /// The backend's live objects for one run.
    type Run: Clone + fmt::Debug;

    /// Starts a run of `cmd`. `retry_id` is the command id of a caller
    /// retry after a crash, if the backend takes one.
    fn start(&self, cmd: Cmd, retry_id: Option<[u8; 16]>) -> Result<Self::Run, NotImplemented>;

    /// Advances the run with the shell's reply to its last need, or with
    /// none at start, and returns its next need.
    fn step(&self, run: &mut Self::Run, reply: Option<&Reply>) -> Result<DNeed, NotImplemented>;
}

/// The phase of a [`RefDriver`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Phase {
    CatchUp,
    Epoch,
    ReactAsk(u64),
    ReactAppend(u64),
    ReactAck(u64),
    ReAck(u64),
    Append,
    Finished,
}

/// The reference driver: design section 5.2, transcribed on its own.
///
/// 1. Catch up from the store.
/// 2. Ask the vault epoch. When the ledger holds a reaction to that epoch,
///    acknowledge it again once per run (restart rule; acknowledgements
///    are idempotent). When the epoch is ahead of the newest reaction in
///    the ledger, run the reaction with `reaction_for` set, append it
///    under its reserved id, and acknowledge it. Then start again from
///    step 1.
///
/// Reading: the vault's epoch reply does not say whether the epoch is
/// still provisional, so the reference acknowledges the newest committed
/// reaction again at the start of every run.
/// 3. Ask the command's queries, if any. Fail closed on a fault (NOTE 2).
///    An answer at another epoch starts again from step 2 (NOTE 3).
/// 4. Append with the expected head. A stale head starts again from step
///    1, up to [`MAX_ATTEMPTS`]. A duplicate is the stored result.
///
/// The M-DRIVER commands ask no query, so step 3 is empty here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefDriver {
    id: [u8; 16],
    phase: Phase,
    head: u64,
    processed: u64,
    reactions: Vec<(u64, u64)>,
    attempts: u8,
    acked: bool,
}

impl RefDriver {
    /// A run of the command with id `id`.
    pub fn new(id: [u8; 16]) -> RefDriver {
        RefDriver {
            id,
            phase: Phase::CatchUp,
            head: 0,
            processed: 0,
            reactions: Vec::new(),
            attempts: 0,
            acked: false,
        }
    }

    fn finish(&mut self, d: DDone) -> DNeed {
        self.phase = Phase::Finished;
        DNeed::Done(d)
    }

    fn restart(&mut self) -> DNeed {
        self.phase = Phase::CatchUp;
        DNeed::ReadFrom(self.head)
    }

    fn stale(&mut self) -> DNeed {
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts >= MAX_ATTEMPTS {
            return self.finish(DDone::Contended);
        }
        self.restart()
    }

    /// The next need after `reply`.
    pub fn next(&mut self, reply: Option<&Reply>) -> DNeed {
        let Some(reply) = reply else {
            if self.id.starts_with(&rv::REACTION_COMMAND_PREFIX) {
                return self.finish(DDone::Refused("reserved command id".to_owned()));
            }
            return self.restart();
        };
        match (self.phase.clone(), reply) {
            (Phase::CatchUp, Reply::Read(entries)) => {
                for e in entries {
                    self.head = self.head.max(e.seq);
                    if let EntryKind::Reaction(epoch) = kind_of(e.command) {
                        self.reactions.push((epoch, e.seq));
                        self.processed = self.processed.max(epoch);
                    }
                }
                self.phase = Phase::Epoch;
                DNeed::Epoch
            }
            (Phase::Epoch, Reply::Epoch(None)) => self.finish(DDone::VaultFault),
            (Phase::Epoch, Reply::Epoch(Some(e))) => {
                let e = *e;
                if !self.acked
                    && let Some((_, seq)) = self.reactions.iter().find(|(x, _)| *x == e)
                {
                    let seq = *seq;
                    self.acked = true;
                    self.phase = Phase::ReAck(e);
                    return DNeed::Ack { epoch: e, seq };
                }
                if e > self.processed {
                    self.phase = Phase::ReactAsk(e);
                    return DNeed::Ask {
                        reaction_for: Some(e),
                        queries: vec![Query::ChangedSince {
                            epoch: VaultEpoch::from_raw(self.processed),
                        }],
                    };
                }
                self.phase = Phase::Append;
                DNeed::Append {
                    expected: self.head,
                    command: self.id,
                }
            }
            (Phase::ReactAsk(_), Reply::Answers(None)) => self.finish(DDone::VaultFault),
            (Phase::ReactAsk(e), Reply::Answers(Some(_))) => {
                self.phase = Phase::ReactAppend(e);
                DNeed::Append {
                    expected: self.head,
                    command: reaction_command_id(e),
                }
            }
            (Phase::ReactAppend(e), Reply::Appended(AppendReply::Ok(seq))) => {
                self.head = *seq;
                self.reactions.push((e, *seq));
                self.acked = true;
                self.phase = Phase::ReactAck(e);
                DNeed::Ack {
                    epoch: e,
                    seq: *seq,
                }
            }
            (Phase::ReactAppend(_), Reply::Appended(AppendReply::Stale(_))) => self.stale(),
            (Phase::ReactAppend(_), Reply::Appended(AppendReply::Duplicate)) => self.restart(),
            (Phase::ReactAck(e) | Phase::ReAck(e), Reply::Acked(true)) => {
                self.processed = self.processed.max(e);
                self.restart()
            }
            (Phase::ReactAck(_) | Phase::ReAck(_), Reply::Acked(false)) => {
                self.finish(DDone::VaultFault)
            }
            (Phase::Append, Reply::Appended(AppendReply::Ok(seq))) => {
                self.head = *seq;
                self.finish(DDone::Ok { head: *seq })
            }
            (Phase::Append, Reply::Appended(AppendReply::Duplicate)) => {
                let head = self.head;
                self.finish(DDone::Ok { head })
            }
            (Phase::Append, Reply::Appended(AppendReply::Stale(_))) => self.stale(),
            (phase, r) => self.finish(DDone::Refused(format!(
                "reply {r:?} does not fit phase {phase:?}"
            ))),
        }
    }
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl DriverBackend for Reference {
    type Run = RefDriver;

    fn start(&self, cmd: Cmd, retry_id: Option<[u8; 16]>) -> Result<RefDriver, NotImplemented> {
        Ok(RefDriver::new(retry_id.unwrap_or(cmd.id())))
    }

    fn step(&self, run: &mut RefDriver, reply: Option<&Reply>) -> Result<DNeed, NotImplemented> {
        Ok(run.next(reply))
    }
}

/// The defect a teeth test seeds (design section 14.2, M-DRIVER row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DriverDefect {
    /// A crash retry runs under a fresh command id.
    RetryWithFreshId,
}

/// The reference driver with one seeded defect.
#[derive(Clone, Copy, Debug)]
pub struct Mutant {
    /// The defect.
    pub defect: DriverDefect,
}

impl DriverBackend for Mutant {
    type Run = RefDriver;

    fn start(&self, cmd: Cmd, retry_id: Option<[u8; 16]>) -> Result<RefDriver, NotImplemented> {
        let id = match (self.defect, retry_id) {
            (DriverDefect::RetryWithFreshId, Some(_)) => FRESH_ID,
            (_, None) => cmd.id(),
        };
        Ok(RefDriver::new(id))
    }

    fn step(&self, run: &mut RefDriver, reply: Option<&Reply>) -> Result<DNeed, NotImplemented> {
        Ok(run.next(reply))
    }
}

/// The production backend: `DriverCore` from genesis. Each run starts
/// from the genesis `CellState` and catches up from the store, as the
/// engine task does after a restart.
#[derive(Clone, Debug)]
pub struct Production {
    genesis: CellState,
    admitted: [Admitted; 2],
    ledger: ProdLedger,
}

/// The cell command of `cmd`: a text write, which asks the vault nothing.
pub fn cell_command(cmd: Cmd) -> CellCommand {
    CellCommand::Text(TextCommand::PutText { id: cmd.id() })
}

/// A passkey session of `account` from `at`, for the gate.
pub fn session_of(account: AccountId, at: Timestamp) -> fstp_auth::SessionView {
    fstp_auth::SessionView {
        id: [0x5E; 16],
        account,
        method: fstp_auth::Method::Passkey,
        started: at,
        last_used: at,
    }
}

/// Why [`admit`] gave no `Admitted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// A stub refusal of the gate, or a seam. It names the operation.
    NotImplemented(NotImplemented),
    /// A refusal of the gate itself. A seam test compares it with the
    /// outcome of the M2 engine, so it never reads as a stub refusal.
    Denied(Deny),
}

impl From<NotImplemented> for AdmitError {
    fn from(e: NotImplemented) -> AdmitError {
        AdmitError::NotImplemented(e)
    }
}

impl fmt::Display for AdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmitError::NotImplemented(e) => write!(f, "{e} (NotImplemented)"),
            AdmitError::Denied(d) => write!(f, "fstp_cell_core::gate::admit refused with {d:?}"),
        }
    }
}

/// The gate's refusal. A stub refusal stays `NotImplemented`, and any
/// other refusal is returned as itself.
fn deny(d: Deny) -> AdmitError {
    match d {
        Deny::NotImplemented(op) => AdmitError::NotImplemented(NotImplemented::new(op)),
        other => AdmitError::Denied(other),
    }
}

/// The P-71 default policy.
pub const POLICY: LoginPolicy = LoginPolicy {
    stepup_freshness_us: crate::reference::auth::P71_DEFAULT_US,
};

/// Not a seam: a bare `CellState` with entries gives no ledger, so no
/// step-up grant can be appended after its head. Pass [`Shell::state`],
/// which carries the shell's ledger.
pub const BARE_STATE_STEPUP: &str = "fstp_celltest::mc::driver_model::admit: a high-risk command over a bare CellState past genesis has no ledger to record its step-up in (pass Shell::state)";

/// Not a seam: the shell's ledger refused a step-up route entry, or the
/// entry did not fold, or the harness passkey could not be built.
/// Production's own `decide` and `fstp_webauthn` made the records, so
/// this is a harness fault, which ends the admission.
pub const STEPUP_GRANT_FAILED: &str = "fstp_celltest::mc::driver_model: a step-up route entry did not append to the shell's ledger or did not fold, or the harness passkey could not be built";

/// What [`admit`] asks the gate over: a folded state, and the ledger it
/// is the replay of, when the caller holds one. [`Shell::state`] gives
/// both. A bare `&CellState` converts with no ledger.
#[derive(Clone, Copy, Debug)]
pub struct GateState<'a> {
    state: &'a CellState,
    ledger: Option<&'a MemStore<CellRecord>>,
}

impl<'a> From<&'a CellState> for GateState<'a> {
    fn from(state: &'a CellState) -> GateState<'a> {
        GateState {
            state,
            ledger: None,
        }
    }
}

impl std::ops::Deref for GateState<'_> {
    type Target = CellState;

    fn deref(&self) -> &CellState {
        self.state
    }
}

impl<'a> GateState<'a> {
    /// The folded state.
    pub fn cell(&self) -> &'a CellState {
        self.state
    }

    /// A copy of the state with the entries of `grant` folded after its
    /// head, appended to a copy of the ledger. Over genesis an empty
    /// ledger serves.
    fn with_grant(&self, grant: &StepUpGrant) -> Result<CellState, NotImplemented> {
        let mut store = match self.ledger {
            Some(l) => l.clone(),
            None if self.state.head() == Seq::ZERO => MemStore::new(),
            None => return Err(NotImplemented::new(BARE_STATE_STEPUP)),
        };
        let mut state = self.state.clone();
        for e in grant.entries() {
            state = append_and_fold(&mut store, &state, &e)?;
        }
        Ok(state)
    }
}

/// Appends the route entry `e` to `store` after `state`'s head, and
/// returns `state` with the stored entries folded by
/// `fstp_cell_core::apply`.
fn append_and_fold(
    store: &mut MemStore<CellRecord>,
    state: &CellState,
    e: &RouteEntry,
) -> Result<CellState, NotImplemented> {
    let failed = || NotImplemented::new(STEPUP_GRANT_FAILED);
    let head = state.head();
    store
        .append(head, e.at.micros(), e.command, e.batch.clone())
        .map_err(|_| failed())?;
    let mut entries = Vec::with_capacity(e.batch.len());
    store
        .read(
            Seq::from_raw(head.raw().saturating_add(1)),
            e.batch.len(),
            &mut entries,
        )
        .map_err(|_| failed())?;
    let mut next = state.clone();
    for x in &entries {
        fstp_cell_core::apply(&mut next, x).map_err(|_| failed())?;
    }
    if next.head() == head {
        return Err(failed());
    }
    Ok(next)
}

/// One append of the step-up route: its command id, its instant and its
/// batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// The command id of the entry.
    pub command: [u8; 16],
    /// The entry instant.
    pub at: Timestamp,
    /// The records.
    pub batch: Vec<CellRecord>,
}

/// What the route `POST /auth/stepup` appends for one command (design
/// section 8.4): the `StepUpGranted` record, after the harness enrolment
/// of the actor's first passkey when the actor holds none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpGrant {
    /// The actor's first passkey, `CredentialRegistered`, when the ledger
    /// held no live passkey of the actor ([`enrol_command_id`]).
    pub enrolment: Option<RouteEntry>,
    /// The command id of the grant's entry ([`stepup_command_id`]).
    pub command: [u8; 16],
    /// The step-up id that production derived.
    pub id: [u8; 16],
    /// The assertion instant, which is the entry instant.
    pub at: Timestamp,
    /// The `StepUpGranted` record.
    pub record: CellRecord,
}

impl StepUpGrant {
    /// The entries to append, in order: the enrolment, then the grant.
    pub fn entries(&self) -> Vec<RouteEntry> {
        let mut out: Vec<RouteEntry> = self.enrolment.iter().cloned().collect();
        out.push(RouteEntry {
            command: self.command,
            at: self.at,
            batch: vec![self.record.clone()],
        });
        out
    }
}

/// A harness command id: a SHA-256 over `label` and `part`, whose first
/// byte is 0x5F. So it lies outside the reserved and system prefixes
/// (`fstp:vc:`, `fstp:st:`) and takes no reserved id.
fn harness_command_id(label: &[u8], part: &[u8]) -> [u8; 16] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(label);
    h.update(part);
    let d = h.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    if let Some(first) = out.first_mut() {
        *first = 0x5F;
    }
    out
}

/// The command id of the step-up grant for the command `command_id`.
pub fn stepup_command_id(command_id: [u8; 16]) -> [u8; 16] {
    harness_command_id(b"fstp-celltest-stepup-route-v1", &command_id)
}

/// The command id of the harness enrolment of `account`'s first passkey.
/// An account is enrolled once: afterwards it holds a passkey.
pub fn enrol_command_id(account: AccountId) -> [u8; 16] {
    harness_command_id(
        b"fstp-celltest-first-passkey-v1",
        &account.raw().to_be_bytes(),
    )
}

/// The step-up route for the command `command_id` of `actor` in the
/// passkey session `session`, for `action_digest`, asserted at `at`, as
/// production records it. `None` when the route or production refuses
/// the grant, or when the ledger already holds the grant entry for this
/// command id.
///
/// The route verifies a passkey assertion of the session's own account
/// with user verification, then issues `GrantStepUp` (design section
/// 8.4). Its admission is lane W3a's
/// (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`). So the harness runs
/// both parts and writes the ledger directly. An actor with no live
/// passkey is enrolled first, with the passkey `credential_of(actor, 0)`
/// verified through `fstp_webauthn`, as a first passkey ceremony does
/// (`mc::auth_model::verified_passkey`). The passkey then asserts, and
/// `fstp_auth::stepup::verify_step_up` decides
/// (`mc::auth_model::verify_harness_stepup`). Only an accepted assertion
/// is granted, with production's record and the id it derives. So the
/// gate never sees a step-up of an account without a passkey.
///
/// # Errors
///
/// A `NotImplemented` of `decide`, or [`STEPUP_GRANT_FAILED`] for a
/// harness passkey that cannot be built or a batch that is not one
/// `StepUpGranted`.
pub fn stepup_grant(
    state: &CellState,
    actor: AccountId,
    session: &fstp_auth::SessionView,
    action_digest: [u8; 32],
    at: Timestamp,
    command_id: [u8; 16],
) -> Result<Option<StepUpGrant>, NotImplemented> {
    use crate::mc::auth_model::{self as am, ProdError};
    let harness = |e: ProdError| match e {
        ProdError::NotImplemented(op) => NotImplemented::new(op),
        ProdError::Refused(_) => NotImplemented::new(STEPUP_GRANT_FAILED),
    };
    let command = stepup_command_id(command_id);
    if state.committed(command).is_some() || session.account != actor {
        return Ok(None);
    }
    let credential = am::credential_of(actor, 0);
    let mut enrolled = None;
    let route = if state.auth().has_any_credential(actor) {
        am::verify_harness_stepup(state, session, &credential, action_digest, true, at)
            .map_err(harness)?
    } else {
        let cred = am::verified_passkey(actor, &credential, &|id: &[u8]| {
            state.auth().is_registered(id)
        })
        .map_err(harness)?;
        let record = AuthRecord::registration(actor, &cred);
        let route = am::verify_stepup_with(
            record.stored_credential(0),
            session,
            &credential,
            action_digest,
            true,
            at,
        )
        .map_err(harness)?;
        enrolled = Some(RouteEntry {
            command: enrol_command_id(actor),
            at,
            batch: vec![CellRecord::Auth(record)],
        });
        route
    };
    if route.is_err() {
        return Ok(None);
    }
    let cmd = CellCommand::Auth(AuthCommand::GrantStepUp {
        session: session.id,
        action_digest,
    });
    let x = CellCtx {
        actor,
        at: at.micros(),
    };
    match fstp_cell_core::decide_with_id(state, &cmd, &x, command, &Answers::new()) {
        Ok(batch) => match batch.as_slice() {
            [
                record @ CellRecord::Auth(AuthRecord::StepUpGranted {
                    id,
                    action_digest: d,
                    session: s,
                }),
            ] if *d == action_digest && *s == session.id => Ok(Some(StepUpGrant {
                enrolment: enrolled,
                command,
                id: *id,
                at,
                record: record.clone(),
            })),
            _ => Err(NotImplemented::new(STEPUP_GRANT_FAILED)),
        },
        Err(CellRefusal::NotImplemented(op)) => Err(NotImplemented::new(op)),
        Err(CellRefusal::Domain(_)) => Ok(None),
    }
}

/// Admits `cmd` by `actor` at `at` through the gate, under `command_id`,
/// in a passkey session ([`session_of`]).
///
/// A high-risk command gets a fresh strong step-up first. Its digest is
/// production's (`mc::stepup_model::prod_action_digest`), and its
/// records are the ones the step-up route writes ([`stepup_grant`]). The
/// gate admits only a step-up the ledger granted. So the gate is asked
/// over a copy of the state with the route's entries folded after the
/// head of `on`'s ledger. [`Shell::execute`] then appends the same
/// entries to the shell's ledger before the driver runs. When the route
/// or production refuses the grant, the command comes without a step-up,
/// and the gate refuses it as a route would.
///
/// # Errors
///
/// The gate's stub refusal or a seam, as [`AdmitError::NotImplemented`].
/// A refusal of the command by the gate, as [`AdmitError::Denied`].
pub fn admit<'a>(
    on: impl Into<GateState<'a>>,
    cmd: CellCommand,
    actor: AccountId,
    at: Timestamp,
    command_id: [u8; 16],
) -> Result<Admitted, AdmitError> {
    let on: GateState<'a> = on.into();
    let session = session_of(actor, at);
    let action = Action::Command(cmd.clone());
    let high = gate::HighRiskAction::of(&action).map_err(deny)?;
    let mut granted: Option<CellState> = None;
    let mut stepup: Option<StepUpView> = None;
    if high.is_some() {
        let action_digest = crate::mc::stepup_model::prod_action_digest(&cmd, command_id)?;
        if let Some(g) = stepup_grant(on.state, actor, &session, action_digest, at, command_id)? {
            granted = Some(on.with_grant(&g)?);
            stepup = Some(StepUpView {
                id: g.id,
                session: session.id,
                action_digest,
                asserted_at: at,
                strong: true,
                consumed: false,
            });
        }
    }
    gate::admit_command(
        granted.as_ref().unwrap_or(on.state),
        &session,
        action,
        command_id,
        stepup.as_ref(),
        at,
        &POLICY,
    )
    .map_err(deny)
}

fn fold_ni(e: FoldError) -> NotImplemented {
    match e {
        FoldError::NotImplemented(op) => NotImplemented::new(op),
        FoldError::Engine(_) => {
            NotImplemented::new("fstp_cell_core::replay refused the genesis ledger")
        }
    }
}

impl Production {
    /// The backend: the genesis state and both commands admitted.
    ///
    /// # Errors
    ///
    /// The first stub refusal of `fstp_cell_core`, or the gate's refusal
    /// of either command.
    pub fn new() -> Result<Production, AdmitError> {
        let genesis = fstp_cell_core::replay(&[]).map_err(fold_ni)?;
        let one = admit(&genesis, cell_command(Cmd::One), ACTOR, AT, Cmd::One.id())?;
        let two = admit(&genesis, cell_command(Cmd::Two), ACTOR, AT, Cmd::Two.id())?;
        Ok(Production {
            genesis,
            admitted: [one, two],
            ledger: ProdLedger::default(),
        })
    }
}

/// One production run.
#[derive(Clone, Debug)]
pub struct ProdRun {
    state: CellState,
    driver: DriverCore,
    need: Option<Need>,
    /// Model sequence and production head of each entry the run read or
    /// appended, from (0, 0).
    seqs: Vec<(u64, u64)>,
    /// The ledger as the run saw it, one production sequence per record.
    mirror: MemStore<CellRecord>,
}

/// The production event for `reply` to `need`.
///
/// # Errors
///
/// [`LEDGER_SEAM`] for a non-empty read: [`Production`] builds those from
/// its own record of each entry, so this function never takes one. A duplicate reply names no earlier entry, so the event names
/// `Seq::ZERO`, which the driver does not read. An append reply carries no
/// chain link, so the event names link zero.
pub fn production_event(need: &Need, reply: &Reply) -> Result<Event, NotImplemented> {
    match (need, reply) {
        (Need::ReadFrom(_), Reply::Read(entries)) if entries.is_empty() => {
            Ok(Event::Read(Vec::new()))
        }
        (Need::Epoch, Reply::Epoch(e)) => Ok(Event::Epoch(
            e.map(VaultEpoch::from_raw).ok_or(VaultFault::Unavailable),
        )),
        (Need::Ask { queries, .. }, Reply::Answers(a)) => Ok(Event::Answers(match a {
            Some(answers) => Ok(domain_answers(queries, answers)),
            None => Err(VaultFault::Refused),
        })),
        (Need::Ack { .. }, Reply::Acked(ok)) => Ok(Event::Acked(if *ok {
            Ok(())
        } else {
            Err(VaultFault::Unavailable)
        })),
        (Need::Append { .. }, Reply::Appended(r)) => Ok(Event::Appended(match r {
            AppendReply::Ok(seq) => Ok((fstp_ledger::Seq::from_raw(*seq), [0; 32])),
            AppendReply::Duplicate => Err(fstp_ledger::AppendError::DuplicateCommand {
                at: fstp_ledger::Seq::ZERO,
            }),
            AppendReply::Stale(head) => Err(fstp_ledger::AppendError::StaleHead {
                head: fstp_ledger::Seq::from_raw(*head),
            }),
        })),
        _ => Err(NotImplemented::new(LEDGER_SEAM)),
    }
}

/// The digest the shell puts on answers. The driver computes the query
/// digests itself (design section 5.2, NOTE 5).
pub const SHELL_DIGEST: ContentDigest = ContentDigest::from_bytes([0; 32]);

/// The domain answers for `queries`, from reference answers in order.
pub fn domain_answers(queries: &[Query], answers: &[RefAnswer]) -> Answers {
    let mut out = Answers::new();
    for (q, a) in queries.iter().zip(answers) {
        out.insert(
            q.clone(),
            Answer {
                holds: a.holds,
                accounts: a.accounts.clone(),
                epoch: VaultEpoch::from_raw(a.epoch),
                digest: SHELL_DIGEST,
            },
        );
    }
    out
}

/// The model's need for a production need.
pub fn model_need(n: &Need) -> DNeed {
    match n {
        Need::ReadFrom(s) => DNeed::ReadFrom(s.raw()),
        Need::Epoch => DNeed::Epoch,
        Need::Ask {
            queries,
            reaction_for,
        } => DNeed::Ask {
            reaction_for: reaction_for.map(VaultEpoch::raw),
            queries: queries.clone(),
        },
        Need::Append {
            expected, command, ..
        } => DNeed::Append {
            expected: expected.raw(),
            command: *command,
        },
        Need::Ack { epoch, seq, .. } => DNeed::Ack {
            epoch: epoch.raw(),
            seq: seq.raw(),
        },
    }
}

/// The model's result for a production result.
///
/// # Errors
///
/// The driver's `NotImplemented`.
pub fn model_done(
    r: &Result<fstp_cell_core::driver::Done, ExecError>,
) -> Result<DDone, NotImplemented> {
    match r {
        Ok(d) => Ok(DDone::Ok { head: d.head.raw() }),
        Err(ExecError::NotImplemented(op)) => Err(NotImplemented::new(op)),
        Err(ExecError::VaultFault) => Ok(DDone::VaultFault),
        Err(e) => Ok(DDone::Refused(format!("{e:?}"))),
    }
}

impl DriverBackend for Production {
    type Run = ProdRun;

    fn start(&self, cmd: Cmd, retry_id: Option<[u8; 16]>) -> Result<ProdRun, NotImplemented> {
        let admitted = self
            .admitted
            .get(cmd.index())
            .cloned()
            .ok_or(NotImplemented::new(COMMAND_ID_SEAM))?;
        let caller = retry_id.unwrap_or(cmd.id());
        Ok(ProdRun {
            state: self.genesis.clone(),
            driver: DriverCore::start_with_id(admitted, caller),
            need: None,
            seqs: vec![(0, 0)],
            mirror: MemStore::new(),
        })
    }

    fn step(&self, run: &mut ProdRun, reply: Option<&Reply>) -> Result<DNeed, NotImplemented> {
        let need = run.need.take();
        let ev = match (&need, reply) {
            (Some(n), Some(r)) => Some(self.event(run, n, r)?),
            _ => None,
        };
        match run.driver.step(&mut run.state, ev) {
            Step::Need(n) => {
                if let Need::Append {
                    at, command, batch, ..
                } = &n
                {
                    self.ledger.remember(*command, *at, batch)?;
                }
                let out = run.model_need(&n)?;
                run.need = Some(n);
                Ok(out)
            }
            Step::Done(r) => {
                run.need = None;
                Ok(DNeed::Done(match model_done(&r)? {
                    DDone::Ok { head } => DDone::Ok {
                        head: run.model_seq(fstp_ledger::Seq::from_raw(head))?,
                    },
                    other => other,
                }))
            }
        }
    }
}

impl Production {
    /// The production event for `reply` to `need`. A read appends the
    /// records of each new model entry to the run's mirror of the ledger,
    /// from the records its writer appended ([`ProdLedger`]), and gives
    /// the mirror's entries after the need's head. An append that
    /// committed adds the run's batch to the mirror.
    fn event(
        &self,
        run: &mut ProdRun,
        need: &Need,
        reply: &Reply,
    ) -> Result<Event, NotImplemented> {
        fn seam<E>(_: E) -> NotImplemented {
            NotImplemented::new(LEDGER_SEAM)
        }
        match (need, reply) {
            (Need::ReadFrom(from), Reply::Read(entries)) => {
                for e in entries {
                    if run.seqs.iter().any(|(m, _)| *m == e.seq) {
                        continue;
                    }
                    let (at, batch) = self.ledger.records(e.command)?;
                    let head = run.mirror.head();
                    let prod = run
                        .mirror
                        .append(head, at, e.command, batch)
                        .map_err(seam)?;
                    run.seqs.push((e.seq, prod.raw()));
                }
                let first = from
                    .raw()
                    .checked_add(1)
                    .ok_or(NotImplemented::new(LEDGER_SEAM))?;
                let mut out = Vec::new();
                run.mirror
                    .read(fstp_ledger::Seq::from_raw(first), usize::MAX, &mut out)
                    .map_err(seam)?;
                Ok(Event::Read(out))
            }
            (
                Need::Append {
                    expected,
                    at,
                    command,
                    batch,
                    ..
                },
                Reply::Appended(AppendReply::Ok(seq)),
            ) => {
                if run.mirror.head() != *expected {
                    return Err(NotImplemented::new(LEDGER_SEAM));
                }
                let prod = run
                    .mirror
                    .append(*expected, *at, *command, batch.clone())
                    .map_err(seam)?;
                run.seqs.push((*seq, prod.raw()));
                Ok(Event::Appended(Ok((prod, [0; 32]))))
            }
            _ => production_event(need, reply),
        }
    }
}

/// The records of every entry a production run asked to append, by
/// command id, with the record of the second writer's entry. The model's
/// ledger holds one sequence per entry, and production one per record,
/// so each run maps the two ([`ProdRun`]).
#[derive(Debug, Default)]
struct ProdLedger(std::sync::Mutex<Batches>);

/// The time and records of each appended batch, by command id.
type Batches = std::collections::BTreeMap<[u8; 16], (i64, Vec<CellRecord>)>;

impl Clone for ProdLedger {
    fn clone(&self) -> ProdLedger {
        ProdLedger(std::sync::Mutex::new(self.lock().clone()))
    }
}

/// Two runs asked to append different records under one command id, so
/// the model's entry names no single batch.
const RECORDS_DIFFER: &str =
    "fstp_celltest::mc::driver_model: two runs appended different records under one command id";

impl ProdLedger {
    fn lock(&self) -> std::sync::MutexGuard<'_, Batches> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remember(
        &self,
        command: [u8; 16],
        at: i64,
        batch: &[CellRecord],
    ) -> Result<(), NotImplemented> {
        let mut map = self.lock();
        match map.get(&command) {
            Some((t, b)) if *t == at && b.as_slice() == batch => Ok(()),
            Some(_) => Err(NotImplemented::new(RECORDS_DIFFER)),
            None => {
                map.insert(command, (at, batch.to_vec()));
                Ok(())
            }
        }
    }

    fn records(&self, command: [u8; 16]) -> Result<(i64, Vec<CellRecord>), NotImplemented> {
        if command == FOREIGN_ID {
            // The second writer's entry: a text write of its own.
            return Ok((
                AT.micros(),
                vec![CellRecord::Text(
                    fstp_cell_core::text::TextRecord::TextPut { id: FOREIGN_ID },
                )],
            ));
        }
        self.lock()
            .get(&command)
            .cloned()
            .ok_or(NotImplemented::new(LEDGER_SEAM))
    }
}

impl ProdRun {
    /// The model sequence of production head `prod`, from what the run
    /// read and appended.
    fn model_seq(&self, prod: fstp_ledger::Seq) -> Result<u64, NotImplemented> {
        self.seqs
            .iter()
            .rev()
            .find(|(_, p)| *p == prod.raw())
            .map(|(m, _)| *m)
            .ok_or(NotImplemented::new(LEDGER_SEAM))
    }

    /// The model's need for production need `n`, its sequences mapped.
    fn model_need(&self, n: &Need) -> Result<DNeed, NotImplemented> {
        Ok(match model_need(n) {
            DNeed::ReadFrom(_) => match n {
                Need::ReadFrom(s) => DNeed::ReadFrom(self.model_seq(*s)?),
                _ => return Err(NotImplemented::new(LEDGER_SEAM)),
            },
            DNeed::Append { command, .. } => match n {
                Need::Append { expected, .. } => DNeed::Append {
                    expected: self.model_seq(*expected)?,
                    command,
                },
                _ => return Err(NotImplemented::new(LEDGER_SEAM)),
            },
            DNeed::Ack { epoch, .. } => match n {
                Need::Ack { seq, .. } => DNeed::Ack {
                    epoch,
                    seq: self.model_seq(*seq)?,
                },
                _ => return Err(NotImplemented::new(LEDGER_SEAM)),
            },
            other => other,
        })
    }
}

// ---------------------------------------------------------------------------
// The model.

/// A backend's live run inside a model state. Every `Live` compares equal,
/// since the abstract state determines it (see the module documentation).
#[derive(Clone, Debug)]
pub struct Live<T>(pub Option<T>);

impl<T> PartialEq for Live<T> {
    fn eq(&self, _other: &Live<T>) -> bool {
        true
    }
}

impl<T> Eq for Live<T> {}

impl<T> Hash for Live<T> {
    fn hash<H: Hasher>(&self, _state: &mut H) {}
}

/// The faults used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DFaults {
    /// The crash after an append, before its reply.
    pub crash: bool,
    /// The lost acknowledgement.
    pub lost_ack: bool,
    /// The second writer's append.
    pub stale: bool,
}

/// The current run.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DRun<L> {
    /// The command.
    pub cmd: Cmd,
    /// The command id of a crash retry.
    pub retry_id: Option<[u8; 16]>,
    /// The replies so far.
    pub replies: Vec<Reply>,
    /// The run's next need.
    pub need: DNeed,
    /// The backend's live run.
    pub live: L,
}

/// One M-DRIVER state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DrvState<L> {
    /// The store.
    pub ledger: Vec<LEntry>,
    /// The vault.
    pub vault: RefVault,
    /// Whether the vault fact was written.
    pub fact_written: bool,
    /// The current run.
    pub run: Option<DRun<L>>,
    /// The last result of each command.
    pub done: [Option<DDone>; 2],
    /// How many runs each command started.
    pub starts: [u8; 2],
    /// The faults used.
    pub faults: DFaults,
    /// The command the caller retried after the crash.
    pub retried: Option<Cmd>,
    /// Set when a backend answered `NotImplemented`. The state is terminal.
    pub halted: Option<String>,
}

impl<L> DrvState<L> {
    /// The sequence of the ledger head.
    pub fn head(&self) -> u64 {
        self.ledger.last().map_or(0, |e| e.seq)
    }

    /// How many entries carry the command of `cmd`, by any id the command
    /// ran under. A crash retry under a fresh id counts too.
    pub fn applied(&self, cmd: Cmd) -> usize {
        self.ledger
            .iter()
            .filter(|e| match kind_of(e.command) {
                EntryKind::Command(c) => c == cmd,
                EntryKind::Other(id) => id == FRESH_ID && self.retried == Some(cmd),
                _ => false,
            })
            .count()
    }
}

/// One M-DRIVER action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DrvAction {
    /// The vault takes the fact.
    WriteFact,
    /// A run of the command starts.
    Start(Cmd),
    /// The shell answers the run's need.
    Deliver,
    /// The second writer appends before the run's append.
    Foreign,
    /// The run's append commits, then the process crashes before the
    /// reply. The caller retries the command.
    Crash,
    /// The run's acknowledgement is lost.
    LoseAck,
}

/// M-DRIVER over a driver backend.
#[derive(Clone, Debug)]
pub struct DriverModel<B> {
    backend: B,
}

/// The most runs one command starts, crash retries included.
pub const MAX_STARTS: u8 = 2;

impl<B: DriverBackend> DriverModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> DriverModel<B> {
        DriverModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn halt(s: &DrvState<Live<B::Run>>, e: &NotImplemented) -> DrvState<Live<B::Run>> {
        let mut t = s.clone();
        t.run = None;
        t.halted = Some(e.operation.to_owned());
        t
    }

    fn append(ledger: &[LEntry], expected: u64, command: [u8; 16]) -> AppendReply {
        if ledger.iter().any(|e| e.command == command) {
            return AppendReply::Duplicate;
        }
        let head = ledger.last().map_or(0, |e| e.seq);
        if head != expected {
            return AppendReply::Stale(head);
        }
        AppendReply::Ok(head.saturating_add(1))
    }

    /// The shell's reply to `need`, and the state after it.
    fn answer(s: &DrvState<Live<B::Run>>, need: &DNeed) -> Option<(Reply, DrvState<Live<B::Run>>)> {
        let mut t = s.clone();
        let reply = match need {
            DNeed::ReadFrom(from) => {
                Reply::Read(s.ledger.iter().filter(|e| e.seq > *from).copied().collect())
            }
            DNeed::Epoch => Reply::Epoch(Some(s.vault.current())),
            DNeed::Ask {
                reaction_for,
                queries,
            } => Reply::Answers(s.vault.ask(*reaction_for, queries).ok()),
            DNeed::Append { expected, command } => {
                let r = Self::append(&s.ledger, *expected, *command);
                if let AppendReply::Ok(seq) = r {
                    t.ledger.push(LEntry {
                        seq,
                        command: *command,
                    });
                }
                Reply::Appended(r)
            }
            DNeed::Ack { epoch, seq } => {
                let ok = t.vault.ack(*epoch, *seq, [0; 32]).is_ok();
                Reply::Acked(ok)
            }
            DNeed::Done(_) => return None,
        };
        Some((reply, t))
    }

    fn advance(
        &self,
        s: &DrvState<Live<B::Run>>,
        mut t: DrvState<Live<B::Run>>,
        reply: Reply,
    ) -> DrvState<Live<B::Run>> {
        let Some(mut run) = t.run.take() else {
            return t;
        };
        let Some(mut live) = run.live.0.take() else {
            return Self::halt(
                s,
                &NotImplemented::new("M-DRIVER: a run lost its live state"),
            );
        };
        let next = match self.backend.step(&mut live, Some(&reply)) {
            Ok(n) => n,
            Err(e) => return Self::halt(s, &e),
        };
        run.replies.push(reply);
        if let DNeed::Done(d) = &next {
            if let Some(slot) = t.done.get_mut(run.cmd.index()) {
                *slot = Some(d.clone());
            }
            return t;
        }
        run.need = next;
        run.live = Live(Some(live));
        t.run = Some(run);
        t
    }

    fn start(
        &self,
        s: &DrvState<Live<B::Run>>,
        cmd: Cmd,
        retry_id: Option<[u8; 16]>,
    ) -> DrvState<Live<B::Run>> {
        let mut t = s.clone();
        let mut live = match self.backend.start(cmd, retry_id) {
            Ok(l) => l,
            Err(e) => return Self::halt(s, &e),
        };
        let need = match self.backend.step(&mut live, None) {
            Ok(n) => n,
            Err(e) => return Self::halt(s, &e),
        };
        if let Some(n) = t.starts.get_mut(cmd.index()) {
            *n = n.saturating_add(1);
        }
        if let DNeed::Done(d) = &need {
            if let Some(slot) = t.done.get_mut(cmd.index()) {
                *slot = Some(d.clone());
            }
            return t;
        }
        t.run = Some(DRun {
            cmd,
            retry_id,
            replies: Vec::new(),
            need,
            live: Live(Some(live)),
        });
        t
    }
}

/// The state at genesis: an empty store and an empty vault.
pub fn genesis<L>() -> DrvState<L> {
    DrvState {
        ledger: Vec::new(),
        vault: RefVault::default(),
        fact_written: false,
        run: None,
        done: [None, None],
        starts: [0, 0],
        faults: DFaults::default(),
        retried: None,
        halted: None,
    }
}

impl<B: DriverBackend> Model for DriverModel<B> {
    type State = DrvState<Live<B::Run>>;
    type Action = DrvAction;

    fn init(&self) -> Vec<DrvState<Live<B::Run>>> {
        vec![genesis()]
    }

    fn actions(&self, s: &DrvState<Live<B::Run>>, out: &mut Vec<DrvAction>) {
        if s.halted.is_some() {
            return;
        }
        out.extend([
            DrvAction::WriteFact,
            DrvAction::Start(Cmd::One),
            DrvAction::Start(Cmd::Two),
            DrvAction::Deliver,
            DrvAction::Foreign,
            DrvAction::Crash,
            DrvAction::LoseAck,
        ]);
    }

    fn step(&self, s: &DrvState<Live<B::Run>>, a: &DrvAction) -> Option<DrvState<Live<B::Run>>> {
        if s.halted.is_some() {
            return None;
        }
        match a {
            DrvAction::WriteFact => {
                if s.fact_written {
                    return None;
                }
                let mut t = s.clone();
                t.vault.write(fact());
                t.fact_written = true;
                Some(t)
            }
            DrvAction::Start(cmd) => {
                let idx = cmd.index();
                let ok_done = matches!(s.done.get(idx), Some(Some(DDone::Ok { .. })));
                let starts = s.starts.get(idx).copied().unwrap_or(MAX_STARTS);
                if s.run.is_some() || ok_done || starts >= MAX_STARTS {
                    return None;
                }
                Some(self.start(s, *cmd, None))
            }
            DrvAction::Deliver => {
                let run = s.run.as_ref()?;
                let (reply, t) = Self::answer(s, &run.need)?;
                Some(self.advance(s, t, reply))
            }
            DrvAction::Foreign => {
                let run = s.run.as_ref()?;
                if s.faults.stale || !matches!(run.need, DNeed::Append { .. }) {
                    return None;
                }
                let mut t = s.clone();
                let seq = t.head().saturating_add(1);
                t.ledger.push(LEntry {
                    seq,
                    command: FOREIGN_ID,
                });
                t.faults.stale = true;
                Some(t)
            }
            DrvAction::Crash => {
                let run = s.run.as_ref()?;
                let DNeed::Append { expected, command } = run.need else {
                    return None;
                };
                if s.faults.crash
                    || is_reaction_command_id(command)
                    || !matches!(
                        Self::append(&s.ledger, expected, command),
                        AppendReply::Ok(_)
                    )
                {
                    return None;
                }
                let (_, mut t) = Self::answer(s, &run.need)?;
                let cmd = run.cmd;
                t.run = None;
                t.faults.crash = true;
                t.retried = Some(cmd);
                if let Some(n) = t.starts.get_mut(cmd.index()) {
                    *n = n.saturating_sub(1);
                }
                Some(self.start(&t, cmd, Some(command)))
            }
            DrvAction::LoseAck => {
                let run = s.run.as_ref()?;
                if s.faults.lost_ack || !matches!(run.need, DNeed::Ack { .. }) {
                    return None;
                }
                let mut t = s.clone();
                t.faults.lost_ack = true;
                Some(self.advance(s, t, Reply::Acked(false)))
            }
        }
    }

    fn is_terminal(&self, s: &DrvState<Live<B::Run>>) -> bool {
        s.halted.is_some()
            || (s.run.is_none()
                && s.fact_written
                && Cmd::ALL.iter().all(|c| {
                    matches!(s.done.get(c.index()), Some(Some(DDone::Ok { .. })))
                        || s.starts.get(c.index()).copied().unwrap_or(MAX_STARTS) >= MAX_STARTS
                }))
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property and witness ids of M-DRIVER.
pub mod ids {
    /// Every backend call answered.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-23: the store only grows by appends.
    pub const I23: &str = "I-23";
    /// I-23: a retried command is a duplicate, never applied twice.
    pub const I23_ONCE: &str = "I-23-once";
    /// NOTE 4: an epoch becomes effective only after its reaction commits.
    pub const NOTE4: &str = "NOTE-4";
    /// Witness: a crash retry is reported as committed.
    pub const W_RETRY_DUPLICATE: &str = "I-23-witness-retry-is-duplicate";
    /// Witness: a command commits after a stale head.
    pub const W_STALE_RETRY: &str = "I-23-witness-stale-head-retried";
    /// Witness: the vault fact becomes effective after a lost
    /// acknowledgement, by the restart rule.
    pub const W_REACK: &str = "NOTE-4-witness-reack-after-loss";
}

fn i23(s_ledger: &[LEntry], t_ledger: &[LEntry]) -> Result<(), String> {
    if t_ledger.len() < s_ledger.len() || t_ledger.get(..s_ledger.len()) != Some(s_ledger) {
        return Err("I-23: an entry of the store changed or went".to_owned());
    }
    Ok(())
}

/// Every M-DRIVER property and witness.
pub fn properties<B: DriverBackend>(_m: &DriverModel<B>) -> Vec<Property<'static, DriverModel<B>>>
where
    B::Run: 'static,
{
    vec![
        Property::always_with(
            ids::BACKEND_ANSWERS,
            |s: &DrvState<Live<B::Run>>| match &s.halted {
                None => Ok(()),
                Some(op) => Err(format!("the backend did not answer: {op} (NotImplemented)")),
            },
        ),
        Property::transition_with(
            ids::I23,
            |s: &DrvState<Live<B::Run>>, _a: &DrvAction, t: &DrvState<Live<B::Run>>| {
                i23(&s.ledger, &t.ledger)
            },
        ),
        Property::always_with(ids::I23_ONCE, |s: &DrvState<Live<B::Run>>| {
            for c in Cmd::ALL {
                let n = s.applied(c);
                if n > 1 {
                    return Err(format!("I-23: {c:?} was applied {n} times"));
                }
            }
            if let Some(e) = s
                .ledger
                .iter()
                .find(|e| matches!(kind_of(e.command), EntryKind::Other(id) if id != FRESH_ID))
            {
                return Err(format!(
                    "I-23: an entry under an unknown command id {:?}",
                    e.command
                ));
            }
            Ok(())
        }),
        Property::transition_with(
            ids::NOTE4,
            |s: &DrvState<Live<B::Run>>, _a: &DrvAction, t: &DrvState<Live<B::Run>>| {
                if t.vault.effective() > s.vault.effective() {
                    let e = t.vault.effective();
                    let committed = s
                        .ledger
                        .iter()
                        .any(|x| kind_of(x.command) == EntryKind::Reaction(e));
                    if !committed {
                        return Err(format!(
                            "NOTE-4: epoch {e} became effective before its reaction was in the store"
                        ));
                    }
                }
                Ok(())
            },
        ),
        Property::reachable(ids::W_RETRY_DUPLICATE, |s: &DrvState<Live<B::Run>>| {
            s.faults.crash
                && s.halted.is_none()
                && Cmd::ALL.iter().any(|c| {
                    s.applied(*c) == 1
                        && matches!(s.done.get(c.index()), Some(Some(DDone::Ok { .. })))
                })
        }),
        Property::reachable(ids::W_STALE_RETRY, |s: &DrvState<Live<B::Run>>| {
            s.faults.stale
                && s.ledger
                    .iter()
                    .skip_while(|e| e.command != FOREIGN_ID)
                    .any(|e| matches!(kind_of(e.command), EntryKind::Command(_)))
        }),
        Property::reachable(ids::W_REACK, |s: &DrvState<Live<B::Run>>| {
            s.faults.lost_ack && s.vault.effective() == 1
        }),
    ]
}

// ---------------------------------------------------------------------------
// The production shell of the seam tests (design section 14.6).

/// Why the shell did not run a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellError {
    /// A production part is a stub or a seam. It names it.
    NotImplemented(String),
    /// The driver asked for something the shell cannot give.
    Protocol(String),
}

impl From<NotImplemented> for ShellError {
    fn from(e: NotImplemented) -> ShellError {
        ShellError::NotImplemented(e.operation.to_owned())
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::NotImplemented(op) => write!(f, "{op} (NotImplemented)"),
            ShellError::Protocol(why) => write!(f, "shell protocol: {why}"),
        }
    }
}

/// How the shell's vault answers.
#[derive(Clone, Debug)]
pub enum ShellVault {
    /// The M2 synthetic vault: every answer from the ground truth at its
    /// epoch, reactions included. Acknowledgements are accepted.
    Truth(fstp_domain_testkit::vault::GroundTruth),
    /// The reference vault with its NOTE 4 protocol.
    Reference(RefVault),
    /// A vault that fails each request kind in `faults`.
    Faulty {
        /// The vault behind the faults.
        inner: Box<ShellVault>,
        /// The request kinds that fail.
        faults: BTreeSet<FaultAt>,
    },
}

/// A request kind a faulty vault fails (NOTE 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultAt {
    /// The epoch request.
    Epoch,
    /// A non-reaction ask.
    Ask,
    /// A reaction ask.
    ReactionAsk,
    /// The acknowledgement.
    Ack,
}

impl ShellVault {
    fn epoch(&self) -> Option<u64> {
        match self {
            ShellVault::Truth(t) => Some(t.epoch().raw()),
            ShellVault::Reference(v) => Some(v.current()),
            ShellVault::Faulty { inner, faults } => {
                if faults.contains(&FaultAt::Epoch) {
                    None
                } else {
                    inner.epoch()
                }
            }
        }
    }

    fn ask(&self, reaction_for: Option<u64>, queries: &[Query]) -> Option<Vec<RefAnswer>> {
        match self {
            ShellVault::Truth(t) => Some(
                queries
                    .iter()
                    .map(|q| {
                        let a = t.answer(q);
                        RefAnswer {
                            holds: a.holds,
                            accounts: a.accounts,
                            epoch: a.epoch.raw(),
                        }
                    })
                    .collect(),
            ),
            ShellVault::Reference(v) => v.ask(reaction_for, queries).ok(),
            ShellVault::Faulty { inner, faults } => {
                let kind = if reaction_for.is_some() {
                    FaultAt::ReactionAsk
                } else {
                    FaultAt::Ask
                };
                if faults.contains(&kind) {
                    None
                } else {
                    inner.ask(reaction_for, queries)
                }
            }
        }
    }

    fn ack(&mut self, epoch: u64, seq: u64) -> bool {
        match self {
            ShellVault::Truth(_) => true,
            ShellVault::Reference(v) => v.ack(epoch, seq, [0; 32]).is_ok(),
            ShellVault::Faulty { inner, faults } => {
                if faults.contains(&FaultAt::Ack) {
                    false
                } else {
                    inner.ack(epoch, seq)
                }
            }
        }
    }
}

/// The shell's vault as the oracle of a composed setup entry
/// ([`Shell::execute_composed`]). A failed ask is the vault being down.
struct ComposeOracle<'a>(&'a ShellVault);

impl fstp_engine::IdentityOracle for ComposeOracle<'_> {
    fn ask(&self, q: &Query) -> Result<Answer, fstp_domain::oracle::OracleDown> {
        let answers = self
            .0
            .ask(None, std::slice::from_ref(q))
            .ok_or(fstp_domain::oracle::OracleDown)?;
        domain_answers(std::slice::from_ref(q), &answers)
            .get(q)
            .cloned()
            .ok_or(fstp_domain::oracle::OracleDown)
    }

    fn epoch(&self) -> Result<VaultEpoch, fstp_domain::oracle::OracleDown> {
        self.0
            .epoch()
            .map(VaultEpoch::from_raw)
            .ok_or(fstp_domain::oracle::OracleDown)
    }
}

/// One batch the driver appended through the shell, as it was handed over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellEntry {
    /// The ledger head after the batch: the sequence of its last entry.
    pub seq: u64,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The records.
    pub batch: Vec<CellRecord>,
}

/// Every need the shell answered, in order, for the seam tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    /// The driver asked for the epoch.
    Epoch,
    /// The driver asked queries.
    Ask {
        /// The reaction epoch, if any.
        reaction_for: Option<u64>,
        /// The query kinds.
        kinds: Vec<fstp_domain::oracle::QueryKind>,
    },
    /// The driver appended under this command id.
    Append([u8; 16]),
    /// The driver acknowledged this epoch.
    Ack(u64),
}

/// The production shell: `DriverCore` over the shell's own ledger, an
/// `fstp_ledger::MemStore`, and a [`ShellVault`].
///
/// The ledger has two writers. The driver appends the batches of the
/// commands it runs ([`Shell::ledger`]). The step-up route appends the
/// `StepUpGranted` record of each admitted step-up before its command
/// runs ([`Shell::stepup_grants`]). The state is always the replay of the
/// whole ledger ([`Shell::entries`], I-23).
///
/// The shell holds no audit chain, so every link it reports is zero.
#[derive(Clone, Debug)]
pub struct Shell {
    state: CellState,
    store: MemStore<CellRecord>,
    ledger: Vec<ShellEntry>,
    grants: Vec<StepUpGrant>,
    vault: ShellVault,
    seen: Vec<Seen>,
}

impl Shell {
    /// The shell at genesis over `vault`.
    ///
    /// # Errors
    ///
    /// The stub refusal of `fstp_cell_core::replay`.
    pub fn genesis(vault: ShellVault) -> Result<Shell, ShellError> {
        let state = fstp_cell_core::replay(&[]).map_err(fold_ni)?;
        Ok(Shell {
            state,
            store: MemStore::new(),
            ledger: Vec::new(),
            grants: Vec::new(),
            vault,
            seen: Vec::new(),
        })
    }

    /// The folded state, with the ledger it is the replay of, so that
    /// [`admit`] can record a step-up grant on a copy.
    pub fn state(&self) -> GateState<'_> {
        GateState {
            state: &self.state,
            ledger: Some(&self.store),
        }
    }

    /// Every batch the driver appended, in order. The step-up grants are
    /// the route's appends, not the driver's: they are in
    /// [`Shell::stepup_grants`] and [`Shell::entries`].
    pub fn ledger(&self) -> &[ShellEntry] {
        &self.ledger
    }

    /// Every step-up grant the shell appended before a command, in order.
    pub fn stepup_grants(&self) -> &[StepUpGrant] {
        &self.grants
    }

    /// Every entry of the ledger, in order, as the store returns them.
    pub fn entries(&self) -> Vec<Entry<CellRecord>> {
        let mut out = Vec::new();
        // A read of the in-memory store never fails.
        let _ = self.store.read(Seq::ZERO, usize::MAX, &mut out);
        out
    }

    /// Every need answered, in order.
    pub fn seen(&self) -> &[Seen] {
        &self.seen
    }

    /// The vault.
    pub fn vault_mut(&mut self) -> &mut ShellVault {
        &mut self.vault
    }

    /// Runs one admitted command to its end, committed at the admission
    /// instant ([`Shell::execute_at`]).
    ///
    /// # Errors
    ///
    /// A stub refusal or a need the shell cannot meet.
    pub fn execute(
        &mut self,
        admitted: Admitted,
    ) -> Result<Result<fstp_cell_core::driver::Done, ExecError>, ShellError> {
        let at = admitted.at();
        self.execute_at(admitted, at)
    }

    /// Runs one admitted command to its end, with `commit_at` as the
    /// clock of the shell's store.
    ///
    /// When the admission names a step-up that the ledger does not hold,
    /// the shell first appends the route entries that [`admit`] folded
    /// into the gate's copy. They are the same entries from
    /// [`stepup_grant`], for the same command id, session and digest.
    /// Then `DriverCore` runs.
    ///
    /// The store's commit clock is apart from the entry instant, which is
    /// the admission instant. As the store does (design sections 5.3 and
    /// 8.4), it refuses an append whose `SideEffects::stepup_fresh_until`
    /// lies before `commit_at`, with a protocol fault that names
    /// `mc::auth_model::STEPUP_STALE_AT_COMMIT`. So a command committed
    /// after its step-up's P-71 limit is refused by the limit that
    /// `DriverCore` computed.
    ///
    /// # Errors
    ///
    /// A stub refusal or a need the shell cannot meet.
    pub fn execute_at(
        &mut self,
        admitted: Admitted,
        commit_at: Timestamp,
    ) -> Result<Result<fstp_cell_core::driver::Done, ExecError>, ShellError> {
        if let Some(u) = admitted.stepup()
            && self.state.auth().stepup_grant(u.id).is_none()
        {
            self.record_grant(&admitted, &u)?;
        }
        let mut driver = DriverCore::start(admitted);
        let mut ev: Option<Event> = None;
        for _ in 0..256 {
            match driver.step(&mut self.state, ev.take()) {
                Step::Done(r) => {
                    if let Err(ExecError::NotImplemented(op)) = &r {
                        return Err(ShellError::NotImplemented((*op).to_owned()));
                    }
                    return Ok(r);
                }
                Step::Need(n) => ev = Some(self.meet(&n, commit_at)?),
            }
        }
        Err(ShellError::Protocol(
            "the driver did not finish in 256 steps".to_owned(),
        ))
    }

    /// Runs a setup `CreateProgramme` or `ActivateProgramme` of an M2 step
    /// at `at` under `command` through the creator path, since strict D2e
    /// refuses both as core commands (M4 design section 15.0, as `52cdc5c`
    /// did for the M4 setups). The entry is the one
    /// `fstp_domain_testkit::activation::run_core` composes, decided on the
    /// shell's state with its vault's answers, and it is appended as a
    /// driver batch. The cell's tenant fold or the step's own flag attests
    /// a tenant admin, as `ProdCell::exec_step` reads it. The inner `Err`
    /// is the domain refusal.
    ///
    /// # Errors
    ///
    /// A system step, a vault whose epoch is ahead of the state's (the
    /// setups process it at the bootstrap), or a batch the store refuses.
    pub fn execute_composed(
        &mut self,
        step: &fstp_domain_testkit::r#gen::roster::Step,
        at: Timestamp,
        command: [u8; 16],
    ) -> Result<Result<(), fstp_domain::refusal::Refusal>, ShellError> {
        use fstp_domain_testkit::activation::{activation_records, open_records};
        let protocol = |why: String| ShellError::Protocol(why);
        let fstp_domain::command::Actor::Account(actor) = step.actor else {
            return Err(protocol("a composed step names no account".to_owned()));
        };
        let epoch = self.vault.epoch();
        if epoch.is_some_and(|e| e > self.state.engine().epoch().raw()) {
            return Err(protocol(
                "the vault is ahead of the state before a composed step".to_owned(),
            ));
        }
        let engine_cmd = fstp_engine::Command::Core(step.cmd.clone());
        let a = fstp_cell_core::attest_at(&self.state, actor, &engine_cmd, command, at);
        let ctx = fstp_domain::command::Ctx {
            now: at,
            actor: step.actor,
            command: fstp_domain::id::CommandId::from_bytes(command),
            via: fstp_domain::command::Via::Web,
            tenant_admin: a.tenant_admin || step.flags.tenant_admin,
            second_tenant_admin: None,
            binds_tenant_admin: a.binds_tenant_admin,
        };
        let oracle = ComposeOracle(&self.vault);
        let engine = self.state.engine();
        let records = match &step.cmd {
            fstp_domain::Command::CreateProgramme { policy } => {
                open_records(engine, &oracle, policy, &ctx)
            }
            cmd => activation_records(engine, &oracle, cmd, &ctx),
        };
        let records = match records {
            Ok(r) => r,
            Err(fstp_engine::ExecError::Refused(r)) => return Ok(Err(r)),
            Err(e) => return Err(protocol(format!("composed step: {e:?}"))),
        };
        let batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
        let expected = self.state.head();
        let mut store = self.store.clone();
        let head = store
            .append(expected, at.micros(), command, batch.clone())
            .map_err(|e| protocol(format!("composed append: {e}")))?;
        let mut entries = Vec::with_capacity(batch.len());
        store
            .read(
                Seq::from_raw(expected.raw().saturating_add(1)),
                batch.len(),
                &mut entries,
            )
            .map_err(|e| protocol(format!("composed read: {e}")))?;
        let mut next = self.state.clone();
        for e in &entries {
            fstp_cell_core::apply(&mut next, e)
                .map_err(|e| protocol(format!("composed fold: {e:?}")))?;
        }
        self.store = store;
        self.state = next;
        self.ledger.push(ShellEntry {
            seq: head.raw(),
            at: at.micros(),
            command,
            batch,
        });
        Ok(Ok(()))
    }

    /// Appends the route entries of the step-up `u` that the gate admitted
    /// for `admitted`, and folds them.
    fn record_grant(&mut self, admitted: &Admitted, u: &gate::StepUpUse) -> Result<(), ShellError> {
        let protocol = |why: &str| ShellError::Protocol(why.to_owned());
        let (Action::Command(_), Principal::Account(actor), Some(command_id)) = (
            admitted.action(),
            admitted.principal(),
            admitted.command_id(),
        ) else {
            return Err(protocol(
                "a step-up names no account command under a command id",
            ));
        };
        let session = session_of(actor, u.asserted_at);
        let grant = stepup_grant(
            &self.state,
            actor,
            &session,
            u.action_digest,
            u.asserted_at,
            command_id,
        )?
        .ok_or_else(|| protocol("the step-up route refuses the grant the gate admitted"))?;
        if grant.id != u.id {
            return Err(protocol(
                "the admitted step-up is not the one the shell's route records",
            ));
        }
        for e in grant.entries() {
            self.state = append_and_fold(&mut self.store, &self.state, &e)?;
        }
        self.grants.push(grant);
        Ok(())
    }

    fn meet(&mut self, n: &Need, commit_at: Timestamp) -> Result<Event, ShellError> {
        Ok(match n {
            Need::ReadFrom(from) => {
                let mut out = Vec::new();
                let start = Seq::from_raw(from.raw().saturating_add(1));
                self.store
                    .read(start, usize::MAX, &mut out)
                    .map_err(|e| ShellError::Protocol(format!("read: {e}")))?;
                Event::Read(out)
            }
            Need::Epoch => {
                self.seen.push(Seen::Epoch);
                Event::Epoch(
                    self.vault
                        .epoch()
                        .map(VaultEpoch::from_raw)
                        .ok_or(VaultFault::Unavailable),
                )
            }
            Need::Ask {
                queries,
                reaction_for,
            } => {
                let rf = reaction_for.map(VaultEpoch::raw);
                self.seen.push(Seen::Ask {
                    reaction_for: rf,
                    kinds: queries.iter().map(Query::kind).collect(),
                });
                Event::Answers(match self.vault.ask(rf, queries) {
                    Some(answers) => Ok(domain_answers(queries, &answers)),
                    None => Err(VaultFault::Refused),
                })
            }
            Need::Append {
                expected,
                at,
                command,
                batch,
                side,
            } => {
                self.seen.push(Seen::Append(*command));
                // The store's own commit clock, not the entry instant.
                if side.stepup_consumed.is_some()
                    && side
                        .stepup_fresh_until
                        .is_none_or(|until| commit_at.micros() > until)
                {
                    return Err(ShellError::Protocol(STEPUP_STALE_AT_COMMIT.to_owned()));
                }
                let r = self.store.append(*expected, *at, *command, batch.clone());
                if let Ok(head) = r {
                    self.ledger.push(ShellEntry {
                        seq: head.raw(),
                        at: *at,
                        command: *command,
                        batch: batch.clone(),
                    });
                }
                Event::Appended(r.map(|head| (head, [0; 32])))
            }
            Need::Ack { epoch, seq, .. } => {
                self.seen.push(Seen::Ack(epoch.raw()));
                Event::Acked(if self.vault.ack(epoch.raw(), seq.raw()) {
                    Ok(())
                } else {
                    Err(VaultFault::Unavailable)
                })
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Proposal paths from genesis, for the production tests of I-17 and I-18.

/// M2 command paths from genesis that take proposal PR1 of lead L1 to each
/// state up to NEGOTIATION, with the instant of each step. They follow
/// `fstp_domain_testkit::mc::life_model::LifeSetup::world` for the original
/// plan, then the cut-off, the IRC assignments and both validations.
///
/// [`paths::check_with_domain`] replays a path through the M2 domain, so a
/// production test never runs on a path that does not reach its state.
pub mod paths {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::command::{Actor, DeclarationSubject};
    use fstp_domain::decision::Vote;
    use fstp_domain::id::{AccountId, BindingId};
    use fstp_domain::rules::StateTag;
    use fstp_domain::scoring::{ScoreKey, Stage};
    use fstp_domain::time::Timestamp;
    use fstp_domain_testkit::r#gen::review::{
        COORDINATOR, IRC, L1, PR1, R1, R2, R3, STRANGER, declare, plan_of, submit,
    };
    use fstp_domain_testkit::r#gen::roster::{Backend, Flags, Step, T0, add_member, call};
    use fstp_domain_testkit::mc::life_model::{
        IRC2, LifeSetup, LifeWorld, T_EVAL, admit, assign_declared, assignment_of, ballots, close,
        cut_off, cut_off_decision, irc_review, knock_out, no_questions, score,
    };
    use fstp_domain_testkit::mc::minor_model::minor_setup;
    use fstp_domain_testkit::vault::GroundTruth;

    /// One step of a path and its instant.
    #[derive(Clone, Debug)]
    pub struct PathStep {
        /// The step.
        pub step: Step,
        /// When it runs.
        pub at: Timestamp,
    }

    /// The states a path reaches, in order.
    pub const STATES: [StateTag; 7] = [
        StateTag::Draft,
        StateTag::Submitted,
        StateTag::Stage1,
        StateTag::Stage2,
        StateTag::Ranked,
        StateTag::IrcReview,
        StateTag::Negotiation,
    ];

    /// The guardian of PR1, added by `AddGuardian` right after the draft
    /// (design section 6.6 step 3). It holds no other role.
    pub const GUARDIAN: AccountId = AccountId::from_raw(401);

    /// The Receiving binding of [`GUARDIAN`] on PR1.
    pub const GUARDIAN_BINDING: BindingId = BindingId::from_raw(9_401);

    /// The setup: PR1 of L1 in call 1, reviewers R1 and R2, P-15 = 2.
    pub fn setup() -> LifeSetup {
        minor_setup(false)
    }

    /// The vault of the setup. With `adult` set, L1 holds an effective
    /// over-18 attestation from before the deadline, so the gate admits PR1
    /// (state-machine NOTE 14). Otherwise PR1 is minor-flagged.
    pub fn truth(adult: bool) -> GroundTruth {
        let mut t = setup().truth();
        if !adult {
            t.withdraw_attestation(L1);
        }
        t
    }

    fn at(steps: Vec<Step>, t: Timestamp) -> Vec<PathStep> {
        steps
            .into_iter()
            .map(|step| PathStep { step, at: t })
            .collect()
    }

    /// The path that takes PR1 to `target`, one of [`STATES`]. The last two
    /// steps of the NEGOTIATION path are the IRC validations. Every path
    /// adds [`GUARDIAN`] to PR1 right after the draft, so a guardian consent
    /// ticket has its lawful recipient.
    ///
    /// # Errors
    ///
    /// A state outside [`STATES`], or a setup the testkit refuses.
    pub fn to(target: StateTag) -> Result<Vec<PathStep>, String> {
        let s = setup();
        let mut out = at(s.draft_steps()?, T0);
        out.push(PathStep {
            step: add_member(L1, PR1, GUARDIAN, GUARDIAN_BINDING, true),
            at: T0,
        });
        if target == StateTag::Draft {
            return Ok(out);
        }
        out.push(PathStep {
            step: submit(L1, PR1, plan_of(PR1), false),
            at: T0,
        });
        if target == StateTag::Submitted {
            return Ok(out);
        }
        let mut eval = Vec::new();
        for r in &s.reviewers {
            eval.extend(assign_declared(*r, PR1, call(1), AssignmentKind::Reviewer));
        }
        eval.push(declare(
            COORDINATOR,
            DeclarationSubject::Proposal(PR1),
            false,
            false,
        ));
        eval.push(knock_out(PR1, true));
        eval.push(admit(PR1));
        if target != StateTag::Stage1 {
            for (r, v) in s.reviewers.iter().zip(&s.start_scores) {
                let key = ScoreKey {
                    assignment: assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer),
                    stage: Stage::One,
                    plan: plan_of(PR1),
                };
                eval.push(score(*r, key, v));
            }
            eval.push(close(Actor::Account(COORDINATOR), PR1));
        }
        if !matches!(target, StateTag::Stage1 | StateTag::Stage2) {
            for r in &s.reviewers {
                let id = assignment_of(*r, PR1, call(1), AssignmentKind::Reviewer);
                eval.push(no_questions(*r, PR1, id));
            }
        }
        if !matches!(
            target,
            StateTag::Stage1 | StateTag::Stage2 | StateTag::Ranked
        ) {
            eval.extend(cut_off(
                R1,
                cut_off_decision(1),
                call(1),
                vec![PR1],
                1,
                false,
                ballots(&[R1, R2, R3], Vote::For),
            ));
            for i in [IRC, IRC2] {
                eval.extend(assign_declared(i, PR1, call(1), AssignmentKind::Irc));
            }
        }
        if target == StateTag::Negotiation {
            for i in [IRC, IRC2] {
                let a = assignment_of(i, PR1, call(1), AssignmentKind::Irc);
                eval.push(irc_review(i, a, true));
            }
        }
        if !STATES.contains(&target) {
            return Err(format!("no path to {target:?}"));
        }
        out.extend(at(eval, T_EVAL));
        Ok(out)
    }

    /// A change the driver seam makes at one step of a path, so that the
    /// M2 engine refuses some inputs and the seam compares refusals
    /// (design sections 5.2 and 14.6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Mutation {
        /// The step as it is.
        Keep,
        /// The step, then the same step again: a repeated command.
        Repeat,
        /// The step first issued by an account with no role and no flags,
        /// then as it is: a wrong actor. A system step is kept.
        Stranger,
    }

    impl Mutation {
        /// Every mutation.
        pub const ALL: [Mutation; 3] = [Mutation::Keep, Mutation::Repeat, Mutation::Stranger];
    }

    /// `path` with `plan[i]` applied at step `i`. Steps past the end of
    /// `plan` are kept.
    pub fn mutated(path: &[PathStep], plan: &[Mutation]) -> Vec<PathStep> {
        let mut out = Vec::new();
        for (i, p) in path.iter().enumerate() {
            match plan.get(i).copied().unwrap_or(Mutation::Keep) {
                Mutation::Keep => {}
                Mutation::Repeat => out.push(p.clone()),
                Mutation::Stranger => {
                    if let Actor::Account(_) = p.step.actor {
                        out.push(PathStep {
                            step: Step {
                                actor: Actor::Account(STRANGER),
                                flags: Flags::NONE,
                                cmd: p.step.cmd.clone(),
                            },
                            at: p.at,
                        });
                    }
                }
            }
            out.push(p.clone());
        }
        out
    }

    /// Replays `path` through the M2 domain over `truth` and returns the
    /// state of PR1 after it.
    ///
    /// # Errors
    ///
    /// The first step the domain or the references refuse.
    pub fn check_with_domain(
        path: &[PathStep],
        truth: GroundTruth,
    ) -> Result<Option<StateTag>, String> {
        let mut w = LifeWorld::new(Backend::Production, truth);
        for p in path {
            w.set_now(p.at);
            w = w.must(&p.step)?;
        }
        Ok(w.life.state_of(PR1))
    }
}

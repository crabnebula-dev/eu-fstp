//! `DriverCore`, the sans-IO state machine that runs one admitted command
//! (design section 5.2, NOTE 2 to NOTE 5, I-23).
//!
//! It follows `fstp_engine::Engine::execute` step for step and adds the
//! acknowledgement of NOTE 4. The M2 `Engine` stays its reference oracle.
//!
//! # Steps
//!
//! 1. Refuse a caller command id with the reserved prefix `fstp:vc:`,
//!    before anything is read, asked or appended. Refuse an account
//!    command under the system task prefix `fstp:st:`, and a system task
//!    command under any other id ([`crate::state::SYSTEM_PREFIX`]).
//! 2. Catch up: [`Need::ReadFrom`] asks for every entry after the state's
//!    head. The entries are folded on a copy, so a read the fold refuses
//!    leaves the state unchanged and ends the command. When the ledger
//!    already holds an entry under the caller's command id, the command
//!    committed before: a crash retry finishes with that stored result and
//!    decides nothing again (ADR-007). [`Done::duplicate`] names the
//!    stored entry, so a caller tells a retry from a fresh commit.
//! 3. Ask the vault epoch. A fault fails the command closed (NOTE 2).
//!    When the ledger holds a committed reaction to the reported epoch,
//!    acknowledge it again, once per run (restart rule; acknowledgements
//!    are idempotent), then start again from step 2. A finding command
//!    without vault questions skips this step and the next, since
//!    `fstp_engine::Engine` never reads the vault for one.
//! 4. When the vault is ahead of the state's epoch, process the change
//!    first (NOTE 3). Ask `ChangedSince` with `reaction_for` set and
//!    decide `VaultChanged` as the M2 engine does. Append it under its
//!    reserved id, keyed by the cell (I-20), and acknowledge it with its
//!    sequence and link (NOTE 4).
//!    Then start again from step 2.
//! 5. Ask the command's queries once. A fault fails closed. An answer at
//!    a newer epoch starts again from step 2, so the change is processed
//!    first.
//! 6. Decide, fold the batch on a copy, and append it with the expected
//!    head. A stale head starts again from step 2, up to
//!    [`fstp_engine::MAX_ATTEMPTS`] attempts. A duplicate command id is
//!    the stored result.
//!
//! A committed batch is folded into the state from the batch the driver
//! handed over, so the state equals the replay of the store after every
//! committed append.
//!
//! Readings, as `fstp_engine::Engine` and lane W1c's reference driver
//! take them:
//! - A finding command never runs a reaction, so it never appends a core
//!   record (I-10). When it has queries and the vault is ahead, it is
//!   refused with `StaleFacts`. Without queries it never reads the vault.
//! - A duplicate command id, met at the append or found in the catch-up,
//!   finishes with the head the driver caught up to, as lane W1c's
//!   reference driver does. It sets [`Done::duplicate`], as M2 returns
//!   `Duplicate { at }`, so it is never mistaken for a fresh commit.
//! - A step-up's freshness is checked at admission. The append carries
//!   its last valid instant in [`SideEffects::stepup_fresh_until`], so the
//!   store refuses a commit after it (design section 8.4).
//! - An event that fits no need ends the command with
//!   [`ExecError::Protocol`].
//! - A re-acknowledgement after a restart names link zero. `Event::Read`
//!   carries no chain links, so the shell fills in the stored link of the
//!   named sequence.

use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_ledger::{AppendError, Entry, Seq, StoreError};

use crate::decide::Who;
use crate::gate::{Action, Admitted};
use crate::state::{self, reaction_command_id};
use crate::{CellCommand, CellRecord, CellRefusal, CellState, FoldError};

/// A chain link, SHA-256.
pub type Link = [u8; 32];

/// The insert-only side effects of an append (design section 5.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SideEffects {
    /// A consumed step-up id.
    pub stepup_consumed: Option<[u8; 16]>,
    /// The last UTC microsecond at which the batch may commit under its
    /// step-up: `asserted_at + P-71` (design section 8.4, ADR-008). The
    /// store checks it against its commit instant, so freshness is checked
    /// again at commit.
    pub stepup_fresh_until: Option<i64>,
    /// Ended sessions.
    pub sessions_ended: Vec<[u8; 16]>,
    /// The bodies of the messages the batch's `EventFired` records list,
    /// in their order (M6 design section 3.1).
    pub outbox: Vec<crate::timeline::MessageBody>,
}

/// What the driver needs from the shell.
#[derive(Clone, Debug)]
pub enum Need {
    /// Every ledger entry after this sequence.
    ReadFrom(Seq),
    /// The vault epoch.
    Epoch,
    /// Answers to queries.
    Ask {
        /// The queries.
        queries: Vec<Query>,
        /// The epoch of a reaction, if this asks for one.
        reaction_for: Option<VaultEpoch>,
    },
    /// An append.
    Append {
        /// The expected head.
        expected: Seq,
        /// UTC microseconds.
        at: i64,
        /// The command id.
        command: [u8; 16],
        /// The records.
        batch: Vec<CellRecord>,
        /// The side effects.
        side: SideEffects,
    },
    /// An acknowledgement to the vault.
    Ack {
        /// The epoch.
        epoch: VaultEpoch,
        /// The ledger sequence of the reaction: the last entry of its
        /// batch.
        seq: Seq,
        /// Its chain link, or zero for a re-acknowledgement.
        link: Link,
    },
}

/// Why the vault did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultFault {
    /// The vault is unavailable.
    Unavailable,
    /// The vault refused.
    Refused,
}

/// What the shell reports back.
#[derive(Clone, Debug)]
pub enum Event {
    /// Ledger entries.
    Read(Vec<Entry<CellRecord>>),
    /// The vault epoch.
    Epoch(Result<VaultEpoch, VaultFault>),
    /// Answers.
    Answers(Result<Answers, VaultFault>),
    /// The append result: the new head and the link of the last entry.
    Appended(Result<(Seq, Link), AppendError>),
    /// The acknowledgement result.
    Acked(Result<(), VaultFault>),
}

/// A reference to the witness receipt of a committed append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptRef {
    /// The witness sequence.
    pub witness_seq: u64,
}

/// A finished command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    /// The ledger head after the command.
    pub head: Seq,
    /// The witness receipt of the append. `Event::Appended` does not carry
    /// it, so the driver leaves it to the shell, which holds the receipt
    /// of every committed append (design section 7.2).
    pub receipt: Option<ReceiptRef>,
    /// The sequence of the entry stored earlier under the command id,
    /// when the run found one and appended nothing. `None` for a commit
    /// of this run.
    pub duplicate: Option<Seq>,
}

/// Why a command did not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// The command id carries the reserved prefix `fstp:vc:`, or an
    /// account command's id carries the system task prefix `fstp:st:`.
    ReservedCommandId,
    /// A system task's command id lacks the system task prefix
    /// `fstp:st:` ([`crate::state::SYSTEM_PREFIX`]).
    NotASystemCommandId,
    /// The command was admitted without the caller's command id, so a
    /// retry could not be told from a new command ([`DriverCore::start`]).
    NoCommandId,
    /// The vault failed, so the command fails closed (NOTE 2).
    VaultFault,
    /// The command, or the reaction processed before it, was refused.
    Refused(CellRefusal),
    /// The admitted action is a read, not a command.
    NotACommand,
    /// The caller's command id differs from the one the gate checked the
    /// step-up digest under.
    CommandIdMismatch,
    /// The id of the reaction to this epoch is held by an entry that did
    /// not process it.
    CommandIdTaken {
        /// The epoch.
        epoch: VaultEpoch,
    },
    /// Other writers moved the head on every attempt.
    Contended,
    /// The store failed or refused the batch.
    Store(StoreError),
    /// The store holds a log the fold refuses, or the shell reported an
    /// append the batch does not fit (I-23).
    Fold(FoldError),
    /// The decided batch does not fold, so it was never appended.
    Unfoldable(FoldError),
    /// An event that fits no need, or a step after the end.
    Protocol,
    /// The command needs a record the sources do not define yet. It names
    /// what is missing.
    NotImplemented(&'static str),
}

/// One step of the driver.
#[derive(Clone, Debug)]
pub enum Step {
    /// The driver needs something from the shell.
    Need(Need),
    /// The command finished.
    Done(Result<Done, ExecError>),
}

/// What a pending append is for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pending {
    /// The reaction to this epoch.
    Reaction(VaultEpoch),
    /// The caller's command.
    Command,
}

/// The phase of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Start,
    CatchUp,
    Epoch,
    ReAck(VaultEpoch),
    ReactChanged(VaultEpoch),
    ReactQueries {
        cmd: Box<fstp_engine::Command>,
        target: VaultEpoch,
        queries: Vec<Query>,
        known: (Query, fstp_domain::oracle::Answer),
    },
    Ask(Vec<Query>),
    Append {
        expected: Seq,
        batch: Vec<CellRecord>,
        command: [u8; 16],
        at: Timestamp,
        pending: Pending,
    },
    ReactAck(VaultEpoch),
    Finished(Result<Done, ExecError>),
}

/// What one run saw of the vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Progress {
    /// The epoch of the reaction processed in this run, if any.
    processed: Option<VaultEpoch>,
    /// The newest epoch an answer carried in this run, if any.
    answered: Option<VaultEpoch>,
    /// The epoch of a reaction whose append met a duplicate id.
    duplicate: Option<VaultEpoch>,
}

impl Progress {
    fn saw(&mut self, epoch: VaultEpoch) {
        if self.answered.is_none_or(|a| epoch > a) {
            self.answered = Some(epoch);
        }
    }
}

/// The sans-IO driver of one admitted command.
#[derive(Clone, Debug)]
pub struct DriverCore {
    admitted: Admitted,
    command: [u8; 16],
    phase: Phase,
    attempts: usize,
    progress: Progress,
    reacked: bool,
    cell: [u8; 16],
}

/// The refusal of a command whose vault questions went unanswered (NOTE 2).
fn oracle_down() -> ExecError {
    ExecError::Refused(CellRefusal::Domain(Refusal::new(
        RuleRef::OracleDown,
        RefusalReason::OracleUnavailable,
    )))
}

/// The refusal of a command whose answers are older than required (NOTE 3).
fn stale_facts() -> ExecError {
    ExecError::Refused(CellRefusal::Domain(Refusal::new(
        RuleRef::StaleFacts,
        RefusalReason::AnswerStale,
    )))
}

impl DriverCore {
    /// Starts the driver for an admitted command, under the command id the
    /// gate admitted it with ([`crate::gate::admit_command`],
    /// [`crate::gate::admit_system`]). A command admitted without one
    /// finishes with [`ExecError::NoCommandId`] before it reads anything:
    /// only the caller's id lets the store report a retry as a duplicate
    /// (I-23, ADR-007).
    pub fn start(admitted: Admitted) -> DriverCore {
        let command = admitted.command_id();
        let mut d = DriverCore::start_with_id(admitted, command.unwrap_or([0; 16]));
        if command.is_none() {
            d.phase = Phase::Finished(Err(ExecError::NoCommandId));
        }
        d
    }

    /// Starts the driver for an admitted command under the caller's
    /// command id (design section 5.2). A retry after a crash passes the
    /// same id, so the store reports the earlier append as a duplicate.
    pub fn start_with_id(admitted: Admitted, command: [u8; 16]) -> DriverCore {
        DriverCore {
            admitted,
            command,
            phase: Phase::Start,
            attempts: 0,
            progress: Progress::default(),
            reacked: false,
            cell: [0; 16],
        }
    }

    /// The driver in the cell `cell`: its reactions are appended under
    /// ids keyed by `cell` ([`state::reaction_command_id`], I-20, Daniel's
    /// decision of 2026-11-13). A driver started without a cell keys them
    /// by the all-zero id. The engine of a serving cell always names its
    /// own cell.
    #[must_use]
    pub fn in_cell(mut self, cell: [u8; 16]) -> DriverCore {
        self.cell = cell;
        self
    }

    /// The cell the driver keys its reaction ids by.
    pub fn cell(&self) -> [u8; 16] {
        self.cell
    }

    /// The admitted command.
    pub fn admitted(&self) -> &Admitted {
        &self.admitted
    }

    /// The command id the run appends under.
    pub fn command_id(&self) -> [u8; 16] {
        self.command
    }

    /// Advances the driver with the shell's last event.
    pub fn step(&mut self, state: &mut CellState, ev: Option<Event>) -> Step {
        let phase = core::mem::replace(&mut self.phase, Phase::Finished(Err(ExecError::Protocol)));
        let next = self.advance(phase, state, ev);
        match next {
            Ok(step) => step,
            Err(e) => self.finish(Err(e)),
        }
    }

    fn finish(&mut self, r: Result<Done, ExecError>) -> Step {
        self.phase = Phase::Finished(r.clone());
        Step::Done(r)
    }

    fn need(&mut self, phase: Phase, n: Need) -> Result<Step, ExecError> {
        self.phase = phase;
        Ok(Step::Need(n))
    }

    fn catch_up(&mut self, state: &CellState) -> Result<Step, ExecError> {
        self.need(Phase::CatchUp, Need::ReadFrom(state.head()))
    }

    /// Starts again from the catch-up, using one attempt.
    fn again(&mut self, state: &CellState) -> Result<Step, ExecError> {
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts >= fstp_engine::MAX_ATTEMPTS {
            return Err(ExecError::Contended);
        }
        self.catch_up(state)
    }

    fn advance(
        &mut self,
        phase: Phase,
        state: &mut CellState,
        ev: Option<Event>,
    ) -> Result<Step, ExecError> {
        match (phase, ev) {
            (Phase::Start, None) => {
                if state::is_reaction_command_id(self.command) {
                    return Err(ExecError::ReservedCommandId);
                }
                let system = matches!(self.admitted.principal(), crate::gate::Principal::System(_));
                match (system, state::is_system_command_id(self.command)) {
                    (false, true) => return Err(ExecError::ReservedCommandId),
                    (true, false) => return Err(ExecError::NotASystemCommandId),
                    _ => {}
                }
                if !matches!(self.admitted.action(), Action::Command(_)) {
                    return Err(ExecError::NotACommand);
                }
                if self
                    .admitted
                    .command_id()
                    .is_some_and(|id| id != self.command)
                {
                    return Err(ExecError::CommandIdMismatch);
                }
                self.catch_up(state)
            }
            (Phase::CatchUp, Some(Event::Read(entries))) => {
                let mut next = state.clone();
                for e in &entries {
                    crate::apply(&mut next, e).map_err(ExecError::Fold)?;
                }
                *state = next;
                if let Some(target) = self.progress.duplicate.take() {
                    // Another driver may have processed this epoch.
                    if state.engine().epoch() < target {
                        return Err(ExecError::CommandIdTaken { epoch: target });
                    }
                    self.progress.processed = Some(target);
                }
                if let Some(at) = state.committed(self.command) {
                    // A crash retry: the command committed before, so its
                    // stored result stands and nothing is decided again
                    // (ADR-007, design section 5.2).
                    return Ok(self.finish(Ok(Done {
                        head: state.head(),
                        receipt: None,
                        duplicate: Some(at),
                    })));
                }
                if self.is_finding() {
                    // `fstp_engine::Engine::execute_finding`: a finding
                    // command without questions never reads the vault.
                    let queries = self.queries(state)?;
                    if queries.is_empty() {
                        return self.decide_command(state, &Answers::new());
                    }
                }
                self.need(Phase::Epoch, Need::Epoch)
            }
            (Phase::Epoch, Some(Event::Epoch(r))) => {
                let reported = r.map_err(|_| ExecError::VaultFault)?;
                self.after_epoch(state, reported)
            }
            (Phase::ReAck(_), Some(Event::Acked(r))) => {
                r.map_err(|_| ExecError::VaultFault)?;
                self.catch_up(state)
            }
            (Phase::ReactChanged(target), Some(Event::Answers(r))) => {
                let answers = r.map_err(|_| ExecError::VaultFault)?;
                self.after_changed(state, target, &answers)
            }
            (
                Phase::ReactQueries {
                    cmd,
                    target,
                    queries,
                    known,
                },
                Some(Event::Answers(r)),
            ) => {
                let mut answers = r.map_err(|_| ExecError::VaultFault)?;
                answers.insert(known.0, known.1);
                self.decide_reaction(state, *cmd, target, &queries, &answers)
            }
            (Phase::Ask(queries), Some(Event::Answers(r))) => {
                let answers = r.map_err(|_| ExecError::VaultFault)?;
                self.after_answers(state, &queries, &answers)
            }
            (
                Phase::Append {
                    expected,
                    batch,
                    command,
                    at,
                    pending,
                },
                Some(Event::Appended(r)),
            ) => self.after_append(state, expected, batch, command, at, pending, r),
            (Phase::ReactAck(_), Some(Event::Acked(r))) => {
                r.map_err(|_| ExecError::VaultFault)?;
                self.again(state)
            }
            (Phase::Finished(r), _) => {
                self.phase = Phase::Finished(r.clone());
                Ok(Step::Done(r))
            }
            _ => Err(ExecError::Protocol),
        }
    }

    /// The command, which the start checked is one.
    fn cell_command(&self) -> Result<&CellCommand, ExecError> {
        match self.admitted.action() {
            Action::Command(c) => Ok(c),
            Action::Read(_) => Err(ExecError::NotACommand),
        }
    }

    fn is_finding(&self) -> bool {
        matches!(
            self.admitted.action(),
            Action::Command(CellCommand::Engine(fstp_engine::Command::Finding(_)))
        )
    }

    /// Who issues the command.
    fn who(&self) -> Result<Who, ExecError> {
        match self.admitted.principal() {
            crate::gate::Principal::Account(actor) => Ok(Who::Account(actor)),
            crate::gate::Principal::System(task) => Ok(Who::System(task)),
            // A public or ceremony step acts for the account it names, which
            // its route admission checked (`gate::admit_recovery_request`).
            // No admission builds one for a completion yet
            // (`gate::ROUTE_ADMISSION_SEAM`).
            crate::gate::Principal::Ceremony(account) => Ok(Who::Account(account)),
            crate::gate::Principal::BreakGlass(_) => Err(ExecError::NotACommand),
        }
    }

    /// The command's vault queries on `state`.
    fn queries(&self, state: &CellState) -> Result<Vec<Query>, ExecError> {
        crate::decide::queries_with_inputs(
            state,
            self.cell_command()?,
            self.who()?,
            self.admitted.at().micros(),
            Some(self.command),
            self.admitted.inputs(),
        )
        .map_err(ExecError::Refused)
    }

    fn after_epoch(&mut self, state: &CellState, reported: VaultEpoch) -> Result<Step, ExecError> {
        if !self.reacked
            && let Some(seq) = state.reaction_to(self.cell, reported.raw())
        {
            self.reacked = true;
            return self.need(
                Phase::ReAck(reported),
                Need::Ack {
                    epoch: reported,
                    seq,
                    link: [0; 32],
                },
            );
        }
        // An answer at a newer epoch is the vault reporting that epoch
        // (NOTE 3), even when the epoch reading lags behind it.
        let vault = match self.progress.answered {
            Some(a) if a > reported => a,
            _ => reported,
        };
        let ours = state.engine().epoch();
        if vault > ours && !self.is_finding() {
            if self.progress.processed.is_some_and(|p| p >= vault) {
                // The change was processed, yet the state's epoch did not move.
                return Err(stale_facts());
            }
            return self.need(
                Phase::ReactChanged(vault),
                Need::Ask {
                    queries: vec![Query::ChangedSince { epoch: ours }],
                    reaction_for: Some(vault),
                },
            );
        }
        let queries = self.queries(state)?;
        if queries.is_empty() {
            return self.decide_command(state, &Answers::new());
        }
        if vault > ours {
            // A finding command with questions while the vault is ahead.
            return Err(stale_facts());
        }
        self.need(
            Phase::Ask(queries.clone()),
            Need::Ask {
                queries,
                reaction_for: None,
            },
        )
    }

    fn after_changed(
        &mut self,
        state: &CellState,
        vault: VaultEpoch,
        answers: &Answers,
    ) -> Result<Step, ExecError> {
        let ours = state.engine().epoch();
        let answer = answers
            .get(&Query::ChangedSince { epoch: ours })
            .ok_or_else(oracle_down)?;
        if answer.epoch < vault {
            // The vault answered at an epoch older than the one it reported.
            return Err(stale_facts());
        }
        // Design 4.1 sets the list on every `ChangedSince` answer. Without
        // it the vault did not say which accounts changed, so fail closed.
        let changed = answer.accounts.clone().ok_or_else(oracle_down)?;
        let target = answer.epoch;
        self.progress.saw(target);
        let cmd = crate::vault_changed(target, changed);
        // The reaction's own questions include the change query, which the
        // vault just answered at the target epoch. Only the others are
        // asked, with `reaction_for` set, so they see the provisional fact.
        let changed_q = Query::ChangedSince { epoch: ours };
        let known = (changed_q.clone(), answer.clone());
        let rest: Vec<Query> = crate::reaction_queries(state, &cmd, self.admitted.at())
            .map_err(ExecError::Refused)?
            .into_iter()
            .filter(|q| *q != changed_q)
            .collect();
        if rest.is_empty() {
            let mut answers = Answers::new();
            answers.insert(known.0, known.1);
            return self.decide_reaction(state, cmd, target, &[], &answers);
        }
        self.need(
            Phase::ReactQueries {
                cmd: Box::new(cmd),
                target,
                queries: rest.clone(),
                known,
            },
            Need::Ask {
                queries: rest,
                reaction_for: Some(target),
            },
        )
    }

    fn decide_reaction(
        &mut self,
        state: &CellState,
        cmd: fstp_engine::Command,
        target: VaultEpoch,
        queries: &[Query],
        answers: &Answers,
    ) -> Result<Step, ExecError> {
        for q in queries {
            let a = answers.get(q).ok_or_else(oracle_down)?;
            if a.epoch > target {
                // The vault moved during the questions (NOTE 3).
                self.progress.saw(a.epoch);
                return self.again(state);
            }
        }
        // The admitted command's session rows, if its route read them: a
        // suspension or a voiding in the reaction then ends the sessions
        // of its account in the same batch (design section 5.1).
        let batch = crate::decide_reaction_with_inputs(
            state,
            &cmd,
            self.admitted.at(),
            self.admitted.inputs(),
            answers,
        )
        .map_err(ExecError::Refused)?;
        // The store writes one `auth_log.session_end` row per ended
        // session, so the side effects name them as a command's do.
        let side = SideEffects {
            sessions_ended: batch
                .iter()
                .filter_map(|r| match r {
                    CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }) => {
                        Some(*session)
                    }
                    _ => None,
                })
                .collect(),
            ..SideEffects::default()
        };
        self.append(
            state,
            batch,
            reaction_command_id(self.cell, target.raw()),
            Pending::Reaction(target),
            side,
        )
    }

    fn after_answers(
        &mut self,
        state: &CellState,
        queries: &[Query],
        answers: &Answers,
    ) -> Result<Step, ExecError> {
        let expected = state.engine().epoch();
        for q in queries {
            let a = answers.get(q).ok_or_else(oracle_down)?;
            if a.epoch > expected {
                // The vault moved during the questions (NOTE 3).
                self.progress.saw(a.epoch);
                if self.is_finding() {
                    return Err(stale_facts());
                }
                return self.again(state);
            }
        }
        self.decide_command(state, answers)
    }

    fn decide_command(&mut self, state: &CellState, answers: &Answers) -> Result<Step, ExecError> {
        let c = self.cell_command()?;
        let stepup = self.admitted.stepup();
        let mut batch = crate::decide::decide_with(
            state,
            c,
            self.who()?,
            self.admitted.at().micros(),
            Some(self.command),
            stepup.map(|u| u.asserted_at),
            self.admitted.inputs(),
            answers,
        )
        .map_err(ExecError::Refused)?;
        let mut side = SideEffects::default();
        if let Some(u) = stepup {
            // The batch carries `StepUpConsumed { id }`, so replay checks
            // single use by structure (design section 5.1).
            batch.push(CellRecord::Auth(fstp_auth::AuthRecord::StepUpConsumed {
                id: u.id,
            }));
            side.stepup_consumed = Some(u.id);
            // An overflow leaves no valid instant, so the commit fails.
            side.stepup_fresh_until = Some(u.fresh_until().unwrap_or(i64::MIN));
        }
        side.sessions_ended = batch
            .iter()
            .filter_map(|r| match r {
                CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }) => Some(*session),
                _ => None,
            })
            .collect();
        // M6 design section 4 step 2: a firing carries the bodies of the
        // outbox rows its `EventFired` lists. The decider checked them.
        if matches!(
            c,
            CellCommand::Timeline(crate::timeline::TimelineCommand::Fire { .. })
        ) {
            side.outbox = self
                .admitted
                .inputs()
                .outbox()
                .map(<[_]>::to_vec)
                .unwrap_or_default();
        }
        self.append(state, batch, self.command, Pending::Command, side)
    }

    /// Folds `batch` on a copy and asks for its append with the expected
    /// head. A batch the fold refuses is never appended.
    fn append(
        &mut self,
        state: &CellState,
        batch: Vec<CellRecord>,
        command: [u8; 16],
        pending: Pending,
        side: SideEffects,
    ) -> Result<Step, ExecError> {
        let at = self.admitted.at();
        let expected = state.head();
        let mut next = state.clone();
        fold_batch(&mut next, at, command, &batch).map_err(ExecError::Unfoldable)?;
        self.need(
            Phase::Append {
                expected,
                batch: batch.clone(),
                command,
                at,
                pending,
            },
            Need::Append {
                expected,
                at: at.micros(),
                command,
                batch,
                side,
            },
        )
    }

    /// Holds the saved values of an account's engine command whose batch
    /// was just folded from `before` into `after` (`crate::creator`).
    fn hold_appended(
        &self,
        before: &CellState,
        after: &mut CellState,
        at: Timestamp,
        batch: &[CellRecord],
    ) {
        let (Ok(CellCommand::Engine(cmd)), Ok(Who::Account(actor))) =
            (self.cell_command(), self.who())
        else {
            return;
        };
        let ctx = crate::decide::account_engine_ctx(before, actor, cmd, at, Some(self.command));
        crate::creator::hold_appended(before, after, cmd, &ctx, batch);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the parts of the pending append and its result"
    )]
    fn after_append(
        &mut self,
        state: &mut CellState,
        expected: Seq,
        batch: Vec<CellRecord>,
        command: [u8; 16],
        at: Timestamp,
        pending: Pending,
        r: Result<(Seq, Link), AppendError>,
    ) -> Result<Step, ExecError> {
        match r {
            Ok((head, link)) => {
                let n = u64::try_from(batch.len()).map_err(|_| ExecError::Protocol)?;
                if expected.raw().checked_add(n) != Some(head.raw()) || state.head() != expected {
                    return Err(ExecError::Fold(FoldError::Engine(
                        fstp_domain::FoldError::OutOfOrder,
                    )));
                }
                let mut next = state.clone();
                fold_batch(&mut next, at, command, &batch).map_err(ExecError::Fold)?;
                if matches!(pending, Pending::Command) {
                    self.hold_appended(state, &mut next, at, &batch);
                }
                *state = next;
                match pending {
                    Pending::Command => Ok(self.finish(Ok(Done {
                        head,
                        receipt: None,
                        duplicate: None,
                    }))),
                    Pending::Reaction(target) => {
                        self.progress.processed = Some(target);
                        self.reacked = true;
                        self.need(
                            Phase::ReactAck(target),
                            Need::Ack {
                                epoch: target,
                                seq: head,
                                link,
                            },
                        )
                    }
                }
            }
            Err(AppendError::StaleHead { .. }) => self.again(state),
            Err(AppendError::DuplicateCommand { at }) => match pending {
                // The command was applied earlier: its stored result.
                Pending::Command => Ok(self.finish(Ok(Done {
                    head: state.head(),
                    receipt: None,
                    duplicate: Some(at),
                }))),
                Pending::Reaction(target) => {
                    self.progress.duplicate = Some(target);
                    self.again(state)
                }
            },
            Err(AppendError::Store(e)) => Err(ExecError::Store(e)),
        }
    }
}

/// Folds `batch` after the state's head, at `at`, under `command`.
fn fold_batch(
    s: &mut CellState,
    at: Timestamp,
    command: [u8; 16],
    batch: &[CellRecord],
) -> Result<(), FoldError> {
    for r in batch {
        let seq = crate::next_seq(s.head())
            .ok_or(FoldError::Engine(fstp_domain::FoldError::OutOfOrder))?;
        state::fold(s, seq, at, command, r)?;
    }
    Ok(())
}

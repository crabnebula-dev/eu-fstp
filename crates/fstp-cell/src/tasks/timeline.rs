//! The timeline: the system commands due at an instant (design sections
//! 5.1 and 8.2, I-23, I-77).
//!
//! At each tick the timeline reads the engine's state and issues, under
//! the system task `Timeline`:
//!
//! 1. `EndSessionsAtBindingEnd { account }` for each account with a
//!    scheduled binding end that is due and not yet recorded. The gate
//!    already refuses those sessions from the end instant on (design
//!    section 5.4 step 2). The record makes the end visible.
//! 2. The M2 System commands that `fstp_domain::due` lists at the tick,
//!    such as `EndScheduledRole`.
//!
//! Each command runs under a system command id bound to its occurrence
//! (I-23, ADR-007):
//!
//! - A session end is bound to its account and end instant. While that
//!   end stays due, every tick issues the same id, so the store reports
//!   a repeat as a duplicate and the end is committed once.
//! - An M2 System command can come due again for the same subject. A
//!   proposal deferred from STAGE2 re-enters STAGE2 in the next call, and
//!   its P-07 window can elapse again (state-machine NOTE 5 and NOTE 8).
//!   So its id is bound to how many earlier occurrences of the same
//!   command the ledger holds: the id of occurrence `k` hashes `k`, and
//!   the timeline issues the first `k` whose id is not committed. A
//!   command `fstp_domain::due` lists is enabled, and its commit disables
//!   it, so occurrence `k` is committed at most once. A restart replays
//!   the same committed ids and derives the same id for the same
//!   occurrence. A retry of an occurrence whose commit the engine has
//!   not folded yet reuses its id, so the store answers it as a
//!   duplicate.

use std::collections::BTreeSet;
use std::time::Duration;

use fstp_cell_core::driver::Done;
use fstp_cell_core::gate::{self, Action, Deny};
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::{CellCommand, CellState, SystemTask, system_command_id};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_rt::ShutdownSignal;
use fstp_rt::future::{Either, race};

use super::Clock;
use crate::engine::{CellEngine, EngineError};

/// The domain label of timeline command ids.
pub const ID_LABEL: &[u8] = b"fstp-timeline-v1";

/// How often the timeline looks for due commands.
pub const TICK: Duration = Duration::from_secs(1);

/// The system command id of occurrence `occurrence` of `cmd`, bound to
/// `instant` for a session end.
pub fn command_id(cmd: &CellCommand, instant: Option<Timestamp>, occurrence: u64) -> [u8; 16] {
    let mut msg = ID_LABEL.to_vec();
    msg.extend_from_slice(&fstp_ledger::Canonical::canonical(cmd));
    if let Some(t) = instant {
        msg.extend_from_slice(&t.micros().to_be_bytes());
    }
    msg.extend_from_slice(&occurrence.to_be_bytes());
    let digest = fstp_crypto::sha256(&msg);
    let mut suffix = [0u8; 8];
    for (d, s) in suffix.iter_mut().zip(digest.iter()) {
        *d = *s;
    }
    system_command_id(suffix)
}

/// The id of the next occurrence of `cmd`: the first occurrence whose id
/// `s` holds no commit under. Every committed occurrence holds one id, so
/// the search ends after at most as many steps as `s` has commits.
pub fn next_occurrence_id(s: &CellState, cmd: &CellCommand) -> [u8; 16] {
    let mut occurrence: u64 = 0;
    loop {
        let id = command_id(cmd, None, occurrence);
        if s.committed(id).is_none() {
            return id;
        }
        match occurrence.checked_add(1) {
            Some(next) => occurrence = next,
            // Unreachable: no ledger holds 2^64 commits. The last id is
            // then committed, so the store answers a duplicate and
            // nothing is committed twice.
            None => return id,
        }
    }
}

/// The commands due at `now`, each with its id, in issue order.
pub fn due_commands(s: &CellState, now: Timestamp) -> Vec<(CellCommand, [u8; 16])> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(AccountId, Timestamp)> = BTreeSet::new();
    for (_, b) in s.engine().core.roster().bindings() {
        let Some(end) = b.scheduled_end else {
            continue;
        };
        if end <= now && s.binding_end_due(b.account, now) && seen.insert((b.account, end)) {
            let cmd = CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account: b.account });
            let id = command_id(&cmd, Some(end), 0);
            out.push((cmd, id));
        }
    }
    for core in fstp_domain::due(&s.engine().core, now) {
        let cmd = CellCommand::Engine(fstp_engine::Command::Core(core));
        let id = next_occurrence_id(s, &cmd);
        out.push((cmd, id));
    }
    out
}

/// What one issued command got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issued {
    /// The gate refused to admit it.
    Denied(Deny),
    /// The engine ran it: a commit, a duplicate, or a refusal.
    Ran(Result<Done, EngineError>),
}

/// One command of a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickItem {
    /// The command.
    pub command: CellCommand,
    /// Its id.
    pub id: [u8; 16],
    /// What it got.
    pub result: Issued,
}

/// Runs one tick at `now`: issues every due command in order.
pub async fn tick(engine: &CellEngine, now: Timestamp) -> Vec<TickItem> {
    let due = due_commands(&engine.state(), now);
    let mut out = Vec::with_capacity(due.len());
    for (command, id) in due {
        let state = engine.state();
        let admitted = gate::admit_system(
            &state,
            Action::Command(command.clone()),
            SystemTask::Timeline,
            id,
            now,
        );
        let result = match admitted {
            Err(d) => Issued::Denied(d),
            Ok(a) => Issued::Ran(engine.execute(a).await),
        };
        out.push(TickItem {
            command,
            id,
            result,
        });
    }
    out
}

/// Runs the timeline every [`TICK`] until `stop` is triggered.
pub async fn run<C: Clock>(clock: &C, engine: &CellEngine, stop: &ShutdownSignal) {
    let step = i64::try_from(TICK.as_micros()).unwrap_or(i64::MAX);
    loop {
        let now = clock.now();
        let _ = tick(engine, Timestamp::from_micros(now)).await;
        let next = now.saturating_add(step);
        match race(stop.notified(), clock.sleep_until(next)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
    }
}

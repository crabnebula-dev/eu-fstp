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
//!    The four sweep kinds are left to step 3.
//! 3. The timeline engine (`fstp_timeline`, M6 design section 4): the plan
//!    that schedules and cancels events, then one entry per due event,
//!    with its `EventFired` record, its outbox rows and its System
//!    command. A firing is bound to its event id, so a repeat is a
//!    duplicate.
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
use fstp_cell_core::timeline::{MessageBody, TimelineCommand};
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

/// Runs one tick at `now`: issues every due command in order, then the
/// timeline step ([`timeline_step`]).
///
/// The four sweep kinds of `fstp_engine::sweep` are left out of the first
/// pass. The timeline fires each in one entry with its `EventFired`
/// record (M6 design section 4, D13), so the cell has one issuer of them.
pub async fn tick(engine: &CellEngine, now: Timestamp) -> Vec<TickItem> {
    let due = due_commands(&engine.state(), now);
    let mut out = Vec::with_capacity(due.len());
    for (command, id) in due {
        if is_sweep(&command) {
            continue;
        }
        let result = issue(engine, command.clone(), id, Vec::new(), now).await;
        out.push(TickItem {
            command,
            id,
            result,
        });
    }
    out.extend(timeline_step(engine, now).await);
    out
}

/// Whether `c` is one of the four sweep kinds.
fn is_sweep(c: &CellCommand) -> bool {
    matches!(
        c,
        CellCommand::Engine(fstp_engine::Command::Core(core))
            if fstp_engine::sweep::kind_of(core).is_some()
    )
}

/// The timeline step of a tick (M6 design section 4): append the plan
/// that brings the scheduled set to the derived set, then fire each due
/// event in its own entry, with the bodies of its outbox rows. A firing
/// that is refused stays scheduled and is tried again at the next tick.
pub async fn timeline_step(engine: &CellEngine, now: Timestamp) -> Vec<TickItem> {
    let mut out = Vec::new();
    let plan = fstp_timeline::plan(&engine.state(), now);
    for chunk in plan.chunks(fstp_timeline::PLAN_CHUNK) {
        let cmd = TimelineCommand::Plan {
            records: chunk.to_vec(),
        };
        let id = fstp_timeline::command_id(&cmd);
        let command = CellCommand::Timeline(cmd);
        let result = issue(engine, command.clone(), id, Vec::new(), now).await;
        out.push(TickItem {
            command,
            id,
            result,
        });
    }
    let state = engine.state();
    for event in fstp_timeline::due_events(state.timeline(), now) {
        let Some(f) = fstp_timeline::firing(&engine.state(), &event, now) else {
            continue;
        };
        let id = fstp_timeline::command_id(&f.command);
        let command = CellCommand::Timeline(f.command);
        let result = issue(engine, command.clone(), id, f.bodies, now).await;
        out.push(TickItem {
            command,
            id,
            result,
        });
    }
    out
}

/// Admits `command` for the timeline task and runs it under `id`, with
/// the outbox bodies of a firing.
async fn issue(
    engine: &CellEngine,
    command: CellCommand,
    id: [u8; 16],
    bodies: Vec<MessageBody>,
    now: Timestamp,
) -> Issued {
    let state = engine.state();
    let admitted = gate::admit_system(
        &state,
        Action::Command(command),
        SystemTask::Timeline,
        id,
        now,
    );
    match admitted {
        Err(d) => Issued::Denied(d),
        Ok(a) if bodies.is_empty() => Issued::Ran(engine.execute(a).await),
        Ok(a) => Issued::Ran(engine.execute(a.with_outbox(bodies)).await),
    }
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

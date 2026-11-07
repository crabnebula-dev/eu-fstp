//! A cell over the synthetic M2 scenarios, driven by the timeline as the
//! cell task drives it: plan, then fire each due event, each through the
//! real decider and fold.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::timeline::{MessageBody, TimelineCommand};
use fstp_cell_core::{CellCommand, CellRecord, CellState, RouteInputs, SystemCtx, SystemTask};
use fstp_domain::oracle::Answers;
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, PR1, plan_of, submit};
use fstp_domain_testkit::r#gen::roster::{Step, T0};
use fstp_domain_testkit::mc::lifecycle_model::lifecycle_config;
use fstp_domain_testkit::scenario::Scenario;
use fstp_ledger::{Entry, Seq};

/// A cell: its ledger, its state and every outbox body it committed.
#[derive(Clone)]
pub(crate) struct Cell {
    pub(crate) entries: Vec<Entry<CellRecord>>,
    pub(crate) state: CellState,
    pub(crate) bodies: Vec<MessageBody>,
    pub(crate) fresh: u64,
}

/// What one command of a tick got.
#[derive(Clone, Debug)]
pub(crate) struct Ran {
    pub(crate) command: CellCommand,
    pub(crate) batch: Vec<CellRecord>,
}

impl Cell {
    /// A cell over an M2 ledger.
    pub(crate) fn from_engine(entries: Vec<Entry<fstp_engine::Record>>) -> Cell {
        let entries: Vec<Entry<CellRecord>> = entries
            .into_iter()
            .map(|e| e.map_record(CellRecord::Engine))
            .collect();
        let state = fstp_cell_core::replay(&entries).unwrap();
        Cell {
            entries,
            state,
            bodies: Vec::new(),
            fresh: 0,
        }
    }

    /// Appends `batch` at `at` under `command`, one entry per record.
    pub(crate) fn append(&mut self, at: i64, command: [u8; 16], batch: Vec<CellRecord>) {
        for record in batch {
            // An entry is built only by a store, so a new one takes the
            // envelope of the first and its own fields.
            let mut e = self.entries[0].clone();
            e.seq = Seq::from_raw(self.state.head().raw() + 1);
            e.at = at;
            e.command = command;
            e.record = record;
            fstp_cell_core::apply(&mut self.state, &e).unwrap();
            self.entries.push(e);
        }
    }

    /// Appends an `OutboxEnqueued` record, as an M2 batch would.
    pub(crate) fn enqueue(&mut self, at: i64, event: OutboxEvent) {
        self.fresh += 1;
        let mut id = [0xA5u8; 16];
        id[8..].copy_from_slice(&self.fresh.to_be_bytes());
        self.append(
            at,
            id,
            vec![CellRecord::Engine(fstp_engine::Record::Core(
                Record::OutboxEnqueued(event),
            ))],
        );
    }

    /// Runs `cmd` as the timeline task at `now` and appends its batch.
    pub(crate) fn run(
        &mut self,
        cmd: TimelineCommand,
        bodies: Vec<MessageBody>,
        now: Timestamp,
    ) -> Result<Ran, String> {
        let id = fstp_timeline::command_id(&cmd);
        let cmd = CellCommand::Timeline(cmd);
        let x = SystemCtx {
            task: SystemTask::Timeline,
            at: now.micros(),
        };
        let inputs = RouteInputs::none().with_outbox(bodies.clone());
        let batch = fstp_cell_core::decide_system_with_inputs(
            &self.state,
            &cmd,
            &x,
            id,
            &inputs,
            &Answers::new(),
        )
        .map_err(|e| format!("{e:?}"))?;
        self.append(now.micros(), id, batch.clone());
        self.bodies.extend(bodies);
        Ok(Ran {
            command: cmd,
            batch,
        })
    }

    /// One tick at `now`: the plan, then every due event.
    pub(crate) fn tick(&mut self, now: Timestamp) -> Result<Vec<Ran>, String> {
        let mut out = Vec::new();
        let plan = fstp_timeline::plan(&self.state, now);
        for chunk in plan.chunks(fstp_timeline::PLAN_CHUNK) {
            let records = chunk.to_vec();
            out.push(self.run(TimelineCommand::Plan { records }, Vec::new(), now)?);
        }
        for event in fstp_timeline::due_events(self.state.timeline(), now) {
            if let Some(f) = fstp_timeline::firing(&self.state, &event, now) {
                out.push(self.run(f.command, f.bodies, now)?);
            }
        }
        Ok(out)
    }

    /// The state the ledger replays to from genesis.
    pub(crate) fn replayed(&self) -> CellState {
        fstp_cell_core::replay(&self.entries).unwrap()
    }
}

fn run_step(scn: &mut Scenario, now: Timestamp, step: &Step) {
    let command = scn.ctx(now, step.actor).command;
    let ctx = step.ctx(now, command);
    if let Err(e) = scn.run_core(&step.cmd, ctx) {
        panic!("{:?} refused: {e:?}", step.cmd.kind());
    }
}

/// The lifecycle world with proposal PR1 of lead L1 submitted at T0.
pub(crate) fn submitted() -> Scenario {
    let setup = lifecycle_config().setup;
    let mut scn = Scenario::new(setup.truth()).unwrap();
    for s in setup.draft_steps().unwrap() {
        run_step(&mut scn, T0, &s);
    }
    run_step(&mut scn, T0, &submit(L1, PR1, plan_of(PR1), false));
    scn
}

/// Runs `step` in `scn` at `now`.
pub(crate) fn step(scn: &mut Scenario, now: Timestamp, step: &Step) {
    run_step(scn, now, step);
}

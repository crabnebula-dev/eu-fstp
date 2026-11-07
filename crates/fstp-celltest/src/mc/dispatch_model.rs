//! M-DISPATCH, T2 of M6 design section 7 (I-25, I-26).
//!
//! Two `fstp_dispatch::Worker`s and one message, over the in-memory
//! delivery log `fstp_dispatch::store::MemDelivery`. The model drives the
//! production worker, one step per action. It explores every interleaving
//! exhaustively, with a crash allowed at every step, a store fault at
//! every write and a sink fault at staging and at the end of DATA, under
//! small budgets. Time moves in ticks of 61 minutes, past every lease and
//! backoff.
//!
//! The property is "at most one end of DATA": the server receives at most
//! one final dot that it did not refuse with a definite reply. A dot
//! answered 4yz or 5yz delivered nothing, and its retry is allowed.
//!
//! [`Variant::Unfenced`] is the teeth: its store passes every commit point
//! without the fence, so a stalled worker sends a second dot.

use fstp_dispatch::store::{CommitFacts, Fault, MemDelivery, Next, Phase, StoreError};
use fstp_dispatch::{
    EndOfData, Envelope, LoadError, Outcome, Prepared, Refused, Source, Step, Store, Transport,
    Worker,
};
use fstp_mc::{Model, Property};

/// Property ids.
pub mod ids {
    /// At most one end of DATA the server did not refuse.
    pub const I26: &str = "I-26";
    /// Every accepted message has its COMMITTING row.
    pub const I25: &str = "I-25";
    /// The message was delivered.
    pub const W_SENT: &str = "W-sent";
    /// The message was recorded IN_DOUBT.
    pub const W_IN_DOUBT: &str = "W-in-doubt";
    /// A stalled worker was fenced at the commit point.
    pub const W_FENCED: &str = "W-fenced";
    /// The message was recorded PERMANENT.
    pub const W_PERMANENT: &str = "W-permanent";
}

/// The message's outbox id.
pub const OUTBOX: [u8; 16] = [7; 16];
/// The first instant.
pub const T0: i64 = 1_794_000_000_000_000;
/// One tick: 61 minutes, past every lease and backoff.
pub const TICK: i64 = 61 * 60 * 1_000_000;

/// Which store the workers run over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variant {
    /// The production rules.
    Production,
    /// Teeth: the commit point passes without the fence.
    Unfenced,
}

/// The budgets of one run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    /// Crashes.
    pub crashes: u8,
    /// Store faults.
    pub store_faults: u8,
    /// Sink faults.
    pub sink_faults: u8,
    /// Ticks.
    pub ticks: u8,
}

/// The default budgets of T2.
pub const BUDGET: Budget = Budget {
    crashes: 2,
    store_faults: 1,
    sink_faults: 1,
    ticks: 3,
};

/// A sink fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SinkFault {
    /// The connection drops while staging.
    DropWhileStaging,
    /// The server answers 451 to the end of DATA.
    Reply451,
    /// The server answers 550 to the end of DATA.
    Reply550,
    /// The server accepts and the reply is lost.
    LostReply,
    /// The connection drops after the dot, before the server accepts.
    DropAfterData,
}

/// An action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Worker `w` runs one step, with an optional store or sink fault.
    Step {
        /// The worker.
        w: u8,
        /// A store fault on its write.
        store: Option<Fault>,
        /// A sink fault.
        sink: Option<SinkFault>,
    },
    /// Worker `w` crashes and restarts from the store.
    Crash {
        /// The worker.
        w: u8,
    },
    /// Time moves one tick.
    Tick,
}

/// A state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DispatchState {
    /// The two workers. The staged session is the worker's index.
    pub workers: [Worker<u8>; 2],
    /// The delivery log.
    pub store: MemDelivery,
    /// Which worker has a staged session at the sink.
    pub staged: [bool; 2],
    /// The ends of DATA the server did not refuse with a definite reply.
    pub ends: u8,
    /// The messages the server accepted.
    pub accepted: u8,
    /// Whether a commit point was refused.
    pub fenced: bool,
    /// Ticks so far.
    pub ticks: u8,
    /// What is left of each budget.
    pub left: Budget,
}

/// M-DISPATCH.
#[derive(Clone, Copy, Debug)]
pub struct DispatchModel {
    /// The store variant.
    pub variant: Variant,
    /// The budgets.
    pub budget: Budget,
}

fn wid(w: u8) -> [u8; 16] {
    [w.wrapping_add(1); 16]
}

fn prepared() -> Prepared {
    Prepared {
        envelope: Envelope {
            from: "noreply@fund.test".to_owned(),
            to: "lead@example.test".to_owned(),
        },
        body: b"Subject: s\r\n\r\nbody\r\n".to_vec(),
        event: [3; 32],
        template_version: 1,
    }
}

struct OneSource;

impl Source for OneSource {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        if outbox == OUTBOX {
            Ok(prepared())
        } else {
            Err(LoadError::Unusable)
        }
    }
}

/// The store of a variant.
struct ModelStore<'a> {
    inner: &'a mut MemDelivery,
    variant: Variant,
}

impl Store for ModelStore<'_> {
    type Fault = StoreError;

    async fn claim(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> Result<Next, StoreError> {
        self.inner.claim(outbox, worker, now)
    }

    async fn commit_point(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> Result<bool, StoreError> {
        let r = self.inner.commit_point(outbox, worker, attempt, facts, now);
        match self.variant {
            Variant::Production => r,
            Variant::Unfenced => Ok(true),
        }
    }

    async fn record(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner
            .record(outbox, worker, attempt, phase, reply_code, now)
    }
}

struct ModelSink<'a> {
    staged: &'a mut [bool; 2],
    ends: &'a mut u8,
    accepted: &'a mut u8,
    w: u8,
    fault: Option<SinkFault>,
}

impl Transport for ModelSink<'_> {
    type Staged = u8;

    async fn stage(&mut self, _e: &Envelope, _body: &[u8]) -> Result<u8, Refused> {
        if self.fault == Some(SinkFault::DropWhileStaging) {
            return Err(Refused::Transient(None));
        }
        if let Some(s) = self.staged.get_mut(usize::from(self.w)) {
            *s = true;
        }
        Ok(self.w)
    }

    async fn end_of_data(&mut self, staged: u8) -> EndOfData {
        let Some(s) = self.staged.get_mut(usize::from(staged)) else {
            return EndOfData::Unknown;
        };
        if !*s {
            return EndOfData::Unknown;
        }
        *s = false;
        match self.fault {
            Some(SinkFault::Reply451) => EndOfData::Reply(451),
            Some(SinkFault::Reply550) => EndOfData::Reply(550),
            Some(SinkFault::DropAfterData) => {
                *self.ends = self.ends.saturating_add(1);
                EndOfData::Unknown
            }
            Some(SinkFault::LostReply) => {
                *self.ends = self.ends.saturating_add(1);
                *self.accepted = self.accepted.saturating_add(1);
                EndOfData::Unknown
            }
            Some(SinkFault::DropWhileStaging) | None => {
                *self.ends = self.ends.saturating_add(1);
                *self.accepted = self.accepted.saturating_add(1);
                EndOfData::Reply(250)
            }
        }
    }

    async fn abandon(&mut self, staged: u8) {
        if let Some(s) = self.staged.get_mut(usize::from(staged)) {
            *s = false;
        }
    }
}

impl DispatchModel {
    /// The model over `variant` with the default budgets.
    pub fn new(variant: Variant) -> DispatchModel {
        DispatchModel {
            variant,
            budget: BUDGET,
        }
    }
}

impl Model for DispatchModel {
    type State = DispatchState;
    type Action = Action;

    fn init(&self) -> Vec<DispatchState> {
        vec![DispatchState {
            workers: [Worker::new(wid(0)), Worker::new(wid(1))],
            store: MemDelivery::new([OUTBOX]),
            staged: [false; 2],
            ends: 0,
            accepted: 0,
            fenced: false,
            ticks: 0,
            left: self.budget,
        }]
    }

    fn actions(&self, s: &DispatchState, out: &mut Vec<Action>) {
        for w in 0..2u8 {
            out.push(Action::Step {
                w,
                store: None,
                sink: None,
            });
            for f in [Fault::Fail, Fault::UnknownApplied, Fault::UnknownLost] {
                out.push(Action::Step {
                    w,
                    store: Some(f),
                    sink: None,
                });
            }
            for f in [
                SinkFault::DropWhileStaging,
                SinkFault::Reply451,
                SinkFault::Reply550,
                SinkFault::LostReply,
                SinkFault::DropAfterData,
            ] {
                out.push(Action::Step {
                    w,
                    store: None,
                    sink: Some(f),
                });
            }
            if s.workers.get(usize::from(w)).is_some_and(|x| !x.is_idle()) {
                out.push(Action::Crash { w });
            }
        }
        out.push(Action::Tick);
    }

    fn step(&self, s: &DispatchState, a: &Action) -> Option<DispatchState> {
        let mut t = s.clone();
        match *a {
            Action::Tick => {
                t.left.ticks = t.left.ticks.checked_sub(1)?;
                t.ticks = t.ticks.saturating_add(1);
            }
            Action::Crash { w } => {
                t.left.crashes = t.left.crashes.checked_sub(1)?;
                *t.workers.get_mut(usize::from(w))? = Worker::new(wid(w));
                *t.staged.get_mut(usize::from(w))? = false;
            }
            Action::Step { w, store, sink } => {
                if t.store.is_settled(&OUTBOX) && t.workers.get(usize::from(w))?.is_idle() {
                    return None;
                }
                let next = t.workers.get(usize::from(w))?.next_step();
                if let Some(f) = store {
                    // A store fault only where the step writes.
                    if !matches!(next, Step::Claim | Step::CommitPoint | Step::Send) {
                        return None;
                    }
                    t.left.store_faults = t.left.store_faults.checked_sub(1)?;
                    t.store.inject(f);
                }
                if let Some(f) = sink {
                    let fits = match f {
                        SinkFault::DropWhileStaging => next == Step::Stage,
                        _ => next == Step::Send,
                    };
                    if !fits {
                        return None;
                    }
                    t.left.sink_faults = t.left.sink_faults.checked_sub(1)?;
                }
                let now = T0.saturating_add(TICK.saturating_mul(i64::from(t.ticks)));
                let DispatchState {
                    workers,
                    store: log,
                    staged,
                    ends,
                    accepted,
                    ..
                } = &mut t;
                let mut st = ModelStore {
                    inner: log,
                    variant: self.variant,
                };
                let mut sinkm = ModelSink {
                    staged,
                    ends,
                    accepted,
                    w,
                    fault: sink,
                };
                let worker = workers.get_mut(usize::from(w))?;
                let out = fstp_rt::future::block_on(worker.step(
                    &mut st,
                    &mut OneSource,
                    &mut sinkm,
                    &[OUTBOX],
                    now,
                ));
                if matches!(out, Outcome::Fenced { .. }) && next == Step::CommitPoint {
                    t.fenced = true;
                }
                // An injected fault the step did not use is dropped, so
                // it never lands on another worker's step.
                if store.is_some() {
                    t.store = without_pending_faults(&t.store);
                }
                if out == Outcome::Idle && t == *s {
                    return None;
                }
            }
        }
        Some(t)
    }

    fn is_terminal(&self, s: &DispatchState) -> bool {
        s.store.is_settled(&OUTBOX)
    }
}

/// `log` with no queued fault.
fn without_pending_faults(log: &MemDelivery) -> MemDelivery {
    let mut out = MemDelivery::new([OUTBOX]);
    for r in log.rows(&OUTBOX) {
        // Rows of `log` met the constraints when they were inserted.
        let _ = out.insert(*r);
    }
    out
}

/// Whether the log holds the COMMITTING row of the message.
fn has_committing(s: &DispatchState) -> bool {
    s.store.rows(&OUTBOX).iter().any(|r| {
        r.phase == Phase::Committing
            && r.commit.is_some_and(|c| {
                c.event == [3; 32]
                    && c.template_version == 1
                    && c.body_digest == fstp_crypto::sha256(&prepared().body)
            })
    })
}

fn head_is(s: &DispatchState, phase: Phase) -> bool {
    s.store.head(&OUTBOX).is_some_and(|h| h.phase == phase)
}

/// Every property of M-DISPATCH.
pub fn properties<'a>() -> Vec<Property<'a, DispatchModel>> {
    vec![
        Property::always_with(ids::I26, |s: &DispatchState| {
            if s.ends <= 1 && s.accepted <= 1 {
                Ok(())
            } else {
                Err(format!(
                    "I-26: {} ends of DATA, {} accepted",
                    s.ends, s.accepted
                ))
            }
        }),
        Property::always_with(ids::I25, |s: &DispatchState| {
            if s.accepted == 0 || has_committing(s) {
                Ok(())
            } else {
                Err("I-25: an accepted message without its COMMITTING row".to_owned())
            }
        }),
        Property::reachable(ids::W_SENT, |s: &DispatchState| head_is(s, Phase::Sent)),
        Property::reachable(ids::W_IN_DOUBT, |s: &DispatchState| {
            head_is(s, Phase::InDoubt)
        }),
        Property::reachable(ids::W_PERMANENT, |s: &DispatchState| {
            head_is(s, Phase::Permanent)
        }),
        Property::reachable(ids::W_FENCED, |s: &DispatchState| s.fenced),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test code")]

    use super::*;
    use crate::mc::tripwires::{M_DISPATCH, tripwire};
    use fstp_mc::{Config, check};

    fn config() -> Config {
        Config::default()
            .with_stop_when_decided(false)
            .with_max_states(tripwire(M_DISPATCH))
    }

    /// I-25, I-26, M6 design section 7 (T2): two workers, one message, a
    /// crash at every step, exhaustive. At most one end of DATA reaches
    /// the server without a definite refusal, and every accepted message
    /// has its COMMITTING row.
    #[test]
    fn i25_i26_m_dispatch_at_most_one_end_of_data() {
        let m = DispatchModel::new(Variant::Production);
        let outcome = check(&m, &properties(), &config());
        eprintln!("M-DISPATCH: {} states", outcome.stats.states);
        assert!(outcome.exhaustive, "M-DISPATCH hit its bound:\n{outcome}");
        if let Err(e) = outcome.require_all_passed() {
            panic!("{e}\n{outcome}");
        }
        assert!(
            outcome.stats.states <= M_DISPATCH,
            "M-DISPATCH grew past its recorded count: {} states",
            outcome.stats.states
        );
    }

    /// I-26 teeth: without the fence at the commit point, a stalled
    /// worker sends a second end of DATA, and the model finds it.
    #[test]
    fn i26_m_dispatch_teeth_unfenced_commit_point_is_caught() {
        let m = DispatchModel::new(Variant::Unfenced);
        let outcome = check(&m, &properties(), &config().with_stop_when_decided(true));
        let failed = outcome
            .verdict(ids::I26)
            .is_some_and(fstp_mc::Verdict::is_failure);
        assert!(
            failed,
            "teeth: the unfenced store went unnoticed\n{outcome}"
        );
    }
}

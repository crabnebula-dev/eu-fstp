//! T1 of M6 design section 7: the I-25 and I-26 property under crash
//! injection, over the in-memory delivery log (lane L6-REC skeleton).
//!
//! A run has 1 to 3 workers, 1 to 20 messages and a random schedule.
//! Faults are drawn per step: a crash at any step, a store write that
//! fails or has an unknown outcome, and sink faults (a dropped connection,
//! 421, 451, 550, a lost final reply). A worker that is not scheduled
//! while time passes stalls past its lease. Crashed workers restart from
//! the store. Checks:
//!
//! - I-26: the sink accepted each idempotency key at most once.
//! - I-25: every accepted message has a COMMITTING row with the same body
//!   digest, event and template version.
//! - Liveness, not an invariant: once faults stop, every message reaches a
//!   terminal phase.
//!
//! Two drivers run the same harness. The reference driver follows the
//! attempt protocol of design section 5.1 step by step, so the store rules
//! are checked now. The dispatcher driver is the seam lane L6-DISP fills
//! with the real worker. Until then its test is red, and the panic names
//! the seam.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use fstp_dispatch::store::{CommitFacts, Fault, MemDelivery, Next, Phase};
use fstp_prop::{Gen, prop_assert};

const T0: i64 = 1_794_000_000_000_000;
const SECOND: i64 = 1_000_000;
const MINUTE: i64 = 60 * SECOND;

/// One message of a run.
#[derive(Clone, Debug)]
struct Msg {
    outbox: [u8; 16],
    idem: [u8; 32],
    event: [u8; 32],
    template_version: u16,
    body: Vec<u8>,
}

/// A sink fault at the end of the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SinkFault {
    /// The connection drops before the end of DATA.
    Drop,
    /// The server answers 421 or 451 to the end of DATA.
    Transient(u16),
    /// The server answers 550 to the end of DATA.
    Permanent,
    /// The server accepted, but the reply was lost.
    LostReply,
    /// The connection drops after the end of DATA was sent, before the
    /// server accepted.
    DropAfterData,
}

/// The submission server: what each worker staged, and what it accepted.
#[derive(Default)]
struct Sink {
    staged: BTreeMap<usize, ([u8; 32], [u8; 32])>,
    accepted: Vec<([u8; 32], [u8; 32])>,
}

impl Sink {
    fn quit(&mut self, w: usize) {
        self.staged.remove(&w);
    }

    /// The end of DATA: the reply, or `None` when it was lost.
    fn end_of_data(&mut self, w: usize, fault: Option<SinkFault>) -> Option<u16> {
        let staged = self.staged.remove(&w)?;
        match fault {
            None => {
                self.accepted.push(staged);
                Some(250)
            }
            Some(SinkFault::LostReply) => {
                self.accepted.push(staged);
                None
            }
            Some(SinkFault::Transient(code)) => Some(code),
            Some(SinkFault::Permanent) => Some(550),
            Some(SinkFault::Drop | SinkFault::DropAfterData) => None,
        }
    }
}

/// Where a reference worker stands in its attempt.
#[derive(Clone, Copy, Debug)]
enum WState {
    Idle,
    Claimed {
        m: usize,
        attempt: u32,
    },
    Rendered {
        m: usize,
        attempt: u32,
        digest: [u8; 32],
    },
    Staged {
        m: usize,
        attempt: u32,
        digest: [u8; 32],
    },
    Committed {
        m: usize,
        attempt: u32,
    },
}

struct World {
    msgs: Vec<Msg>,
    store: MemDelivery,
    sink: Sink,
    now: i64,
    workers: Vec<WState>,
}

/// The faults drawn for one step.
#[derive(Clone, Copy, Debug, Default)]
struct StepFaults {
    crash: bool,
    store: Option<Fault>,
    sink: Option<SinkFault>,
}

fn worker_id(w: usize) -> [u8; 16] {
    [u8::try_from(w).unwrap() + 1; 16]
}

/// One step of the attempt protocol of design section 5.1, as the
/// reference driver runs it.
fn reference_step(world: &mut World, w: usize, f: StepFaults) -> Result<(), String> {
    if f.crash {
        world.workers[w] = WState::Idle;
        world.sink.quit(w);
        return Ok(());
    }
    if let Some(fault) = f.store {
        world.store.inject(fault);
    }
    let id = worker_id(w);
    let now = world.now;
    world.workers[w] = match world.workers[w] {
        WState::Idle => {
            let n = world.msgs.len();
            let pick = (0..n)
                .map(|i| (i + w * 7) % n)
                .find(|i| !world.store.is_settled(&world.msgs[*i].outbox));
            match pick {
                // S1: claim, or recover an ended lease.
                Some(m) => match world.store.claim(world.msgs[m].outbox, id, now) {
                    Ok(Next::Claim { attempt }) => WState::Claimed { m, attempt },
                    _ => WState::Idle,
                },
                None => WState::Idle,
            }
        }
        // S2: render. No write.
        WState::Claimed { m, attempt } => WState::Rendered {
            m,
            attempt,
            digest: fstp_crypto::sha256(&world.msgs[m].body),
        },
        // S3: stage the body without the final dot.
        WState::Rendered { m, attempt, digest } => {
            if f.sink == Some(SinkFault::Drop) {
                let _ = world.store.record(
                    world.msgs[m].outbox,
                    id,
                    attempt,
                    Phase::Transient,
                    None,
                    now,
                );
                WState::Idle
            } else {
                world.sink.staged.insert(w, (world.msgs[m].idem, digest));
                WState::Staged { m, attempt, digest }
            }
        }
        // S4: the commit point. Anything but a known success quits
        // without the final dot.
        WState::Staged { m, attempt, digest } => {
            let msg = &world.msgs[m];
            let facts = CommitFacts {
                event: msg.event,
                template_version: msg.template_version,
                body_digest: digest,
            };
            match world
                .store
                .commit_point(msg.outbox, id, attempt, facts, now)
            {
                Ok(true) => WState::Committed { m, attempt },
                _ => {
                    world.sink.quit(w);
                    WState::Idle
                }
            }
        }
        // S5 and S6: send the final dot, read the reply, record it.
        WState::Committed { m, attempt } => {
            let reply = world.sink.end_of_data(w, f.sink);
            let phase = match reply {
                Some(250) => Some(Phase::Sent),
                Some(c) if (400..500).contains(&c) => Some(Phase::Transient),
                Some(_) => Some(Phase::Permanent),
                // The outcome is unknown: leave the COMMITTING head for
                // recovery, which records IN_DOUBT.
                None => None,
            };
            if let Some(p) = phase {
                let _ = world
                    .store
                    .record(world.msgs[m].outbox, id, attempt, p, reply, now);
            }
            WState::Idle
        }
    };
    Ok(())
}

/// The dispatcher driver: the seam of lane L6-DISP.
fn dispatcher_step(_world: &mut World, _w: usize, _f: StepFaults) -> Result<(), String> {
    Err("seam: the fstp-dispatch worker over MemDelivery and the sink (lane L6-DISP)".to_owned())
}

type Step = fn(&mut World, usize, StepFaults) -> Result<(), String>;

fn draw_faults(g: &mut Gen) -> StepFaults {
    let mut f = StepFaults::default();
    match g.weighted(&[10, 2, 2, 3]) {
        1 => f.crash = true,
        2 => {
            f.store = Some(*g.pick(&[Fault::Fail, Fault::UnknownApplied, Fault::UnknownLost]));
        }
        3 => {
            f.sink = Some(*g.pick(&[
                SinkFault::Drop,
                SinkFault::Transient(421),
                SinkFault::Transient(451),
                SinkFault::Permanent,
                SinkFault::LostReply,
                SinkFault::DropAfterData,
            ]));
        }
        _ => {}
    }
    f
}

fn run_case(g: &mut Gen, step: Step) -> Result<(), String> {
    let n_workers = g.usize_in(1..=3);
    let n_msgs = g.usize_in(1..=20);
    let msgs: Vec<Msg> = (0..n_msgs)
        .map(|i| {
            let b = u8::try_from(i).unwrap();
            Msg {
                outbox: [b; 16],
                idem: fstp_crypto::sha256(&[b, 1]),
                event: fstp_crypto::sha256(&[b / 3, 2]),
                template_version: u16::from(b % 2) + 1,
                body: vec![b; 8],
            }
        })
        .collect();
    let mut world = World {
        store: MemDelivery::new(msgs.iter().map(|m| m.outbox)),
        msgs,
        sink: Sink::default(),
        now: T0,
        workers: vec![WState::Idle; n_workers],
    };
    // The faulty phase: a random schedule with faults and stalls.
    let steps = g.usize_in(0..=150);
    for _ in 0..steps {
        let w = g.usize_in(0..=n_workers - 1);
        world.now += *g.pick(&[0, SECOND, 61 * SECOND, 2 * MINUTE, 31 * MINUTE, 61 * MINUTE]);
        let f = draw_faults(g);
        step(&mut world, w, f)?;
    }
    // The quiet phase: no faults, every lease and backoff ends.
    for _ in 0..400 {
        if world.msgs.iter().all(|m| world.store.is_settled(&m.outbox)) {
            break;
        }
        for w in 0..n_workers {
            for _ in 0..5 {
                step(&mut world, w, StepFaults::default())?;
            }
        }
        world.now += 61 * MINUTE;
    }
    check(&world)
}

fn check(world: &World) -> Result<(), String> {
    // I-26: at most one acceptance per idempotency key.
    let mut seen: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for (idem, _) in &world.sink.accepted {
        *seen.entry(*idem).or_default() += 1;
    }
    for (idem, n) in &seen {
        prop_assert!(*n <= 1, "I-26: idem {idem:02x?} accepted {n} times");
    }
    // I-25: every accepted message traces to its COMMITTING row.
    for (idem, digest) in &world.sink.accepted {
        let msg = world
            .msgs
            .iter()
            .find(|m| m.idem == *idem)
            .ok_or("I-25: the sink accepted an unknown message")?;
        let traced = world.store.rows(&msg.outbox).iter().any(|r| {
            r.phase == Phase::Committing
                && r.commit.is_some_and(|c| {
                    c.body_digest == *digest
                        && c.event == msg.event
                        && c.template_version == msg.template_version
                })
        });
        prop_assert!(
            traced,
            "I-25: an accepted message without its COMMITTING row"
        );
    }
    // Liveness once faults stop.
    for m in &world.msgs {
        prop_assert!(
            world.store.is_settled(&m.outbox),
            "liveness: a message never reached a terminal phase: {:?}",
            world.store.head(&m.outbox)
        );
    }
    Ok(())
}

/// I-25, I-26, M6 design sections 5.1 and 7 (T1): the attempt protocol
/// over the delivery rules accepts each idempotency key at most once and
/// traces every accepted message, under crashes, store faults, sink faults
/// and stalls past the lease.
#[test]
fn i25_i26_reference_protocol_sends_at_most_once_under_crashes() {
    fstp_prop::check(
        "i25_i26_reference_protocol_sends_at_most_once_under_crashes",
        |g: &mut Gen| run_case(g, reference_step),
    );
}

/// I-25, I-26, M6 design section 7 (T1): the same property over the
/// dispatcher's worker. Red until lane L6-DISP lands the worker behind
/// `dispatcher_step`.
#[test]
fn i25_i26_dispatcher_sends_at_most_once_under_crashes() {
    fstp_prop::check(
        "i25_i26_dispatcher_sends_at_most_once_under_crashes",
        |g: &mut Gen| run_case(g, dispatcher_step),
    );
}

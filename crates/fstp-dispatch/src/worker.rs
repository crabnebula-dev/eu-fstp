//! The dispatch worker: the attempt protocol of M6 design section 5.1
//! (I-25, I-26).
//!
//! A [`Worker`] takes one [`Step`] per call of [`Worker::step`], so each
//! step is also a crash point in tests. Its in-memory state is lost in a
//! crash, and a restarted worker starts again from the delivery log.
//!
//! | Step | Action |
//! | --- | --- |
//! | [`Step::Claim`] (S1) | Claim the next attempt under a lease, or record IN_DOUBT or PERMANENT on recovery |
//! | [`Step::Render`] (S2) | Load the stored message and compute its digest. No write |
//! | [`Step::Stage`] (S3) | Run the session up to the body, without the final dot |
//! | [`Step::CommitPoint`] (S4) | Insert COMMITTING while the head is this worker's CLAIMED attempt. Otherwise quit without the dot |
//! | [`Step::Send`] (S5, S6) | Send the final dot, read the reply, record SENT, TRANSIENT or PERMANENT |
//!
//! After the dot, an unknown outcome records nothing. The COMMITTING head
//! stays, and recovery records IN_DOUBT once its lease ends. Such a message
//! is never sent again automatically. The attempt number fences S4, so a
//! stalled worker whose lease was taken over never sends the dot.

use std::future::Future;

use fstp_pgstore::{CommitFacts, DeliveryLog, Next, Phase, StoreFault};
use fstp_rt::Runtime;

use crate::prepare::{Envelope, Prepared};
use crate::store::{MemDelivery, StoreError};

/// A named step of an attempt (M6 design section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// S1: claim or recover.
    Claim,
    /// S2: load and digest the message.
    Render,
    /// S3: stage the body without the final dot.
    Stage,
    /// S4: the commit point.
    CommitPoint,
    /// S5 and S6: the final dot and its record.
    Send,
}

/// The delivery log, as the worker uses it. Each call is one transaction
/// under the message's lock.
pub trait Store {
    /// The store's failure. Its outcome may be unknown.
    type Fault: std::fmt::Debug;

    /// S1 and recovery ([`fstp_pgstore::next_step`]).
    fn claim(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> impl Future<Output = Result<Next, Self::Fault>> + Send;

    /// S4 ([`fstp_pgstore::may_commit`]).
    fn commit_point(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> impl Future<Output = Result<bool, Self::Fault>> + Send;

    /// S6 ([`fstp_pgstore::may_record`]).
    fn record(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> impl Future<Output = Result<bool, Self::Fault>> + Send;
}

impl Store for MemDelivery {
    type Fault = StoreError;

    fn claim(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> impl Future<Output = Result<Next, StoreError>> + Send {
        std::future::ready(MemDelivery::claim(self, outbox, worker, now))
    }

    fn commit_point(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        std::future::ready(MemDelivery::commit_point(
            self, outbox, worker, attempt, facts, now,
        ))
    }

    fn record(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        std::future::ready(MemDelivery::record(
            self, outbox, worker, attempt, phase, reply_code, now,
        ))
    }
}

impl<R: Runtime> Store for DeliveryLog<R> {
    type Fault = StoreFault;

    fn claim(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> impl Future<Output = Result<Next, StoreFault>> + Send {
        DeliveryLog::claim(self, outbox, worker, now)
    }

    fn commit_point(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreFault>> + Send {
        DeliveryLog::commit_point(self, outbox, worker, attempt, facts, now)
    }

    fn record(
        &mut self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreFault>> + Send {
        DeliveryLog::record(self, outbox, worker, attempt, phase, reply_code, now)
    }
}

/// Why a stored message could not be loaded (S2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadError {
    /// Not now, such as a database or keystore fault. Retried.
    Unavailable,
    /// Never: the message does not open or parse. Recorded PERMANENT.
    Unusable,
}

/// Where the worker loads a message from (S2).
pub trait Source {
    /// The message `outbox`, ready to stage.
    fn load(
        &mut self,
        outbox: [u8; 16],
    ) -> impl Future<Output = Result<Prepared, LoadError>> + Send;
}

/// A definite refusal before the final dot (S3). The server accepted
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refused {
    /// A 4yz reply or a transport failure, with the code if any.
    Transient(Option<u16>),
    /// A 5yz reply or a message the server can never take.
    Permanent(Option<u16>),
}

/// The reply to the final dot (S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndOfData {
    /// A complete reply with this code.
    Reply(u16),
    /// No definite reply. The server may have accepted the message.
    Unknown,
}

/// The submission server, as the worker uses it.
pub trait Transport {
    /// A session with the body sent except the final dot.
    type Staged: Send;

    /// S3: runs a session up to the body and streams `body` without the
    /// final dot.
    fn stage(
        &mut self,
        envelope: &Envelope,
        body: &[u8],
    ) -> impl Future<Output = Result<Self::Staged, Refused>> + Send;

    /// S5: sends the final dot and reads the reply.
    fn end_of_data(&mut self, staged: Self::Staged) -> impl Future<Output = EndOfData> + Send;

    /// Closes the session without the final dot.
    fn abandon(&mut self, staged: Self::Staged) -> impl Future<Output = ()> + Send;
}

/// Where a worker stands in its attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum State<S> {
    Idle,
    Claimed {
        outbox: [u8; 16],
        attempt: u32,
    },
    Rendered {
        outbox: [u8; 16],
        attempt: u32,
        prepared: Prepared,
        digest: [u8; 32],
    },
    Staged {
        outbox: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        staged: S,
    },
    Committed {
        outbox: [u8; 16],
        attempt: u32,
        staged: S,
    },
}

/// What one step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// No message could be claimed now.
    Idle,
    /// The step succeeded and the attempt goes on with `next`.
    Advanced {
        /// The message.
        outbox: [u8; 16],
        /// The attempt.
        attempt: u32,
        /// The step that comes next.
        next: Step,
    },
    /// The worker recorded `phase` for the message. TRANSIENT is retried
    /// after its backoff. PERMANENT and IN_DOUBT raise an alert.
    Recorded {
        /// The message.
        outbox: [u8; 16],
        /// The attempt.
        attempt: u32,
        /// The phase.
        phase: Phase,
        /// The reply code, if a reply was read.
        reply_code: Option<u16>,
    },
    /// The commit point refused: another worker took the lease over, or
    /// the store's answer was not a known success. The session was closed
    /// without the final dot.
    Fenced {
        /// The message.
        outbox: [u8; 16],
        /// The attempt.
        attempt: u32,
    },
    /// The final dot was sent and no outcome was recorded. The COMMITTING
    /// head stays, and recovery records IN_DOUBT once its lease ends.
    Unconfirmed {
        /// The message.
        outbox: [u8; 16],
        /// The attempt.
        attempt: u32,
    },
    /// A store write of `step` failed or has an unknown outcome. The
    /// attempt ended, and the delivery log decides what follows.
    StoreFault {
        /// The step.
        step: Step,
    },
}

impl Outcome {
    /// Whether the outcome raises an alert on the tenant admin's delivery
    /// list: a PERMANENT or IN_DOUBT record (M6 design section 5.1).
    pub fn is_alert(&self) -> bool {
        matches!(
            self,
            Outcome::Recorded {
                phase: Phase::Permanent | Phase::InDoubt,
                ..
            }
        )
    }
}

/// The phase a reply code records, or `None` when the code is no
/// definite answer.
fn phase_of_reply(code: u16) -> Option<Phase> {
    match code {
        200..=299 => Some(Phase::Sent),
        400..=499 => Some(Phase::Transient),
        500..=599 => Some(Phase::Permanent),
        _ => None,
    }
}

/// A reply code the delivery log can hold.
fn storable(code: Option<u16>) -> Option<u16> {
    code.filter(|c| (200..=599).contains(c))
}

/// One dispatch worker, holding at most one attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Worker<S> {
    id: [u8; 16],
    state: State<S>,
}

impl<S: Send> Worker<S> {
    /// A worker with id `id` and no attempt, as at start or after a crash.
    pub fn new(id: [u8; 16]) -> Worker<S> {
        Worker {
            id,
            state: State::Idle,
        }
    }

    /// The worker id, written on each row.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The step the next call runs.
    pub fn next_step(&self) -> Step {
        match self.state {
            State::Idle => Step::Claim,
            State::Claimed { .. } => Step::Render,
            State::Rendered { .. } => Step::Stage,
            State::Staged { .. } => Step::CommitPoint,
            State::Committed { .. } => Step::Send,
        }
    }

    /// Whether the worker holds no attempt.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }

    /// Runs one step at `now`. An idle worker tries `candidates` in order
    /// and claims the first it may.
    pub async fn step<St, So, T>(
        &mut self,
        store: &mut St,
        source: &mut So,
        transport: &mut T,
        candidates: &[[u8; 16]],
        now: i64,
    ) -> Outcome
    where
        St: Store + Send,
        So: Source + Send,
        T: Transport<Staged = S> + Send,
    {
        let id = self.id;
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Idle => {
                for outbox in candidates {
                    match store.claim(*outbox, id, now).await {
                        Ok(Next::Claim { attempt }) => {
                            self.state = State::Claimed {
                                outbox: *outbox,
                                attempt,
                            };
                            return Outcome::Advanced {
                                outbox: *outbox,
                                attempt,
                                next: Step::Render,
                            };
                        }
                        Ok(Next::RecordInDoubt { attempt }) => {
                            return Outcome::Recorded {
                                outbox: *outbox,
                                attempt,
                                phase: Phase::InDoubt,
                                reply_code: None,
                            };
                        }
                        Ok(Next::GiveUp { attempt }) => {
                            return Outcome::Recorded {
                                outbox: *outbox,
                                attempt,
                                phase: Phase::Permanent,
                                reply_code: None,
                            };
                        }
                        Ok(Next::Busy { .. } | Next::Wait { .. } | Next::Done) => {}
                        Err(_) => return Outcome::StoreFault { step: Step::Claim },
                    }
                }
                Outcome::Idle
            }
            State::Claimed { outbox, attempt } => match source.load(outbox).await {
                Ok(prepared) => {
                    let digest = fstp_crypto::sha256(&prepared.body);
                    self.state = State::Rendered {
                        outbox,
                        attempt,
                        prepared,
                        digest,
                    };
                    Outcome::Advanced {
                        outbox,
                        attempt,
                        next: Step::Stage,
                    }
                }
                Err(e) => {
                    let phase = match e {
                        LoadError::Unavailable => Phase::Transient,
                        LoadError::Unusable => Phase::Permanent,
                    };
                    record(store, id, outbox, attempt, phase, None, now, Step::Render).await
                }
            },
            State::Rendered {
                outbox,
                attempt,
                prepared,
                digest,
            } => match transport.stage(&prepared.envelope, &prepared.body).await {
                Ok(staged) => {
                    self.state = State::Staged {
                        outbox,
                        attempt,
                        facts: CommitFacts {
                            event: prepared.event,
                            template_version: prepared.template_version,
                            body_digest: digest,
                        },
                        staged,
                    };
                    Outcome::Advanced {
                        outbox,
                        attempt,
                        next: Step::CommitPoint,
                    }
                }
                Err(r) => {
                    let (phase, code) = match r {
                        Refused::Transient(c) => (Phase::Transient, c),
                        Refused::Permanent(c) => (Phase::Permanent, c),
                    };
                    record(
                        store,
                        id,
                        outbox,
                        attempt,
                        phase,
                        storable(code),
                        now,
                        Step::Stage,
                    )
                    .await
                }
            },
            State::Staged {
                outbox,
                attempt,
                facts,
                staged,
            } => match store.commit_point(outbox, id, attempt, facts, now).await {
                Ok(true) => {
                    self.state = State::Committed {
                        outbox,
                        attempt,
                        staged,
                    };
                    Outcome::Advanced {
                        outbox,
                        attempt,
                        next: Step::Send,
                    }
                }
                // A refusal, a failure or an unknown outcome: never send
                // the dot. An unknown outcome that did apply leaves a
                // COMMITTING head, which recovery records IN_DOUBT.
                Ok(false) | Err(_) => {
                    transport.abandon(staged).await;
                    Outcome::Fenced { outbox, attempt }
                }
            },
            State::Committed {
                outbox,
                attempt,
                staged,
            } => match transport.end_of_data(staged).await {
                EndOfData::Reply(code) => match phase_of_reply(code) {
                    Some(phase) => {
                        match record(
                            store,
                            id,
                            outbox,
                            attempt,
                            phase,
                            Some(code),
                            now,
                            Step::Send,
                        )
                        .await
                        {
                            Outcome::StoreFault { .. } => Outcome::Unconfirmed { outbox, attempt },
                            o => o,
                        }
                    }
                    None => Outcome::Unconfirmed { outbox, attempt },
                },
                EndOfData::Unknown => Outcome::Unconfirmed { outbox, attempt },
            },
        }
    }
}

/// Records `phase` for the attempt and reports it. A refused record means
/// another worker settled the message first.
#[allow(clippy::too_many_arguments)]
async fn record<St: Store>(
    store: &mut St,
    id: [u8; 16],
    outbox: [u8; 16],
    attempt: u32,
    phase: Phase,
    reply_code: Option<u16>,
    now: i64,
    step: Step,
) -> Outcome {
    match store
        .record(outbox, id, attempt, phase, reply_code, now)
        .await
    {
        Ok(true) => Outcome::Recorded {
            outbox,
            attempt,
            phase,
            reply_code,
        },
        Ok(false) => Outcome::Fenced { outbox, attempt },
        Err(_) => Outcome::StoreFault { step },
    }
}

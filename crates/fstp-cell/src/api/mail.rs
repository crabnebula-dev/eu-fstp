//! The delivery of a message the API core's ports enqueue (ADR-026 record
//! of lane L5, I-25, I-26, M6 design section 5.1).
//!
//! A port that fires a timeline event with a message, such as the
//! invitation of `crate::api::accounts`, delivers it right after the fire
//! entry commits: one `fstp_dispatch::Worker` runs over `ops.delivery` for
//! that one outbox row, through the cell's [`Relay`]. The attempt protocol
//! is the dispatcher's own. The COMMITTING row is written before the final
//! dot, and an unknown outcome stays IN_DOUBT and is never sent again, so
//! each message is delivered at most once (I-26) whichever worker takes it.
//!
//! The worker loads the message from the bytes the port composed and
//! sealed into the row in the same append, so the port never opens the
//! sealed row. The body digest key is derived from the App chain `Lookup`
//! key (`crate::tasks::dispatch::digest_key`).
//!
//! Lane L4 builds the configured relay of the cell. It plugs in behind
//! [`Relay`] at merge. Until then a test world passes its own.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fstp_dispatch::{
    DigestKey, EndOfData, Envelope, LoadError, Outcome, Prepared, Refused, Source, Transport,
    Worker,
};
use fstp_pgstore::{DeliveryLog, Pool};
use fstp_rt::Runtime;

/// A boxed future of the relay.
pub type RelayFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The cell's submission relay, as a port delivers through it (ADR-018,
/// ADR-026 record of lane L5). It is `fstp_dispatch::Transport` in a form
/// a cell can hold as an object: staging stops before the final dot, so
/// the worker records the commit point first.
pub trait Relay: Send + Sync + 'static {
    /// The address the cell's mail is sent from: the envelope sender and
    /// the `From` of each composed message.
    fn sender(&self) -> &str;

    /// S3: runs a session up to the body and streams `body` without the
    /// final dot.
    fn stage<'a>(
        &'a self,
        envelope: &'a Envelope,
        body: &'a [u8],
    ) -> RelayFuture<'a, Result<Box<dyn StagedMail>, Refused>>;
}

/// A relay session with the body sent except the final dot.
pub trait StagedMail: Send {
    /// S5: sends the final dot and reads the reply.
    fn end_of_data(self: Box<Self>) -> RelayFuture<'static, EndOfData>;

    /// Closes the session without the final dot.
    fn abandon(self: Box<Self>) -> RelayFuture<'static, ()>;
}

/// The cell's relay, shared by the ports that deliver.
pub(crate) type SharedRelay = Arc<dyn Relay>;

/// `fstp_dispatch::Transport` over a [`Relay`].
struct RelayTransport(SharedRelay);

impl Transport for RelayTransport {
    type Staged = Box<dyn StagedMail>;

    fn stage(
        &mut self,
        envelope: &Envelope,
        body: &[u8],
    ) -> impl Future<Output = Result<Self::Staged, Refused>> + Send {
        let relay = Arc::clone(&self.0);
        let envelope = envelope.clone();
        let body = body.to_vec();
        async move { relay.stage(&envelope, &body).await }
    }

    fn end_of_data(&mut self, staged: Self::Staged) -> impl Future<Output = EndOfData> + Send {
        staged.end_of_data()
    }

    fn abandon(&mut self, staged: Self::Staged) -> impl Future<Output = ()> + Send {
        staged.abandon()
    }
}

/// The one message a delivery loads: the composed bytes of its row.
struct One {
    outbox: [u8; 16],
    prepared: Prepared,
}

impl Source for One {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        if outbox == self.outbox {
            Ok(self.prepared.clone())
        } else {
            Err(LoadError::Unavailable)
        }
    }
}

/// Most steps one delivery takes: the five steps of one attempt, with
/// room for a recovery step before them.
const MAX_STEPS: usize = 8;

/// Delivers the message `body` of the outbox row `outbox` once, through
/// `relay`, with the delivery log over the app pool `app` (module
/// documentation). `now` reads the cell clock at each step. Returns the
/// last outcome of the worker, or `None` when the body does not prepare,
/// in which case nothing is recorded and the row waits for the
/// dispatcher.
pub(crate) async fn deliver_once<R: Runtime>(
    app: &Pool<R>,
    relay: &SharedRelay,
    key: DigestKey,
    outbox: [u8; 16],
    body: &[u8],
    now: impl Fn() -> i64,
) -> Option<Outcome> {
    let prepared = fstp_dispatch::prepare(body, relay.sender()).ok()?;
    let mut log = DeliveryLog::new(app.clone()).ok()?;
    let worker_id = fstp_crypto::random_array::<16>().ok()?;
    let mut worker: Worker<Box<dyn StagedMail>> = Worker::new(worker_id, key);
    let mut source = One { outbox, prepared };
    let mut transport = RelayTransport(Arc::clone(relay));
    let mut last = None;
    for _ in 0..MAX_STEPS {
        let out = worker
            .step(&mut log, &mut source, &mut transport, &[outbox], now())
            .await;
        let done = matches!(
            out,
            Outcome::Idle
                | Outcome::StoreFault { .. }
                | Outcome::Recorded { .. }
                | Outcome::Fenced { .. }
                | Outcome::Unconfirmed { .. }
        ) && worker.is_idle();
        last = Some(out);
        if done {
            break;
        }
    }
    last
}

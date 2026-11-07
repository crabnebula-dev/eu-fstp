//! The dispatcher task (M6 design section 5.1, I-25, I-26). Lane
//! L6-DISP.
//!
//! Each tick lists the email messages of `ops.outbox` without a terminal
//! delivery row and runs one `fstp_dispatch::Worker` over them until it
//! is idle. A PERMANENT or IN_DOUBT record is returned as an alert for
//! the tenant admin's delivery list. The worker never sends a message
//! again once its COMMITTING row exists, so a restart of the cell is a
//! crash the delivery log recovers from.

use std::time::Duration;

use fstp_cell_core::timeline::OUTBOX_KIND_EMAIL;
use fstp_dispatch::{LoadError, Outcome, Prepared, Source, Store, Transport, Worker, prepare};
use fstp_pgstore::{DeliveryLog, OutboxReader};
use fstp_rt::future::{Either, race};
use fstp_rt::{Runtime, ShutdownSignal};

use super::Clock;

/// How often the dispatcher looks for messages.
pub const TICK: Duration = Duration::from_secs(1);

/// Most messages one tick looks at.
pub const BATCH: u16 = 64;

/// Most steps of one tick: five steps for each message of a batch.
const MAX_STEPS: usize = 5 * BATCH as usize;

/// S2 over `ops.outbox`: opens the stored message and reads its envelope,
/// event and template version.
pub struct OutboxSource<R: Runtime> {
    reader: OutboxReader<R>,
    sender: String,
}

impl<R: Runtime> OutboxSource<R> {
    /// The source over `reader`, sending from `sender`.
    pub fn new(reader: OutboxReader<R>, sender: &str) -> OutboxSource<R> {
        OutboxSource {
            reader,
            sender: sender.to_owned(),
        }
    }
}

impl<R: Runtime> Source for OutboxSource<R> {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        match self.reader.open(outbox, OUTBOX_KIND_EMAIL).await {
            Ok(Some(raw)) => prepare(&raw, &self.sender).map_err(|_| LoadError::Unusable),
            Ok(None) => Err(LoadError::Unusable),
            Err(_) => Err(LoadError::Unavailable),
        }
    }
}

/// One tick at `now`: steps `worker` over `candidates` until it is idle,
/// and returns the alerts it raised.
pub async fn tick<St, So, T>(
    worker: &mut Worker<T::Staged>,
    store: &mut St,
    source: &mut So,
    transport: &mut T,
    candidates: &[[u8; 16]],
    now: i64,
) -> Vec<Outcome>
where
    St: Store + Send,
    So: Source + Send,
    T: Transport + Send,
{
    let mut alerts = Vec::new();
    for _ in 0..MAX_STEPS {
        let out = worker.step(store, source, transport, candidates, now).await;
        if out.is_alert() {
            alerts.push(out);
        }
        if matches!(out, Outcome::Idle | Outcome::StoreFault { .. }) && worker.is_idle() {
            break;
        }
    }
    alerts
}

/// Runs the dispatcher every [`TICK`] until `stop` is triggered.
/// `on_alert` receives each alert.
pub async fn run<C, R, So, T>(
    clock: &C,
    worker: &mut Worker<T::Staged>,
    log: &mut DeliveryLog<R>,
    source: &mut So,
    transport: &mut T,
    stop: &ShutdownSignal,
    mut on_alert: impl FnMut(Outcome) + Send,
) where
    C: Clock,
    R: Runtime,
    So: Source + Send,
    T: Transport + Send,
{
    let step = i64::try_from(TICK.as_micros()).unwrap_or(i64::MAX);
    loop {
        let now = clock.now();
        if let Ok(candidates) = log.pending(OUTBOX_KIND_EMAIL, BATCH).await {
            for a in tick(worker, log, source, transport, &candidates, now).await {
                on_alert(a);
            }
        }
        let next = now.saturating_add(step);
        match race(stop.notified(), clock.sleep_until(next)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_dispatch::store::MemDelivery;
    use fstp_dispatch::{EndOfData, Envelope, Refused};
    use fstp_pgstore::Phase;

    struct One;

    impl Source for One {
        async fn load(&mut self, _o: [u8; 16]) -> Result<Prepared, LoadError> {
            Ok(Prepared {
                envelope: Envelope {
                    from: "noreply@fund.test".to_owned(),
                    to: "lead@example.test".to_owned(),
                },
                body: b"Subject: s\r\n\r\nb\r\n".to_vec(),
                event: [1; 32],
                template_version: 1,
            })
        }
    }

    /// Accepts each end of DATA with `code`, or loses the reply.
    struct Sink(Option<u16>, u32);

    impl Transport for Sink {
        type Staged = ();
        async fn stage(&mut self, _e: &Envelope, _b: &[u8]) -> Result<(), Refused> {
            Ok(())
        }
        async fn end_of_data(&mut self, _s: ()) -> EndOfData {
            self.1 = self.1.saturating_add(1);
            self.0.map_or(EndOfData::Unknown, EndOfData::Reply)
        }
        async fn abandon(&mut self, _s: ()) {}
    }

    const T: i64 = 1_794_050_000_000_000;

    /// I-26, M6 design section 5.1: a tick sends each message once, and a
    /// lost reply leaves it COMMITTING until recovery records IN_DOUBT and
    /// raises an alert. It is never sent again.
    #[test]
    fn i26_tick_sends_once_and_alerts_in_doubt() {
        let ids = [[1; 16], [2; 16]];
        let mut log = MemDelivery::new(ids);
        let mut w = Worker::new([9; 16]);
        let mut sink = Sink(Some(250), 0);
        let a = fstp_rt::future::block_on(tick(&mut w, &mut log, &mut One, &mut sink, &ids, T));
        assert!(a.is_empty());
        assert_eq!(sink.1, 2);
        assert!(
            ids.iter()
                .all(|o| log.head(o).map(|h| h.phase) == Some(Phase::Sent))
        );

        let mut log = MemDelivery::new([[3; 16]]);
        let mut lost = Sink(None, 0);
        let ids = [[3; 16]];
        let a = fstp_rt::future::block_on(tick(&mut w, &mut log, &mut One, &mut lost, &ids, T));
        assert!(a.is_empty());
        let later = T + fstp_pgstore::DELIVERY_LEASE_US;
        let a = fstp_rt::future::block_on(tick(&mut w, &mut log, &mut One, &mut lost, &ids, later));
        assert_eq!(a.len(), 1, "{a:?}");
        assert!(a.iter().all(Outcome::is_alert));
        assert_eq!(log.head(&[3; 16]).map(|h| h.phase), Some(Phase::InDoubt));
        assert_eq!(lost.1, 1, "I-26: an IN_DOUBT message is never sent again");
    }
}

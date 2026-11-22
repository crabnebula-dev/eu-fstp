//! The anonymous draft store of a serving cell and its sweep (ADR-032,
//! Daniel 2026-11-22).
//!
//! - [`PgAnonymousDrafts`] is the `fstp_api_core::anon::AnonymousDrafts`
//!   port over `workspace.anonymous_drafts` (`fstp_pgstore::ApiStore`).
//!   The text is sealed under the cell's ledger key generation with the
//!   token digest in the AAD (R-NF-08). The draft routes and the claim of
//!   the API core share one store.
//! - [`run`] deletes every expired draft once an [`INTERVAL_US`], so an
//!   unclaimed draft is gone within an hour of its expiry: 30 days after
//!   its start, or at its call's deadline if that is earlier. A draft has
//!   no upload and no pre-check run, so its row is all there is to delete.
//!   An expired row is never served in the meantime.
//!
//! The sweep writes no log line with a count or an id, so the operator
//! learns nothing of the drafts (I-21).

use std::sync::Arc;

use fstp_api_core::anon::{AnonFuture, AnonymousDrafts, Draft, Row};
use fstp_api_core::port::PortError;
use fstp_domain::id::CallId;
use fstp_domain::time::Timestamp;
use fstp_rt::Runtime;

use crate::tasks::Clock;

/// How often the sweep runs: once an hour.
pub const INTERVAL_US: i64 = 3_600 * crate::tasks::SECOND_US;

/// The anonymous draft store over the cell's app pool.
pub struct PgAnonymousDrafts<R: Runtime> {
    store: fstp_pgstore::ApiStore<R>,
}

impl<R: Runtime> PgAnonymousDrafts<R> {
    /// The store over `store`.
    pub fn new(store: fstp_pgstore::ApiStore<R>) -> PgAnonymousDrafts<R> {
        PgAnonymousDrafts { store }
    }
}

fn unavailable<T>(_: T) -> PortError {
    PortError::Unavailable
}

impl<R: Runtime> AnonymousDrafts for PgAnonymousDrafts<R> {
    fn start(&self, digest: [u8; 32], row: Row) -> AnonFuture<'_, ()> {
        Box::pin(async move {
            let plain = row.draft.encode().ok_or(PortError::Refused)?;
            self.store
                .anon_start(
                    digest,
                    row.call.raw().to_be_bytes(),
                    &plain,
                    row.started.micros(),
                    row.expires.micros(),
                )
                .await
                .map_err(|e| match e {
                    fstp_pgstore::StoreFault::Refused(_) => PortError::Refused,
                    _ => PortError::Unavailable,
                })
        })
    }

    fn open(&self, digest: [u8; 32], now: Timestamp) -> AnonFuture<'_, Option<Row>> {
        Box::pin(async move {
            let Some(r) = self
                .store
                .anon_open(digest, now.micros())
                .await
                .map_err(unavailable)?
            else {
                return Ok(None);
            };
            // A value that opened but does not decode fails closed.
            let draft = Draft::decode(&r.plain).ok_or(PortError::Unavailable)?;
            Ok(Some(Row {
                call: CallId::from_raw(u128::from_be_bytes(r.call)),
                draft,
                started: Timestamp::from_micros(r.started),
                expires: Timestamp::from_micros(r.expires),
            }))
        })
    }

    fn save(&self, digest: [u8; 32], draft: Draft, now: Timestamp) -> AnonFuture<'_, bool> {
        Box::pin(async move {
            let plain = draft.encode().ok_or(PortError::Refused)?;
            self.store
                .anon_save(digest, &plain, now.micros())
                .await
                .map_err(unavailable)
        })
    }

    fn remove(&self, digest: [u8; 32]) -> AnonFuture<'_, bool> {
        Box::pin(async move { self.store.anon_remove(digest).await.map_err(unavailable) })
    }

    fn live(&self, now: Timestamp) -> AnonFuture<'_, u64> {
        Box::pin(async move {
            self.store
                .anon_live(now.micros())
                .await
                .map_err(unavailable)
        })
    }

    fn sweep(&self, now: Timestamp) -> AnonFuture<'_, u64> {
        Box::pin(async move {
            self.store
                .anon_sweep(now.micros())
                .await
                .map_err(unavailable)
        })
    }
}

/// One sweep at `now`: deletes every draft expired at `now`. A store
/// fault deletes nothing, and the next sweep tries again.
pub async fn sweep_once(store: &dyn AnonymousDrafts, now: Timestamp) -> Result<u64, PortError> {
    store.sweep(now).await
}

/// Runs the sweep once an [`INTERVAL_US`] until `stop` is triggered, the
/// first time at the start.
pub async fn run<C: Clock>(
    clock: &C,
    store: Arc<dyn AnonymousDrafts>,
    stop: &fstp_rt::ShutdownSignal,
) {
    use fstp_rt::future::{Either, race};
    loop {
        let now = clock.now();
        let _ = sweep_once(store.as_ref(), Timestamp::from_micros(now)).await;
        let next = now.saturating_add(INTERVAL_US);
        match race(stop.notified(), clock.sleep_until(next)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_api_core::anon::MemoryAnonymousDrafts;

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("the memory store never waits"),
        }
    }

    /// ADR-032 (Daniel 2026-11-22): one sweep deletes exactly the drafts
    /// expired at its instant, and the sweep runs at least hourly.
    #[test]
    fn adr032_sweep_deletes_expired_drafts_only() {
        let s = MemoryAnonymousDrafts::new();
        for (i, expires) in [10_i64, 20, 30].into_iter().enumerate() {
            let row = Row {
                call: CallId::from_raw(1),
                draft: Draft::default(),
                started: Timestamp::from_micros(0),
                expires: Timestamp::from_micros(expires),
            };
            block(s.start([u8::try_from(i).unwrap_or(0); 32], row)).unwrap();
        }
        assert_eq!(
            block(sweep_once(&s, Timestamp::from_micros(20))).unwrap(),
            2
        );
        assert_eq!(s.len(), 1);
        assert!(INTERVAL_US <= 3_600 * crate::tasks::SECOND_US);
    }
}

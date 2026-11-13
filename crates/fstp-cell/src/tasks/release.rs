//! The licence refresh and the update check of a self-hosted cell
//! (design sections 10.1 to 10.3, I-38, I-39).
//!
//! - Each call runs at most once a day after an answered call, with a
//!   10-second timeout, and backs off after failures: 1 minute, doubling
//!   up to a day ([`Schedule`]).
//! - Neither cell start nor any request waits for it, and a shutdown ends
//!   a call in flight. The task holds no handle that a request handler
//!   reaches, and the engine never asks it anything (I-39).
//! - A SaaS cell runs no call at all (B12). The connector refuses one
//!   anyway ([`crate::egress::CnClient`]).
//! - Request bytes come only from `fstp_release::egress::encode` (I-38).
//! - An answered refresh is adopted only when `apply_refresh` accepts it
//!   under the pinned key set. An update answer is recorded with its time
//!   and outcome only. Metadata cannot be verified before I-91 (M9), so
//!   the cell never announces an update in M3 (design section 10.3).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_release::egress::{Channel, CnCall, LicenceRefresh, ProductVersion, UpdateCheck};
use fstp_release::licence::{KeySet, LicenceId, VerifiedToken};
use fstp_rt::ShutdownSignal;
use fstp_rt::future::{Either, race};

use super::{Clock, DAY_US, SECOND_US};
use crate::config::Mode;
use crate::egress::{CnClient, CnFault, CnTransport};

/// How long a call may take before the task gives up (design section 10.2).
pub const CALL_TIMEOUT_US: i64 = 10 * SECOND_US;
/// The first wait after a failed call.
pub const BACKOFF_BASE_US: i64 = 60 * SECOND_US;
/// The most attempts the view keeps.
pub const VIEW_LIMIT: usize = 4096;

/// Which call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallKind {
    /// The licence refresh.
    Licence,
    /// The update check.
    Update,
}

/// How one call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The service answered with a response the cell accepted.
    Answered,
    /// The task gave up after [`CALL_TIMEOUT_US`].
    TimedOut,
    /// The connection failed, the service refused, or the answer was not
    /// accepted.
    Failed(CnFault),
}

/// One call, as the admin view shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// Which call.
    pub kind: CallKind,
    /// The host it went to.
    pub host: &'static str,
    /// When it started, UTC microseconds.
    pub started: i64,
    /// When the task stopped waiting for it.
    pub ended: i64,
    /// How it ended.
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    next: i64,
    failures: u32,
}

impl Slot {
    fn record(&mut self, started: i64, ended: i64, answered: bool) {
        if answered {
            self.failures = 0;
            self.next = started.saturating_add(DAY_US);
        } else {
            self.failures = self.failures.saturating_add(1);
            self.next = ended.saturating_add(backoff(self.failures));
        }
    }
}

/// The wait after `failures` failed calls in a row: 1 minute, doubling,
/// at most a day.
pub fn backoff(failures: u32) -> i64 {
    let shift = failures.saturating_sub(1).min(20);
    BACKOFF_BASE_US
        .checked_mul(2_i64.checked_pow(shift).unwrap_or(i64::MAX))
        .unwrap_or(DAY_US)
        .min(DAY_US)
}

/// When each call is due next. Pure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    licence: Option<Slot>,
    update: Slot,
}

impl Schedule {
    /// Both calls due at `now`. A cell without a licence token runs the
    /// update check only.
    pub fn new(now: i64, with_licence: bool) -> Schedule {
        let first = Slot {
            next: now,
            failures: 0,
        };
        Schedule {
            licence: with_licence.then_some(first),
            update: first,
        }
    }

    /// The call due first and its instant. The licence refresh wins a tie.
    pub fn next(&self) -> (CallKind, i64) {
        match self.licence {
            Some(l) if l.next <= self.update.next => (CallKind::Licence, l.next),
            _ => (CallKind::Update, self.update.next),
        }
    }

    /// Records how a call of `kind` ended.
    pub fn record(&mut self, kind: CallKind, started: i64, ended: i64, answered: bool) {
        match kind {
            CallKind::Licence => {
                if let Some(l) = self.licence.as_mut() {
                    l.record(started, ended, answered);
                }
            }
            CallKind::Update => self.update.record(started, ended, answered),
        }
    }
}

/// What the release tasks call with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseSettings {
    /// The licence of the cell, once it holds one. Before the first token
    /// is imported there is none, and only the update check runs (design
    /// section 10.2, Q41).
    pub licence: Option<LicenceId>,
    /// The running version.
    pub version: ProductVersion,
    /// The update channel.
    pub channel: Channel,
}

/// The licence token the cell holds, with the keys it is checked under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenceHold {
    /// The adopted token.
    pub token: VerifiedToken,
    /// The pinned key set.
    pub keys: KeySet,
}

#[derive(Debug, Default)]
struct ViewState {
    attempts: Vec<Attempt>,
    hold: Option<LicenceHold>,
}

/// The admin view of the release tasks: every attempt with its time and
/// outcome, and the adopted licence token (design section 10.3). It holds
/// no handle to the task, so nothing can wait for a call through it.
#[derive(Clone, Debug, Default)]
pub struct ReleaseView {
    state: Arc<Mutex<ViewState>>,
}

impl ReleaseView {
    fn lock(&self) -> MutexGuard<'_, ViewState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every attempt so far, oldest first, at most [`VIEW_LIMIT`].
    pub fn attempts(&self) -> Vec<Attempt> {
        self.lock().attempts.clone()
    }

    /// The last attempt of `kind`.
    pub fn last(&self, kind: CallKind) -> Option<Attempt> {
        self.lock()
            .attempts
            .iter()
            .rev()
            .find(|a| a.kind == kind)
            .copied()
    }

    /// The licence token the cell holds.
    pub fn hold(&self) -> Option<LicenceHold> {
        self.lock().hold.clone()
    }

    /// Whether the cell announces an update. Never in M3: metadata cannot
    /// be verified before I-91 (design section 10.3).
    pub fn announces_update(&self) -> bool {
        fstp_release::metadata::announces_update()
    }

    fn push(&self, a: Attempt) {
        let mut st = self.lock();
        if st.attempts.len() >= VIEW_LIMIT {
            st.attempts.remove(0);
        }
        st.attempts.push(a);
    }

    fn adopt(&self, hold: LicenceHold) {
        self.lock().hold = Some(hold);
    }
}

/// The call of `kind`, or `None` for a licence refresh without a
/// licence. The schedule never asks for one ([`run`]).
fn call_of(kind: CallKind, s: &ReleaseSettings) -> Option<CnCall> {
    match kind {
        CallKind::Licence => s.licence.map(|licence| {
            CnCall::Licence(LicenceRefresh {
                licence,
                version: s.version,
            })
        }),
        CallKind::Update => Some(CnCall::Update(UpdateCheck {
            version: s.version,
            channel: s.channel,
        })),
    }
}

/// Runs the release tasks until `stop` is triggered. A SaaS cell returns
/// at once and sends nothing (B12).
///
/// `hold` is the licence token the cell holds. Without one, or without
/// a licence in `settings`, the licence refresh does not run: the
/// refresh is authenticated by the token it refreshes (design section
/// 10.1).
pub async fn run<C: Clock, T: CnTransport>(
    clock: &C,
    client: &CnClient<T>,
    mode: Mode,
    settings: ReleaseSettings,
    hold: Option<LicenceHold>,
    view: &ReleaseView,
    stop: &ShutdownSignal,
) {
    if mode != Mode::SelfHosted {
        return;
    }
    if let Some(h) = hold.clone() {
        view.adopt(h);
    }
    let mut schedule = Schedule::new(clock.now(), hold.is_some() && settings.licence.is_some());
    loop {
        let (kind, due) = schedule.next();
        match race(stop.notified(), clock.sleep_until(due)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
        if stop.is_triggered() {
            return;
        }
        let started = clock.now();
        let Some(call) = call_of(kind, &settings) else {
            // Unreachable: the schedule holds no licence slot without a
            // licence. Ending the task sends nothing.
            return;
        };
        let deadline = started.saturating_add(CALL_TIMEOUT_US);
        // A shutdown never waits for a call: the stop signal ends it too.
        // A call that has ended wins a tie, so its outcome is recorded.
        let answer = match race(
            race(client.call(call), clock.sleep_until(deadline)),
            stop.notified(),
        )
        .await
        {
            Either::Left(a) => a,
            Either::Right(()) => return,
        };
        let ended = clock.now();
        let outcome = match answer {
            Either::Right(()) => Outcome::TimedOut,
            Either::Left(Err(f)) => Outcome::Failed(f),
            Either::Left(Ok(resp)) => match kind {
                CallKind::Update => Outcome::Answered,
                CallKind::Licence => match view.hold() {
                    Some(h) => {
                        let now_s = ended.div_euclid(SECOND_US);
                        match fstp_release::licence::apply_refresh(
                            &h.token, &h.keys, &resp.body, now_s,
                        ) {
                            Ok(r) => {
                                view.adopt(LicenceHold {
                                    token: r.token,
                                    keys: r.keys,
                                });
                                Outcome::Answered
                            }
                            Err(_) => Outcome::Failed(CnFault::Malformed),
                        }
                    }
                    None => Outcome::Failed(CnFault::Malformed),
                },
            },
        };
        schedule.record(kind, started, ended, outcome == Outcome::Answered);
        view.push(Attempt {
            kind,
            host: call.host(),
            started,
            ended,
            outcome,
        });
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small constants"
)]
mod tests {
    use super::*;

    /// I-39, design section 10.2: the backoff starts at a minute, doubles,
    /// never shrinks and stops at a day.
    #[test]
    fn i39_release_backoff_doubles_up_to_a_day() {
        let waits: Vec<i64> = (1..=30).map(backoff).collect();
        assert_eq!(waits.first(), Some(&BACKOFF_BASE_US));
        assert!(waits.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(waits.last(), Some(&DAY_US));
    }

    /// I-39, design section 10.2: an answered call is next due a day after
    /// it started, and a failed one after its backoff.
    #[test]
    fn i39_release_schedule_runs_at_most_daily_after_an_answer() {
        let mut s = Schedule::new(0, true);
        assert_eq!(s.next(), (CallKind::Licence, 0));
        s.record(CallKind::Licence, 0, 5, true);
        assert_eq!(s.next(), (CallKind::Update, 0));
        s.record(CallKind::Update, 0, 10, false);
        assert_eq!(s.next(), (CallKind::Update, 10 + BACKOFF_BASE_US));
        s.record(CallKind::Update, 100, 100, true);
        assert_eq!(s.next(), (CallKind::Licence, DAY_US));
    }
}

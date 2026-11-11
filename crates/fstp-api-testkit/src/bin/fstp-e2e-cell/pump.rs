//! The background pump of the demo cell (M5 design section 7, lane
//! L-DEMO). It plays the parts of the cell that the fake ports do not
//! run on their own, through the real commands:
//!
//! - the sweep: `StartExecution`, `Complete` and the other due System
//!   commands, as the cell's timeline task issues them;
//! - the checks runner: a passed run of the submission and acceptance
//!   checks (I-32) for each payment request that awaits one, against the
//!   fake forge. One release of the fake forge answers 404 once, when
//!   the demo page arms it (`arm_forge_failure`), so the checks fail and
//!   the lead resubmits (R-PR-02).
//!
//! Test only: this module lives in `fstp-e2e-cell` and never ships.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use fstp_api_core::port::{TextClass, TextOwner, TextStore};
use fstp_domain::command::{Actor, Command as Core, Ctx, SystemCause, Via};
use fstp_domain::id::{CommandId, ContentDigest, TextId, TextRef};
use fstp_domain::payment::{CheckKind, CheckPhase, CheckResult, RequestStatus};
use fstp_domain::time::Timestamp;

use crate::{Inner, Site};

/// The public repository of the fake forge, `/demo/forge/` on the cell
/// origin (M5 design section 7).
pub(crate) const FORGE_REPO: &str = "http://a.fstp.localhost/demo/forge/synthetic-sensor-kit";
/// The release of the fake forge that exists.
pub(crate) const FORGE_RELEASE: &str = "v1.0.0";

/// Whether the next submission checks fail on the fake forge's 404.
static FAIL_NEXT: AtomicBool = AtomicBool::new(false);
/// A counter for the command ids of the pump.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Arms the fake forge's 404 for the next submission checks.
pub(crate) fn arm_forge_failure() {
    FAIL_NEXT.store(true, Ordering::SeqCst);
}

fn next_id() -> CommandId {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut b = *b"fstp:e2e:pump\0\0\0";
    for (slot, x) in b.iter_mut().skip(8).zip(n.to_be_bytes()) {
        *slot = x;
    }
    CommandId::from_bytes(b)
}

fn ctx(now: Timestamp, cause: SystemCause) -> Ctx {
    Ctx {
        now,
        actor: Actor::System(cause),
        command: next_id(),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// Runs the due sweep commands at `now`.
pub(crate) fn sweep(inner: &Inner, now: Timestamp) -> Result<(), String> {
    let state = inner.ports.engine.state();
    let due = fstp_engine::sweep::due(&state, now).map_err(|e| format!("sweep: {e:?}"))?;
    for cmd in due {
        inner
            .ports
            .engine
            .environment(cmd, ctx(now, SystemCause::Timeline))
            .map_err(|e| format!("sweep command: {e}"))?;
    }
    Ok(())
}

/// Records the checks each waiting payment request awaits.
pub(crate) fn run_checks_now(inner: &Inner, now: Timestamp) -> Result<(), String> {
    // Submission first, then acceptance, as the runner is asked in turn.
    run_phase(inner, now)?;
    run_phase(inner, now)
}

fn run_phase(inner: &Inner, now: Timestamp) -> Result<(), String> {
    let state = inner.ports.engine.state();
    let waiting: Vec<_> = state
        .core
        .payments()
        .summaries()
        .filter(|s| {
            (s.status == RequestStatus::Submitted && !s.submission_passed)
                || (s.status == RequestStatus::UnderReview
                    && s.submission_passed
                    && !s.acceptance_passed)
        })
        .collect();
    for s in waiting {
        let phase = if s.submission_passed {
            CheckPhase::Acceptance
        } else {
            CheckPhase::Submission
        };
        let failing = phase == CheckPhase::Submission && FAIL_NEXT.swap(false, Ordering::SeqCst);
        let failure = if failing {
            let text = "The fake forge answered 404 for the release of the deliverable.";
            let r = fstp_rt::future::block_on(inner.ports.texts.put(
                TextClass::Confidential,
                TextOwner::Proposal(s.grant),
                text.as_bytes(),
            ))
            .map_err(|e| format!("text: {e:?}"))?;
            Some(TextRef::new(
                TextId::from_raw(r.0),
                ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
            ))
        } else {
            None
        };
        let results = s
            .lines
            .iter()
            .map(|l| CheckResult {
                line: Some(l.line),
                check: if failing {
                    CheckKind::PublicLocation
                } else {
                    CheckKind::Evidence
                },
                failure,
            })
            .collect();
        inner
            .ports
            .engine
            .environment(
                fstp_engine::Command::Core(Core::RecordChecks {
                    request: s.request,
                    phase,
                    results,
                    snapshot: ContentDigest::from_bytes([7; 32]),
                }),
                ctx(now, SystemCause::Timeline),
            )
            .map_err(|e| format!("checks: {e}"))?;
    }
    Ok(())
}

/// One tick: the sweep, then the checks, at the cell clock.
pub(crate) fn tick(inner: &Inner) {
    let now = inner.ports.clock.read();
    let _ = sweep(inner, now);
    let _ = run_checks_now(inner, now);
}

/// Starts the pump thread over `sites`. It ticks every half second until
/// the process ends.
pub(crate) fn spawn(sites: Vec<Arc<Site>>) {
    let _ = std::thread::Builder::new()
        .name("demo-pump".to_owned())
        .spawn(move || {
            loop {
                for s in &sites {
                    tick(&s.inner());
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
}

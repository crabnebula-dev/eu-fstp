//! The background pump of the demo cell (M5 design section 7, lane
//! L-DEMO). It plays the parts of the cell that the fake ports do not
//! run on their own, through the real commands:
//!
//! - the sweep: `StartExecution`, `Complete` and the other due System
//!   commands, as the cell's timeline task issues them;
//! - the re-run timeout: `AbandonRerun` for a re-run in flight for
//!   `RERUN_TIMEOUT_US` (issue 6 M3);
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

/// Abandons each re-run that has been in flight for `RERUN_TIMEOUT_US` at
/// `now` (issue 6 M3, I-10), as the cell's timeline task does. The fake
/// port runs a re-run inside the request, so a run that never returns
/// would hold its slot. This cell keeps no ledger across a restart, so it
/// has no start clean-up.
pub(crate) fn abandon_stale_reruns(inner: &Inner, now: Timestamp) -> Result<(), String> {
    let state = inner.ports.engine.state();
    for cmd in fstp_engine::findings::stale_reruns(&state, now) {
        inner
            .ports
            .engine
            .environment(
                fstp_engine::Command::Finding(cmd),
                ctx(now, SystemCause::Timeline),
            )
            .map_err(|e| format!("abandon re-run: {e}"))?;
    }
    Ok(())
}

/// The most passes of one `run_checks_now`. A request needs at most two
/// runs, so this bound is reached only if requests keep arriving.
const MAX_PASSES: usize = 8;

/// Records the checks each waiting payment request awaits (I-32).
///
/// Submission first, then acceptance, as the runner is asked in turn.
/// Each pass reads the state afresh, and the passes repeat until no
/// request waits. A request submitted between two passes then gets both
/// runs in this call. With a fixed two passes it got only its submission
/// run, and its acceptance run waited a whole tick (F-068).
pub(crate) fn run_checks_now(inner: &Inner, now: Timestamp) -> Result<(), String> {
    for _ in 0..MAX_PASSES {
        if run_phase(inner, now)? == 0 {
            break;
        }
    }
    Ok(())
}

/// Records one run for each request that awaits one, and returns how
/// many it recorded.
fn run_phase(inner: &Inner, now: Timestamp) -> Result<usize, String> {
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
    let recorded = waiting.len();
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
    Ok(recorded)
}

/// One tick: the sweep, then the checks, at the cell clock.
pub(crate) fn tick(inner: &Inner) {
    let now = inner.ports.clock.read();
    let _ = sweep(inner, now);
    let _ = abandon_stale_reruns(inner, now);
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

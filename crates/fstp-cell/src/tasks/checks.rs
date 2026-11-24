//! The checks runner of payment requests (I-32, R-PR-02, R-PR-03; ADR-026
//! section "Written by lane `m10/checks-runner`", interim, pending Daniel).
//!
//! At each tick the runner reads the committed state and runs the
//! automated checks of each request that awaits a run
//! (`fstp_domain::payment::awaiting_checks`): the submission run of a
//! request in SUBMITTED, then the acceptance run of a request in
//! UNDER_REVIEW. The checks are `fstp_checks::runner::run`, unchanged. Each
//! run is recorded as `RecordChecks` under the system task `PaymentPort`,
//! which the gate admits for that command only, and the domain decides it
//! with every guard of its row.
//!
//! - **Inputs.** `fstp_domain::payment::checks_input` gives the lines with
//!   the evidence the lead gave, the balances and P-26. P-65 is not in the
//!   policy record yet, so the runner applies "public deliverables", the
//!   stricter option. The location and release texts are opened through
//!   [`EvidenceTexts`]. A text that is not the grant's own, or whose bytes
//!   do not match the digest the request names, counts as missing
//!   evidence, so its check fails. A text that cannot be opened now leaves
//!   the request waiting, and a later tick tries again. No pass is ever
//!   recorded without the evidence it judges.
//! - **Ids.** A run's command id is bound to the cell, the request and the
//!   phase ([`run_id`]). Each request has at most one run of each phase,
//!   so a repeat after a crash, or a second tick before the first commit
//!   folded, is a duplicate in the store and is recorded once (I-23).
//! - **Reasons.** Each failed check's reason is stored first as a
//!   confidential text of the grant, then the command names it. A crash
//!   between the two leaves an unreferenced text only.
//! - **Fetches.** They go through the cell's forge client
//!   (`crate::egress::ForgeClient`, ADR-009 amendment of 2026-11-24).
//!   Retrieved bytes are hashed and dropped by the checks (TH-24).

use std::collections::BTreeSet;
use std::future::Future;
use std::time::Duration;

use fstp_api_core::port::{TextClass, TextOwner};
use fstp_cell_core::driver::Done;
use fstp_cell_core::gate::{self, Action, Deny};
use fstp_cell_core::{CellCommand, SystemTask, system_command_id};
use fstp_checks::runner::{EvidenceInput, Fetch, LineInput, PartialEvidence, RequestInput, Rules};
use fstp_domain::id::{ContentDigest, ProposalId, RequestId, TextId, TextRef};
use fstp_domain::payment::{CheckPhase, ChecksInput};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_rt::ShutdownSignal;
use fstp_rt::future::{Either, race};

use super::Clock;
use crate::engine::{CellEngine, EngineError};

/// How often the runner looks for requests that await a run.
pub const TICK: Duration = Duration::from_secs(2);

/// The domain label of run command ids.
pub const ID_LABEL: &[u8] = b"fstp-checks-run-v1";

/// The most passes of one tick. A request needs at most two runs, so a
/// request submitted before a tick gets both in that tick.
const MAX_PASSES: usize = 4;

/// The P-65 option the runner applies until the policy record holds P-65:
/// "public deliverables", the stricter option and SuperSAFE's (I-62).
pub const PARTIAL_EVIDENCE: PartialEvidence = PartialEvidence::PublicDeliverables;

/// The command id of the `phase` run of `request` in the cell `cell`: an
/// HMAC-SHA256 keyed by the cell id, as the timeline's ids are, so two
/// cells never share an id for the same request (I-20, I-23).
pub fn run_id(cell: [u8; 16], request: RequestId, phase: CheckPhase) -> [u8; 16] {
    let mut msg = ID_LABEL.to_vec();
    msg.extend_from_slice(&request.raw().to_be_bytes());
    msg.push(match phase {
        CheckPhase::Submission => 1,
        CheckPhase::Acceptance => 2,
    });
    let digest = fstp_crypto::hmac_sha256(&cell, &msg);
    let mut suffix = [0u8; 8];
    for (d, s) in suffix.iter_mut().zip(digest.iter()) {
        *d = *s;
    }
    system_command_id(suffix)
}

/// Each run due in `core`, with its id, in request order: every request
/// that awaits a run whose id `committed` does not hold yet.
pub fn due(
    cell: [u8; 16],
    core: &State,
    committed: impl Fn([u8; 16]) -> bool,
) -> Vec<(RequestId, CheckPhase, [u8; 16])> {
    fstp_domain::payment::awaiting_checks(core)
        .into_iter()
        .map(|(r, p)| (r, p, run_id(cell, r, p)))
        .filter(|(_, _, id)| !committed(*id))
        .collect()
}

/// The future of [`EvidenceTexts::open`].
pub type OpenFuture<'a> =
    std::pin::Pin<Box<dyn Future<Output = Option<(TextClass, TextOwner, Vec<u8>)>> + Send + 'a>>;

/// The future of [`EvidenceTexts::put`].
pub type PutFuture<'a> = std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// Where the runner opens the evidence texts and stores its reasons: the
/// cell's erasure task in production ([`ErasureTexts`]).
pub trait EvidenceTexts: Send + Sync {
    /// The class, owner and bytes of text `id`, or `None` when it cannot
    /// be opened now.
    fn open(&self, id: TextId) -> OpenFuture<'_>;

    /// Stores `text` as the confidential text `id` of `grant`. `false`
    /// when it was not stored.
    fn put<'a>(&'a self, grant: ProposalId, id: TextId, text: &'a str) -> PutFuture<'a>;
}

/// What opening one evidence text gave.
enum Opened {
    /// The grant's own text, matching its digest.
    Text(String),
    /// Another owner's text, a digest mismatch or bytes that are not text:
    /// counted as missing evidence.
    Foreign,
    /// Not openable now.
    Unavailable,
}

async fn open_one<T: EvidenceTexts + ?Sized>(texts: &T, grant: ProposalId, r: TextRef) -> Opened {
    let Some((class, owner, bytes)) = texts.open(r.id()).await else {
        return Opened::Unavailable;
    };
    let own = class == TextClass::Confidential && owner == TextOwner::Proposal(grant);
    let digest = ContentDigest::from_bytes(fstp_crypto::sha256(&bytes));
    match String::from_utf8(bytes) {
        Ok(s) if own && digest == r.digest() => Opened::Text(s),
        _ => Opened::Foreign,
    }
}

async fn open_opt<T: EvidenceTexts + ?Sized>(
    texts: &T,
    grant: ProposalId,
    r: Option<TextRef>,
) -> Option<Option<String>> {
    match r {
        None => Some(None),
        Some(r) => match open_one(texts, grant, r).await {
            Opened::Text(s) => Some(Some(s)),
            Opened::Foreign => Some(None),
            Opened::Unavailable => None,
        },
    }
}

/// One run ready to record: the `RecordChecks` and the reason texts it
/// names, which the grant owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The grant.
    pub grant: ProposalId,
    /// Whether every check passed.
    pub passed: bool,
    /// The `RecordChecks`.
    pub command: fstp_domain::Command,
    /// Each reason text with the reference the command names it by.
    pub reasons: Vec<(TextRef, String)>,
}

fn minor(a: fstp_money::NonNegAmount) -> i64 {
    a.amount().minor()
}

/// The runner's input of `input`, with the evidence texts opened, or
/// `None` when a text cannot be opened now.
async fn request_input<T: EvidenceTexts + ?Sized>(
    input: &ChecksInput,
    texts: &T,
    now: Timestamp,
) -> Option<RequestInput> {
    let mut lines = Vec::with_capacity(input.lines.len());
    for l in &input.lines {
        let location = open_opt(texts, input.grant, l.evidence.location).await?;
        let release = open_opt(texts, input.grant, l.evidence.release).await?;
        lines.push(LineInput {
            line: l.line,
            milestone: l.milestone,
            amount: l.amount.amount().minor(),
            evidence: EvidenceInput {
                location,
                release,
                licence: l.evidence.licence.as_ref().map(|s| s.0.clone()),
                report: l.evidence.report.map(TextRef::digest),
            },
        });
    }
    Some(RequestInput {
        request: input.request,
        phase: input.phase,
        lines,
        available: input
            .available
            .iter()
            .map(|(m, a)| (*m, minor(*a)))
            .collect(),
        contract_total: minor(input.contract_total),
        claimed_elsewhere: input.claimed_elsewhere.map_or(0, minor),
        retrieved_at: now,
    })
}

/// A fresh random text id for a reason.
fn reason_id() -> Option<TextId> {
    fstp_crypto::random_array::<16>()
        .ok()
        .map(|b| TextId::from_raw(u128::from_be_bytes(b)))
}

/// Runs the checks of `request` in `core` at `now`, fetching through
/// `fetch`, and builds its `RecordChecks`. `None` when the request awaits
/// no run, or when an evidence text cannot be opened now.
pub async fn prepare<F: Fetch, T: EvidenceTexts + ?Sized>(
    core: &State,
    request: RequestId,
    fetch: &F,
    texts: &T,
    now: Timestamp,
) -> Option<Prepared> {
    let input = fstp_domain::payment::checks_input(core, request)?;
    let req = request_input(&input, texts, now).await?;
    let rules = Rules {
        licences: &input.licences,
        partial: PARTIAL_EVIDENCE,
    };
    let run = fstp_checks::runner::run(&req, &rules, fetch).await;
    let passed = run.passed();
    let mut ids = Vec::new();
    for _ in 0..run.outcomes.iter().filter(|o| o.failure.is_some()).count() {
        ids.push(reason_id()?);
    }
    let mut ids = ids.into_iter();
    let fallback = TextId::from_raw(0);
    let (command, reasons) = run.into_command(|| ids.next().unwrap_or(fallback));
    Some(Prepared {
        grant: input.grant,
        passed,
        command,
        reasons,
    })
}

/// What one run of a tick got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunResult {
    /// An evidence text or a reason could not be read or stored now. The
    /// request waits for the next tick.
    Waiting,
    /// The gate refused to admit the command.
    Denied(Deny),
    /// The engine ran it: a commit, a duplicate, or a refusal.
    Ran(Result<Done, EngineError>),
}

/// One run of a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunItem {
    /// The request.
    pub request: RequestId,
    /// The phase.
    pub phase: CheckPhase,
    /// Its command id.
    pub id: [u8; 16],
    /// Whether every check passed, once the checks ran.
    pub passed: Option<bool>,
    /// What it got.
    pub result: RunResult,
}

/// Records `prepared` under `id`: its reasons first, then the command as
/// the system task `PaymentPort`.
async fn record<T: EvidenceTexts + ?Sized>(
    engine: &CellEngine,
    texts: &T,
    prepared: Prepared,
    id: [u8; 16],
    now: Timestamp,
) -> RunResult {
    for (r, why) in &prepared.reasons {
        if !texts.put(prepared.grant, r.id(), why).await {
            return RunResult::Waiting;
        }
    }
    let command = CellCommand::Engine(fstp_engine::Command::Core(prepared.command));
    match gate::admit_system(
        &engine.state(),
        Action::Command(command),
        SystemTask::PaymentPort,
        id,
        now,
    ) {
        Err(d) => RunResult::Denied(d),
        Ok(a) => RunResult::Ran(engine.execute(a).await),
    }
}

/// One tick at `now`: each due run in turn, then again while a pass
/// recorded something, so a submission run that passed is followed by the
/// acceptance run in the same tick. A request whose run is waiting is not
/// tried again before the next tick.
pub async fn tick<F: Fetch, T: EvidenceTexts + ?Sized>(
    engine: &CellEngine,
    fetch: &F,
    texts: &T,
    now: Timestamp,
) -> Vec<RunItem> {
    let mut out = Vec::new();
    let mut waiting: BTreeSet<RequestId> = BTreeSet::new();
    for _ in 0..MAX_PASSES {
        let state = engine.state();
        let runs = due(engine.cell(), &state.engine().core, |id| {
            state.committed(id).is_some()
        });
        let mut recorded = false;
        for (request, phase, id) in runs {
            if waiting.contains(&request) {
                continue;
            }
            let now_state = engine.state();
            let (passed, result) =
                match prepare(&now_state.engine().core, request, fetch, texts, now).await {
                    None => (None, RunResult::Waiting),
                    Some(p) => {
                        let passed = p.passed;
                        (Some(passed), record(engine, texts, p, id, now).await)
                    }
                };
            match &result {
                RunResult::Ran(Ok(_)) => recorded = true,
                _ => {
                    waiting.insert(request);
                }
            }
            out.push(RunItem {
                request,
                phase,
                id,
                passed,
                result,
            });
        }
        if !recorded {
            break;
        }
    }
    out
}

/// Runs the checks every [`TICK`] until `stop` is triggered.
pub async fn run<C: Clock, F: Fetch, T: EvidenceTexts + ?Sized>(
    clock: &C,
    engine: &CellEngine,
    fetch: &F,
    texts: &T,
    stop: &ShutdownSignal,
) {
    let step = i64::try_from(TICK.as_micros()).unwrap_or(i64::MAX);
    loop {
        let now = clock.now();
        let _ = tick(engine, fetch, texts, Timestamp::from_micros(now)).await;
        let next = now.saturating_add(step);
        match race(stop.notified(), clock.sleep_until(next)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
    }
}

/// The evidence texts of the cell's erasure task, in the stored form of
/// the text store (`crate::api`): the class and owner sealed in front of
/// the text, each text under a data key of its own.
#[derive(Clone, Debug)]
pub struct ErasureTexts(pub super::erasure::ErasureHandle);

impl EvidenceTexts for ErasureTexts {
    fn open(&self, id: TextId) -> OpenFuture<'_> {
        Box::pin(async move {
            let plain = self.0.open_text(id.raw().to_be_bytes()).await.ok()?;
            let (class, owner, body) = crate::api::parse_text(&plain)?;
            Some((class, owner, body.to_vec()))
        })
    }

    fn put<'a>(&'a self, grant: ProposalId, id: TextId, text: &'a str) -> PutFuture<'a> {
        Box::pin(async move {
            let Ok(group) = fstp_crypto::random_array::<16>() else {
                return false;
            };
            let mut plain =
                crate::api::text_header(TextClass::Confidential, TextOwner::Proposal(grant))
                    .to_vec();
            plain.extend_from_slice(text.as_bytes());
            self.0.add_group(group).await.is_ok()
                && self
                    .0
                    .put_text(group, id.raw().to_be_bytes(), plain)
                    .await
                    .is_ok()
        })
    }
}

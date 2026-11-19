//! The pre-check provider of test and demo cells (M7 design sections 4
//! and 7; R-LA-06, I-21). Test only (layering rule A9).
//!
//! A run strips the draft in the cell (`fstp_assessor::CellJob`), sends
//! one job line through a [`Link`] and validates the result line before
//! anything is kept (I-10). The default link runs the synthetic model in
//! this process. The e2e cell sets a child link to the real
//! `fstp-assessor` binary, so the demo crosses the process boundary.
//!
//! Runs live here, beside the draft, keyed by proposal. They never enter
//! the `FindingStore` (I-21). A run whose assessor cannot be reached is
//! kept as `Unavailable` with no findings, and it still counts (P-23,
//! R-NF-10). The P-23 limits are counted by the API core when the run is
//! requested, so this port only runs and stores.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    Clock, InferenceProvider, PortError, Precheck, PrecheckEvidence, PrecheckFinding,
    PrecheckQuota, PrecheckRefusal, PrecheckRun, PrecheckRunId, PrecheckRunState, PrecheckSection,
    PrecheckSnapshot,
};
use fstp_assess::{SubmissionPart, SyntheticNameMask};
use fstp_assessor::{CellJob, Intake, JobConfig, Link};
use fstp_domain::id::{AccountId, ContentDigest, ProposalId, TextId, TextRef};
use fstp_findings::{EvidenceRef, UntrustedText};
use fstp_infer::{DataLabel, Decoding, ModelName, Protocol};

use super::{FakeClock, FakeEngine, lock};

/// The most runs one proposal keeps.
const MAX_RUNS: usize = 64;

/// The pre-check provider. Cloning shares its runs and its link.
#[derive(Clone, Debug)]
pub struct FakePrecheck {
    clock: FakeClock,
    link: Arc<Mutex<Link>>,
    runs: Arc<Mutex<BTreeMap<ProposalId, Vec<PrecheckRun>>>>,
    next: Arc<Mutex<u128>>,
    /// The engine handle a re-run records through, as the system. The
    /// API core issues no system command (I-84), so the provider does.
    engine: Option<FakeEngine>,
}

/// What one run of the full assessment gave (issue 6 M3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessmentRun {
    /// The findings of the run, each under the call's pin (I-11).
    pub findings: Vec<fstp_findings::Finding>,
    /// The stages the validator dropped.
    pub refused: Vec<fstp_findings::RefusedStage>,
}

impl FakePrecheck {
    /// A provider on `clock` that runs the synthetic model in process.
    pub fn new(clock: FakeClock) -> FakePrecheck {
        FakePrecheck {
            clock,
            link: Arc::new(Mutex::new(Link::InProcess)),
            runs: Arc::default(),
            next: Arc::new(Mutex::new(1)),
            engine: None,
        }
    }

    /// Gives the provider the engine handle a re-run records through.
    #[must_use]
    pub fn with_engine(mut self, engine: FakeEngine) -> FakePrecheck {
        self.engine = Some(engine);
        self
    }

    /// Records the result of an assessment of `proposal` as the system
    /// (issue 6 M3, I-10: the only path from the assessor to domain state
    /// is `Record` and `RecordRefusals`). A finding with the kind,
    /// criterion and statement of one the proposal holds is skipped. A run
    /// that gave nothing records the earlier list again, which ends the run
    /// in flight and changes nothing else (R-NF-10).
    fn record_run(
        &self,
        engine: &FakeEngine,
        snapshot: &PrecheckSnapshot,
        proposal: ProposalId,
        run: Option<AssessmentRun>,
    ) {
        use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
        use fstp_engine::{Command, FindingCommand};
        let call = snapshot.pin.call;
        let state = engine.state();
        let earlier = state.findings.refusals_of(proposal).to_vec();
        let have: Vec<_> = state
            .findings
            .findings_of(call)
            .into_iter()
            .filter(|f| f.proposal == proposal)
            .map(|f| (f.kind, f.criterion, f.statement.as_data().to_owned()))
            .collect();
        let (findings, refused) = run.map_or((Vec::new(), earlier), |r| (r.findings, r.refused));
        let exec = |cmd: FindingCommand| {
            static COMMANDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = COMMANDS
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            let mut id = *b"fstp:fake:rerun\0";
            for (slot, b) in id.iter_mut().skip(8).zip(n.to_be_bytes()) {
                *slot = b;
            }
            let ctx = Ctx {
                now: self.clock.now(),
                actor: Actor::System(SystemCause::Timeline),
                command: fstp_domain::id::CommandId::from_bytes(id),
                via: Via::Web,
                tenant_admin: false,
                second_tenant_admin: None,
                binds_tenant_admin: false,
            };
            let _ = engine.environment(Command::Finding(cmd), ctx);
        };
        for f in findings {
            let key = (f.kind, f.criterion, f.statement.as_data().to_owned());
            if f.call == call && f.proposal == proposal && !have.contains(&key) {
                exec(FindingCommand::Record(f));
            }
        }
        exec(FindingCommand::RecordRefusals {
            call,
            proposal,
            refused,
        });
    }

    /// Sends every later run through `link`, such as the child process of
    /// the e2e cell.
    pub fn set_link(&self, link: Link) {
        *lock(&self.link) = link;
    }

    /// The link runs go through.
    pub fn link(&self) -> Link {
        lock(&self.link).clone()
    }
}

/// The text reference of section `k` of run `run`.
fn text_ref(run: u128, k: u128, text: &str) -> TextRef {
    TextRef::new(
        TextId::from_raw(run.saturating_mul(10).saturating_add(k)),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

/// The job configuration of a snapshot's pin (I-11).
pub fn job_config(s: &PrecheckSnapshot) -> Option<JobConfig> {
    let e = s.pin.endpoint.as_ref();
    let protocol = match e.map(|e| e.provider) {
        Some(InferenceProvider::ChatCompletions) => Protocol::ChatCompletions,
        _ => Protocol::Anthropic,
    };
    let criteria = s.pin.criteria.clone();
    if criteria.is_empty() || criteria.len() > fstp_assessor::MAX_CRITERIA {
        return None;
    }
    Some(JobConfig {
        protocol,
        model: ModelName::new(&s.pin.model.0).ok()?,
        decoding: Decoding {
            max_tokens: e.map_or(2048, |e| e.max_tokens),
            temperature_milli: e.map_or(0, |e| e.temperature_milli),
            seed: e.map_or(0, |e| e.seed),
        },
        criteria,
    })
}

/// Runs one pre-check of `s` through `link` and returns its findings, or
/// `None` when the assessor could not answer or its answer was refused.
pub async fn run_snapshot(
    link: &Link,
    run: u128,
    proposal: ProposalId,
    s: &PrecheckSnapshot,
) -> Option<Vec<PrecheckFinding>> {
    let config = job_config(s)?;
    let sections = [
        (PrecheckSection::Title, DataLabel::Title, &s.title),
        (PrecheckSection::Summary, DataLabel::Summary, &s.summary),
        (
            PrecheckSection::Narrative,
            DataLabel::Narrative,
            &s.narrative,
        ),
    ];
    let mut parts = Vec::new();
    let mut by_ref = Vec::new();
    for (k, (section, label, text)) in (1_u128..).zip(sections) {
        if text.as_data().trim().is_empty() {
            continue;
        }
        let r = text_ref(run, k, text.as_data());
        by_ref.push((r, section, text.as_data()));
        parts.push(SubmissionPart {
            label,
            text_ref: r,
            text: text.clone(),
        });
    }
    if parts.is_empty() {
        return Some(Vec::new());
    }
    let job = CellJob::prepare(
        run,
        proposal,
        config,
        parts,
        Vec::new(),
        &SyntheticNameMask::new(Vec::new()),
    )
    .await
    .ok()?;
    let lines = link.run(&[job.line().to_line()]).await.ok()?;
    let Intake::Done { findings, .. } = job.intake(lines.first()?).ok()? else {
        return None;
    };
    Some(
        findings
            .into_iter()
            .map(|f| PrecheckFinding {
                kind: f.kind,
                criterion: f.criterion,
                element: f.element.map(|e| e.as_str().to_owned()),
                severity: f.severity,
                statement: f.statement,
                evidence: f
                    .evidence
                    .iter()
                    .filter_map(|e| match e {
                        EvidenceRef::Submission { text, start, end } => {
                            let (_, section, original) =
                                by_ref.iter().find(|(r, _, _)| r == text)?;
                            let quote = original.get(*start as usize..*end as usize)?;
                            Some(PrecheckEvidence {
                                section: *section,
                                quote: UntrustedText::new(quote.to_owned()),
                            })
                        }
                        EvidenceRef::Retrieved { .. } => None,
                    })
                    .collect(),
            })
            .collect(),
    )
}

impl Precheck for FakePrecheck {
    fn can_rerun(&self) -> bool {
        self.engine.is_some()
    }

    async fn start_rerun(
        &self,
        proposal: ProposalId,
        snapshot: PrecheckSnapshot,
    ) -> Result<(), PortError> {
        let Some(engine) = self.engine.clone() else {
            return Err(PortError::Unavailable);
        };
        let run = {
            let mut n = lock(&self.next);
            let r = *n;
            *n = n.saturating_add(1);
            r
        };
        let link = self.link();
        let result = assess_snapshot(&link, run, proposal, &snapshot).await;
        self.record_run(&engine, &snapshot, proposal, result);
        Ok(())
    }

    async fn request(
        &self,
        proposal: ProposalId,
        account: AccountId,
        snapshot: PrecheckSnapshot,
    ) -> Result<PrecheckRunId, PrecheckRefusal> {
        let _ = account;
        let run = {
            let mut n = lock(&self.next);
            let r = *n;
            *n = n.saturating_add(1);
            r
        };
        let requested = self.clock.now();
        let link = self.link();
        let found = run_snapshot(&link, run, proposal, &snapshot).await;
        let entry = PrecheckRun {
            run: PrecheckRunId::from_raw(run),
            requested,
            config: snapshot.pin.config,
            state: if found.is_some() {
                PrecheckRunState::Done
            } else {
                PrecheckRunState::Unavailable
            },
            findings: found.unwrap_or_default(),
        };
        let mut runs = lock(&self.runs);
        let list = runs.entry(proposal).or_default();
        list.insert(0, entry);
        list.truncate(MAX_RUNS);
        Ok(PrecheckRunId::from_raw(run))
    }

    async fn runs(&self, proposal: ProposalId) -> Result<Vec<PrecheckRun>, PortError> {
        Ok(lock(&self.runs).get(&proposal).cloned().unwrap_or_default())
    }

    async fn quota(
        &self,
        proposal: ProposalId,
        account: AccountId,
    ) -> Result<PrecheckQuota, PortError> {
        // The API core counts P-23 (dispatch `precheck.rs`); this port
        // holds no counts of its own.
        let _ = (proposal, account);
        Err(PortError::Unavailable)
    }
}

/// Runs the full assessment of `s` through `link` (issue 6 M3, I-10,
/// I-11): the findings under the call's pin and the stages the validator
/// dropped, as stage and code only. `None` when the assessor could not
/// answer or its answer was refused.
pub async fn assess_snapshot(
    link: &Link,
    run: u128,
    proposal: ProposalId,
    s: &PrecheckSnapshot,
) -> Option<AssessmentRun> {
    let config = job_config(s)?;
    let sections = [
        (DataLabel::Title, &s.title),
        (DataLabel::Summary, &s.summary),
        (DataLabel::Narrative, &s.narrative),
    ];
    let mut parts = Vec::new();
    for (k, (label, text)) in (1_u128..).zip(sections) {
        if text.as_data().trim().is_empty() {
            continue;
        }
        parts.push(SubmissionPart {
            label,
            text_ref: text_ref(run, k, text.as_data()),
            text: text.clone(),
        });
    }
    let job = CellJob::prepare(
        run,
        proposal,
        config,
        parts,
        Vec::new(),
        &SyntheticNameMask::new(Vec::new()),
    )
    .await
    .ok()?;
    let lines = link.run(&[job.line().to_line()]).await.ok()?;
    let Intake::Done {
        findings, refused, ..
    } = job.intake(lines.first()?).ok()?
    else {
        return None;
    };
    let findings = (1_u128..)
        .zip(findings)
        .map(|(k, f)| fstp_findings::Finding {
            id: fstp_findings::FindingId::from_raw(
                70_000_000_000_u128
                    .saturating_add(run.saturating_mul(1_000))
                    .saturating_add(k),
            ),
            call: s.pin.call,
            proposal,
            config: s.pin.config,
            kind: f.kind,
            criterion: f.criterion,
            severity: f.severity,
            confidence: fstp_findings::Confidence::from_permille(0)
                .unwrap_or(fstp_findings::Confidence::FULL),
            statement: f.statement,
            evidence: f.evidence,
            trace: fstp_findings::TraceRef::from_raw(run),
        })
        .collect();
    let refused = refused
        .iter()
        .filter_map(|r| fstp_findings::RefusedStage::parse(r.stage, r.code))
        .collect();
    Some(AssessmentRun { findings, refused })
}

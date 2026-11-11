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

use super::{FakeClock, lock};

/// The most runs one proposal keeps.
const MAX_RUNS: usize = 64;

/// The pre-check provider. Cloning shares its runs and its link.
#[derive(Clone, Debug)]
pub struct FakePrecheck {
    clock: FakeClock,
    link: Arc<Mutex<Link>>,
    runs: Arc<Mutex<BTreeMap<ProposalId, Vec<PrecheckRun>>>>,
    next: Arc<Mutex<u128>>,
}

impl FakePrecheck {
    /// A provider on `clock` that runs the synthetic model in process.
    pub fn new(clock: FakeClock) -> FakePrecheck {
        FakePrecheck {
            clock,
            link: Arc::new(Mutex::new(Link::InProcess)),
            runs: Arc::default(),
            next: Arc::new(Mutex::new(1)),
        }
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

//! The assessment of the e2e cell (M7 design section 7, lane L-DEMO).
//! Test only (layering rule A9).
//!
//! `--assessor synthetic` (the default) or `--assessor replay:<dir>`
//! picks how the cell reaches a model. Either way the cell spawns the
//! real `fstp-assessor` binary beside its own executable, with
//! `--inference synthetic` or `--inference replay:<dir>`, so the process
//! boundary, the stripping, the encoding, the result validation and the
//! recording all run offline. No real model is called. A `live:` value is
//! refused: the demo never calls a model API (Q1, Q2).
//!
//! When a seed submits a proposal, [`on_submit`] assesses it at once:
//! stages 1 and 2 in the cell, one job line to the child, intake of the
//! result line, and one `FindingCommand::Record` per finding under a
//! system actor. That is the only path from the assessor to domain state
//! (I-10). The findings carry the call's pin (I-11). When the child is
//! missing or fails, nothing is recorded and the proposal reads "pending"
//! on the coordinator's board (R-NF-10).
//!
//! The demo proposals take their narratives from the synthetic corpus
//! (`corpus/v1`, generator `template-v1`): a clean item, an omission, a
//! direct injection, a hidden-character injection and an inflated claim.
//! The contact block of each item is left out, so no corpus person data
//! reaches a reviewer page.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fstp_assess::{SubmissionPart, SyntheticNameMask};
use fstp_assessor::{CellJob, Intake, JobConfig, Link};
use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::id::{CallId, CommandId, ContentDigest, ProposalId, TextId, TextRef};
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, FindingCommand};
use fstp_findings::{Confidence, Finding, FindingId, TraceRef, UntrustedText};
use fstp_infer::{DataLabel, Decoding, ModelName, Protocol};
use fstp_json::Value;

use crate::Inner;

/// How the cell reaches a model (`--assessor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The synthetic model in the child process. Never an LLM result.
    Synthetic,
    /// Saved responses only, from this directory.
    Replay(PathBuf),
}

impl Mode {
    /// Reads an `--assessor` value.
    pub(crate) fn parse(s: &str) -> Result<Mode, String> {
        if s == "synthetic" {
            return Ok(Mode::Synthetic);
        }
        if let Some(dir) = s.strip_prefix("replay:").filter(|d| !d.is_empty()) {
            return Ok(Mode::Replay(PathBuf::from(dir)));
        }
        if s.starts_with("live:") {
            return Err(
                "--assessor live: is not wired in the demo cell; it never calls a model API (M7 Q1, Q2)"
                    .to_owned(),
            );
        }
        Err(format!("unknown --assessor value {s}"))
    }
}

static MODE: OnceLock<Mode> = OnceLock::new();

/// Sets the cell's mode once, at start.
pub(crate) fn set_mode(m: Mode) {
    let _ = MODE.set(m);
}

/// The mode, synthetic unless `--assessor` said otherwise.
pub(crate) fn mode() -> Mode {
    MODE.get().cloned().unwrap_or(Mode::Synthetic)
}

/// The child link of the mode: the `fstp-assessor` binary beside this
/// executable. Without a known executable path, the link points at a
/// binary that does not exist, so every job stays pending (R-NF-10).
pub(crate) fn link() -> Link {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("fstp-assessor")))
        .unwrap_or_else(|| PathBuf::from("fstp-assessor-not-found"));
    let inference = match mode() {
        Mode::Synthetic => "synthetic".to_owned(),
        Mode::Replay(dir) => format!("replay:{}", dir.display()),
    };
    Link::Child {
        exe,
        args: vec!["--inference".to_owned(), inference],
        timeout: Duration::from_secs(60),
    }
}

/// The tenant's endpoint record for the mode: provider `synthetic` in
/// synthetic mode, so every panel says "Synthetic assessor (demo)".
pub(crate) fn endpoint() -> fstp_api_core::port::InferenceEndpoint {
    fstp_api_core::port::InferenceEndpoint {
        provider: match mode() {
            Mode::Synthetic => fstp_api_core::port::InferenceProvider::Synthetic,
            Mode::Replay(_) => fstp_api_core::port::InferenceProvider::Anthropic,
        },
        url: None,
        max_tokens: 2048,
        temperature_milli: 0,
        seed: 0,
        fallbacks: Vec::new(),
        trust_anchors_pem: Vec::new(),
    }
}

/// The corpus items of the demo proposals, by seed key.
const CORPUS: [(&str, &str); 5] = [
    ("x", include_str!("../../../../../corpus/v1/items/b01.json")),
    (
        "z",
        include_str!("../../../../../corpus/v1/items/b02-omission.json"),
    ),
    (
        "w",
        include_str!("../../../../../corpus/v1/items/b01-direct.json"),
    ),
    (
        "v",
        include_str!("../../../../../corpus/v1/items/b02-hidden.json"),
    ),
    (
        "u",
        include_str!("../../../../../corpus/v1/items/b01-inflated.json"),
    ),
];

/// The narrative of the corpus item of seed key `key`, without its
/// contact block, or `None` for a key without one.
pub(crate) fn corpus_narrative(key: &str) -> Option<String> {
    let (_, json) = CORPUS.iter().find(|(k, _)| *k == key)?;
    let v = fstp_json::parse(json.as_bytes()).ok()?;
    let n = v
        .get("proposal")?
        .get("narrative")
        .and_then(Value::as_str)?;
    let body = n.split_once("\n\nContact\n").map_or(n, |(head, _)| head);
    Some(body.trim_end().to_owned())
}

static COMMANDS: AtomicU32 = AtomicU32::new(0);
static FINDINGS: AtomicU32 = AtomicU32::new(0);

/// A fresh command id for a system command of this module.
fn command_id() -> CommandId {
    let n = COMMANDS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let mut id = *b"fstp:e2e:assess\0";
    for (slot, b) in id.iter_mut().skip(12).zip(n.to_be_bytes()) {
        *slot = b;
    }
    CommandId::from_bytes(id)
}

/// The text reference of section `k` of `proposal`'s submission.
fn text_ref(proposal: ProposalId, k: u128, text: &str) -> TextRef {
    TextRef::new(
        TextId::from_raw(
            90_000_000_u128
                .saturating_add(proposal.raw().saturating_mul(10))
                .saturating_add(k),
        ),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

/// What one assessment did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Assessed {
    /// This many findings were recorded.
    Recorded(usize),
    /// The assessor was unreachable or its result was refused. Nothing
    /// was recorded (R-NF-10, I-10).
    Pending,
}

/// Assesses the submitted texts of `proposal` in `call` at `now` through
/// `link` and records every finding through `FindingCommand::Record`.
///
/// # Errors
///
/// A refusal of a `Record` command, which would be a bug in the intake.
pub(crate) async fn assess(
    inner: &Inner,
    link: &Link,
    now: Timestamp,
    call: CallId,
    proposal: ProposalId,
    texts: [&str; 3],
) -> Result<Assessed, String> {
    let state = inner.ports.engine.state();
    let Some(view) = state.core.calls().get(call) else {
        return Err(format!("call {} is unknown", call.raw()));
    };
    let (Some(config), Some(frozen)) = (view.llm_config(), view.frozen()) else {
        return Err("the call has no assessor pin".to_owned());
    };
    let values = frozen.values();
    let criteria = values.p01.items().iter().map(|c| c.id).collect();
    let Ok(model) = ModelName::new(&values.p21.primary.0) else {
        return Ok(Assessed::Pending);
    };
    let job_config = JobConfig {
        protocol: Protocol::Anthropic,
        model,
        decoding: Decoding {
            max_tokens: 2048,
            temperature_milli: 0,
            seed: 0,
        },
        criteria,
    };
    let labels = [DataLabel::Title, DataLabel::Summary, DataLabel::Narrative];
    let parts = (1_u128..)
        .zip(labels.into_iter().zip(texts))
        .map(|(k, (label, text))| SubmissionPart {
            label,
            text_ref: text_ref(proposal, k, text),
            text: UntrustedText::new(text.to_owned()),
        })
        .collect();
    let job_id = u128::from(COMMANDS.load(Ordering::Relaxed))
        .saturating_add(proposal.raw().saturating_mul(1_000));
    let Ok(job) = CellJob::prepare(
        job_id,
        proposal,
        job_config,
        parts,
        Vec::new(),
        &SyntheticNameMask::new(Vec::new()),
    )
    .await
    else {
        return Ok(Assessed::Pending);
    };
    let Ok(lines) = link.run(&[job.line().to_line()]).await else {
        return Ok(Assessed::Pending);
    };
    let Some(Ok(Intake::Done { findings, .. })) = lines.first().map(|l| job.intake(l)) else {
        return Ok(Assessed::Pending);
    };
    let n = findings.len();
    for f in findings {
        let id = 50_000_000_u128
            .saturating_add(proposal.raw().saturating_mul(1_000))
            .saturating_add(u128::from(
                FINDINGS.fetch_add(1, Ordering::Relaxed).saturating_add(1),
            ));
        let finding = Finding {
            id: FindingId::from_raw(id),
            call,
            proposal,
            config,
            kind: f.kind,
            criterion: f.criterion,
            severity: f.severity,
            // The synthetic model reports no confidence of its own.
            confidence: Confidence::from_permille(0).unwrap_or(Confidence::FULL),
            statement: f.statement,
            evidence: f.evidence,
            trace: TraceRef::from_raw(job_id),
        };
        let ctx = Ctx {
            now,
            actor: Actor::System(SystemCause::Timeline),
            command: command_id(),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        inner
            .ports
            .engine
            .environment(Command::Finding(FindingCommand::Record(finding)), ctx)
            .map_err(|e| format!("a finding by the assessor: {e}"))?;
    }
    Ok(Assessed::Recorded(n))
}

/// Assesses a proposal the seed just submitted, through the cell's link.
///
/// # Errors
///
/// As [`assess`].
pub(crate) async fn on_submit(
    inner: &Inner,
    now: Timestamp,
    call: CallId,
    proposal: ProposalId,
    texts: [&str; 3],
) -> Result<Assessed, String> {
    let link = inner.ports.precheck.link();
    assess(inner, &link, now, call, proposal, texts).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M7 design section 7: the five demo narratives come from the
    /// corpus, without the contact block, and the injected items keep
    /// their injection as data.
    #[test]
    fn m7_demo_narratives_come_from_the_corpus() {
        for key in ["x", "z", "w", "v", "u"] {
            let n = corpus_narrative(key).unwrap();
            assert!(n.starts_with("Problem\n"), "{key}");
            assert!(!n.contains("@example.org"), "{key}: no contact block");
        }
        assert!(corpus_narrative("w").unwrap().contains("Assessment system"));
        assert!(
            corpus_narrative("v")
                .unwrap()
                .chars()
                .any(|c| ('\u{e0000}'..='\u{e007f}').contains(&c))
        );
        assert!(
            !corpus_narrative("z")
                .unwrap()
                .contains("Team and experience")
        );
        assert_eq!(corpus_narrative("q"), None);
    }

    /// M7 design section 7: `--assessor` takes synthetic and replay, and
    /// refuses live, so the demo never calls a model API.
    #[test]
    fn m7_assessor_flag_refuses_live() {
        assert_eq!(Mode::parse("synthetic"), Ok(Mode::Synthetic));
        assert_eq!(
            Mode::parse("replay:/tmp/r"),
            Ok(Mode::Replay(PathBuf::from("/tmp/r")))
        );
        assert!(Mode::parse("live:/etc/x").is_err());
        assert!(Mode::parse("replay:").is_err());
        assert!(Mode::parse("other").is_err());
    }

    fn info() -> crate::SiteInfo {
        crate::SiteInfo {
            name: "a",
            host: "a.fstp.localhost".to_owned(),
            origin: "http://a.fstp.localhost:8640".to_owned(),
            control: "http://127.0.0.1:8641".to_owned(),
            assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
                .unwrap(),
            auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
            demo_signin: false,
        }
    }

    /// I-10, I-11, R-LA-01, M7 design section 7: a submission assessed
    /// through the queue line handling enters the ledger only through
    /// `FindingCommand::Record`, every finding under the call's pin. The
    /// direct injection of w is an integrity finding, never an instruction.
    #[test]
    fn i11_demo_findings_enter_through_record_under_the_pin() {
        let stage = crate::scenario::ReviewAt::parse("stage1").unwrap();
        let (inner, _) =
            fstp_rt::future::block_on(crate::scenario::build_review(&info(), stage)).unwrap();
        let call = CallId::from_raw(1);
        let w = ProposalId::from_raw(1003);
        let before = inner.ports.engine.state().findings.findings_of(call).len();
        let n = corpus_narrative("w").unwrap();
        let done = fstp_rt::future::block_on(assess(
            &inner,
            &Link::InProcess,
            Timestamp::from_micros(1_793_350_900_000_000),
            call,
            w,
            ["Synthetic mesh router firmware", "Free firmware.", &n],
        ))
        .unwrap();
        let Assessed::Recorded(k) = done else {
            panic!("the in-process run completes");
        };
        let state = inner.ports.engine.state();
        let pin = state
            .core
            .calls()
            .get(call)
            .and_then(|c| c.llm_config())
            .unwrap();
        let all = state.findings.findings_of(call);
        assert_eq!(all.len(), before + k);
        assert!(all.iter().all(|f| f.config == pin), "I-11");
        assert!(
            all.iter()
                .any(|f| f.proposal == w && f.kind == fstp_findings::FindingKind::Integrity)
        );
    }

    /// R-NF-10: an unreachable assessor records nothing; the proposal
    /// stays pending.
    #[test]
    fn r_nf_10_unreachable_assessor_records_nothing() {
        let stage = crate::scenario::ReviewAt::parse("submitted").unwrap();
        let (inner, _) =
            fstp_rt::future::block_on(crate::scenario::build_review(&info(), stage)).unwrap();
        let call = CallId::from_raw(1);
        let before = inner.ports.engine.state().findings.findings_of(call).len();
        let missing = Link::Child {
            exe: PathBuf::from("/nonexistent/fstp-assessor"),
            args: Vec::new(),
            timeout: Duration::from_secs(1),
        };
        let done = fstp_rt::future::block_on(assess(
            &inner,
            &missing,
            Timestamp::from_micros(1_793_350_900_000_000),
            call,
            ProposalId::from_raw(1001),
            ["t", "s", "n"],
        ))
        .unwrap();
        assert_eq!(done, Assessed::Pending);
        assert_eq!(
            inner.ports.engine.state().findings.findings_of(call).len(),
            before
        );
    }
}

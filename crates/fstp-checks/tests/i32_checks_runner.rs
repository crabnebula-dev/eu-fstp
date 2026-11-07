//! I-32, R-PR-02, R-PR-03, TH-24, I-58, I-31, I-62, P-26, P-34, P-65: the
//! checks runner over a synthetic forge, recorded through `RecordChecks`
//! into the M-PAY world of `fstp-domain-testkit`.
//!
//! The world grants lead c 4.00 over two milestones of 2.00 and starts
//! execution. The testkit's synthetic checks runner is off, so only this
//! runner moves a request out of SUBMITTED.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, ready};
use std::sync::Mutex;

use fstp_checks::runner::{
    CheckRun, EvidenceInput, Fetch, FetchFault, Fetched, LineInput, PartialEvidence, RequestInput,
    Rules, run,
};
use fstp_checks::snapshot::Retrieval;
use fstp_checks::url::DeliverableUrl;
use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::id::{ContentDigest, LineId, MilestoneId, RequestId, TextId};
use fstp_domain::payment::{CheckKind, CheckPhase, PaymentKind};
use fstp_domain::policy::{LicenceSet, SpdxId};
use fstp_domain::record::Record;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{LC, MoneyWorld, PC, milestone_n, request_payment_as};
use fstp_domain_testkit::r#gen::roster::{Backend, Flags, Step};
use fstp_domain_testkit::mc::pay_model::pay_world;
use fstp_domain_testkit::reference::payment::RequestState;

const REPO: &str = "https://forge.example/synthetic/alpha";
const PAGE: &[u8] = b"<html>synthetic repository alpha</html>";
const EUPL: &[u8] = b"Synthetic licence file\nSPDX-License-Identifier: EUPL-1.2\n";

/// A synthetic forge: a map from URL to status and body. Unknown URLs
/// answer 404. Hosts in `refused` stand for the cell egress refusal.
#[derive(Default)]
struct Forge {
    pages: Mutex<BTreeMap<String, (u16, Vec<u8>)>>,
    refused: BTreeSet<String>,
}

impl Forge {
    fn standard() -> Forge {
        let f = Forge::default();
        f.put(REPO, 200, PAGE);
        f.put(&format!("{REPO}/raw/v1.0.0/LICENSE"), 200, EUPL);
        f
    }

    fn put(&self, url: &str, status: u16, body: &[u8]) {
        self.pages
            .lock()
            .unwrap()
            .insert(url.to_owned(), (status, body.to_vec()));
    }
}

impl Fetch for Forge {
    fn fetch(
        &self,
        url: &DeliverableUrl,
    ) -> impl Future<Output = Result<Fetched, FetchFault>> + Send {
        let out = if self.refused.contains(url.host()) {
            Err(FetchFault::Refused)
        } else {
            let pages = self.pages.lock().unwrap();
            let (status, body) = pages
                .get(&url.to_string())
                .cloned()
                .unwrap_or((404, Vec::new()));
            Ok(Fetched { status, body })
        };
        ready(out)
    }
}

fn p26() -> LicenceSet {
    LicenceSet(
        ["EUPL-1.2", "MIT", "Apache-2.0"]
            .iter()
            .map(|s| SpdxId((*s).to_owned()))
            .collect(),
    )
}

fn milestone(n: u8) -> MilestoneId {
    milestone_n(PC, u128::from(n))
}

fn request_id(n: u128) -> RequestId {
    RequestId::from_raw(61_000u128.saturating_add(n))
}

fn line_id(n: u128) -> LineId {
    LineId::from_raw(161_000u128.saturating_add(n))
}

fn evidence(release: &str, licence: &str) -> EvidenceInput {
    EvidenceInput {
        location: Some(REPO.to_owned()),
        release: Some(release.to_owned()),
        licence: Some(licence.to_owned()),
        report: Some(ContentDigest::from_bytes([3; 32])),
    }
}

/// The runner input of request `n`: one line of `cents` on milestone 0,
/// whose 2.00 is still available.
fn input(n: u128, phase: CheckPhase, cents: i64, ev: EvidenceInput) -> RequestInput {
    RequestInput {
        request: request_id(n),
        phase,
        lines: vec![LineInput {
            line: line_id(n),
            milestone: milestone(0),
            amount: cents,
            evidence: ev,
        }],
        available: [(milestone(0), 200), (milestone(1), 200)].into(),
        contract_total: 400,
        claimed_elsewhere: 0,
        retrieved_at: Timestamp::from_micros(1_800_000_000_000_000),
    }
}

fn rules(p26: &LicenceSet, partial: PartialEvidence) -> Rules<'_> {
    Rules {
        licences: p26,
        partial,
    }
}

fn exec<F: Future>(f: F) -> F::Output {
    fstp_rt::future::block_on(f)
}

/// The world with request `n` of `cents` on milestone 0 in SUBMITTED.
fn submitted(n: u128, cents: i64) -> MoneyWorld {
    let mut w = pay_world(Backend::Production).unwrap();
    w.auto_checks = false;
    let step = request_payment_as(
        LC,
        request_id(n),
        PC,
        PaymentKind::Milestone,
        &[(line_id(n), milestone(0), cents)],
        None,
    )
    .unwrap();
    let (next, _) = w.step(&step).unwrap().expect("the request is accepted");
    assert_eq!(state(&next, request_id(n)), Some(RequestState::Submitted));
    next
}

fn state(w: &MoneyWorld, r: RequestId) -> Option<RequestState> {
    w.money.pay.requests.get(&r).map(|x| x.state)
}

/// Records `run` through `RecordChecks` by the System. Returns the next
/// world, the records and the reason texts with their references.
fn record(
    w: &MoneyWorld,
    run: CheckRun,
) -> (
    MoneyWorld,
    Vec<Record>,
    Vec<(fstp_domain::id::TextRef, String)>,
) {
    let mut next_text = 90_000u128;
    let (cmd, texts) = run.into_command(|| {
        next_text = next_text.saturating_add(1);
        TextId::from_raw(next_text)
    });
    let step = Step {
        actor: Actor::System(SystemCause::PaymentPort),
        flags: Flags::NONE,
        cmd,
    };
    let (next, records) = w.step(&step).unwrap().expect("RecordChecks is accepted");
    (next, records, texts)
}

fn failures(run: &CheckRun) -> Vec<(CheckKind, String)> {
    run.outcomes
        .iter()
        .filter_map(|o| o.failure.clone().map(|f| (o.check, f)))
        .collect()
}

/// I-32, R-PR-03: a request with passing evidence gets a passed run, the
/// snapshot digest is the SHA-256 of the snapshot bytes, and the licence
/// file's content hash is in the snapshot. The request moves to
/// UNDER_REVIEW, and a passed acceptance run records the second snapshot.
#[test]
fn i32_r_pr_03_passing_evidence_gets_a_passed_run_and_a_snapshot_digest() {
    let forge = Forge::standard();
    let p26 = p26();
    let r = rules(&p26, PartialEvidence::PublicDeliverables);
    let w = submitted(1, 120);
    let sub = exec(run(
        &input(
            1,
            CheckPhase::Submission,
            120,
            evidence("v1.0.0", "EUPL-1.2"),
        ),
        &r,
        &forge,
    ));
    assert!(sub.passed(), "{:?}", failures(&sub));
    assert_eq!(
        sub.digest,
        ContentDigest::from_bytes(fstp_crypto::sha256(&sub.snapshot.encode()))
    );
    assert_ne!(sub.digest, ContentDigest::from_bytes([0; 32]));
    let line = sub.snapshot.lines.first().unwrap();
    assert_eq!(
        line.licence_file,
        Some(Retrieval::Got {
            status: 200,
            sha256: fstp_crypto::sha256(EUPL),
            len: EUPL.len() as u64,
        })
    );
    assert_eq!(line.detected.as_deref(), Some("EUPL-1.2"));
    let sub_digest = sub.digest;
    let (w, records, texts) = record(&w, sub);
    assert!(texts.is_empty());
    assert!(records.iter().any(|r| matches!(
        r,
        Record::ChecksRecorded { snapshot, phase: CheckPhase::Submission, .. } if *snapshot == sub_digest
    )));
    assert_eq!(state(&w, request_id(1)), Some(RequestState::UnderReview));

    let acc = exec(run(
        &input(
            1,
            CheckPhase::Acceptance,
            120,
            evidence("v1.0.0", "EUPL-1.2"),
        ),
        &r,
        &forge,
    ));
    assert!(acc.passed());
    let (w, records, _) = record(&w, acc);
    assert!(records.iter().any(|r| matches!(
        r,
        Record::ChecksRecorded {
            phase: CheckPhase::Acceptance,
            ..
        }
    )));
    assert_eq!(state(&w, request_id(1)), Some(RequestState::UnderReview));
}

/// R-PR-02: a failing check moves the request to CHECKS_FAILED, and each
/// failure carries a reason whose reference digests its text.
#[test]
fn r_pr_02_failing_check_moves_the_request_to_checks_failed_with_reasons() {
    let forge = Forge::standard();
    let p26 = p26();
    let w = submitted(2, 120);
    let run = exec(run(
        &input(
            2,
            CheckPhase::Submission,
            120,
            evidence("v9.9.9", "EUPL-1.2"),
        ),
        &rules(&p26, PartialEvidence::PublicDeliverables),
        &forge,
    ));
    assert!(!run.passed());
    let f = failures(&run);
    assert!(
        f.iter()
            .any(|(k, why)| *k == CheckKind::Licence && why.contains("v9.9.9")),
        "{f:?}"
    );
    let (w, records, texts) = record(&w, run);
    assert_eq!(state(&w, request_id(2)), Some(RequestState::ChecksFailed));
    assert!(!texts.is_empty());
    for (r, text) in &texts {
        assert_eq!(
            r.digest(),
            ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes()))
        );
    }
    let Some(Record::ChecksRecorded { results, .. }) = records
        .iter()
        .find(|r| matches!(r, Record::ChecksRecorded { .. }))
    else {
        panic!("no ChecksRecorded");
    };
    let refs: Vec<_> = results.iter().filter_map(|c| c.failure).collect();
    assert_eq!(refs, texts.iter().map(|(r, _)| *r).collect::<Vec<_>>());
}

/// TH-24, R-PR-03: an upstream licence change after a snapshot leaves the
/// recorded evidence unchanged, and a new run records a new digest.
#[test]
fn th24_upstream_change_after_a_snapshot_leaves_the_recorded_evidence_unchanged() {
    let forge = Forge::standard();
    let p26 = p26();
    let r = rules(&p26, PartialEvidence::PublicDeliverables);
    let i = input(
        3,
        CheckPhase::Submission,
        120,
        evidence("v1.0.0", "EUPL-1.2"),
    );
    let first = exec(run(&i, &r, &forge));
    let bytes = first.snapshot.encode();
    let digest = first.digest;
    forge.put(
        &format!("{REPO}/raw/v1.0.0/LICENSE"),
        200,
        b"SPDX-License-Identifier: MIT\n",
    );
    let second = exec(run(&i, &r, &forge));
    assert_eq!(first.snapshot.encode(), bytes);
    assert_eq!(first.digest, digest);
    assert_ne!(second.digest, digest);
    assert!(!second.passed(), "the detected licence now differs");
}

/// P-26, R-PR-02: a declared and detected licence outside P-26 fails the
/// licence check.
#[test]
fn p26_r_pr_02_licence_outside_p26_fails() {
    let forge = Forge::standard();
    forge.put(
        &format!("{REPO}/raw/v2.0.0/LICENSE"),
        200,
        b"SPDX-License-Identifier: LicenseRef-synthetic-proprietary\n",
    );
    let p26 = p26();
    let run = exec(run(
        &input(
            4,
            CheckPhase::Submission,
            100,
            evidence("v2.0.0", "LicenseRef-synthetic-proprietary"),
        ),
        &rules(&p26, PartialEvidence::PublicDeliverables),
        &forge,
    ));
    assert!(
        failures(&run)
            .iter()
            .any(|(k, why)| *k == CheckKind::Licence && why.contains("P-26"))
    );
}

/// R-PR-02: a detected licence that differs from the declared one fails.
#[test]
fn r_pr_02_detected_licence_differs_from_declared() {
    let forge = Forge::standard();
    let p26 = p26();
    let run = exec(run(
        &input(5, CheckPhase::Submission, 100, evidence("v1.0.0", "MIT")),
        &rules(&p26, PartialEvidence::PublicDeliverables),
        &forge,
    ));
    let f = failures(&run);
    assert!(
        f.iter().any(|(k, why)| *k == CheckKind::Licence
            && why.contains("EUPL-1.2")
            && why.contains("MIT")),
        "{f:?}"
    );
}

/// R-PR-02: a location that needs authentication fails the public
/// location check, and a host the egress refuses fails it too.
#[test]
fn r_pr_02_location_not_public_fails() {
    let forge = Forge::standard();
    forge.put(REPO, 401, b"");
    let p26 = p26();
    let r = rules(&p26, PartialEvidence::PublicDeliverables);
    let run1 = exec(run(
        &input(
            6,
            CheckPhase::Submission,
            100,
            evidence("v1.0.0", "EUPL-1.2"),
        ),
        &r,
        &forge,
    ));
    assert!(
        failures(&run1)
            .iter()
            .any(|(k, why)| *k == CheckKind::PublicLocation && why.contains("authentication"))
    );
    let mut refusing = Forge::standard();
    refusing.refused.insert("forge.example".to_owned());
    let run2 = exec(run(
        &input(
            6,
            CheckPhase::Submission,
            100,
            evidence("v1.0.0", "EUPL-1.2"),
        ),
        &r,
        &refusing,
    ));
    let f = failures(&run2);
    assert!(
        f.iter()
            .any(|(k, why)| *k == CheckKind::PublicLocation && why.contains("allowlist")),
        "{f:?}"
    );
    assert_eq!(
        run2.snapshot.lines.first().unwrap().location_page,
        Some(Retrieval::Refused)
    );
}

/// P-34, P-65, I-62: under the progress report option a partial line
/// passes with a report alone, but the line that brings the milestone to
/// fully claimed needs public deliverables.
#[test]
fn i62_p65_final_line_needs_public_deliverables_under_progress_report() {
    let forge = Forge::standard();
    let p26 = p26();
    let r = rules(&p26, PartialEvidence::ProgressReport);
    let report_only = EvidenceInput {
        location: None,
        release: None,
        licence: None,
        report: Some(ContentDigest::from_bytes([4; 32])),
    };
    let partial = exec(run(
        &input(7, CheckPhase::Submission, 100, report_only.clone()),
        &r,
        &forge,
    ));
    assert!(partial.passed(), "{:?}", failures(&partial));
    let last = exec(run(
        &input(7, CheckPhase::Submission, 200, report_only),
        &r,
        &forge,
    ));
    assert!(
        failures(&last)
            .iter()
            .any(|(k, why)| *k == CheckKind::Evidence && why.contains("public location"))
    );
    let missing_report = EvidenceInput {
        report: None,
        ..evidence("v1.0.0", "EUPL-1.2")
    };
    let pub_run = exec(run(
        &input(7, CheckPhase::Submission, 100, missing_report),
        &rules(&p26, PartialEvidence::PublicDeliverables),
        &forge,
    ));
    assert!(
        failures(&pub_run)
            .iter()
            .any(|(k, why)| *k == CheckKind::Evidence && why.contains("report"))
    );
}

/// I-58, I-31: a line above its milestone's available balance, and a
/// request above the contract total, fail the balance check.
#[test]
fn i58_i31_balance_failures() {
    let forge = Forge::standard();
    let p26 = p26();
    let r = rules(&p26, PartialEvidence::PublicDeliverables);
    let over = exec(run(
        &input(
            8,
            CheckPhase::Submission,
            201,
            evidence("v1.0.0", "EUPL-1.2"),
        ),
        &r,
        &forge,
    ));
    assert!(
        failures(&over)
            .iter()
            .any(|(k, why)| *k == CheckKind::Balance && why.contains("I-58"))
    );
    let mut i = input(
        8,
        CheckPhase::Submission,
        150,
        evidence("v1.0.0", "EUPL-1.2"),
    );
    i.claimed_elsewhere = 300;
    let total = exec(run(&i, &r, &forge));
    let f = failures(&total);
    assert!(
        f.iter()
            .any(|(k, why)| *k == CheckKind::Balance && why.contains("I-31")),
        "{f:?}"
    );
    assert!(
        total
            .outcomes
            .iter()
            .any(|o| o.line.is_none() && o.check == CheckKind::Balance)
    );
}

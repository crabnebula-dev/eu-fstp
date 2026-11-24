//! I-32, R-PR-02, R-PR-03: the checks runner of the production cell
//! (`fstp_cell::tasks::checks`, ADR-026 section "Written by lane
//! `m10/checks-runner`").
//!
//! The runner's core reads the domain state, opens the evidence texts,
//! runs `fstp_checks` through a forge, and builds `RecordChecks`. These
//! tests drive it over the M-PAY world of the domain test kit, a grant in
//! IN_EXECUTION, with a synthetic forge and text store. Every command the
//! runner builds is decided by production `decide` in that world as the
//! payment port's, so a test passes only if the domain accepts the runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Mutex;

use fstp_api_core::port::{TextClass, TextOwner};
use fstp_cell::tasks::checks::{EvidenceTexts, OpenFuture, PutFuture, due, prepare, run_id};
use fstp_checks::runner::{Fetch, FetchFault, Fetched};
use fstp_checks::url::DeliverableUrl;
use fstp_domain::Command;
use fstp_domain::id::{ContentDigest, LineId, ProposalId, RequestId, TextId, TextRef};
use fstp_domain::payment::{CheckPhase, PaymentKind};
use fstp_domain::policy::SpdxId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyWorld, PC, accept_line, milestone_n, record_checks, request_payment_as,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::{Backend, Step};
use fstp_domain_testkit::mc::pay_model::pay_world;
use fstp_domain_testkit::reference::payment::RequestState;

const CELL: [u8; 16] = [0x3C; 16];
const LOCATION: &str = "https://forge.example.test/team/sensor-kit";
const RELEASE: &str = "v1.0.0";
const LICENCE_FILE: &str = "https://forge.example.test/team/sensor-kit/raw/v1.0.0/LICENSE";
const NOW: i64 = 1_900_000_000_000_000;

/// A synthetic forge: each URL answers its scripted status and body.
struct Forge {
    answers: BTreeMap<String, (u16, Vec<u8>)>,
    gets: Mutex<Vec<String>>,
}

impl Forge {
    fn new(licence: (u16, &str)) -> Forge {
        let mut answers = BTreeMap::new();
        answers.insert(LOCATION.to_owned(), (200, b"synthetic sensor kit".to_vec()));
        answers.insert(
            LICENCE_FILE.to_owned(),
            (licence.0, licence.1.as_bytes().to_vec()),
        );
        Forge {
            answers,
            gets: Mutex::new(Vec::new()),
        }
    }
}

impl Fetch for Forge {
    async fn fetch(&self, url: &DeliverableUrl) -> Result<Fetched, FetchFault> {
        let u = url.to_string();
        self.gets.lock().unwrap().push(u.clone());
        match self.answers.get(&u) {
            Some((status, body)) => Ok(Fetched {
                status: *status,
                body: body.clone(),
            }),
            None => Err(FetchFault::Unreachable),
        }
    }
}

/// The stored texts: each id with its class, owner and bytes.
type Stored = BTreeMap<TextId, (TextClass, TextOwner, Vec<u8>)>;

/// A synthetic text store in the stored form of the cell.
#[derive(Default)]
struct Texts {
    stored: Mutex<Stored>,
    down: bool,
}

impl Texts {
    fn add(&self, id: u128, owner: TextOwner, s: &str) -> TextRef {
        let id = TextId::from_raw(id);
        self.stored
            .lock()
            .unwrap()
            .insert(id, (TextClass::Confidential, owner, s.as_bytes().to_vec()));
        TextRef::new(
            id,
            ContentDigest::from_bytes(fstp_crypto::sha256(s.as_bytes())),
        )
    }
}

impl EvidenceTexts for Texts {
    fn open(&self, id: TextId) -> OpenFuture<'_> {
        let got = if self.down {
            None
        } else {
            self.stored.lock().unwrap().get(&id).cloned()
        };
        Box::pin(std::future::ready(got))
    }

    fn put<'a>(&'a self, grant: ProposalId, id: TextId, text: &'a str) -> PutFuture<'a> {
        self.stored.lock().unwrap().insert(
            id,
            (
                TextClass::Confidential,
                TextOwner::Proposal(grant),
                text.as_bytes().to_vec(),
            ),
        );
        let done: Pin<Box<dyn std::future::Future<Output = bool> + Send>> =
            Box::pin(std::future::ready(true));
        done
    }
}

fn request() -> RequestId {
    RequestId::from_raw(51_000)
}

fn line() -> LineId {
    LineId::from_raw(151_000)
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    fstp_rt::future::block_on(f)
}

/// The M-PAY world, with the synthetic checks off, and lead c's request
/// of one line of 0.50 on milestone 0 whose evidence texts live in
/// `texts`. With `foreign`, the location text belongs to another grant.
fn world_with_request(texts: &Texts, foreign: bool) -> MoneyWorld {
    let mut w = pay_world(Backend::Production).unwrap();
    w.auto_checks = false;
    let owner = TextOwner::Proposal(PC);
    let other = TextOwner::Proposal(ProposalId::from_raw(999));
    let location = texts.add(901, if foreign { other } else { owner }, LOCATION);
    let release = texts.add(902, owner, RELEASE);
    let report = texts.add(903, owner, "Synthetic delivery report.");
    let mut step = request_payment_as(
        LC,
        request(),
        PC,
        PaymentKind::Milestone,
        &[(line(), milestone_n(PC, 0), 50)],
        None,
    )
    .unwrap();
    if let Command::RequestPayment { lines, .. } = &mut step.cmd {
        lines[0].evidence.location = Some(location);
        lines[0].evidence.release = Some(release);
        lines[0].evidence.licence = Some(SpdxId("Apache-2.0".to_owned()));
        lines[0].evidence.report = Some(report);
    }
    must(&mut w, &step);
    w
}

/// Runs `step`, which production and the references must both accept.
fn must(w: &mut MoneyWorld, step: &Step) {
    let (next, _) = w
        .step(step)
        .unwrap()
        .unwrap_or_else(|| panic!("{:?} was refused", step.cmd));
    *w = next;
}

/// The runner's command as the payment port's step.
fn as_port(cmd: Command) -> Step {
    let mut s = record_checks(request(), CheckPhase::Submission, &[line()], false);
    s.cmd = cmd;
    s
}

fn state_of(w: &MoneyWorld) -> Option<RequestState> {
    w.money.pay.requests.get(&request()).map(|r| r.state)
}

/// I-32, R-PR-02, R-PR-03: the runner records the submission run, then
/// the acceptance run, each with its snapshot, and then the reviewer's
/// decision on the last line accepts the request. Before the runs, that
/// decision is refused.
#[test]
fn i32_r_pr_02_runner_records_both_runs_then_the_last_line_accepts() {
    let texts = Texts::default();
    let mut w = world_with_request(&texts, false);
    let forge = Forge::new((200, "SPDX-License-Identifier: Apache-2.0\n"));
    let accept = accept_line(R1, request(), line(), 50, false).unwrap();
    assert!(
        w.step(&accept).unwrap().is_none(),
        "I-32: a decision before any run is refused"
    );
    for phase in [CheckPhase::Submission, CheckPhase::Acceptance] {
        let core = w.life.rev.sod.state.clone();
        let runs = due(CELL, &core, |_| false);
        assert_eq!(
            runs,
            vec![(request(), phase, run_id(CELL, request(), phase))]
        );
        let p = block(prepare(
            &core,
            request(),
            &forge,
            &texts,
            Timestamp::from_micros(NOW),
        ))
        .expect("the evidence opens");
        assert!(p.passed, "{phase:?}: {:?}", p.command);
        assert!(p.reasons.is_empty());
        match &p.command {
            Command::RecordChecks {
                request: r,
                phase: ph,
                snapshot,
                ..
            } => {
                assert_eq!((*r, *ph), (request(), phase));
                assert_ne!(*snapshot, ContentDigest::from_bytes([0; 32]));
            }
            other => panic!("not a run: {other:?}"),
        }
        must(&mut w, &as_port(p.command));
    }
    assert!(due(CELL, &w.life.rev.sod.state, |_| false).is_empty());
    assert_eq!(
        forge.gets.lock().unwrap().as_slice(),
        [LOCATION, LICENCE_FILE, LOCATION, LICENCE_FILE]
    );
    must(&mut w, &accept);
    assert_eq!(state_of(&w), Some(RequestState::Accepted));
}

/// R-PR-02, I-32: a release without its licence file fails the
/// submission run. Its reason is stored as a confidential text of the
/// grant before the command names it, the request returns in
/// CHECKS_FAILED, and it awaits no further run.
#[test]
fn i32_r_pr_02_failed_check_returns_the_request_with_a_reason() {
    let texts = Texts::default();
    let mut w = world_with_request(&texts, false);
    let forge = Forge::new((404, "not found"));
    let core = w.life.rev.sod.state.clone();
    let p = block(prepare(
        &core,
        request(),
        &forge,
        &texts,
        Timestamp::from_micros(NOW),
    ))
    .unwrap();
    assert!(!p.passed);
    assert_eq!(p.grant, PC);
    assert_eq!(p.reasons.len(), 1);
    let (r, why) = &p.reasons[0];
    assert!(why.contains("v1.0.0"), "{why}");
    assert_eq!(
        r.digest(),
        ContentDigest::from_bytes(fstp_crypto::sha256(why.as_bytes()))
    );
    for (r, why) in &p.reasons {
        assert!(block(texts.put(p.grant, r.id(), why)));
    }
    must(&mut w, &as_port(p.command));
    assert_eq!(state_of(&w), Some(RequestState::ChecksFailed));
    assert!(due(CELL, &w.life.rev.sod.state, |_| false).is_empty());
}

/// I-32, I-23: a run's id is bound to the cell, the request and the
/// phase, so a repeat after a crash is the same id and the store answers
/// it as a duplicate. A run whose id the ledger holds is not due again.
#[test]
fn i32_i23_checks_run_ids_are_stable_so_a_repeat_is_a_duplicate() {
    let sub = run_id(CELL, request(), CheckPhase::Submission);
    assert_eq!(sub, run_id(CELL, request(), CheckPhase::Submission));
    assert_ne!(sub, run_id(CELL, request(), CheckPhase::Acceptance));
    assert_ne!(sub, run_id([0x3D; 16], request(), CheckPhase::Submission));
    assert_ne!(
        sub,
        run_id(CELL, RequestId::from_raw(51_001), CheckPhase::Submission)
    );
    assert!(fstp_cell_core::is_system_command_id(sub));
    let texts = Texts::default();
    let w = world_with_request(&texts, false);
    let core = &w.life.rev.sod.state;
    assert_eq!(due(CELL, core, |_| false).len(), 1);
    assert!(due(CELL, core, |id| id == sub).is_empty());
}

/// I-32: a text that cannot be opened leaves the request waiting with no
/// run and no fetch. A text of another grant counts as missing evidence,
/// so the run fails rather than passing on evidence it never judged.
#[test]
fn i32_unreadable_evidence_records_nothing() {
    let down = Texts {
        down: true,
        ..Texts::default()
    };
    let w = world_with_request(&down, false);
    let forge = Forge::new((200, "SPDX-License-Identifier: Apache-2.0\n"));
    let core = w.life.rev.sod.state.clone();
    assert_eq!(
        block(prepare(
            &core,
            request(),
            &forge,
            &down,
            Timestamp::from_micros(NOW)
        )),
        None
    );
    assert!(forge.gets.lock().unwrap().is_empty());

    let texts = Texts::default();
    let w = world_with_request(&texts, true);
    let core = w.life.rev.sod.state.clone();
    let p = block(prepare(
        &core,
        request(),
        &forge,
        &texts,
        Timestamp::from_micros(NOW),
    ))
    .unwrap();
    assert!(!p.passed, "a foreign location text never passes");
    assert!(
        p.reasons
            .iter()
            .any(|(_, why)| why.contains("public location")),
        "{:?}",
        p.reasons
    );
}

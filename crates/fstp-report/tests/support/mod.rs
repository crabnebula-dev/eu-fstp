//! A synthetic ledger of one call cycle for the funder output tests.
//!
//! Every value is synthetic. The ledger is built record by record, not by
//! running commands, because the generator reads records only. Records
//! whose payloads have no public constructor (`GrantDecided`,
//! `PaymentReleased`) are decoded from their JSON form, with member
//! spellings taken from records that do have one.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_domain::Record;
use fstp_domain::command::{Actor, ContractEvent, SystemCause};
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, CallSeq, ContentDigest, ContractId, DecisionId,
    HardshipEvidenceId, LineId, LlmConfigId, MilestoneId, PlanVersionId, PolicyVersionId,
    ProgrammeId, ProposalId, RequestId, TextId, TextRef,
};
use fstp_domain::payment::{LineEvidence, PaymentKind, PaymentLine};
use fstp_domain::record::{RulesVersion, Transitioned};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::time::{MICROS_PER_DAY, Timestamp, ZoneName};
use fstp_json::{FromJson, Object, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::{Amount, Currency, NonNegAmount, PosAmount};
use fstp_prop::Gen;
use fstp_report::{Entry, Snapshot};

/// The programme.
pub(crate) const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(1);
/// The call.
pub(crate) const CALL: CallId = CallId::from_raw(10);
/// Another call of the programme, never published.
pub(crate) const OTHER_CALL: CallId = CallId::from_raw(11);
/// The programme manager.
pub(crate) const PM: AccountId = AccountId::from_raw(7_000_000_001);
/// The reviewer.
pub(crate) const REVIEWER: AccountId = AccountId::from_raw(7_000_000_002);
/// The finance approver.
pub(crate) const FIN: AccountId = AccountId::from_raw(7_000_000_003);
/// The payment releaser.
pub(crate) const REL: AccountId = AccountId::from_raw(7_000_000_004);
/// The first lead; lead `i` is `LEAD_BASE + i`.
pub(crate) const LEAD_BASE: u128 = 9_100_000_000;
/// The publication instant: 2026-01-05T00:00:00Z.
pub(crate) const T_PUBLISH: i64 = 1_767_571_200_000_000;

/// A day after publication.
pub(crate) fn day(n: i64) -> Timestamp {
    Timestamp::from_micros(T_PUBLISH + n * MICROS_PER_DAY)
}

/// `cents` in EUR.
pub(crate) fn eur(cents: i64) -> NonNegAmount {
    NonNegAmount::new(Amount::from_minor(cents, Currency::Eur).unwrap()).unwrap()
}

fn pos(cents: i64) -> PosAmount {
    PosAmount::new(Amount::from_minor(cents, Currency::Eur).unwrap()).unwrap()
}

fn digest(n: u8) -> ContentDigest {
    ContentDigest::from_bytes([n; 32])
}

fn text(n: u128) -> TextRef {
    TextRef::new(TextId::from_raw(n), digest(7))
}

/// How a payment request ends in the fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Lines accepted, never approved.
    Pending,
    /// Released, not yet confirmed.
    Released,
    /// Released and confirmed paid.
    Paid,
    /// Withdrawn before release.
    Withdrawn,
}

/// One payment request.
#[derive(Clone, Debug)]
pub(crate) struct ReqSpec {
    /// `(requested, approved)` cents per line.
    pub(crate) lines: Vec<(i64, i64)>,
    /// The outcome.
    pub(crate) outcome: Outcome,
    /// The day after publication it was released or decided.
    pub(crate) day: i64,
    /// Whether it is a hardship contribution.
    pub(crate) hardship: bool,
}

/// How a grant is closed in the fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Closure {
    /// Still running.
    Open,
    /// COMPLETED on this day.
    Completed(i64),
    /// TERMINATED on this day.
    Terminated(i64),
}

/// One grant.
#[derive(Clone, Debug)]
pub(crate) struct GrantSpec {
    /// The granted cents.
    pub(crate) granted: i64,
    /// The day after publication it was decided.
    pub(crate) day: i64,
    /// Its requests.
    pub(crate) requests: Vec<ReqSpec>,
    /// Its closure.
    pub(crate) closure: Closure,
}

impl GrantSpec {
    /// The cents paid: approved lines of released or paid requests.
    pub(crate) fn paid(&self) -> i64 {
        self.requests
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Released | Outcome::Paid))
            .flat_map(|r| r.lines.iter().map(|l| l.1))
            .sum()
    }

    /// The cents paid within `[from, to)` days.
    pub(crate) fn paid_between(&self, from: i64, to: i64) -> i64 {
        self.requests
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Released | Outcome::Paid))
            .filter(|r| r.day >= from && r.day < to)
            .flat_map(|r| r.lines.iter().map(|l| l.1))
            .sum()
    }
}

/// The proposal of grant `i`.
pub(crate) fn proposal(i: usize) -> ProposalId {
    ProposalId::from_raw(100 + i as u128)
}

/// The lead of grant `i`.
pub(crate) fn lead(i: usize) -> AccountId {
    AccountId::from_raw(LEAD_BASE + i as u128)
}

/// A ledger under construction.
pub(crate) struct Ledger {
    entries: Vec<Entry>,
}

impl Ledger {
    /// An empty ledger.
    pub(crate) fn new() -> Ledger {
        Ledger {
            entries: Vec::new(),
        }
    }

    /// Appends `record` at `at`.
    pub(crate) fn push(&mut self, at: Timestamp, record: Record) {
        let seq = Seq::from_raw(self.entries.len() as u64 + 1);
        self.entries.push(Entry { seq, at, record });
    }

    /// The snapshot of every record so far. Grants are built one after
    /// another, so their records interleave in time. A stable sort by
    /// time keeps each grant's own order and gives the ledger order.
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot::new(self.ordered()).unwrap_or_else(|e| panic!("fixture snapshot: {e}"))
    }

    /// The records in ledger order, numbered from 1.
    pub(crate) fn ordered(&self) -> Vec<Entry> {
        let mut v = self.entries.clone();
        v.sort_by_key(|e| e.at);
        for (i, e) in v.iter_mut().enumerate() {
            e.seq = Seq::from_raw(i as u64 + 1);
        }
        v
    }

    /// The records so far.
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

/// A member of the JSON form of `r`.
fn member(r: &Record, name: &str) -> Value {
    r.to_json()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("fixture: no member {name}"))
}

fn id_str(n: u128) -> Value {
    Value::String(n.to_string())
}

/// Decodes the record of `members`.
fn decode(members: Vec<(&str, Value)>) -> Record {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v);
    }
    Record::from_json(&Value::Object(o)).unwrap_or_else(|e| panic!("fixture record: {e}"))
}

/// The programme, the call and its publication.
pub(crate) fn publish(l: &mut Ledger) {
    l.push(
        day(-30),
        Record::ProgrammeCreated {
            programme: PROGRAMME,
            currency: Currency::Eur,
            by: PM,
        },
    );
    l.push(
        day(-20),
        Record::CallDrafted {
            call: CALL,
            programme: PROGRAMME,
            opens: day(0),
            deadline: day(60),
            deadline_zone: ZoneName::new("Europe/Brussels").unwrap(),
            budget: eur(50_000_000),
            text: text(1),
            author: PM,
        },
    );
    l.push(
        day(0),
        Record::CallPublished {
            call: CALL,
            policy: PolicyVersionId::from_raw(3),
            seq: CallSeq::FIRST,
            config: LlmConfigId::from_raw(4),
            by: PM,
        },
    );
}

/// The records of grant `i` per `g`.
pub(crate) fn grant(l: &mut Ledger, i: usize, g: &GrantSpec) {
    let p = proposal(i);
    let base = 1_000 * (i as u128 + 1);
    l.push(
        day(1),
        Record::ProposalCreated {
            proposal: p,
            call: CALL,
            lead: lead(i),
            minor: false,
        },
    );
    l.push(
        day(70),
        Record::NoQuestionsRecorded {
            proposal: p,
            assignment: AssignmentId::from_raw(base + 1),
        },
    );
    let determined = Record::AmountDetermined {
        decision: DecisionId::from_raw(base + 2),
        proposal: p,
        plan_total: eur(g.granted),
        deductions: Vec::new(),
        granted: eur(g.granted),
        agreed: PlanVersionId::from_raw(base + 3),
        by: REVIEWER,
        rules: RulesVersion::M2,
    };
    let rules = member(&determined, "rules");
    l.push(day(g.day), determined);
    l.push(
        day(g.day),
        Record::ContractFactRecorded {
            proposal: p,
            contract: ContractId::from_raw(base + 4),
            event: ContractEvent::Effective,
        },
    );
    let epoch = member(
        &Record::VaultEpochProcessed {
            epoch: fstp_domain::id::VaultEpoch::GENESIS,
        },
        "epoch",
    );
    l.push(
        day(g.day),
        decode(vec![
            ("type", Value::String("GrantDecided".into())),
            ("proposal", id_str(p.raw())),
            (
                "granted",
                Value::String(eur(g.granted).amount().to_string()),
            ),
            ("agreed_plan", id_str(base + 3)),
            ("acceptance", id_str(base + 5)),
            ("approval", id_str(base + 6)),
            ("contract", id_str(base + 4)),
            ("epoch", epoch),
            ("rules", rules),
            ("currency", Value::String("EUR".into())),
        ]),
    );
    for (k, r) in g.requests.iter().enumerate() {
        request(l, i, k, r);
    }
    let (to, row, at) = match g.closure {
        Closure::Open => return,
        Closure::Completed(d) => (StateTag::Completed, Row::InExecutionToCompleted, d),
        Closure::Terminated(d) => (StateTag::Terminated, Row::InExecutionToTerminated, d),
    };
    l.push(
        day(at),
        Record::Transitioned(Transitioned {
            proposal: p,
            from: StateTag::InExecution,
            to,
            row,
            actor: Actor::System(SystemCause::Timeline),
            decision: None,
        }),
    );
}

/// The request id of request `k` of grant `i`.
pub(crate) fn request_id(i: usize, k: usize) -> RequestId {
    RequestId::from_raw(50_000 + 100 * i as u128 + k as u128)
}

fn request(l: &mut Ledger, i: usize, k: usize, r: &ReqSpec) {
    let p = proposal(i);
    let id = request_id(i, k);
    let lines: Vec<PaymentLine> = r
        .lines
        .iter()
        .enumerate()
        .map(|(j, (req, _))| PaymentLine {
            line: LineId::from_raw(id.raw() * 100 + j as u128),
            milestone: MilestoneId::from_raw(p.raw() * 10 + j as u128),
            amount: pos(*req),
            evidence: LineEvidence {
                location: None,
                release: None,
                licence: None,
                report: Some(text(id.raw())),
            },
        })
        .collect();
    let kind = if r.hardship {
        PaymentKind::Hardship(HardshipEvidenceId::from_raw(id.raw()))
    } else {
        PaymentKind::Milestone
    };
    l.push(
        day(r.day),
        Record::PaymentRequested {
            request: id,
            grant: p,
            kind,
            lines: lines.clone(),
        },
    );
    if r.outcome == Outcome::Withdrawn {
        l.push(
            day(r.day),
            Record::PaymentRequestWithdrawn {
                request: id,
                by: lead(i),
            },
        );
        return;
    }
    for (line, (_, approved)) in lines.iter().zip(&r.lines) {
        l.push(
            day(r.day),
            Record::LineAccepted {
                request: id,
                line: line.line,
                by: REVIEWER,
                approved: eur(*approved),
                reason: None,
            },
        );
    }
    if r.outcome == Outcome::Pending {
        return;
    }
    l.push(
        day(r.day),
        Record::PaymentApproved {
            request: id,
            by: FIN,
        },
    );
    l.push(day(r.day), released(id, p));
    if r.outcome == Outcome::Paid {
        l.push(
            day(r.day),
            Record::PaymentConfirmed {
                request: id,
                by: Actor::System(SystemCause::PaymentPort),
            },
        );
    }
}

/// A `PaymentReleased` of `request` on `grant`.
pub(crate) fn released(request: RequestId, grant: ProposalId) -> Record {
    let file = member(
        &Record::ChecksRecorded {
            request,
            phase: fstp_domain::payment::CheckPhase::Submission,
            results: Vec::new(),
            snapshot: digest(9),
        },
        "snapshot",
    );
    decode(vec![
        ("type", Value::String("PaymentReleased".into())),
        ("request", id_str(request.raw())),
        ("grant", id_str(grant.raw())),
        (
            "acceptors",
            Value::Array(vec![id_str(REVIEWER.raw())].into()),
        ),
        ("approver", id_str(FIN.raw())),
        ("releaser", id_str(REL.raw())),
        ("record_file", file),
    ])
}

/// The ledger of `grants` under one published call.
pub(crate) fn ledger_of(grants: &[GrantSpec]) -> Ledger {
    let mut l = Ledger::new();
    publish(&mut l);
    for (i, g) in grants.iter().enumerate() {
        grant(&mut l, i, g);
    }
    l
}

/// The fixed fixture: three grants, one completed with a hardship line,
/// one terminated, one running with a pending and a withdrawn request.
pub(crate) fn fixed() -> Vec<GrantSpec> {
    vec![
        GrantSpec {
            granted: 1_500_000,
            day: 90,
            requests: vec![
                ReqSpec {
                    lines: vec![(500_000, 500_000), (250_000, 200_000)],
                    outcome: Outcome::Paid,
                    day: 120,
                    hardship: false,
                },
                ReqSpec {
                    lines: vec![(300_000, 300_000)],
                    outcome: Outcome::Released,
                    day: 200,
                    hardship: true,
                },
            ],
            closure: Closure::Completed(250),
        },
        GrantSpec {
            granted: 900_000,
            day: 95,
            requests: vec![ReqSpec {
                lines: vec![(400_000, 400_000)],
                outcome: Outcome::Paid,
                day: 130,
                hardship: false,
            }],
            closure: Closure::Terminated(210),
        },
        GrantSpec {
            granted: 2_000_000,
            day: 100,
            requests: vec![
                ReqSpec {
                    lines: vec![(700_000, 650_000)],
                    outcome: Outcome::Pending,
                    day: 220,
                    hardship: false,
                },
                ReqSpec {
                    lines: vec![(100_000, 0)],
                    outcome: Outcome::Withdrawn,
                    day: 150,
                    hardship: false,
                },
            ],
            closure: Closure::Open,
        },
    ]
}

/// Random grants that reconcile: approved never above requested, paid
/// never above the granted amount.
pub(crate) fn grants(g: &mut Gen) -> Vec<GrantSpec> {
    g.vec(0..=4, |g| {
        let granted = g.i64_in(1..=5_000_000);
        let mut left = granted;
        let requests = g.vec(0..=3, |g| {
            let lines = g.vec(1..=3, |g| {
                let req = g.i64_in(1..=2_000_000);
                let appr = g.i64_in(0..=req);
                (req, appr)
            });
            let outcome = *g.pick(&[
                Outcome::Pending,
                Outcome::Released,
                Outcome::Paid,
                Outcome::Withdrawn,
            ]);
            ReqSpec {
                lines,
                outcome,
                day: g.i64_in(100..=400),
                hardship: g.bool(),
            }
        });
        let requests: Vec<ReqSpec> = requests
            .into_iter()
            .map(|mut r| {
                if matches!(r.outcome, Outcome::Released | Outcome::Paid) {
                    let sum: i64 = r.lines.iter().map(|l| l.1).sum();
                    if sum > left {
                        r.outcome = Outcome::Pending;
                    } else {
                        left -= sum;
                    }
                }
                r
            })
            .collect();
        let closure = match g.u8_in(0..=2) {
            0 => Closure::Open,
            1 => Closure::Completed(g.i64_in(401..=500)),
            _ => Closure::Terminated(g.i64_in(401..=500)),
        };
        GrantSpec {
            granted,
            day: g.i64_in(80..=99),
            requests,
            closure,
        }
    })
}

/// A snapshot whose records went through their JSON form and back.
pub(crate) fn round_tripped(s: &Snapshot) -> Snapshot {
    let entries = s
        .entries()
        .iter()
        .map(|e| Entry {
            seq: e.seq,
            at: e.at,
            record: Record::from_json(&e.record.to_json()).unwrap(),
        })
        .collect();
    Snapshot::new(entries).unwrap()
}

/// Grant `i` paid `cents` as a string, for comparisons.
pub(crate) fn money(cents: i64) -> String {
    eur(cents).amount().to_string()
}

use fstp_pdf::{Block, BlockKind};
use fstp_report::Period;

pub(crate) fn para(t: &str) -> Block {
    Block {
        kind: BlockKind::Paragraph,
        text: t.to_owned(),
    }
}

/// A synthetic stored Guide that states the five I-48 elements.
pub(crate) const GUIDE: &str = concat!(
    "[\"fstp.guide\",1]\n",
    "[\"title\",\"Guide for Applicants\"]\n",
    "[\"h\",2,[[\"t\",\"2. Call at a glance\"]]]\n",
    "[\"p\",[[[\"t\",\"Call \"],[\"v\",\"call.identifier\",[\"text\",\"SYN-2026-01\"]]]]]\n",
    "[\"p\",[[[\"t\",\"Maximum per recipient \"],[\"v\",\"P-05\",[\"text\",\"60000.00\"]]]]]\n",
    "[\"h\",2,[[\"t\",\"3. What we fund\"]]]\n",
    "[\"v\",\"P-55.list\",[\"list\",[\"Synthetic activity A\",\"Synthetic activity B\"]]]\n",
    "[\"h\",2,[[\"t\",\"4. Who can apply\"]]]\n",
    "[\"v\",\"eligibility.persons\",[\"paragraphs\",[\"Synthetic natural persons.\"]]]\n",
    "[\"h\",2,[[\"t\",\"6. How proposals are evaluated\"]]]\n",
    "[\"v\",\"P-01.table\",[\"table\",[\"Criterion\",\"Weight\"],[[\"Synthetic excellence\",\"50\"]]]]\n",
    "[\"h\",2,[[\"t\",\"7. How the amount is set\"]]]\n",
    "[\"v\",\"annexe.amount_criteria\",[\"paragraphs\",[\"Synthetic amount criteria.\"]]]\n",
);

pub(crate) const PRIVACY: &str = "https://privacy.fstp.example/statement";

pub(crate) fn package_parts() -> (Vec<Block>, Vec<Block>, Vec<Block>) {
    (
        vec![para("Synthetic proposal form: title, plan, milestones.")],
        vec![para("Synthetic contract template clause.")],
        vec![para(&format!(
            "Synthetic notice: recipient data reaches the granting authority. Portal Privacy Statement: {PRIVACY}"
        ))],
    )
}

pub(crate) fn periods() -> Vec<Period> {
    vec![
        Period {
            start: day(0),
            end: day(180),
        },
        Period {
            start: day(180),
            end: day(540),
        },
    ]
}

/// The shipped Horizon Europe profile, version 1 (P-53).
pub(crate) fn he() -> fstp_report::FunderProfile {
    fstp_report::profile::shipped("horizon-europe", 1).unwrap()
}

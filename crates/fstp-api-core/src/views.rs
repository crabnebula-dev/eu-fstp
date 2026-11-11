//! The read models of the review and applicant pages (design sections
//! 2.2 J4 to J8 and 3.6), as the pages of `web/src` decode them.
//!
//! Each model holds ids, state tags, scores, amounts and the texts the
//! design names for its read. None holds an identity field (I-17): no
//! display name, no email and no vault fact. Committee members appear by
//! their pseudonymous display handle only, and only to the coordinator
//! who assigns them. Ids, instants and amounts are decimal strings, and
//! P-01 scores and counts are JSON integers (interim, pending Daniel).

use fstp_json::{Array, Number, Object, ToJson, Value};

use crate::McpSafe;

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// A JSON integer.
fn int(n: u64) -> Value {
    Number::from_lexeme(&n.to_string()).map_or(Value::Null, Value::from)
}

/// A text value, or `null`.
fn text_or_null(t: &Option<String>) -> Value {
    t.as_deref().map_or(Value::Null, Value::from)
}

fn array<T: ToJson>(items: &[T]) -> Value {
    let mut a = Array::new();
    for i in items {
        a.push(i.to_json());
    }
    Value::Array(a)
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// One proposal of a call: "Proposal" plus its id, its state and its
/// submitted title (`intake.queue`, `call.board`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRow {
    /// The proposal.
    pub proposal: u128,
    /// Its state tag, such as `STAGE1`.
    pub state: &'static str,
    /// Its submitted title.
    pub title: String,
}

impl ToJson for ProposalRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("proposal", dec(self.proposal)),
            ("state", Value::from(self.state)),
            ("title", Value::from(self.title.as_str())),
        ])
    }
}

impl McpSafe for ProposalRow {}

/// One P-09 knock-out criterion, in P-09 order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnockOutCriterion {
    /// The criterion id.
    pub id: u128,
    /// Its wording.
    pub text: String,
}

impl ToJson for KnockOutCriterion {
    fn to_json(&self) -> Value {
        object(vec![
            ("id", dec(self.id)),
            ("text", Value::from(self.text.as_str())),
        ])
    }
}

/// `intake.queue`: the call's P-09 criteria and its submitted proposals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeQueue {
    /// The knock-out criteria.
    pub knock_out: Vec<KnockOutCriterion>,
    /// The proposals in SUBMITTED.
    pub proposals: Vec<ProposalRow>,
}

impl ToJson for IntakeQueue {
    fn to_json(&self) -> Value {
        object(vec![
            ("knock_out", array(&self.knock_out)),
            ("proposals", array(&self.proposals)),
        ])
    }
}

impl McpSafe for IntakeQueue {}

/// `review.declaration_view`: the title and the applicant-written neutral
/// summary, and nothing else (Q9, R-CF-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclarationView {
    /// The submitted title.
    pub title: String,
    /// The submitted neutral summary.
    pub neutral_summary: String,
}

impl ToJson for DeclarationView {
    fn to_json(&self) -> Value {
        object(vec![
            ("title", Value::from(self.title.as_str())),
            (
                "neutral_summary",
                Value::from(self.neutral_summary.as_str()),
            ),
        ])
    }
}

impl McpSafe for DeclarationView {}

/// `review.read_content` and `irc.case`: the submitted proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentView {
    /// The proposal.
    pub proposal: u128,
    /// Its current call.
    pub call: u128,
    /// Its state tag.
    pub state: &'static str,
    /// The submitted title.
    pub title: String,
    /// The submitted narrative.
    pub text: String,
    /// For an IRC case, the outcome that brought it there: `nominated`.
    pub outcome: Option<&'static str>,
}

impl ToJson for ContentView {
    fn to_json(&self) -> Value {
        let mut members = vec![
            ("proposal", dec(self.proposal)),
            ("state", Value::from(self.state)),
            ("title", Value::from(self.title.as_str())),
            ("text", Value::from(self.text.as_str())),
        ];
        match self.outcome {
            // The IRC case has no call member, only its outcome (R-IR-03).
            Some(o) => members.push(("outcome", Value::from(o))),
            None => members.push(("call", dec(self.call))),
        }
        object(members)
    }
}

/// One P-01 criterion of a score sheet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SheetCriterion {
    /// The criterion id.
    pub id: u128,
    /// Its label.
    pub text: String,
    /// N of P-01: the top of the integer scale 0 to N.
    pub max: u8,
}

impl ToJson for SheetCriterion {
    fn to_json(&self) -> Value {
        object(vec![
            ("id", dec(self.id)),
            ("text", Value::from(self.text.as_str())),
            ("max", int(u64::from(self.max))),
        ])
    }
}

/// `review.score_sheet`: what the reviewer scores now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoreSheet {
    /// `One` or `Two`.
    pub stage: &'static str,
    /// The plan version being scored.
    pub plan: u128,
    /// The P-01 criteria, in P-01 order.
    pub criteria: Vec<SheetCriterion>,
    /// The reviewer's current score of this plan: the plan id it is named
    /// by, and one value per criterion.
    pub current: Option<(u128, Vec<u8>)>,
}

impl ToJson for ScoreSheet {
    fn to_json(&self) -> Value {
        let current = match &self.current {
            None => Value::Null,
            Some((score, values)) => object(vec![
                ("score", dec(score)),
                (
                    "values",
                    Value::Array(values.iter().map(|v| int(u64::from(*v))).collect()),
                ),
            ]),
        };
        object(vec![
            ("stage", Value::from(self.stage)),
            ("plan", dec(self.plan)),
            ("criteria", array(&self.criteria)),
            ("current", current),
        ])
    }
}

impl McpSafe for ScoreSheet {}

/// One entry of a stage 2 thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadItem {
    /// `question` or `answer`.
    pub kind: &'static str,
    /// The asking reviewer's P-11 handle, for a question under P-11
    /// anonymous.
    pub author: Option<String>,
    /// The text.
    pub text: String,
    /// The day it was written, as `YYYY-MM-DD` in UTC. Applicants see days
    /// only (TH-08).
    pub day: String,
}

/// `review.stage2_thread`: the thread as an assigned reviewer reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2Thread {
    /// The proposal's state tag.
    pub state: &'static str,
    /// Whether the question window is open (NOTE 4).
    pub open: bool,
    /// Whether the caller recorded "no questions".
    pub own_no_questions: bool,
    /// The entries, oldest first.
    pub entries: Vec<ThreadItem>,
}

impl ToJson for Stage2Thread {
    fn to_json(&self) -> Value {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                object(vec![
                    ("kind", Value::from(e.kind)),
                    ("author", text_or_null(&e.author)),
                    ("text", Value::from(e.text.as_str())),
                ])
            })
            .collect();
        object(vec![
            ("state", Value::from(self.state)),
            ("open", Value::Bool(self.open)),
            ("own_no_questions", Value::Bool(self.own_no_questions)),
            ("entries", Value::Array(entries.into_iter().collect())),
        ])
    }
}

impl McpSafe for Stage2Thread {}

/// One finding of the assessor on the reviewer's proposal
/// (`review.findings`, design section 2.13). The statement is untrusted
/// data, shown as text only (TH-01). It names no account (I-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRow {
    /// The finding, which `review.mark_finding` names.
    pub finding: u128,
    /// `Completeness`, `Quality`, `Accuracy` or `Integrity`.
    pub kind: &'static str,
    /// `Info`, `Minor` or `Major`.
    pub severity: &'static str,
    /// The model-reported confidence in permille.
    pub confidence: u16,
    /// The plain-language observation.
    pub statement: String,
    /// The reader's own mark, `Agreed` or `Disputed`, if any (I-10).
    pub mark: Option<&'static str>,
    /// `synthetic` for the demo cell's synthetic assessor, else `model`
    /// (M7 design section 7, R-LA-08).
    pub assessor: &'static str,
}

impl ToJson for FindingRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("finding", dec(self.finding)),
            ("kind", Value::from(self.kind)),
            ("severity", Value::from(self.severity)),
            ("confidence", int(u64::from(self.confidence))),
            ("statement", Value::from(self.statement.as_str())),
            ("mark", self.mark.map_or(Value::Null, Value::from)),
            ("assessor", Value::from(self.assessor)),
        ])
    }
}

impl McpSafe for FindingRow {}

/// One weighted criterion score of a ranking row (D9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CriterionScore {
    /// The criterion id.
    pub criterion: u128,
    /// The mean weighted score, with two decimals.
    pub weighted: String,
}

impl ToJson for CriterionScore {
    fn to_json(&self) -> Value {
        object(vec![
            ("criterion", dec(self.criterion)),
            ("weighted", Value::from(self.weighted.as_str())),
        ])
    }
}

/// One row of the committee ranking view (R-EV-08, Q16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RankingRow {
    /// A proposal the viewer has a conflict fact on: "recused" only.
    Recused {
        /// The proposal.
        proposal: u128,
    },
    /// A proposal the viewer may read.
    Ranked {
        /// The proposal.
        proposal: u128,
        /// The reviewers' title, once recorded.
        title: Option<String>,
        /// The reviewers' neutral summary, once recorded.
        neutral_summary: Option<String>,
        /// The reviewers' rationale, once recorded.
        rationale: Option<String>,
        /// The effective score, a percentage with two decimals.
        effective: String,
        /// The weighted score per criterion, in P-01 order.
        criterion_scores: Vec<CriterionScore>,
        /// The requested total of the effective plan (ADR-006).
        requested: String,
        /// The remaining call budget as `fstp_money::Amount` displays it.
        /// It is signed, because a call can be over-nominated. The
        /// encoding never sends the sign (ADR-006, see [`budget_members`]).
        remaining_budget: String,
    },
}

/// The members that spell a signed remaining budget, given as
/// `fstp_money::Amount` displays it (ADR-006, design 3.7). Zero and above
/// is `remaining_budget` as written, with no shortfall. Below zero is a
/// zero `remaining_budget` and a positive `shortfall`, as the domain codec
/// spells a signed amount. So each signed value has one spelling, and no
/// served amount carries a sign.
fn budget_members(signed: &str) -> Vec<(&'static str, Value)> {
    let shortfall = signed
        .strip_prefix('-')
        .filter(|s| s.bytes().any(|b| b.is_ascii_digit() && b != b'0'));
    match shortfall {
        None => vec![(
            "remaining_budget",
            Value::from(signed.strip_prefix('-').unwrap_or(signed)),
        )],
        Some(shortfall) => {
            let zero = match shortfall.split_once('.') {
                Some((_, fraction)) => format!("0.{}", "0".repeat(fraction.len())),
                None => "0".to_owned(),
            };
            vec![
                ("remaining_budget", Value::String(zero)),
                ("shortfall", Value::from(shortfall)),
            ]
        }
    }
}

impl ToJson for RankingRow {
    fn to_json(&self) -> Value {
        match self {
            RankingRow::Recused { proposal } => object(vec![
                ("proposal", dec(proposal)),
                ("recused", Value::Bool(true)),
            ]),
            RankingRow::Ranked {
                proposal,
                title,
                neutral_summary,
                rationale,
                effective,
                criterion_scores,
                requested,
                remaining_budget,
            } => {
                let mut members = vec![
                    ("proposal", dec(proposal)),
                    ("recused", Value::Bool(false)),
                    ("title", text_or_null(title)),
                    ("neutral_summary", text_or_null(neutral_summary)),
                    ("rationale", text_or_null(rationale)),
                    ("effective", Value::from(effective.as_str())),
                    ("criterion_scores", array(criterion_scores)),
                    ("requested", Value::from(requested.as_str())),
                ];
                members.extend(budget_members(remaining_budget));
                object(members)
            }
        }
    }
}

impl McpSafe for RankingRow {}

/// A committee member the coordinator may assign, by display handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The account id.
    pub account: u128,
    /// The pseudonymous display handle. Never an email.
    pub label: String,
}

/// The workspace of a proposal (I-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceView {
    /// The title.
    pub title: String,
    /// The neutral summary.
    pub summary: String,
    /// The narrative.
    pub narrative: String,
}

impl ToJson for WorkspaceView {
    fn to_json(&self) -> Value {
        object(vec![
            ("title", Value::from(self.title.as_str())),
            ("summary", Value::from(self.summary.as_str())),
            ("narrative", Value::from(self.narrative.as_str())),
        ])
    }
}

impl McpSafe for WorkspaceView {}

/// `ratio` times `scale`, with two decimals, rounded down: the spelling of
/// effective and weighted scores (P-02 NOTE 6). `None` when it overflows.
pub(crate) fn two_decimals(num: u64, den: u64, scale: u64) -> Option<String> {
    let hundredths = u128::from(num)
        .checked_mul(u128::from(scale))?
        .checked_mul(100)?
        .checked_div(u128::from(den))?;
    let whole = hundredths.checked_div(100)?;
    let frac = hundredths.checked_rem(100)?;
    Some(format!("{whole}.{frac:02}"))
}

/// Lowercase hexadecimal of `bytes`.
fn hex(bytes: &[u8]) -> Value {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    Value::String(s)
}

/// Where one message of the delivery log stands: the phase of its head
/// row in `ops.delivery` (M6 design section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryPhase {
    /// A worker claimed it.
    Claimed,
    /// A worker passed the commit point.
    Committing,
    /// The server accepted it (250).
    Sent,
    /// A 4xx reply. It is retried.
    Transient,
    /// A 5xx reply, or the retries ran out.
    Permanent,
    /// The outcome is unknown. It is never sent again (I-26).
    InDoubt,
}

impl DeliveryPhase {
    /// The wire name.
    pub const fn name(self) -> &'static str {
        match self {
            DeliveryPhase::Claimed => "claimed",
            DeliveryPhase::Committing => "committing",
            DeliveryPhase::Sent => "sent",
            DeliveryPhase::Transient => "transient",
            DeliveryPhase::Permanent => "permanent",
            DeliveryPhase::InDoubt => "in_doubt",
        }
    }
}

/// One message of the tenant's delivery log, `tenant.deliveries` (M6
/// design section 6, I-27). The type has no member for a body, an
/// address or a recipient, so the read can never show one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryRow {
    /// The `ops.outbox` row id.
    pub outbox: [u8; 16],
    /// The template code, which names the kind of message.
    pub template: &'static str,
    /// The timeline event.
    pub event: [u8; 32],
    /// The template version.
    pub template_version: u16,
    /// The phase of its head row.
    pub phase: DeliveryPhase,
    /// The attempts so far.
    pub attempts: u32,
    /// The last SMTP reply code, when one was read.
    pub reply_code: Option<u16>,
}

impl ToJson for DeliveryRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("outbox", hex(&self.outbox)),
            ("template", Value::from(self.template)),
            ("event", hex(&self.event)),
            ("template_version", dec(self.template_version)),
            ("phase", Value::from(self.phase.name())),
            ("attempts", int(u64::from(self.attempts))),
            (
                "reply_code",
                self.reply_code.map_or(Value::Null, |c| int(u64::from(c))),
            ),
        ])
    }
}

/// Where one timeline event stands (R-NT-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventState {
    /// Scheduled, not fired yet.
    Scheduled,
    /// Cancelled, never deleted (R-NT-01 AC).
    Cancelled,
    /// Fired.
    Fired,
}

/// One event of a programme's timeline, `programme.timeline` (M6 design
/// section 6): its id, kind, due instant and state. No message content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimelineRow {
    /// The event id.
    pub event: [u8; 32],
    /// The kind code of `fstp_timeline::kind`.
    pub kind: u16,
    /// When it is due, UTC microseconds.
    pub due: i64,
    /// Where it stands.
    pub state: EventState,
}

/// The wire name of a timeline kind code, as `fstp_timeline::kind`
/// numbers them. An unknown code reads as `immediate`, which no source
/// derives beyond those codes.
const fn kind_name(kind: u16) -> &'static str {
    match kind {
        2 => "stage2_expiry",
        3 => "re_enter",
        4 => "start_execution",
        5 => "complete",
        6 => "milestone_reminder",
        7 => "milestone_overdue",
        8 => "corrigendum",
        9 => "notice_issued",
        10 => "copy_requested",
        _ => "immediate",
    }
}

impl ToJson for TimelineRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("event", hex(&self.event)),
            ("kind", Value::from(kind_name(self.kind))),
            ("due", dec(self.due)),
            (
                "status",
                Value::from(match self.state {
                    EventState::Scheduled => "scheduled",
                    EventState::Cancelled => "cancelled",
                    EventState::Fired => "fired",
                }),
            ),
        ])
    }
}

/// The tenant's mail relay as `tenant.get_mail_relay` shows it (ADR-018):
/// the host and whether a CA is pinned. The name of the credential's cell
/// secret is never shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailRelayView {
    /// The relay, when one is set.
    pub relay: Option<(String, bool)>,
}

impl ToJson for MailRelayView {
    fn to_json(&self) -> Value {
        let relay = match &self.relay {
            None => Value::Null,
            Some((host, pinned)) => object(vec![
                ("host", Value::from(host.as_str())),
                ("ca_pinned", Value::Bool(*pinned)),
            ]),
        };
        object(vec![("relay", relay)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-02 NOTE 6: scores are spelled with two decimals and never rounded
    /// up, so 75.00 exactly reads as 75.00 and 2/3 as 66.66.
    #[test]
    fn i08_scores_are_spelled_with_two_decimals_rounded_down() {
        assert_eq!(two_decimals(3, 4, 100).as_deref(), Some("75.00"));
        assert_eq!(two_decimals(2, 3, 100).as_deref(), Some("66.66"));
        assert_eq!(two_decimals(9, 2, 1).as_deref(), Some("4.50"));
        assert_eq!(two_decimals(0, 1, 100).as_deref(), Some("0.00"));
        assert_eq!(two_decimals(1, 0, 100), None);
    }

    /// R-IR-03: the IRC case holds the proposal and its outcome, and no call,
    /// score, ballot or rationale member.
    #[test]
    fn r_ir_03_irc_case_members() {
        let v = ContentView {
            proposal: 1,
            call: 2,
            state: "IRC_REVIEW",
            title: "t".to_owned(),
            text: "x".to_owned(),
            outcome: Some("nominated"),
        }
        .to_json();
        let keys: Vec<&str> = v
            .as_object()
            .map(|o| o.keys().collect())
            .unwrap_or_default();
        assert_eq!(keys, ["proposal", "state", "title", "text", "outcome"]);
    }
}

/// One stage 2 question as the applicant team reads it (`stage2.view`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// The asking reviewer's P-11 handle.
    pub handle: String,
    /// The day it was asked, `YYYY-MM-DD` (TH-08: no time of day).
    pub asked: String,
    /// The question.
    pub text: String,
}

impl ToJson for Question {
    fn to_json(&self) -> Value {
        object(vec![
            ("handle", Value::from(self.handle.as_str())),
            ("asked", Value::from(self.asked.as_str())),
            ("text", Value::from(self.text.as_str())),
        ])
    }
}

impl McpSafe for Question {}

/// One notice of the caller (`me.notices`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The outbox record kind: `ProposalOutcome` or `IrcConcern`.
    pub kind: &'static str,
    /// The proposal it concerns.
    pub proposal: u128,
    /// The day it was recorded, when known.
    pub day: Option<String>,
}

impl ToJson for Notice {
    fn to_json(&self) -> Value {
        let mut members = vec![
            ("kind", Value::from(self.kind)),
            ("proposal", dec(self.proposal)),
        ];
        if let Some(d) = &self.day {
            members.push(("day", Value::from(d.as_str())));
        }
        object(members)
    }
}

impl McpSafe for Notice {}

/// One quoted piece of evidence of a pre-check finding (M7 design
/// section 4). The quote is untrusted data, shown as text only (TH-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckEvidenceRow {
    /// `title`, `summary` or `narrative`.
    pub section: &'static str,
    /// The quoted text.
    pub quote: String,
}

impl ToJson for PrecheckEvidenceRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("section", Value::from(self.section)),
            ("quote", Value::from(self.quote.as_str())),
        ])
    }
}

/// One pre-check finding: no confidence and no number (TH-02, R-LA-06).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckFindingRow {
    /// `completeness`, `quality`, `accuracy` or `integrity`.
    pub kind: &'static str,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<u128>,
    /// `info`, `minor` or `major`.
    pub severity: &'static str,
    /// The observation, untrusted data.
    pub statement: String,
    /// Quotes from the draft.
    pub evidence: Vec<PrecheckEvidenceRow>,
}

impl ToJson for PrecheckFindingRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("kind", Value::from(self.kind)),
            ("criterion", self.criterion.map_or(Value::Null, dec)),
            ("severity", Value::from(self.severity)),
            ("statement", Value::from(self.statement.as_str())),
            ("evidence", array(&self.evidence)),
        ])
    }
}

/// One pre-check run of a draft (M7 design section 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckRunRow {
    /// The run.
    pub run: u128,
    /// When it was requested, UTC microseconds.
    pub requested: i64,
    /// `pending`, `done` or `unavailable`.
    pub state: &'static str,
    /// Its findings.
    pub findings: Vec<PrecheckFindingRow>,
}

impl ToJson for PrecheckRunRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("run", dec(self.run)),
            ("requested", dec(self.requested)),
            ("state", Value::from(self.state)),
            ("findings", array(&self.findings)),
        ])
    }
}

/// `proposal.precheck` and `proposal.precheck_runs`: the runs of a draft
/// and the remaining P-23 checks, which are the only numbers shown
/// (M7 design section 2, reading 4; TH-29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckView {
    /// `synthetic` for the demo cell's synthetic assessor, else `model`.
    pub assessor: &'static str,
    /// Runs left today on this proposal.
    pub proposal_today: u32,
    /// Runs left in this call on this proposal.
    pub proposal_call: u32,
    /// Runs left for this account across its drafts in this call.
    pub account_call: u32,
    /// When the next run becomes available, if none is left now.
    pub next: Option<i64>,
    /// The runs, newest first.
    pub runs: Vec<PrecheckRunRow>,
}

impl ToJson for PrecheckView {
    fn to_json(&self) -> Value {
        object(vec![
            ("assessor", Value::from(self.assessor)),
            (
                "remaining",
                object(vec![
                    ("proposal_today", int(u64::from(self.proposal_today))),
                    ("proposal_call", int(u64::from(self.proposal_call))),
                    ("account_call", int(u64::from(self.account_call))),
                    ("next", self.next.map_or(Value::Null, dec)),
                ]),
            ),
            ("runs", array(&self.runs)),
        ])
    }
}

/// One row of `assess.findings_status`: counts only, never a statement
/// (M7 design section 7, I-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingsStatusRow {
    /// The proposal.
    pub proposal: u128,
    /// `pending` while no finding is recorded, else `ready`.
    pub status: &'static str,
    /// How many findings are recorded.
    pub findings: u64,
}

impl ToJson for FindingsStatusRow {
    fn to_json(&self) -> Value {
        object(vec![
            ("proposal", dec(self.proposal)),
            ("status", Value::from(self.status)),
            ("findings", int(self.findings)),
        ])
    }
}

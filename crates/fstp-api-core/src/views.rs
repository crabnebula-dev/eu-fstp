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

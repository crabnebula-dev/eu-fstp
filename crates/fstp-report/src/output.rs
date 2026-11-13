//! The five outputs of `SPEC/03-architecture/funder-reporting.md`
//! (R-RP-04), generated under a versioned funder profile (M9 design
//! section 2.5). The profile names the template of each output and the
//! fields that carry figures. Each field names a ledger fold of
//! [`Figure`], so every figure is computed here from the reconciled books
//! (I-44). Members that carry no figure, such as dates and ids, are fixed
//! by the output kind.
//!
//! | Output | Form | Source |
//! | --- | --- | --- |
//! | Call publication record | JSON | Frozen call record, budget, dates |
//! | Open call package | PDF | Stored Guide, proposal form, contract template, notice |
//! | Periodic reporting data | JSON | Contracts and payments per period |
//! | Audit file per call | PDF | Record kinds, sequence numbers and hashes |
//! | Deliverable draft | PDF | Per-call selection report from the ledger |
//!
//! Every output reconciles its snapshot first (I-44). Equal snapshots and
//! inputs give equal bytes (R-RP-01). Recipients appear only by a
//! pseudonymous grant reference. Legal form and country are joined on the
//! vault origin at download (M5 design reading 7), so no output of the
//! cell holds them. No output names an account.
//!
//! TODO(legal): L-09. The field lists and formats of every template
//! depend on the current portal forms and the SuperSAFE grant agreement.
//! Daniel checks them before any template leaves draft status.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{CallId, ContentDigest, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_json::{Object, ToJson, Value};
use fstp_money::{Amount, Currency};
use fstp_pdf::{Block, BlockKind, Document};
use fstp_report_core::{ProfilePin, ReportKind, Scope};

use crate::ReportError;
use crate::books::{Books, GrantBook, reconcile};
use crate::profile::{Figure, FunderProfile, Level, OutputSpec, ProfileError};
use crate::snapshot::{Snapshot, record_digest};
use crate::time::{date, utc};

/// A reporting period from the Data Sheet: `start` inclusive, `end`
/// exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period {
    /// The first instant.
    pub start: Timestamp,
    /// The instant after the last.
    pub end: Timestamp,
}

/// The parts of the open call package besides the stored Guide.
#[derive(Clone, Copy, Debug)]
pub struct PackageInputs<'a> {
    /// The stored canonical Guide document of the call.
    pub guide: &'a [u8],
    /// The proposal form.
    pub proposal_form: &'a [Block],
    /// The contract template.
    pub contract_template: &'a [Block],
    /// The data protection notice. It must reference the Portal Privacy
    /// Statement at `privacy_statement_url`.
    pub data_protection: &'a [Block],
    /// The funder's privacy statement address.
    pub privacy_statement_url: &'a str,
}

/// One output to generate.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// The call publication record, with the call's public identifier.
    CallPublicationRecord {
        /// The call.
        call: CallId,
        /// Its public identifier.
        identifier: &'a str,
    },
    /// The open call package.
    OpenCallPackage {
        /// The call.
        call: CallId,
        /// The parts.
        package: &'a PackageInputs<'a>,
    },
    /// The periodic reporting data.
    PeriodicReportingData {
        /// The programme.
        programme: ProgrammeId,
        /// The reporting periods, in order, not overlapping.
        periods: &'a [Period],
    },
    /// The audit file of a call.
    AuditFile {
        /// The call.
        call: CallId,
    },
    /// The selection report of a call.
    DeliverableDraft {
        /// The call.
        call: CallId,
    },
}

/// The content of an output, before its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// Data, written as RFC 8785 JSON.
    Data(Value),
    /// A document, written by `fstp-pdf`.
    Document(Document),
}

/// A generated output, a draft until approved (R-RP-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The output.
    pub kind: ReportKind,
    /// What it covers.
    pub scope: Scope,
    /// The template version, from the profile.
    pub template: String,
    /// The funder profile it was generated under (P-53).
    pub profile: ProfilePin,
    /// The digest of the snapshot it was generated from.
    pub snapshot: ContentDigest,
    /// The content.
    pub content: Content,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The SHA-256 of the bytes.
    pub digest: ContentDigest,
}

impl Output {
    /// The media type of the bytes.
    pub fn media(&self) -> &'static str {
        match self.content {
            Content::Data(_) => "application/json",
            Content::Document(_) => "application/pdf",
        }
    }
}

/// What one output is generated under: the profile, its output entry and
/// the snapshot digest.
struct Under<'a> {
    profile: &'a FunderProfile,
    spec: &'a OutputSpec,
    snapshot: ContentDigest,
}

/// Generates one output from `snap` under `profile` (module
/// documentation). An output the profile does not define is refused.
pub fn generate(
    snap: &Snapshot,
    profile: &FunderProfile,
    request: &Request<'_>,
) -> Result<Output, ReportError> {
    let books = reconcile(snap)?;
    let snapshot = snap.digest()?;
    let kind = request.kind();
    let spec = profile
        .output(kind)
        .ok_or(ReportError::NotInProfile(kind))?;
    let u = Under {
        profile,
        spec,
        snapshot,
    };
    let (scope, content) = match *request {
        Request::CallPublicationRecord { call, identifier } => (
            Scope::Call(call),
            Content::Data(publication(&u, snap, &books, call, identifier)?),
        ),
        Request::OpenCallPackage { call, package } => (
            Scope::Call(call),
            Content::Document(open_call_package(&u, &books, call, package)?),
        ),
        Request::PeriodicReportingData { programme, periods } => (
            Scope::Programme(programme),
            Content::Data(periodic(&u, &books, programme, periods)?),
        ),
        Request::AuditFile { call } => (
            Scope::Call(call),
            Content::Document(audit_file(&u, snap, &books, call)?),
        ),
        Request::DeliverableDraft { call } => (
            Scope::Call(call),
            Content::Document(selection_report(&u, snap, &books, call)?),
        ),
    };
    let bytes = match &content {
        Content::Data(v) => v
            .to_canonical()
            .map_err(|_| ReportError::Encoding)?
            .into_bytes(),
        Content::Document(d) => fstp_pdf::write(d).map_err(ReportError::Pdf)?,
    };
    let digest = ContentDigest::from_bytes(fstp_crypto::sha256(&bytes));
    Ok(Output {
        kind,
        scope,
        template: spec.template().to_owned(),
        profile: profile.pin(),
        snapshot,
        content,
        bytes,
        digest,
    })
}

impl Request<'_> {
    /// The output this request asks for.
    pub fn kind(&self) -> ReportKind {
        match self {
            Request::CallPublicationRecord { .. } => ReportKind::CallPublicationRecord,
            Request::OpenCallPackage { .. } => ReportKind::OpenCallPackage,
            Request::PeriodicReportingData { .. } => ReportKind::PeriodicReportingData,
            Request::AuditFile { .. } => ReportKind::AuditFile,
            Request::DeliverableDraft { .. } => ReportKind::DeliverableDraft,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn s(t: impl Into<String>) -> Value {
    Value::String(t.into())
}

fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn add(a: Amount, b: Amount) -> Result<Amount, ReportError> {
    a.checked_add(b).map_err(|_| ReportError::Money)
}

fn sub(a: Amount, b: Amount) -> Result<Amount, ReportError> {
    a.checked_sub(b).map_err(|_| ReportError::Money)
}

fn header(o: &mut Object, u: &Under<'_>) {
    o.insert("profile", s(u.profile.id()));
    o.insert("profile_version", s(u.profile.version().to_string()));
    o.insert("profile_digest", s(hex(u.profile.digest())));
    o.insert("output", s(u.spec.kind().name()));
    o.insert("template", s(u.spec.template()));
    o.insert("snapshot", s(hex(u.snapshot)));
}

fn block(kind: BlockKind, text: impl Into<String>) -> Block {
    Block {
        kind,
        text: text.into(),
    }
}

fn h1(t: impl Into<String>) -> Block {
    block(BlockKind::Heading1, t)
}

fn h2(t: impl Into<String>) -> Block {
    block(BlockKind::Heading2, t)
}

fn p(t: impl Into<String>) -> Block {
    block(BlockKind::Paragraph, t)
}

/// The draft status line every document carries until L-09 is checked.
fn status(u: &Under<'_>) -> Block {
    p(format!(
        "Template {}. Funder profile {} version {}. Draft for approval by a Financial signatory. Field list not yet checked against the portal forms (L-09).",
        u.spec.template(),
        u.profile.id(),
        u.profile.version()
    ))
}

/// A figure: an amount of money or a count.
#[derive(Clone, Copy, Debug)]
enum Fig {
    Amount(Amount),
    Count(u64),
}

impl Fig {
    fn count(n: usize) -> Fig {
        Fig::Count(u64::try_from(n).unwrap_or(u64::MAX))
    }

    /// The JSON value: amounts as decimal strings (ADR-006), counts as
    /// integers.
    fn json(self) -> Value {
        match self {
            Fig::Amount(a) => s(a.to_string()),
            Fig::Count(n) => Value::Number(n.into()),
        }
    }

    /// The document line of a field labelled `label`.
    fn line(self, label: &str) -> String {
        match self {
            Fig::Amount(a) => format!("{label}: {a} {}.", a.currency().code()),
            Fig::Count(n) => format!("{label}: {n}."),
        }
    }
}

/// A figure the parser lets no field name at that level.
fn undefined() -> ReportError {
    ReportError::Profile(ProfileError::Shape("a figure not defined at its level"))
}

/// Inserts the fields of `u` at `level` into `o`, each by `value`.
fn fields_into(
    o: &mut Object,
    u: &Under<'_>,
    level: Level,
    value: impl Fn(Figure) -> Result<Fig, ReportError>,
) -> Result<(), ReportError> {
    for f in u.spec.at(level) {
        o.insert(f.name(), value(f.figure())?.json());
    }
    Ok(())
}

fn document(title: &str, blocks: Vec<Block>) -> Document {
    Document {
        title: title.to_owned(),
        lang: "en".to_owned(),
        blocks,
        signature_fields: Vec::new(),
    }
}

/// The book of a published call.
fn published(books: &Books, call: CallId) -> Result<&crate::books::CallBook, ReportError> {
    books
        .calls
        .get(&call)
        .filter(|c| c.published.is_some())
        .ok_or(ReportError::UnknownCall)
}

// ---------------------------------------------------------------------------
// Call-level figures
// ---------------------------------------------------------------------------

/// The folds of one published call (level [`Level::Call`]).
struct CallFigures<'b> {
    budget: Amount,
    currency: Currency,
    created: usize,
    submitted: usize,
    knocked: usize,
    grants: Vec<&'b GrantBook>,
}

impl<'b> CallFigures<'b> {
    fn of(snap: &Snapshot, books: &'b Books, call: CallId) -> Result<CallFigures<'b>, ReportError> {
        let c = published(books, call)?;
        let currency = books
            .currency_of_call(call)
            .ok_or(ReportError::UnknownCall)?;
        let proposals: BTreeSet<_> = books
            .proposals
            .iter()
            .filter(|(_, k)| **k == call)
            .map(|(p, _)| *p)
            .collect();
        let mut submitted = BTreeSet::new();
        let mut knocked = BTreeSet::new();
        for e in snap.entries() {
            match &e.record {
                fstp_domain::Record::Submitted { proposal, .. } if proposals.contains(proposal) => {
                    submitted.insert(*proposal);
                }
                fstp_domain::Record::KnockOutRecorded { proposal, .. }
                    if proposals.contains(proposal) =>
                {
                    knocked.insert(*proposal);
                }
                _ => {}
            }
        }
        Ok(CallFigures {
            budget: c.budget.amount(),
            currency,
            created: proposals.len(),
            submitted: submitted.len(),
            knocked: knocked.len(),
            grants: books.grants.values().filter(|g| g.call == call).collect(),
        })
    }

    fn get(&self, f: Figure) -> Result<Fig, ReportError> {
        scope_figure(f, &self.grants, self.currency).or_else(|_| match f {
            Figure::CallBudget => Ok(Fig::Amount(self.budget)),
            Figure::ProposalsCreated => Ok(Fig::count(self.created)),
            Figure::ProposalsSubmitted => Ok(Fig::count(self.submitted)),
            Figure::KnockOutDecisions => Ok(Fig::count(self.knocked)),
            _ => Err(undefined()),
        })
    }
}

/// The figures a call and a programme share, over their decided grants.
fn scope_figure(f: Figure, grants: &[&GrantBook], c: Currency) -> Result<Fig, ReportError> {
    let zero = Amount::zero(c);
    let sum = |h: &dyn Fn(&GrantBook) -> Result<Amount, ReportError>| {
        grants.iter().try_fold(zero, |acc, g| add(acc, h(g)?))
    };
    match f {
        Figure::RecipientCount => Ok(Fig::count(grants.len())),
        Figure::GrantsClosed => Ok(Fig::count(
            grants.iter().filter(|g| g.closed.is_some()).count(),
        )),
        Figure::Committed => Ok(Fig::Amount(sum(&|g| Ok(g.committed))?)),
        Figure::Paid => Ok(Fig::Amount(sum(&|g| Ok(g.paid))?)),
        Figure::ReleasedCommitments => Ok(Fig::Amount(sum(&|g| match g.closed {
            Some(_) => sub(g.committed, g.paid),
            None => Ok(zero),
        })?)),
        _ => Err(undefined()),
    }
}

// ---------------------------------------------------------------------------
// Call publication record
// ---------------------------------------------------------------------------

fn publication(
    u: &Under<'_>,
    snap: &Snapshot,
    books: &Books,
    call: CallId,
    identifier: &str,
) -> Result<Value, ReportError> {
    let c = published(books, call)?;
    let (policy, seq, at) = c.published.ok_or(ReportError::UnknownCall)?;
    let figures = CallFigures::of(snap, books, call)?;
    let mut o = Object::new();
    header(&mut o, u);
    o.insert("call", s(identifier));
    o.insert("programme", s(c.programme.raw().to_string()));
    o.insert("opens", s(utc(c.opens)));
    o.insert("deadline", s(utc(c.deadline)));
    o.insert("deadline_time_zone", s(c.zone.clone()));
    o.insert("currency", s(figures.currency.code()));
    o.insert("frozen_policy", s(policy.raw().to_string()));
    o.insert("publication_sequence", s(seq.get().to_string()));
    o.insert("published_at", s(utc(at)));
    fields_into(&mut o, u, Level::Call, |f| figures.get(f))?;
    Ok(Value::Object(o))
}

// ---------------------------------------------------------------------------
// Open call package (I-48)
// ---------------------------------------------------------------------------

/// The five elements of I-48 and the Guide placeholders that state them.
/// Interim, pending Daniel: an element is stated when one of its keys is
/// bound to text that is not blank.
const I48: [(&str, &[&str]); 5] = [
    ("maximum per recipient", &["P-05", "P-04.max"]),
    ("criteria for the exact amount", &["annexe.amount_criteria"]),
    ("closed list of activity types", &["P-55.list"]),
    ("persons supported", &["eligibility.persons"]),
    ("award criteria and procedure", &["P-01.table"]),
];

fn open_call_package(
    u: &Under<'_>,
    books: &Books,
    call: CallId,
    package: &PackageInputs<'_>,
) -> Result<Document, ReportError> {
    published(books, call)?;
    let guide = crate::guide::read_canonical(package.guide).map_err(ReportError::Guide)?;
    let mut missing: Vec<&'static str> = I48
        .iter()
        .filter(|(_, keys)| {
            !keys
                .iter()
                .any(|k| guide.value(k).is_some_and(|v| !v.trim().is_empty()))
        })
        .map(|(name, _)| *name)
        .collect();
    let filled = |b: &[Block]| b.iter().any(|x| !x.text.trim().is_empty());
    if !filled(package.proposal_form) {
        missing.push("proposal form");
    }
    if !filled(package.contract_template) {
        missing.push("contract template");
    }
    let url = package.privacy_statement_url.trim();
    if url.is_empty() || !package.data_protection.iter().any(|b| b.text.contains(url)) {
        missing.push("data protection notice");
    }
    if !missing.is_empty() {
        return Err(ReportError::Package(missing));
    }
    let identifier = guide
        .value("call.identifier")
        .map_or_else(|| call.raw().to_string(), str::to_owned);
    let mut blocks = vec![
        h1("Open call package"),
        p(format!("Call {identifier}.")),
        status(u),
    ];
    blocks.extend(guide.blocks().iter().cloned());
    blocks.push(h1("Proposal form"));
    blocks.extend(package.proposal_form.iter().cloned());
    blocks.push(h1("Contract template"));
    blocks.extend(package.contract_template.iter().cloned());
    blocks.push(h1("Data protection notice"));
    blocks.extend(package.data_protection.iter().cloned());
    Ok(document(&format!("Open call package {identifier}"), blocks))
}

// ---------------------------------------------------------------------------
// Periodic reporting data
// ---------------------------------------------------------------------------

/// The folds of one recipient in one period (level [`Level::Recipient`]).
#[derive(Clone, Copy)]
struct RowFigures {
    committed: Amount,
    paid: Amount,
    hardship: Amount,
    released: Amount,
}

impl RowFigures {
    fn get(&self, f: Figure) -> Result<Fig, ReportError> {
        match f {
            Figure::Committed => Ok(Fig::Amount(self.committed)),
            Figure::PaidInPeriod => Ok(Fig::Amount(self.paid)),
            Figure::PaidHardshipInPeriod => Ok(Fig::Amount(self.hardship)),
            Figure::ReleasedCommitmentInPeriod => Ok(Fig::Amount(self.released)),
            _ => Err(undefined()),
        }
    }
}

/// The folds of one period (level [`Level::Period`]): sums over its rows.
fn period_figure(f: Figure, rows: &[RowFigures], c: Currency) -> Result<Fig, ReportError> {
    let sum = |h: fn(&RowFigures) -> Amount| {
        rows.iter()
            .try_fold(Amount::zero(c), |acc, r| add(acc, h(r)))
    };
    match f {
        Figure::PaidInPeriod => Ok(Fig::Amount(sum(|r| r.paid)?)),
        Figure::PaidHardshipInPeriod => Ok(Fig::Amount(sum(|r| r.hardship)?)),
        Figure::ReleasedCommitmentInPeriod => Ok(Fig::Amount(sum(|r| r.released)?)),
        Figure::RecipientCount => Ok(Fig::count(rows.len())),
        _ => Err(undefined()),
    }
}

fn periodic(
    u: &Under<'_>,
    books: &Books,
    programme: ProgrammeId,
    periods: &[Period],
) -> Result<Value, ReportError> {
    let currency: Currency = *books
        .programmes
        .get(&programme)
        .ok_or(ReportError::UnknownCall)?;
    if periods.is_empty()
        || periods.iter().any(|p| p.start >= p.end)
        || periods
            .windows(2)
            .any(|w| matches!(w, [a, b] if b.start < a.end))
    {
        return Err(ReportError::Periods);
    }
    let zero = Amount::zero(currency);
    let grants: Vec<_> = books
        .grants
        .iter()
        .filter(|(_, g)| books.calls.get(&g.call).map(|c| c.programme) == Some(programme))
        .collect();
    let mut out_periods = Vec::new();
    for period in periods {
        let within = |t: Timestamp| t >= period.start && t < period.end;
        let mut rows = Vec::new();
        let mut figures = Vec::new();
        for (proposal, g) in &grants {
            if g.decided >= period.end {
                continue;
            }
            let mut paid = zero;
            let mut hardship = zero;
            for r in books.requests.values().filter(|r| r.grant == **proposal) {
                let Some(at) = r.released else { continue };
                if !within(at) {
                    continue;
                }
                let a = r.approved(currency).unwrap_or(zero);
                paid = add(paid, a)?;
                if r.hardship {
                    hardship = add(hardship, a)?;
                }
            }
            let released = match g.closed {
                Some(t) if within(t) => sub(g.committed, g.paid)?,
                _ => zero,
            };
            let f = RowFigures {
                committed: g.committed,
                paid,
                hardship,
                released,
            };
            let mut row = Object::new();
            row.insert("recipient", s(format!("G-{}", proposal.raw())));
            row.insert("call", s(g.call.raw().to_string()));
            fields_into(&mut row, u, Level::Recipient, |x| f.get(x))?;
            rows.push(Value::Object(row));
            figures.push(f);
        }
        let mut po = Object::new();
        po.insert("start", s(utc(period.start)));
        po.insert("end", s(utc(period.end)));
        po.insert("recipients", Value::Array(rows.into()));
        fields_into(&mut po, u, Level::Period, |x| {
            period_figure(x, &figures, currency)
        })?;
        out_periods.push(Value::Object(po));
    }
    let all: Vec<&GrantBook> = grants.iter().map(|(_, g)| *g).collect();
    let mut totals = Object::new();
    fields_into(&mut totals, u, Level::Total, |x| {
        scope_figure(x, &all, currency)
    })?;
    let mut o = Object::new();
    header(&mut o, u);
    o.insert("programme", s(programme.raw().to_string()));
    o.insert("currency", s(currency.code()));
    o.insert("cost_category", s("financial_support_to_third_parties"));
    o.insert(
        "vault_attributes",
        Value::Array(vec![s("legal_form"), s("country")].into()),
    );
    o.insert("periods", Value::Array(out_periods.into()));
    o.insert("totals", Value::Object(totals));
    Ok(Value::Object(o))
}

// ---------------------------------------------------------------------------
// Audit file per call
// ---------------------------------------------------------------------------

/// The sections of the audit file and the record kinds each lists.
const AUDIT: [(&str, &[&str]); 8] = [
    ("Knock-out decisions", &["KnockOutRecorded"]),
    (
        "Scores",
        &[
            "ScoreRecorded",
            "ScoreVoided",
            "Stage1Closed",
            "EffectiveScoreSet",
        ],
    ),
    (
        "Stage 2 records",
        &[
            "QuestionAsked",
            "NoQuestionsRecorded",
            "AnswersRecorded",
            "RevisionSubmitted",
        ],
    ),
    (
        "Ranking and cut-off rationale",
        &[
            "RankingSummaryRecorded",
            "CutOffRoundOpened",
            "BallotCast",
            "VoteDelegated",
            "CutOffRecorded",
        ],
    ),
    ("IRC validations", &["IrcReviewRecorded"]),
    (
        "Conflict declarations",
        &["ConflictDeclared", "ConflictDetected"],
    ),
    (
        "Contracts",
        &[
            "AmountDetermined",
            "GrantAccepted",
            "GrantApproved",
            "ContractFactRecorded",
            "GrantDecided",
            "TerminationRecorded",
            "AmendmentActivated",
        ],
    ),
    (
        "Payment evidence",
        &[
            "PaymentRequested",
            "ChecksRecorded",
            "LineAccepted",
            "PaymentApproved",
            "PaymentReleased",
            "PaymentConfirmed",
            "DeliverableRecorded",
            "MilestoneClosed",
        ],
    ),
];

/// The call's own ids as the stored record form spells them.
#[derive(Default)]
struct Related {
    call: String,
    proposals: BTreeSet<String>,
    assignments: BTreeSet<String>,
    requests: BTreeSet<String>,
    rounds: BTreeSet<String>,
}

impl Related {
    fn member<'v>(v: &'v Value, k: &str) -> Option<&'v str> {
        v.get(k).and_then(Value::as_str)
    }

    /// Learns the ids `v` adds to the call, then answers whether `v`
    /// concerns the call.
    fn concerns(&mut self, tag: &str, v: &Value) -> bool {
        let m = |k| Related::member(v, k);
        match tag {
            "ProposalCreated" | "ReEntered"
                if m("call") == Some(&self.call) || m("to_call") == Some(&self.call) =>
            {
                if let Some(p) = m("proposal") {
                    self.proposals.insert(p.to_owned());
                }
            }
            "Assigned" if m("proposal").is_some_and(|p| self.proposals.contains(p)) => {
                if let Some(a) = m("assignment") {
                    self.assignments.insert(a.to_owned());
                }
            }
            "PaymentRequested" if m("grant").is_some_and(|p| self.proposals.contains(p)) => {
                if let Some(r) = m("request") {
                    self.requests.insert(r.to_owned());
                }
            }
            "CutOffRoundOpened" if m("call") == Some(&self.call) => {
                if let Some(r) = m("round") {
                    self.rounds.insert(r.to_owned());
                }
            }
            _ => {}
        }
        m("call") == Some(&self.call)
            || m("proposal").is_some_and(|p| self.proposals.contains(p))
            || m("grant").is_some_and(|p| self.proposals.contains(p))
            || m("assignment").is_some_and(|a| self.assignments.contains(a))
            || m("request").is_some_and(|r| self.requests.contains(r))
            || m("round").is_some_and(|r| self.rounds.contains(r))
    }
}

fn audit_file(
    u: &Under<'_>,
    snap: &Snapshot,
    books: &Books,
    call: CallId,
) -> Result<Document, ReportError> {
    published(books, call)?;
    let mut related = Related {
        call: call.raw().to_string(),
        ..Related::default()
    };
    let mut sections: BTreeMap<usize, Vec<Block>> = BTreeMap::new();
    for e in snap.entries() {
        let v = e.record.to_json();
        let Some(tag) = v.get("type").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if !related.concerns(&tag, &v) {
            continue;
        }
        let Some(section) = AUDIT
            .iter()
            .position(|(_, kinds)| kinds.contains(&tag.as_str()))
        else {
            continue;
        };
        let d = ContentDigest::from_bytes(record_digest(&e.record)?);
        sections.entry(section).or_default().push(p(format!(
            "seq {}, {}, {tag}, sha256 {}",
            e.seq.raw(),
            utc(e.at),
            hex(d)
        )));
    }
    let mut blocks = vec![
        h1("Audit file"),
        p(format!(
            "Call {}. Snapshot sha256 {}.",
            call.raw(),
            hex(u.snapshot)
        )),
        status(u),
        p(
            "Each line names a ledger record by sequence number, time, kind and the SHA-256 of its stored form. Contractual notices join in M6.",
        ),
    ];
    for (i, (title, _)) in AUDIT.iter().enumerate() {
        blocks.push(h2(*title));
        match sections.remove(&i) {
            Some(lines) => blocks.extend(lines),
            None => blocks.push(p("No records.")),
        }
    }
    Ok(document("Audit file", blocks))
}

// ---------------------------------------------------------------------------
// Deliverable draft: the per-call selection report
// ---------------------------------------------------------------------------

fn selection_report(
    u: &Under<'_>,
    snap: &Snapshot,
    books: &Books,
    call: CallId,
) -> Result<Document, ReportError> {
    let c = published(books, call)?;
    let figures = CallFigures::of(snap, books, call)?;
    let mut blocks = vec![
        h1("Selection report"),
        p(format!(
            "Call {}. Snapshot sha256 {}.",
            call.raw(),
            hex(u.snapshot)
        )),
        status(u),
        h2("Call"),
        p(format!(
            "Opened {}. Deadline {} ({}).",
            date(c.opens),
            utc(c.deadline),
            c.zone
        )),
        h2("Figures"),
    ];
    for f in u.spec.at(Level::Call) {
        blocks.push(p(figures.get(f.figure())?.line(f.label())));
    }
    Ok(document("Selection report", blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_rp_04_kind_names_round_trip() {
        for k in ReportKind::ALL {
            assert_eq!(ReportKind::from_name(k.name()), Some(k));
        }
    }

    /// R-RP-01: the shipped profile names a template of its own for every
    /// output it defines.
    #[test]
    fn r_rp_01_shipped_templates_are_profile_refs() {
        for p in crate::profile::shipped_all().unwrap_or_default() {
            for o in p.outputs() {
                assert!(o.template().starts_with(&format!("{}/", p.id())));
            }
        }
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(ContentDigest::from_bytes([0xab; 32])).len(), 64);
        assert!(hex(ContentDigest::from_bytes([0xab; 32])).starts_with("abab"));
    }
}

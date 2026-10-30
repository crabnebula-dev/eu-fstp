//! The placeholder resolvers (I-51, R-GA-01, M4 design section 3.10:
//! "Placeholders such as `{{P-04.min}}` or `{{call.deadline}}` each have
//! one resolver over the draft or frozen policy, the call record or
//! programme artefacts").
//!
//! [`RESOLVERS`] holds one row per key the template may use, and no key
//! twice. A `P-NN` key reads parameter P-NN of the policy and nothing
//! else. The policy and the artefacts are read back through
//! `fstp_programme::decompile`, the exact inverse of `compile`, so a gap
//! of the draft is a gap here and is refused by key. The profile's
//! placeholder value of a gap is never shown.
//!
//! P-05 and P-13 are live parameters. When [`GuideInputs::publication`]
//! holds the call's publication snapshot, their resolvers read it, never
//! the live value (design section 3.10). A draft preview has no snapshot
//! and reads the draft.
//!
//! Interim readings, each pending Daniel:
//!
//! - the wording each value is shown with, such as "28 days" for P-07 or
//!   the sentence for P-75, read from `SPEC/02-domain/policy-parameters.md`;
//! - instants are shown in UTC to the minute, or to the second when the
//!   seconds are not zero, beside the IANA zone kept as text (M2 does not
//!   interpret zones);
//! - `{{timeline.table}}` lists the opening, the deadline and the P-07,
//!   P-08 and P-61 windows, until the M6 timeline engine replaces it;
//! - the data protection summary and the privacy statement address come
//!   from the caller, because no artefact field holds them. Without them
//!   the Guide is refused by key, never filled with invented text;
//! - a disabled pre-check (P-23) refuses `{{P-23.per_day}}` and
//!   `{{P-23.per_call}}`, because the template describes the pre-check;
//! - an empty list or text is refused, never rendered empty;
//! - a stored narrative is read from [`GuideInputs::texts`]. Checking its
//!   digest needs `fstp-crypto`, which this crate does not depend on.

use fstp_domain::id::TextRef;
use fstp_domain::policy::{LiveSnapshot, McpBindingActions, ReviewerAnonymity};
use fstp_domain::programme::CallView;
use fstp_domain::rules::ParamId;
use fstp_domain::time::{MICROS_PER_DAY, Timestamp, ZoneName};
use fstp_html::SafeUrl;
use fstp_programme::kinds::{PartialClaimEvidence, UnclaimedBalances};
use fstp_programme::value::Token;
use fstp_programme::{Compiled, Field, FieldId, FieldValue, Narrative, ProgrammeSpec, decompile};

use crate::{KeyName, known_name};

/// Where a resolver reads its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The draft or frozen policy.
    Policy,
    /// The call record.
    CallRecord,
    /// The programme artefacts.
    Artefacts,
    /// Something else the caller supplies: the Guide version, the
    /// platform address and the data protection texts.
    Other,
}

/// Where a placeholder's value may stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Shape {
    /// Text inside a line.
    Inline,
    /// An address inside a line, shown as a link.
    Link,
    /// Paragraphs, a list or a table, alone between blank lines.
    Block,
}

/// What a resolver computes. Private, so a row comes only from
/// [`RESOLVERS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    ArtefactText(FieldId),
    ArtefactBlock(FieldId),
    CallIdentifier,
    CallOpens,
    CallDeadline,
    CallZone,
    CallBudget,
    GuideVersion,
    PlatformUrl,
    DataProtection,
    PrivacyStatement,
    Timeline,
    P01Table,
    P02,
    P03,
    P04Min,
    P04Max,
    P05,
    P07,
    P08,
    P09List,
    P11,
    P13List,
    P23PerDay,
    P23PerCall,
    P25,
    P26List,
    P29,
    P30,
    P34List,
    P36,
    P41,
    P55List,
    P57End,
    P59,
    P61,
    P62,
    P63,
    P64,
    P65,
    P67,
    P75,
    P77,
}

/// One placeholder key and its resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolver {
    /// The key, such as `P-04.min`.
    pub key: &'static str,
    /// Where the value comes from.
    pub source: Source,
    /// The parameter the value shows, for a parameter-bound key.
    pub param: Option<ParamId>,
    /// Where the value may stand.
    pub shape: Shape,
    kind: Kind,
}

impl Resolver {
    /// Whether a person may edit the value's text before publication. Only
    /// the programme artefacts are edited by hand, in the creator.
    /// Parameter-bound text never is (I-51).
    pub fn editable(&self) -> bool {
        self.source == Source::Artefacts
    }
}

const fn row(key: &'static str, source: Source, shape: Shape, kind: Kind) -> Resolver {
    Resolver {
        key,
        source,
        param: None,
        shape,
        kind,
    }
}

const fn param(key: &'static str, p: ParamId, shape: Shape, kind: Kind) -> Resolver {
    Resolver {
        key,
        source: Source::Policy,
        param: Some(p),
        shape,
        kind,
    }
}

use Shape::{Block as B, Inline as I, Link as L};

/// Every placeholder key a Guide template may use, with its resolver, in
/// the order the shipped Horizon Europe template first uses them.
pub const RESOLVERS: &[Resolver] = &[
    row(
        "programme.name",
        Source::Artefacts,
        I,
        Kind::ArtefactText(FieldId::ProgrammeName),
    ),
    row(
        "programme.narrative",
        Source::Artefacts,
        B,
        Kind::ArtefactBlock(FieldId::ProgrammeNarrative),
    ),
    row(
        "action.number",
        Source::Artefacts,
        I,
        Kind::ArtefactText(FieldId::ActionNumber),
    ),
    row(
        "action.acronym",
        Source::Artefacts,
        I,
        Kind::ArtefactText(FieldId::ActionAcronym),
    ),
    row(
        "coordinator.name",
        Source::Artefacts,
        I,
        Kind::ArtefactText(FieldId::CoordinatorName),
    ),
    row(
        "call.identifier",
        Source::CallRecord,
        I,
        Kind::CallIdentifier,
    ),
    row("call.opens", Source::CallRecord, I, Kind::CallOpens),
    row("call.deadline", Source::CallRecord, I, Kind::CallDeadline),
    row(
        "call.deadline_time_zone",
        Source::CallRecord,
        I,
        Kind::CallZone,
    ),
    row("call.budget", Source::CallRecord, I, Kind::CallBudget),
    param("P-04.min", ParamId::P04, I, Kind::P04Min),
    param("P-04.max", ParamId::P04, I, Kind::P04Max),
    param("P-05", ParamId::P05, I, Kind::P05),
    param("P-25", ParamId::P25, I, Kind::P25),
    row("guide.version", Source::Other, I, Kind::GuideVersion),
    row(
        "programme.scope",
        Source::Artefacts,
        I,
        Kind::ArtefactText(FieldId::ProgrammeScope),
    ),
    param("P-55.list", ParamId::P55, B, Kind::P55List),
    param("P-26.list", ParamId::P26, I, Kind::P26List),
    row(
        "eligibility.persons",
        Source::Artefacts,
        B,
        Kind::ArtefactBlock(FieldId::PersonsSupported),
    ),
    param("P-13.list", ParamId::P13, B, Kind::P13List),
    row("platform.url", Source::Other, L, Kind::PlatformUrl),
    param("P-23.per_day", ParamId::P23, I, Kind::P23PerDay),
    param("P-23.per_call", ParamId::P23, I, Kind::P23PerCall),
    param("P-09.list", ParamId::P09, B, Kind::P09List),
    param("P-03", ParamId::P03, I, Kind::P03),
    param("P-01.table", ParamId::P01, B, Kind::P01Table),
    param("P-02", ParamId::P02, I, Kind::P02),
    param("P-08", ParamId::P08, I, Kind::P08),
    param("P-07", ParamId::P07, I, Kind::P07),
    param("P-75.description", ParamId::P75, I, Kind::P75),
    param("P-77.description", ParamId::P77, I, Kind::P77),
    param("P-11.description", ParamId::P11, I, Kind::P11),
    row(
        "annexe.amount_criteria",
        Source::Artefacts,
        B,
        Kind::ArtefactBlock(FieldId::AmountCriteria),
    ),
    param("P-57.end", ParamId::P57, I, Kind::P57End),
    param("P-29", ParamId::P29, I, Kind::P29),
    param("P-30.description", ParamId::P30, I, Kind::P30),
    param("P-34.list", ParamId::P34, B, Kind::P34List),
    param("P-65.description", ParamId::P65, I, Kind::P65),
    param("P-59", ParamId::P59, I, Kind::P59),
    param("P-67.description", ParamId::P67, I, Kind::P67),
    param("P-36", ParamId::P36, I, Kind::P36),
    row(
        "gdpr.notice_summary",
        Source::Other,
        B,
        Kind::DataProtection,
    ),
    row(
        "funder.privacy_statement_url",
        Source::Other,
        L,
        Kind::PrivacyStatement,
    ),
    param("P-41", ParamId::P41, I, Kind::P41),
    row("timeline.table", Source::CallRecord, B, Kind::Timeline),
    param("P-61", ParamId::P61, I, Kind::P61),
    param("P-62", ParamId::P62, I, Kind::P62),
    param("P-63", ParamId::P63, I, Kind::P63),
    param("P-64", ParamId::P64, I, Kind::P64),
    row(
        "programme.contact",
        Source::Artefacts,
        B,
        Kind::ArtefactBlock(FieldId::ProgrammeContact),
    ),
    row(
        "programme.faq",
        Source::Artefacts,
        B,
        Kind::ArtefactBlock(FieldId::Faq),
    ),
];

/// A known placeholder key: its row of [`RESOLVERS`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Key {
    ix: usize,
    row: &'static Resolver,
}

impl PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        self.ix == other.ix
    }
}

impl Eq for Key {}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Key) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Key) -> std::cmp::Ordering {
        self.ix.cmp(&other.ix)
    }
}

impl Key {
    /// Its resolver.
    pub(crate) fn resolver(self) -> &'static Resolver {
        self.row
    }

    /// Its name.
    pub(crate) fn name(self) -> KeyName {
        known_name(self.row.key)
    }
}

/// The key `name`, if a resolver holds it.
pub(crate) fn lookup(name: &str) -> Option<Key> {
    RESOLVERS
        .iter()
        .enumerate()
        .find(|(_, r)| r.key == name)
        .map(|(ix, row)| Key { ix, row })
}

/// A bound value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// Text in a line.
    Text(String),
    /// An address in a line.
    Link(SafeUrl),
    /// Paragraphs.
    Paragraphs(Vec<String>),
    /// A bullet list.
    List(Vec<String>),
    /// A table with a header row.
    Table {
        head: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

impl Value {
    /// The value's text without markup: paragraphs apart by a blank line,
    /// list items and table rows one per line, cells apart by ` | `.
    pub(crate) fn plain(&self) -> String {
        match self {
            Value::Text(t) => t.clone(),
            Value::Link(u) => u.as_str().to_owned(),
            Value::Paragraphs(p) => p.join("\n\n"),
            Value::List(items) => items.join("\n"),
            Value::Table { head, rows } => std::iter::once(head)
                .chain(rows)
                .map(|r| r.join(" | "))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// The source of stored narrative texts (ADR-007): a `TextRef` read
/// back as its text.
pub trait StoredTexts {
    /// The text `text` names, if the source holds it.
    fn text(&self, text: TextRef) -> Option<&str>;
}

/// A source with no stored text. Every stored narrative is refused by
/// key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoStoredTexts;

impl StoredTexts for NoStoredTexts {
    fn text(&self, _text: TextRef) -> Option<&str> {
        None
    }
}

/// The call record a Guide shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuideCall {
    /// The call's public identifier, 1 to 128 bytes.
    pub identifier: String,
    /// When the call opens.
    pub opens: Timestamp,
    /// The deadline, a UTC instant.
    pub deadline: Timestamp,
    /// The IANA zone of the deadline, kept as text.
    pub deadline_zone: ZoneName,
    /// The call budget in its ADR-006 spelling, such as `250000.00`.
    pub budget: String,
}

impl GuideCall {
    /// The record of `view`, published under `identifier`.
    pub fn from_view(identifier: &str, view: &CallView) -> GuideCall {
        GuideCall {
            identifier: identifier.to_owned(),
            opens: view.opens(),
            deadline: view.deadline(),
            deadline_zone: view.deadline_zone().clone(),
            budget: view.budget().amount().to_string(),
        }
    }
}

/// Everything one Guide is bound from.
#[derive(Clone, Copy)]
pub struct GuideInputs<'a> {
    /// The compiled draft, or the compiled version of the frozen policy:
    /// its policy, its artefacts and its gaps.
    pub compiled: &'a Compiled,
    /// The call's P-05 and P-13 snapshot at publication. P-05 and P-13
    /// read it when it is present.
    pub publication: Option<&'a LiveSnapshot>,
    /// The call record.
    pub call: &'a GuideCall,
    /// The Guide version, from 1.
    pub guide_version: u32,
    /// The `https:` address applicants create an account on.
    pub platform_url: &'a str,
    /// The data protection summary, `{{gdpr.notice_summary}}`.
    pub data_protection_summary: Option<&'a str>,
    /// The `https:` address of the funder's privacy statement,
    /// `{{funder.privacy_statement_url}}`.
    pub privacy_statement_url: Option<&'a str>,
    /// The stored narrative texts.
    pub texts: &'a dyn StoredTexts,
}

const UNSET: &str = "the draft leaves its field unset";
const MISMATCH: &str = "the field holds a value of another kind";
const EMPTY: &str = "the text or list is empty";
const NOT_STORED: &str = "the stored text is not available to the Guide";
const PRECHECK_OFF: &str = "the pre-check is disabled, and the template describes it";
const NOT_HTTPS: &str = "the address is not an https address";
const NO_SUMMARY: &str = "no data protection summary was supplied";
const NO_PRIVACY: &str = "no privacy statement address was supplied";
const BAD_INSTANT: &str = "the instant lies outside the years 1970 to 9999";
const BAD_IDENTIFIER: &str = "the call identifier is empty or longer than 128 bytes";
const BAD_BUDGET: &str = "the call budget is not an ADR-006 amount string";
const BAD_VERSION: &str = "the Guide version is 0";
const UNDESCRIBED: &str = "a class of the publication snapshot has no description";

/// The value of field `$id` of the decompiled spec, or the reason.
macro_rules! get {
    ($ctx:expr, $id:ident) => {
        match $ctx.spec.get(FieldId::$id) {
            Field::Set(FieldValue::$id(v)) => v,
            Field::Set(_) => return Err(MISMATCH),
            Field::Unset => return Err(UNSET),
        }
    };
}

/// One resolution over one set of inputs.
pub(crate) struct Ctx<'a> {
    inputs: &'a GuideInputs<'a>,
    spec: ProgrammeSpec,
}

/// `n` with the singular or the plural noun.
fn count(n: impl Into<u64>, one: &str, many: &str) -> String {
    let n = n.into();
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `s` with its first character in upper case.
fn capitalised(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The words of a policy token, such as `SPDX licence` for
/// `spdx_licence`.
fn words(t: &Token) -> String {
    t.as_str()
        .split('_')
        .filter(|w| !w.is_empty())
        .map(|w| match w {
            "spdx" => "SPDX",
            "qes" => "QES",
            "qtsp" => "QTSP",
            "mou" => "MoU",
            "cra" => "CRA",
            "eu" => "EU",
            "eudi" => "EUDI",
            "irc" => "IRC",
            "fstp" => "FSTP",
            "mcp" => "MCP",
            "ai" => "AI",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `y` is a leap year.
fn leap(y: i64) -> bool {
    (y.checked_rem(4) == Some(0) && y.checked_rem(100) != Some(0)) || y.checked_rem(400) == Some(0)
}

/// The civil date of day `days` after 1970-01-01, within the years 1970
/// to 9999.
fn civil(mut days: i64) -> Option<(i64, i64, i64)> {
    if days < 0 {
        return None;
    }
    let mut year: i64 = 1970;
    loop {
        let len = if leap(year) { 366 } else { 365 };
        if days < len {
            break;
        }
        days = days.checked_sub(len)?;
        year = year.checked_add(1)?;
        if year > 9999 {
            return None;
        }
    }
    let feb = if leap(year) { 29 } else { 28 };
    let mut month: i64 = 1;
    for len in [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] {
        if days < len {
            return Some((year, month, days.checked_add(1)?));
        }
        days = days.checked_sub(len)?;
        month = month.checked_add(1)?;
    }
    None
}

/// `t` in UTC, to the minute, or to the second when its seconds are not
/// zero.
fn instant(t: Timestamp) -> Result<String, &'static str> {
    utc(t.micros()).ok_or(BAD_INSTANT)
}

/// [`instant`] over microseconds since the epoch, `None` before 1970 or
/// after 9999.
fn utc(micros: i64) -> Option<String> {
    if micros < 0 {
        return None;
    }
    let days = micros.checked_div(MICROS_PER_DAY)?;
    let secs = micros.checked_rem(MICROS_PER_DAY)?.checked_div(1_000_000)?;
    let (h, m, s) = (
        secs.checked_div(3600)?,
        secs.checked_rem(3600)?.checked_div(60)?,
        secs.checked_rem(60)?,
    );
    let (y, mo, d) = civil(days)?;
    Some(if s == 0 {
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
    } else {
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
    })
}

/// Whether `s` is spelled as an ADR-006 amount: digits, then optionally
/// a point and digits.
fn amount_spelling(s: &str) -> bool {
    let (whole, frac) = s.split_once('.').unwrap_or((s, "0"));
    s.len() <= 32
        && !whole.is_empty()
        && !frac.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.bytes().all(|b| b.is_ascii_digit())
}

/// An `https:` address the writer accepts.
fn https(url: &str) -> Result<SafeUrl, &'static str> {
    SafeUrl::new(url)
        .ok()
        .filter(|_| url.starts_with("https://"))
        .ok_or(NOT_HTTPS)
}

/// Paragraphs of `text`: runs of lines apart by blank lines, each line
/// trimmed.
fn paragraphs(text: &str) -> Result<Vec<String>, &'static str> {
    let mut out = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() {
            if !cur.is_empty() {
                out.push(cur.join("\n"));
                cur.clear();
            }
        } else {
            cur.push(l);
        }
    }
    if !cur.is_empty() {
        out.push(cur.join("\n"));
    }
    if out.is_empty() {
        return Err(EMPTY);
    }
    Ok(out)
}

/// `items` when there is at least one.
fn non_empty(items: Vec<String>) -> Result<Vec<String>, &'static str> {
    if items.is_empty() {
        Err(EMPTY)
    } else {
        Ok(items)
    }
}

impl<'a> Ctx<'a> {
    /// The resolution context of `inputs`.
    pub(crate) fn new(inputs: &'a GuideInputs<'a>) -> Ctx<'a> {
        let c = inputs.compiled;
        Ctx {
            inputs,
            spec: decompile(&c.policy, &c.artefacts, &c.unset),
        }
    }

    /// The text of a narrative.
    fn narrative(&self, n: &Narrative) -> Result<String, &'static str> {
        let text = match n {
            Narrative::Inline(s) => s.as_str(),
            Narrative::Stored(s) => self.inputs.texts.text(s.text_ref()).ok_or(NOT_STORED)?,
        };
        if text.trim().is_empty() {
            return Err(EMPTY);
        }
        Ok(text.to_owned())
    }

    /// The text of the artefact field `id`.
    fn artefact(&self, id: FieldId) -> Result<String, &'static str> {
        match self.spec.get(id) {
            Field::Unset => Err(UNSET),
            Field::Set(FieldValue::ActionNumber(a)) => Ok(a.as_str().to_owned()),
            Field::Set(
                FieldValue::ProgrammeName(n)
                | FieldValue::ProgrammeNarrative(n)
                | FieldValue::ProgrammeScope(n)
                | FieldValue::ProgrammeContact(n)
                | FieldValue::Faq(n)
                | FieldValue::ActionAcronym(n)
                | FieldValue::CoordinatorName(n)
                | FieldValue::PersonsSupported(n)
                | FieldValue::AmountCriteria(n),
            ) => self.narrative(&n),
            Field::Set(_) => Err(MISMATCH),
        }
    }

    fn opens(&self) -> Result<String, &'static str> {
        instant(self.inputs.call.opens)
    }

    fn deadline(&self) -> Result<String, &'static str> {
        instant(self.inputs.call.deadline)
    }

    fn p07(&self) -> Result<String, &'static str> {
        Ok(count(get!(self, P07).get(), "day", "days"))
    }

    fn working(&self, w: fstp_programme::value::WorkingDays) -> String {
        count(w.0, "working day", "working days")
    }

    fn p13_list(&self) -> Result<Vec<String>, &'static str> {
        match self.inputs.publication {
            Some(snap) => {
                let named = self.spec_artefacts_classes();
                let items = snap
                    .p13
                    .0
                    .iter()
                    .map(|id| {
                        named
                            .iter()
                            .find(|(c, _)| c == id)
                            .ok_or(UNDESCRIBED)
                            .and_then(|(_, n)| self.narrative(n))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                non_empty(items)
            }
            None => {
                let classes = get!(self, P13);
                non_empty(
                    classes
                        .items()
                        .iter()
                        .map(|c| self.narrative(&c.description))
                        .collect::<Result<_, _>>()?,
                )
            }
        }
    }

    /// The P-13 class descriptions the artefacts hold, in their order.
    fn spec_artefacts_classes(&self) -> Vec<(fstp_domain::id::ClassId, Narrative)> {
        self.inputs.compiled.artefacts.class_descriptions().to_vec()
    }

    /// Resolves `key`, or says why it has no value.
    pub(crate) fn resolve(&self, key: Key) -> Result<Value, &'static str> {
        let t = |s: String| -> Result<Value, &'static str> { Ok(Value::Text(s)) };
        match key.resolver().kind {
            Kind::ArtefactText(id) => t(self.artefact(id)?),
            Kind::ArtefactBlock(id) => Ok(Value::Paragraphs(paragraphs(&self.artefact(id)?)?)),
            Kind::CallIdentifier => {
                let id = self.inputs.call.identifier.trim();
                if id.is_empty() || self.inputs.call.identifier.len() > 128 {
                    return Err(BAD_IDENTIFIER);
                }
                t(id.to_owned())
            }
            Kind::CallOpens => t(self.opens()?),
            Kind::CallDeadline => t(self.deadline()?),
            Kind::CallZone => t(self.inputs.call.deadline_zone.as_str().to_owned()),
            Kind::CallBudget => {
                let b = &self.inputs.call.budget;
                if !amount_spelling(b) {
                    return Err(BAD_BUDGET);
                }
                t(b.clone())
            }
            Kind::GuideVersion => {
                if self.inputs.guide_version == 0 {
                    return Err(BAD_VERSION);
                }
                t(self.inputs.guide_version.to_string())
            }
            Kind::PlatformUrl => Ok(Value::Link(https(self.inputs.platform_url)?)),
            Kind::DataProtection => Ok(Value::Paragraphs(paragraphs(
                self.inputs.data_protection_summary.ok_or(NO_SUMMARY)?,
            )?)),
            Kind::PrivacyStatement => Ok(Value::Link(https(
                self.inputs.privacy_statement_url.ok_or(NO_PRIVACY)?,
            )?)),
            Kind::Timeline => {
                let zone = self.inputs.call.deadline_zone.as_str();
                Ok(Value::Table {
                    head: vec!["Step".to_owned(), "When".to_owned()],
                    rows: vec![
                        vec!["Call opens".to_owned(), self.opens()?],
                        vec!["Deadline".to_owned(), format!("{} ({zone})", self.deadline()?)],
                        vec![
                            "Answers to stage 2 questions".to_owned(),
                            format!("Within {} of the questions", self.p07()?),
                        ],
                        vec![
                            "Notice if not selected".to_owned(),
                            format!("Within {}", self.working(get!(self, P08))),
                        ],
                        vec![
                            "Complaints".to_owned(),
                            format!(
                                "Within {} of the decision notice",
                                self.working(get!(self, P61))
                            ),
                        ],
                    ],
                })
            }
            Kind::P01Table => {
                let c = get!(self, P01);
                let scale = format!("0 to {}", c.scale_max());
                let rows = c
                    .criteria()
                    .iter()
                    .map(|k| {
                        Ok(vec![
                            self.narrative(&k.name)?,
                            k.weight.to_string(),
                            scale.clone(),
                        ])
                    })
                    .collect::<Result<Vec<_>, &'static str>>()?;
                Ok(Value::Table {
                    head: vec![
                        "Criterion".to_owned(),
                        "Weight".to_owned(),
                        "Score scale".to_owned(),
                    ],
                    rows: rows_non_empty(rows)?,
                })
            }
            Kind::P02 => t(format!("{} %", get!(self, P02))),
            Kind::P03 => t(get!(self, P03).get().to_string()),
            Kind::P04Min => t(get!(self, P04).min().amount().to_string()),
            Kind::P04Max => t(get!(self, P04).max().amount().to_string()),
            Kind::P05 => match self.inputs.publication {
                Some(snap) => t(snap.p05.amount().to_string()),
                None => t(get!(self, P05).amount().to_string()),
            },
            Kind::P07 => t(self.p07()?),
            Kind::P08 => t(self.working(get!(self, P08))),
            Kind::P09List => Ok(Value::List(non_empty(
                get!(self, P09)
                    .items()
                    .iter()
                    .map(|k| self.narrative(&k.text))
                    .collect::<Result<_, _>>()?,
            )?)),
            Kind::P11 => t(match get!(self, P11) {
                ReviewerAnonymity::Anonymous => "anonymous",
                ReviewerAnonymity::Named => "named",
            }
            .to_owned()),
            Kind::P13List => Ok(Value::List(self.p13_list()?)),
            Kind::P23PerDay | Kind::P23PerCall => {
                let p = get!(self, P23);
                if !p.enabled {
                    return Err(PRECHECK_OFF);
                }
                let n = if key.resolver().kind == Kind::P23PerDay {
                    p.per_day_per_proposal
                } else {
                    p.per_call_per_proposal
                };
                t(count(n, "time", "times"))
            }
            Kind::P25 => t(get!(self, P25).as_str().to_owned()),
            Kind::P26List => t(non_empty(
                get!(self, P26)
                    .items()
                    .iter()
                    .map(|l| l.as_str().to_owned())
                    .collect(),
            )?
            .join(", ")),
            Kind::P29 => {
                let c = get!(self, P29);
                let instrument = match c.instrument.as_str() {
                    "mou" => "memorandum of understanding (MoU)".to_owned(),
                    _ => words(&c.instrument),
                };
                t(format!(
                    "{instrument}, contract template {} version {}",
                    c.template.id.as_str(),
                    c.template.version
                ))
            }
            Kind::P30 => t(non_empty(get!(self, P30).items().iter().map(words).collect())?
                .join(", then ")),
            Kind::P34List => Ok(Value::List(non_empty(
                get!(self, P34)
                    .items()
                    .iter()
                    .map(|w| capitalised(&words(w)))
                    .collect(),
            )?)),
            Kind::P36 => t(count(get!(self, P36).get(), "day", "days")),
            Kind::P41 => t(count(get!(self, P41).years.get(), "year", "years")),
            Kind::P55List => Ok(Value::List(non_empty(
                get!(self, P55)
                    .items()
                    .iter()
                    .map(|a| self.narrative(&a.name))
                    .collect::<Result<_, _>>()?,
            )?)),
            Kind::P57End => {
                let e = get!(self, P57).end;
                t(format!("{:04}-{:02}-{:02}", e.year(), e.month(), e.day()))
            }
            Kind::P59 => t(count(get!(self, P59).get(), "day", "days")),
            Kind::P61 => t(self.working(get!(self, P61))),
            Kind::P62 => t(self.working(get!(self, P62))),
            Kind::P63 => t(self.working(get!(self, P63))),
            Kind::P64 => t(self.working(get!(self, P64))),
            Kind::P65 => t(match get!(self, P65) {
                PartialClaimEvidence::PublicDeliverables => {
                    "A partial claim needs public deliverables, as a full claim does."
                }
                PartialClaimEvidence::ProgressReport => {
                    "A partial claim needs a progress report, with the deliverables at the final claim."
                }
            }
            .to_owned()),
            Kind::P67 => t(match get!(self, P67) {
                UnclaimedBalances::ReturnToFstpBudget => {
                    "Milestone amounts not claimed by the end of your grant return to the FSTP budget of the action."
                }
                UnclaimedBalances::LapseAndReportUnspent => {
                    "Milestone amounts not claimed by the end of your grant lapse and are reported as unspent."
                }
            }
            .to_owned()),
            Kind::P75 => t(if get!(self, P75) {
                "Their agents may read the full content of your proposal."
            } else {
                "Their agents cannot read the full content of your proposal."
            }
            .to_owned()),
            Kind::P77 => t(match get!(self, P77) {
                McpBindingActions::DraftOnly => {
                    "Agents only prepare drafts, and the reviewer confirms every binding action in the platform."
                }
                McpBindingActions::Allowed => {
                    "Agents may complete binding actions for the reviewer through the agent interface."
                }
            }
            .to_owned()),
        }
    }
}

/// `rows` when there is at least one.
fn rows_non_empty(rows: Vec<Vec<String>>) -> Result<Vec<Vec<String>>, &'static str> {
    if rows.is_empty() {
        Err(EMPTY)
    } else {
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use std::num::NonZeroU16;

    use super::*;

    /// I-51: every row holds a valid key, and no key has two rows.
    #[test]
    fn i51_resolver_keys_are_valid_and_unique() {
        for (i, r) in RESOLVERS.iter().enumerate() {
            assert!(KeyName::new(r.key).is_some(), "{}", r.key);
            assert_eq!(lookup(r.key).map(|k| k.ix), Some(i), "{}", r.key);
            let p = r.key.split('.').next().unwrap_or("");
            assert_eq!(
                r.param.map(ParamId::spec_id),
                p.starts_with("P-").then_some(p),
                "{}",
                r.key
            );
        }
    }

    /// I-51: instants are shown in UTC from the civil calendar.
    #[test]
    fn i51_instants_are_shown_in_utc() {
        let at = |m: i64| instant(Timestamp::from_micros(m));
        assert_eq!(at(0).unwrap(), "1970-01-01 00:00 UTC");
        assert_eq!(at(1_793_610_000_000_000).unwrap(), "2026-11-02 09:00 UTC");
        assert_eq!(at(1_801_238_400_000_000).unwrap(), "2027-01-29 16:00 UTC");
        assert_eq!(at(951_825_599_000_000).unwrap(), "2000-02-29 11:59:59 UTC");
        assert_eq!(at(-1), Err(BAD_INSTANT));
        assert_eq!(at(i64::MAX), Err(BAD_INSTANT));
    }

    /// ADR-006: only amount spellings pass as a call budget.
    #[test]
    fn adr006_call_budget_spelling() {
        assert!(amount_spelling("250000.00"));
        assert!(amount_spelling("7"));
        for bad in ["", ".5", "5.", "-1.00", "1,000.00", "1e5", "1.0.0"] {
            assert!(!amount_spelling(bad), "{bad}");
        }
    }

    /// The checked count helper covers the u16 values the policy holds.
    #[test]
    fn counts_and_words() {
        assert_eq!(count(1_u16, "day", "days"), "1 day");
        assert_eq!(count(28_u16, "day", "days"), "28 days");
        assert_eq!(count(NonZeroU16::MIN.get(), "year", "years"), "1 year");
        assert_eq!(capitalised("spdx"), "Spdx");
        assert_eq!(
            words(&Token::new("qtsp_remote_qes").unwrap()),
            "QTSP remote QES"
        );
    }
}

//! Diary items built at read time (I-97, I-27, `SPEC/12-journey-ui.md`
//! sections 7.1 and 7.3).
//!
//! [`items`] turns journey rows into diary items. Each item's sentence
//! parameters come from the source record at the entry's ledger sequence
//! number, never from a stored text. A text reference stays a reference:
//! a live text is a [`TextSlot::Live`] reference the viewer resolves
//! under their own rights, and an erased text is the erasure-log
//! placeholder of section 7.3. No item holds free text, and no item
//! derived from a message record carries a score (I-27).
//!
//! The visibility function (`crate::visibility::visible`) filters the
//! items per request.
//!
//! A source record that names a ledger sequence number the ledger does
//! not hold is refused with [`DiaryError::MissingSource`], never guessed.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::id::{TextId, TextRef};
use fstp_domain::record::{OutboxEvent, Record as CoreRecord};
use fstp_domain::scoring::ScoreVector;
use fstp_engine::Record;
use fstp_ledger::Entry;

use crate::projector::{Rows, Subject};
use crate::visibility::EntryKind;

/// The erasure-log facts of one erased text (section 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Erasure {
    /// When the erasure completed, in microseconds since the epoch in UTC.
    pub on: i64,
    /// The cause, as the erasure log's closed code.
    pub cause: u16,
}

/// One text reference of an item, as the viewer receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextSlot {
    /// A live text: the reference only (I-97).
    Live(TextRef),
    /// An erased text: "Entry text erased on <date>, reason: <cause>".
    Erased(Erasure),
}

/// A sentence parameter derived at read time from the source record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Param {
    /// A formal state name.
    State(StateTag),
    /// An amount as an ADR-006 canonical decimal string.
    Amount(String),
    /// A ledger sequence number.
    Sequence(u64),
    /// A score vector, shown only where O-54 allows it.
    Score(ScoreVector),
    /// A yes or no outcome, such as a vault verification.
    Outcome(bool),
    /// A time in microseconds since the epoch in UTC.
    Time(i64),
}

/// One diary item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DiaryItem {
    /// The entry.
    pub entry_id: [u8; 16],
    /// The ledger sequence number of the source record.
    pub source_seq: u64,
    /// The subject.
    pub subject: Subject,
    /// The kind.
    pub kind: EntryKind,
    /// The catalogue key index of the sentence.
    pub summary_key: u16,
    /// When, in microseconds since the epoch in UTC.
    pub occurred_at: i64,
    /// The related deadline's zone index.
    pub deadline_zone: Option<u16>,
    /// The sentence parameters.
    pub params: Vec<Param>,
    /// The text references, in `ord` order.
    pub texts: Vec<TextSlot>,
}

/// Why the items could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiaryError {
    /// An entry names a ledger sequence number the ledger does not hold.
    MissingSource(u64),
}

impl core::fmt::Display for DiaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DiaryError::MissingSource(seq) => write!(f, "no ledger entry {seq}"),
        }
    }
}

impl std::error::Error for DiaryError {}

/// The diary items of `rows`, one per entry row, with parameters read
/// from `ledger` and erased texts replaced by their placeholder.
///
/// Items keep the order of `rows.entries`, which is ledger order.
pub fn items(
    rows: &Rows,
    ledger: &[Entry<Record>],
    erasures: &BTreeMap<TextId, Erasure>,
) -> Result<Vec<DiaryItem>, DiaryError> {
    let by_seq: BTreeMap<u64, &Entry<Record>> = ledger.iter().map(|e| (e.seq.raw(), e)).collect();
    let mut texts: BTreeMap<[u8; 16], Vec<(u16, TextRef)>> = BTreeMap::new();
    for t in &rows.texts {
        texts.entry(t.entry_id).or_default().push((t.ord, t.text));
    }
    let mut out = Vec::with_capacity(rows.entries.len());
    for r in &rows.entries {
        let source = by_seq
            .get(&r.source_seq)
            .ok_or(DiaryError::MissingSource(r.source_seq))?;
        let mut refs = texts.get(&r.entry_id).cloned().unwrap_or_default();
        refs.sort_by_key(|(ord, _)| *ord);
        let slots = refs
            .into_iter()
            .map(|(_, t)| match erasures.get(&t.id()) {
                Some(e) => TextSlot::Erased(*e),
                None => TextSlot::Live(t),
            })
            .collect();
        out.push(DiaryItem {
            entry_id: r.entry_id,
            source_seq: r.source_seq,
            subject: r.subject,
            kind: r.kind,
            summary_key: r.summary_key,
            occurred_at: r.occurred_at,
            deadline_zone: r.deadline_zone,
            params: params(&source.record),
            texts: slots,
        });
    }
    Ok(out)
}

/// The sentence parameters of a source record: states, times, outcomes,
/// ADR-006 amounts and scores, never a text, a zone name or an account.
///
/// I-27: a message record, an outbox event, gives a state at most and
/// never a score. Only a score record gives a score, and the visibility
/// function decides who sees it (O-54).
pub fn params(record: &Record) -> Vec<Param> {
    let Record::Core(r) = record else {
        return Vec::new();
    };
    match r {
        CoreRecord::Transitioned(t) => vec![Param::State(t.from), Param::State(t.to)],
        CoreRecord::CallEdited {
            opens, deadline, ..
        } => vec![Param::Time(opens.micros()), Param::Time(deadline.micros())],
        CoreRecord::ScoreRecorded(s) => vec![Param::Score(s.values.clone())],
        CoreRecord::OutboxEnqueued(OutboxEvent::ProposalOutcome { state, .. }) => {
            vec![Param::State(*state)]
        }
        CoreRecord::ConflictDeclared(c) => vec![Param::Outcome(c.conflicted)],
        CoreRecord::ConflictDetected(_) => vec![Param::Outcome(true)],
        CoreRecord::AmountDetermined { granted, .. } => {
            vec![Param::Amount(granted.amount().to_string())]
        }
        CoreRecord::GrantDecided(g) => vec![Param::Amount(g.granted().amount().to_string())],
        CoreRecord::LineAccepted { approved, .. } => {
            vec![Param::Amount(approved.amount().to_string())]
        }
        _ => Vec::new(),
    }
}

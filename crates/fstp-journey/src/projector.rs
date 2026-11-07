//! The journey projector (I-92, ADR-015 "Read model only" and "Storage
//! and roles", `SPEC/12-journey-ui.md` sections 3, 7.1 and 11).
//!
//! The projector is a pure fold of the cell's one ledger into journey
//! rows: per proposal its legs with times, from which its current node
//! follows, and the diary entries of section 7.1 with their text
//! references. It writes no ledger entry and holds no authority. The
//! rows are its whole state: [`Projector::resume`] continues from rows
//! read back from the `journey` schema, so a checkpoint plus the
//! remaining entries equals a full replay. Deleting every row and
//! replaying gives byte-identical rows ([`Rows::encode`]).
//!
//! No row holds free text (I-97, R-NF-08). A diary sentence is built at
//! read time from [`EntryRow::summary_key`] and the source record at
//! [`EntryRow::source_seq`] (`crate::diary`). Text references are ids
//! with salted digests.
//!
//! # What the fold reads
//!
//! Each ledger record gives at most one diary entry, so an entry id is a
//! function of its source sequence number alone. The records and their
//! kinds:
//!
//! - `Transitioned`: a state transition, and one leg of the route.
//! - `ProposalCreated`: the route start, at DRAFT. It is no entry.
//! - `CallDrafted`, `CallEdited`: no entry. They record a call before
//!   publication, which no diary shows (R-AC-01). A deadline set or
//!   moved comes from timeline events once that source exists.
//! - `QuestionAsked`, `AnswersRecorded`, `NoQuestionsRecorded`: a stage 2
//!   clarification, with its text reference.
//! - `ScoreRecorded`, `ScoreVoided`, `RankingSummaryRecorded`: a reviewer
//!   score or comment. A score that corrects an earlier one supersedes
//!   its entry (I-23).
//! - `ConflictDeclared`, `ConflictDetected`, and an `AssignmentReleased`
//!   after a conflict: a conflict declared or reassigned.
//! - The outbox events `ProposalOutcome` and `IrcConcern`: a notice sent.
//! - `ContractFactRecorded`, `AmountDetermined`, `GrantAccepted`,
//!   `GrantApproved`, `GrantDecided`, `TerminationRecorded`,
//!   `AmendmentProposed`: contract versions and signatures.
//! - The payment request records, `MilestoneClosed` and
//!   `DeliverableRecorded`: milestone and payment request states.
//! - A guardian's Receiving binding: a guardian step (O-60).
//! - `Assigned`: no entry, but the assignment's proposal, so that later
//!   records naming the assignment find their subject.
//!
//! Interim, pending Daniel (`docs/handoff/m4-design.md` section 15.0,
//! lane j2): the ledger holds no complaint or agent action record yet,
//! and a `VaultOutcome` record names no subject, so no entry of those
//! kinds is projected. `KnockOutRecorded` and the committee records have
//! no kind of section 7.2 and give no entry. Audit-log references and
//! timeline events are not folded until their sources exist.
//!
//! # Storage
//!
//! The `app` role holds INSERT and SELECT only on the journey tables
//! (ADR-015), so every row is append-only. A leg is never changed, and the
//! cursor gains one row per folded ledger entry, keyed by the projector
//! and the sequence number. A rebuild therefore writes the same rows as
//! the incremental fold.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::assignment::ReleaseCause;
use fstp_domain::id::{AssignmentId, CallId, ProposalId, RequestId, TextRef};
use fstp_domain::record::{Declared, OutboxEvent, Record as CoreRecord};
use fstp_domain::roles::{BindingScope, Role};
use fstp_engine::Record;
use fstp_ledger::Entry;

use crate::summary::SummaryKey;
use crate::visibility::{EntryKind, scope_mask};

/// The one projector of this crate, as `journey.projection_cursor` names it.
pub const PROJECTOR: u16 = 1;

/// The subject of a diary entry (section 7.1). A grant is its proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// A proposal or the grant it became.
    Proposal(ProposalId),
    /// A call.
    Call(CallId),
    /// A payment request.
    PaymentRequest(RequestId),
}

impl Subject {
    /// The stored `subject_kind` code.
    pub const fn kind_code(self) -> u16 {
        match self {
            Subject::Proposal(_) => 1,
            Subject::Call(_) => 2,
            Subject::PaymentRequest(_) => 3,
        }
    }

    /// The stored `subject_id`: the id's 16 bytes, big-endian.
    pub const fn id_bytes(self) -> [u8; 16] {
        match self {
            Subject::Proposal(p) => p.raw().to_be_bytes(),
            Subject::Call(c) => c.raw().to_be_bytes(),
            Subject::PaymentRequest(r) => r.raw().to_be_bytes(),
        }
    }
}

/// One row of `journey.entry` (section 11).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntryRow {
    /// 16 random-looking bytes, the same on every rebuild.
    pub entry_id: [u8; 16],
    /// The ledger sequence number of the source record, 1 or more.
    pub source_seq: u64,
    /// The subject.
    pub subject: Subject,
    /// The kind of section 7.2.
    pub kind: EntryKind,
    /// Microseconds since the epoch in UTC: the time of the source entry.
    pub occurred_at: i64,
    /// The index of the related deadline's zone in the shipped zone table.
    pub deadline_zone: Option<u16>,
    /// The coarse set of role classes that may see it. The visibility
    /// function still decides per request (I-93).
    pub scope_mask: u32,
    /// The catalogue key index of the sentence.
    pub summary_key: u16,
    /// The entry this one corrects (I-23).
    pub supersedes: Option<[u8; 16]>,
}

/// One row of `journey.entry_text`: a text reference of an entry (I-97).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EntryTextRow {
    /// The entry.
    pub entry_id: [u8; 16],
    /// The position among the entry's references.
    pub ord: u16,
    /// The reference: a text id and its salted digest, never the text.
    pub text: TextRef,
}

/// One completed leg of a proposal's route: one state transition, a row
/// of `journey.leg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LegRow {
    /// The proposal.
    pub proposal: ProposalId,
    /// The position of the leg in the proposal's route, from 0.
    pub ord: u32,
    /// The state left.
    pub from: StateTag,
    /// The state reached.
    pub to: StateTag,
    /// When, in microseconds since the epoch in UTC.
    pub at: i64,
    /// The ledger sequence number of the `Transitioned` record.
    pub source_seq: u64,
}

/// The start of a proposal's route at DRAFT, a row of
/// `journey.route_start`. The call is the one the proposal was created
/// in, whose frozen policy drives the overlay of a deferred proposal
/// (NOTE 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StartRow {
    /// The proposal.
    pub proposal: ProposalId,
    /// The call it was created in.
    pub call: CallId,
    /// When, in microseconds since the epoch in UTC.
    pub at: i64,
    /// The ledger sequence number of the `ProposalCreated` record.
    pub source_seq: u64,
}

/// The proposal of one assignment, a row of `journey.assignment`. Score
/// and conflict records name the assignment only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AssignmentRow {
    /// The assignment.
    pub assignment: AssignmentId,
    /// Its proposal.
    pub proposal: ProposalId,
    /// The ledger sequence number of the `Assigned` record.
    pub source_seq: u64,
}

/// One row of `journey.projection_cursor`: one folded ledger entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CursorRow {
    /// The projector.
    pub projector: u16,
    /// The ledger sequence number folded.
    pub last_ledger_seq: u64,
}

/// A proposal's current position on the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Position {
    /// The current node, a formal state.
    pub node: StateTag,
    /// When the proposal reached it.
    pub since: i64,
    /// The ledger sequence number of the record that put it there.
    pub source_seq: u64,
}

/// Every journey row, table by table, each in the order the fold wrote it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rows {
    /// `journey.entry`.
    pub entries: Vec<EntryRow>,
    /// `journey.entry_text`.
    pub texts: Vec<EntryTextRow>,
    /// `journey.leg`.
    pub legs: Vec<LegRow>,
    /// `journey.route_start`.
    pub starts: Vec<StartRow>,
    /// `journey.assignment`.
    pub assignments: Vec<AssignmentRow>,
    /// `journey.projection_cursor`.
    pub cursor: Vec<CursorRow>,
}

/// The stored code of a state: its position in `StateTag::ALL`, from 1.
fn state_code(s: StateTag) -> u16 {
    StateTag::ALL
        .iter()
        .position(|t| *t == s)
        .and_then(|i| u16::try_from(i).ok())
        .map_or(0, |i| i.saturating_add(1))
}

/// The stored code of an entry kind: its position in `EntryKind::ALL`,
/// from 1.
fn kind_code(k: EntryKind) -> u16 {
    EntryKind::ALL
        .iter()
        .position(|t| *t == k)
        .and_then(|i| u16::try_from(i).ok())
        .map_or(0, |i| i.saturating_add(1))
}

/// The byte writer of [`Rows::encode`].
struct Out(Vec<u8>);

impl Out {
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.bytes(&v.to_be_bytes());
    }
    fn len(&mut self, n: usize) {
        self.u64(u64::try_from(n).unwrap_or(u64::MAX));
    }
    fn table(&mut self, tag: u8, rows: usize) {
        self.bytes(&[tag]);
        self.len(rows);
    }
}

impl Rows {
    /// The stored bytes of every row, table by table, each table in
    /// primary key order. Two equal projections give equal bytes. Every
    /// field is a fixed-width id, code, sequence number or time, so the
    /// bytes hold no text (I-97).
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out(b"fstp-journey-rows-v1".to_vec());

        let mut entries: Vec<&EntryRow> = self.entries.iter().collect();
        entries.sort_by_key(|r| r.entry_id);
        o.table(1, entries.len());
        for r in entries {
            o.bytes(&r.entry_id);
            o.u64(r.source_seq);
            o.u16(r.subject.kind_code());
            o.bytes(&r.subject.id_bytes());
            o.u16(kind_code(r.kind));
            o.i64(r.occurred_at);
            match r.deadline_zone {
                Some(z) => {
                    o.bytes(&[1]);
                    o.u16(z);
                }
                None => o.bytes(&[0]),
            }
            o.u32(r.scope_mask);
            o.u16(r.summary_key);
            match r.supersedes {
                Some(s) => {
                    o.bytes(&[1]);
                    o.bytes(&s);
                }
                None => o.bytes(&[0]),
            }
        }

        let mut texts: Vec<&EntryTextRow> = self.texts.iter().collect();
        texts.sort_by_key(|t| (t.entry_id, t.ord));
        o.table(2, texts.len());
        for t in texts {
            o.bytes(&t.entry_id);
            o.u16(t.ord);
            o.bytes(&t.text.id().raw().to_be_bytes());
            o.bytes(&t.text.digest().bytes());
        }

        let mut legs: Vec<&LegRow> = self.legs.iter().collect();
        legs.sort_by_key(|l| (l.proposal, l.ord));
        o.table(3, legs.len());
        for l in legs {
            o.bytes(&l.proposal.raw().to_be_bytes());
            o.u32(l.ord);
            o.u16(state_code(l.from));
            o.u16(state_code(l.to));
            o.i64(l.at);
            o.u64(l.source_seq);
        }

        let mut starts: Vec<&StartRow> = self.starts.iter().collect();
        starts.sort_by_key(|s| s.proposal);
        o.table(4, starts.len());
        for s in starts {
            o.bytes(&s.proposal.raw().to_be_bytes());
            o.bytes(&s.call.raw().to_be_bytes());
            o.i64(s.at);
            o.u64(s.source_seq);
        }

        let mut assignments: Vec<&AssignmentRow> = self.assignments.iter().collect();
        assignments.sort_by_key(|a| a.assignment);
        o.table(5, assignments.len());
        for a in assignments {
            o.bytes(&a.assignment.raw().to_be_bytes());
            o.bytes(&a.proposal.raw().to_be_bytes());
            o.u64(a.source_seq);
        }

        let mut cursor: Vec<&CursorRow> = self.cursor.iter().collect();
        cursor.sort_by_key(|c| (c.projector, c.last_ledger_seq));
        o.table(6, cursor.len());
        for c in cursor {
            o.u16(c.projector);
            o.u64(c.last_ledger_seq);
        }
        o.0
    }

    /// The last ledger sequence number the rows fold, 0 for none.
    pub fn last_seq(&self) -> u64 {
        self.cursor
            .iter()
            .filter(|c| c.projector == PROJECTOR)
            .map(|c| c.last_ledger_seq)
            .max()
            .unwrap_or(0)
    }

    /// The current position of `proposal`: the state its last leg
    /// reached, or DRAFT from its route start. `None` for a proposal the
    /// rows do not know.
    pub fn position(&self, proposal: ProposalId) -> Option<Position> {
        let last = self
            .legs
            .iter()
            .filter(|l| l.proposal == proposal)
            .max_by_key(|l| l.ord);
        if let Some(l) = last {
            return Some(Position {
                node: l.to,
                since: l.at,
                source_seq: l.source_seq,
            });
        }
        self.start(proposal).map(|s| Position {
            node: StateTag::Draft,
            since: s.at,
            source_seq: s.source_seq,
        })
    }

    /// The legs of `proposal`, in route order.
    pub fn legs_of(&self, proposal: ProposalId) -> Vec<LegRow> {
        let mut out: Vec<LegRow> = self
            .legs
            .iter()
            .filter(|l| l.proposal == proposal)
            .copied()
            .collect();
        out.sort_by_key(|l| l.ord);
        out
    }

    /// The route start of `proposal`.
    pub fn start(&self, proposal: ProposalId) -> Option<StartRow> {
        self.starts.iter().find(|s| s.proposal == proposal).copied()
    }

    /// The states `proposal` has been in, in route order, from DRAFT.
    /// Empty for a proposal the rows do not know.
    pub fn path(&self, proposal: ProposalId) -> Vec<StateTag> {
        let legs = self.legs_of(proposal);
        let mut out = Vec::with_capacity(legs.len().saturating_add(1));
        match legs.first() {
            Some(l) => out.push(l.from),
            None if self.start(proposal).is_some() => out.push(StateTag::Draft),
            None => {}
        }
        out.extend(legs.iter().map(|l| l.to));
        out
    }
}

/// Why the projector refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProjectError {
    /// An entry does not follow the last one folded.
    OutOfOrder {
        /// The sequence number the fold expected.
        expected: u64,
        /// The sequence number it got.
        got: u64,
    },
    /// Stored rows are not a projection the fold can continue.
    Corrupt,
}

impl core::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProjectError::OutOfOrder { expected, got } => {
                write!(f, "ledger entry {got} folded where {expected} was due")
            }
            ProjectError::Corrupt => write!(f, "the stored journey rows cannot be continued"),
        }
    }
}

impl std::error::Error for ProjectError {}

/// The entry id of the record at `seq`: the first 16 bytes of a SHA-256
/// over a fixed label and the sequence number. It looks random and is the
/// same on every rebuild. The hash is no cryptographic control here.
pub fn entry_id(seq: u64) -> [u8; 16] {
    let mut input = b"fstp-journey-entry-v1".to_vec();
    input.extend_from_slice(&seq.to_be_bytes());
    let digest = fstp_crypto::sha256(&input);
    let mut out = [0u8; 16];
    for (slot, b) in out.iter_mut().zip(digest.iter()) {
        *slot = *b;
    }
    out
}

/// The indexes a fold reads, all derived from the rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Index {
    /// The last folded sequence number.
    last: u64,
    /// The entry id of each source sequence number.
    by_seq: BTreeMap<u64, [u8; 16]>,
    /// The number of legs of each proposal.
    legs: BTreeMap<ProposalId, u32>,
    /// The proposals with a route start.
    starts: BTreeMap<ProposalId, CallId>,
    /// The proposal of each assignment.
    assignments: BTreeMap<AssignmentId, ProposalId>,
}

impl Index {
    /// The indexes of `rows`, or `Corrupt` for rows no fold from genesis
    /// writes.
    fn of(rows: &Rows) -> Result<Index, ProjectError> {
        let mut ix = Index::default();
        for c in &rows.cursor {
            let next = ix.last.checked_add(1).ok_or(ProjectError::Corrupt)?;
            if c.projector != PROJECTOR || c.last_ledger_seq != next {
                return Err(ProjectError::Corrupt);
            }
            ix.last = next;
        }
        for r in &rows.entries {
            let fresh = r.source_seq >= 1
                && r.source_seq <= ix.last
                && r.entry_id == entry_id(r.source_seq)
                && ix.by_seq.insert(r.source_seq, r.entry_id).is_none();
            if !fresh {
                return Err(ProjectError::Corrupt);
            }
        }
        for t in &rows.texts {
            if !ix.by_seq.values().any(|id| *id == t.entry_id) {
                return Err(ProjectError::Corrupt);
            }
        }
        for l in &rows.legs {
            let n = ix.legs.entry(l.proposal).or_insert(0);
            if l.ord != *n || l.source_seq > ix.last {
                return Err(ProjectError::Corrupt);
            }
            *n = n.checked_add(1).ok_or(ProjectError::Corrupt)?;
        }
        for s in &rows.starts {
            if s.source_seq > ix.last || ix.starts.insert(s.proposal, s.call).is_some() {
                return Err(ProjectError::Corrupt);
            }
        }
        for a in &rows.assignments {
            if a.source_seq > ix.last || ix.assignments.insert(a.assignment, a.proposal).is_some() {
                return Err(ProjectError::Corrupt);
            }
        }
        Ok(ix)
    }
}

/// What one record contributes to the diary.
struct Derived {
    subject: Subject,
    kind: EntryKind,
    key: SummaryKey,
    texts: Vec<TextRef>,
    deadline_zone: Option<u16>,
    supersedes: Option<u64>,
}

impl Derived {
    fn new(subject: Subject, kind: EntryKind, key: SummaryKey) -> Derived {
        Derived {
            subject,
            kind,
            key,
            texts: Vec::new(),
            deadline_zone: None,
            supersedes: None,
        }
    }

    fn texts(mut self, texts: impl IntoIterator<Item = TextRef>) -> Derived {
        self.texts.extend(texts);
        self
    }
}

/// The fold over the ledger. Its state is its rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Projector {
    rows: Rows,
    ix: Index,
}

impl Projector {
    /// A projector over an empty ledger.
    pub fn new() -> Projector {
        Projector::default()
    }

    /// Continues from rows read back from the `journey` schema. Rows that
    /// no fold from genesis writes are refused with `Corrupt`: a cursor
    /// with a gap, an entry id that is not its sequence number's, or a
    /// leg out of route order.
    pub fn resume(rows: Rows) -> Result<Projector, ProjectError> {
        let ix = Index::of(&rows)?;
        Ok(Projector { rows, ix })
    }

    /// Folds the next ledger entry. An entry that does not follow the last
    /// one folded is refused with `OutOfOrder`, so a checkpoint never
    /// misses or doubles a record.
    pub fn fold(&mut self, entry: &Entry<Record>) -> Result<(), ProjectError> {
        let expected = self.ix.last.checked_add(1).ok_or(ProjectError::Corrupt)?;
        let seq = entry.seq.raw();
        if seq != expected {
            return Err(ProjectError::OutOfOrder { expected, got: seq });
        }
        if let Record::Core(r) = &entry.record {
            self.fold_core(seq, entry.at, r)?;
        }
        self.rows.cursor.push(CursorRow {
            projector: PROJECTOR,
            last_ledger_seq: seq,
        });
        self.ix.last = seq;
        Ok(())
    }

    /// The rows so far.
    pub fn rows(&self) -> &Rows {
        &self.rows
    }

    /// The rows so far, by value.
    pub fn into_rows(self) -> Rows {
        self.rows
    }

    fn fold_core(&mut self, seq: u64, at: i64, r: &CoreRecord) -> Result<(), ProjectError> {
        match r {
            CoreRecord::Transitioned(t) => {
                let n = self.ix.legs.entry(t.proposal).or_insert(0);
                let ord = *n;
                *n = n.checked_add(1).ok_or(ProjectError::Corrupt)?;
                self.rows.legs.push(LegRow {
                    proposal: t.proposal,
                    ord,
                    from: t.from,
                    to: t.to,
                    at,
                    source_seq: seq,
                });
            }
            // The first record of a proposal or an assignment wins.
            CoreRecord::ProposalCreated { proposal, call, .. } => {
                if let std::collections::btree_map::Entry::Vacant(v) =
                    self.ix.starts.entry(*proposal)
                {
                    let _ = v.insert(*call);
                    self.rows.starts.push(StartRow {
                        proposal: *proposal,
                        call: *call,
                        at,
                        source_seq: seq,
                    });
                }
            }
            CoreRecord::Assigned(a) => {
                if let std::collections::btree_map::Entry::Vacant(v) =
                    self.ix.assignments.entry(a.assignment)
                {
                    let _ = v.insert(a.proposal);
                    self.rows.assignments.push(AssignmentRow {
                        assignment: a.assignment,
                        proposal: a.proposal,
                        source_seq: seq,
                    });
                }
            }
            _ => {}
        }
        if let Some(d) = self.derive(r) {
            self.push_entry(seq, at, d)?;
        }
        Ok(())
    }

    /// The proposal of `assignment`, as an entry subject.
    fn of_assignment(&self, assignment: AssignmentId) -> Option<Subject> {
        self.ix
            .assignments
            .get(&assignment)
            .map(|p| Subject::Proposal(*p))
    }

    /// The diary entry `r` gives, if any (module documentation).
    fn derive(&self, r: &CoreRecord) -> Option<Derived> {
        use EntryKind as K;
        use SummaryKey as S;
        let p = |id: ProposalId| Subject::Proposal(id);
        let pay = |id: RequestId| Subject::PaymentRequest(id);
        let d = match r {
            CoreRecord::Transitioned(t) => {
                Derived::new(p(t.proposal), K::StateTransition, S::StateTransitioned)
            }
            // An unpublished call's drafting history is no diary entry:
            // a call is public only once published (R-AC-01). "Deadline
            // set or moved" comes from timeline events once they exist.
            CoreRecord::CallDrafted { .. } | CoreRecord::CallEdited { .. } => return None,
            CoreRecord::QuestionAsked { proposal, text, .. } => {
                Derived::new(p(*proposal), K::Clarification, S::QuestionAsked).texts([*text])
            }
            CoreRecord::AnswersRecorded { proposal, text } => {
                Derived::new(p(*proposal), K::Clarification, S::AnswersRecorded).texts([*text])
            }
            CoreRecord::NoQuestionsRecorded { proposal, .. } => {
                Derived::new(p(*proposal), K::Clarification, S::NoQuestions)
            }
            CoreRecord::ScoreRecorded(s) => {
                let mut d = Derived::new(
                    self.of_assignment(s.key.assignment)?,
                    K::ReviewerScore,
                    S::ScoreRecorded,
                )
                .texts(s.reason);
                d.supersedes = s.supersedes.map(|q| q.raw());
                d
            }
            CoreRecord::ScoreVoided(s) => Derived::new(
                self.of_assignment(s.key.assignment)?,
                K::ReviewerScore,
                S::ScoreVoided,
            ),
            CoreRecord::RankingSummaryRecorded {
                proposal,
                rationale,
                ..
            } => {
                // The rationale only: the title and neutral summary are
                // proposal content, which no diary entry carries (7.2).
                Derived::new(p(*proposal), K::ReviewerScore, S::RankingSummary).texts([*rationale])
            }
            CoreRecord::ConflictDeclared(c) => {
                let subject = match c.subject {
                    Declared::Assignment(a) => self.of_assignment(a)?,
                    Declared::Proposal { proposal, .. } => p(proposal),
                };
                Derived::new(subject, K::Conflict, S::ConflictDeclared)
            }
            CoreRecord::ConflictDetected(c) => {
                Derived::new(p(c.proposal), K::Conflict, S::ConflictDetected)
            }
            CoreRecord::AssignmentReleased(a) => match a.cause {
                ReleaseCause::DeclaredConflict | ReleaseCause::DetectedConflict => Derived::new(
                    self.of_assignment(a.assignment)?,
                    K::Conflict,
                    S::Reassigned,
                ),
                ReleaseCause::Unassigned
                | ReleaseCause::BindingEnded
                | ReleaseCause::BindingSuspended
                | ReleaseCause::BindingVoided => return None,
            },
            CoreRecord::OutboxEnqueued(o) => match o {
                OutboxEvent::ProposalOutcome { proposal, .. } => {
                    Derived::new(p(*proposal), K::NoticeSent, S::OutcomeNotice)
                }
                OutboxEvent::IrcConcern { proposal, concern } => {
                    Derived::new(p(*proposal), K::NoticeSent, S::IrcConcernNotice).texts([*concern])
                }
                // A copy request is the applicant's own, with no diary entry
                // (M6 lane L6-API).
                OutboxEvent::NotifiableConflict { .. }
                | OutboxEvent::BindingEnded { .. }
                | OutboxEvent::CopyRequested { .. } => {
                    return None;
                }
            },
            CoreRecord::ContractFactRecorded { proposal, .. } => {
                Derived::new(p(*proposal), K::Contract, S::ContractEffective)
            }
            CoreRecord::AmountDetermined { proposal, .. } => {
                Derived::new(p(*proposal), K::Contract, S::AmountDetermined)
            }
            CoreRecord::GrantAccepted { proposal, .. } => {
                Derived::new(p(*proposal), K::Contract, S::GrantAccepted)
            }
            CoreRecord::GrantApproved { proposal, .. } => {
                Derived::new(p(*proposal), K::Contract, S::GrantApproved)
            }
            CoreRecord::GrantDecided(g) => {
                Derived::new(p(g.proposal()), K::Contract, S::GrantDecided)
            }
            CoreRecord::TerminationRecorded {
                proposal, reason, ..
            } => Derived::new(p(*proposal), K::Contract, S::Terminated).texts([*reason]),
            CoreRecord::AmendmentProposed { grant, .. } => {
                Derived::new(p(*grant), K::Contract, S::AmendmentProposed)
            }
            CoreRecord::PaymentRequested { request, .. } => {
                Derived::new(pay(*request), K::MilestonePayment, S::PaymentRequested)
            }
            CoreRecord::LineAccepted {
                request, reason, ..
            } => Derived::new(pay(*request), K::MilestonePayment, S::LineAccepted).texts(*reason),
            CoreRecord::PaymentApproved { request, .. } => {
                Derived::new(pay(*request), K::MilestonePayment, S::PaymentApproved)
            }
            CoreRecord::PaymentReleased(r) => {
                Derived::new(pay(r.request()), K::MilestonePayment, S::PaymentReleased)
            }
            CoreRecord::PaymentConfirmed { request, .. } => {
                Derived::new(pay(*request), K::MilestonePayment, S::PaymentConfirmed)
            }
            CoreRecord::PaymentRequestWithdrawn { request, .. } => {
                Derived::new(pay(*request), K::MilestonePayment, S::PaymentWithdrawn)
            }
            CoreRecord::PaymentChangesRequested {
                request, reason, ..
            } => Derived::new(
                pay(*request),
                K::MilestonePayment,
                S::PaymentChangesRequested,
            )
            .texts([*reason]),
            CoreRecord::PaymentRequestClosed {
                request, reason, ..
            } => {
                Derived::new(pay(*request), K::MilestonePayment, S::PaymentClosed).texts([*reason])
            }
            CoreRecord::MilestoneClosed {
                proposal, reason, ..
            } => {
                Derived::new(p(*proposal), K::MilestonePayment, S::MilestoneClosed).texts([*reason])
            }
            CoreRecord::DeliverableRecorded(d) => {
                Derived::new(p(d.grant), K::MilestonePayment, S::DeliverableRecorded)
                    .texts([d.public_location, d.release])
            }
            CoreRecord::BindingGranted(b) => match (b.role, b.scope) {
                (Role::Guardian, BindingScope::Proposal { proposal, .. }) => {
                    Derived::new(p(proposal), K::GuardianStep, S::GuardianAdded)
                }
                _ => return None,
            },
            _ => return None,
        };
        Some(d)
    }

    fn push_entry(&mut self, seq: u64, at: i64, d: Derived) -> Result<(), ProjectError> {
        let id = entry_id(seq);
        let supersedes = d
            .supersedes
            .filter(|s| *s < seq)
            .and_then(|s| self.ix.by_seq.get(&s).copied());
        self.rows.entries.push(EntryRow {
            entry_id: id,
            source_seq: seq,
            subject: d.subject,
            kind: d.kind,
            occurred_at: at,
            deadline_zone: d.deadline_zone,
            scope_mask: scope_mask(d.kind),
            summary_key: d.key.code(),
            supersedes,
        });
        if self.ix.by_seq.insert(seq, id).is_some() {
            return Err(ProjectError::Corrupt);
        }
        for (i, text) in d.texts.into_iter().enumerate() {
            let ord = u16::try_from(i).map_err(|_| ProjectError::Corrupt)?;
            self.rows.texts.push(EntryTextRow {
                entry_id: id,
                ord,
                text,
            });
        }
        Ok(())
    }
}

/// The rows of a full replay of `ledger` from genesis.
pub fn project(ledger: &[Entry<Record>]) -> Result<Rows, ProjectError> {
    let mut p = Projector::new();
    for e in ledger {
        p.fold(e)?;
    }
    Ok(p.into_rows())
}

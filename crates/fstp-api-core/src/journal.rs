//! A projection of the ledger, for the read models whose data the M2
//! domain does not expose (design section 3.6).
//!
//! The domain's state keeps plans, submissions, scores and the stage 2
//! thread behind crate-private accessors. Its public surface gives the
//! proposal state, the assignments, the ranking view and the effective
//! score only. So [`Journal`] folds the members the read models show:
//!
//! - the plan versions of each proposal, in the order recorded;
//! - the plan each proposal was submitted with, and its revisions;
//! - the current values of every score key, after corrections;
//! - the stage 2 questions, with the asking assignment, and the answers;
//! - the assignments that recorded "no questions";
//! - every notifiable conflict a declaration raised (R-CF-04);
//! - when an IRC concern was raised on a proposal (R-IR-02);
//! - each cut-off round: its call, order, position, texts and status,
//!   and each member's own ballot or delegation (change D5).
//!
//! # Sources
//!
//! When the engine port serves its ledger (`AsyncEngine::ledger_after`),
//! the journal folds the ledger's records, entry by entry, before every
//! read ([`Journal::sync`]). It then holds every proposal and round the
//! ledger holds, including those recorded before this core started or
//! by another process. Each entry is folded once, by its sequence number.
//!
//! An engine port with no ledger leaves the journal on its fallback: it
//! folds the commands this core appended ([`Journal::fold`]). Either way
//! it folds only what the domain accepted and appended, so it never
//! holds a value the ledger does not.
//!
//! # Fail closed
//!
//! On the fallback, the projection is complete for a proposal only when
//! this core folded its creation or its submission. Such a proposal is
//! *known*. Every read of an unknown proposal answers [`Unknown`], and
//! dispatch refuses it as unavailable. So a proposal recorded elsewhere
//! gets no read model and no derived member, never a wrong one.
//!
//! Every map is bounded. A fold that would pass a bound makes its
//! proposal unknown, and its reads then fail closed too.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::command::{Command as Core, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, DecisionId, LineId, PlanVersionId, ProposalId, RequestId,
    TextRef,
};
use fstp_domain::payment::LineEvidence;
use fstp_domain::record::{Declared, Record as CoreRecord};
use fstp_domain::scoring::ScoreKey;
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState, Record};
use fstp_ledger::{Entry, Seq};

/// The most proposals the projection tracks.
const MAX_PROPOSALS: usize = 100_000;

/// The most plan versions or revisions of one proposal it tracks.
const MAX_PLANS: usize = 1_000;

/// The most stage 2 entries of one proposal it tracks.
const MAX_THREAD: usize = 1_000;

/// The most score keys and "no questions" assignments it tracks.
const MAX_KEYS: usize = 1_000_000;

/// The most payment requests whose line evidence it keeps.
const MAX_REQUESTS: usize = 100_000;

/// The most lines of one payment request whose evidence it keeps.
const MAX_LINES: usize = 1_000;

/// The most cut-off rounds it tracks.
const MAX_ROUNDS: usize = 100_000;

/// The most ballots and delegations of one round it tracks.
const MAX_VOTERS: usize = 10_000;

/// The projection does not hold the proposal's history (module
/// documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unknown;

/// One entry of the stage 2 thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadEntry {
    /// A question by the reviewer of an assignment.
    Question {
        /// The asking assignment.
        assignment: AssignmentId,
        /// The question.
        text: TextRef,
        /// When it was asked.
        at: Timestamp,
    },
    /// The team's answer.
    Answer {
        /// The answer.
        text: TextRef,
        /// When it was given.
        at: Timestamp,
    },
}

/// The status of a cut-off round, as the commands this core folded set
/// it (change D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoundStatus {
    /// Members cast and delegate, and a member may record the cut-off.
    Open,
    /// The cut-off was recorded.
    Recorded,
    /// A later round of the call replaced it. Nothing acts in it.
    Superseded,
}

/// One cut-off round opened through this core (change D5, R-EV-08,
/// R-EV-09). Each ballot and delegation is the acting member's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoundFacts {
    /// The call.
    pub(crate) call: CallId,
    /// The order the round was opened with, top first.
    pub(crate) order: Vec<ProposalId>,
    /// The cut-off rank position.
    pub(crate) nominated: u32,
    /// The recorded rationale.
    pub(crate) rationale: TextRef,
    /// The recorded P-17 tie-break, if any.
    pub(crate) tie_breaks: Option<TextRef>,
    /// The status.
    pub(crate) status: RoundStatus,
    /// The ballot each member cast, by member.
    pub(crate) cast: BTreeMap<AccountId, Vote>,
    /// Each delegation, from the delegating member to the holder.
    pub(crate) delegated: BTreeMap<AccountId, AccountId>,
}

/// Where the journal's facts come from (module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Source {
    /// No sync has run yet.
    #[default]
    Unset,
    /// The ledger, folded up to and including this entry.
    Ledger(Seq),
    /// The commands this core appended: the engine has no ledger.
    Commands,
}

/// One fact of a proposal, from a command or from a record.
enum Fact {
    Created,
    Plan(PlanVersionId),
    Submitted(PlanVersionId),
    Revision(PlanVersionId),
    Score(ScoreKey, Vec<u8>),
    Question(AssignmentId, TextRef),
    Answer(TextRef),
    Concern,
    NoQuestions(AssignmentId),
    Notifiable,
}

/// One act on a cut-off round, from a command or from a record.
enum RoundAct {
    Open {
        round: DecisionId,
        call: CallId,
        order: Vec<ProposalId>,
        nominated: u32,
        rationale: TextRef,
        tie_breaks: Option<TextRef>,
    },
    Cast(DecisionId, AccountId, Vote),
    Delegate(DecisionId, AccountId, AccountId),
    Record(DecisionId),
}

/// The projection of one cell process. See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct Journal {
    source: Source,
    /// The proposal of each assignment the ledger recorded, so a record
    /// that names an assignment only is folded under its proposal.
    assignments: BTreeMap<AssignmentId, ProposalId>,
    created: BTreeSet<ProposalId>,
    lost: BTreeSet<ProposalId>,
    saturated: bool,
    recorded: BTreeMap<ProposalId, Vec<PlanVersionId>>,
    submitted: BTreeMap<ProposalId, PlanVersionId>,
    revisions: BTreeMap<ProposalId, Vec<PlanVersionId>>,
    scores: BTreeMap<ScoreKey, Vec<u8>>,
    thread: BTreeMap<ProposalId, Vec<ThreadEntry>>,
    no_questions: BTreeSet<AssignmentId>,
    notifiable: BTreeSet<ProposalId>,
    concerns: BTreeMap<ProposalId, Timestamp>,
    rounds: BTreeMap<DecisionId, RoundFacts>,
    open_rounds: BTreeMap<CallId, DecisionId>,
    /// Lane m5/polish-access: the evidence of each line of each payment
    /// request this core recorded, for the line review view (R-PR-08).
    evidence: BTreeMap<RequestId, Vec<(LineId, LineEvidence)>>,
}

/// The proposal a folded command concerns, read against the state before
/// it, or `None` for a command the projection does not fold.
fn proposal_of(c: &Core, before: &EngineState) -> Option<ProposalId> {
    let of = |a: AssignmentId| before.core.review().get(a).map(|x| x.proposal);
    match c {
        Core::CreateDraft { proposal, .. }
        | Core::RecordPlanVersion { proposal, .. }
        | Core::Submit { proposal, .. }
        | Core::SubmitRevision { proposal, .. }
        | Core::AskQuestion { proposal, .. }
        | Core::AnswerQuestions { proposal, .. } => Some(*proposal),
        Core::RecordScore { key, .. } | Core::CorrectScore { key, .. } => of(key.assignment),
        Core::RecordNoQuestions { assignment, .. }
        | Core::RecordIrcReview {
            assignment,
            verdict: fstp_domain::decision::IrcVerdict::Concern(_),
        } => of(*assignment),
        Core::DeclareConflict {
            subject,
            conflicted: true,
            notifiable: true,
        } => match subject {
            DeclarationSubject::Proposal(p) => Some(*p),
            DeclarationSubject::Assignment(a) => of(*a),
        },
        _ => None,
    }
}

/// The fact of a folded command whose proposal [`proposal_of`] named.
fn fact_of(c: &Core) -> Option<Fact> {
    Some(match c {
        Core::CreateDraft { .. } => Fact::Created,
        Core::RecordPlanVersion { plan, .. } => Fact::Plan(*plan),
        Core::Submit { plan, .. } => Fact::Submitted(*plan),
        Core::SubmitRevision { plan, .. } => Fact::Revision(*plan),
        Core::RecordScore { key, values } | Core::CorrectScore { key, values, .. } => {
            Fact::Score(*key, values.0.clone())
        }
        Core::AskQuestion {
            assignment, text, ..
        } => Fact::Question(*assignment, *text),
        Core::AnswerQuestions { text, .. } => Fact::Answer(*text),
        Core::RecordIrcReview { .. } => Fact::Concern,
        Core::RecordNoQuestions { assignment, .. } => Fact::NoQuestions(*assignment),
        Core::DeclareConflict { .. } => Fact::Notifiable,
        _ => return None,
    })
}

/// The round act of a command by `actor`, if it is one.
fn round_act_of(c: &Core, actor: AccountId) -> Option<RoundAct> {
    Some(match c {
        Core::OpenCutOffRound {
            round,
            call,
            order,
            nominated,
            rationale,
            tie_breaks,
        } => RoundAct::Open {
            round: *round,
            call: *call,
            order: order.clone(),
            nominated: *nominated,
            rationale: *rationale,
            tie_breaks: *tie_breaks,
        },
        Core::CastBallot { round, vote } => RoundAct::Cast(*round, actor, *vote),
        Core::DelegateVote { round, to } => RoundAct::Delegate(*round, actor, *to),
        Core::RecordCutOff { round } => RoundAct::Record(*round),
        _ => return None,
    })
}

/// The round act a ledger record states, if it is one.
fn round_act_of_record(r: &CoreRecord) -> Option<RoundAct> {
    Some(match r {
        CoreRecord::CutOffRoundOpened {
            round,
            call,
            order,
            nominated,
            rationale,
            tie_breaks,
            ..
        } => RoundAct::Open {
            round: *round,
            call: *call,
            order: order.clone(),
            nominated: *nominated,
            rationale: *rationale,
            tie_breaks: *tie_breaks,
        },
        CoreRecord::BallotCast { round, voter, vote } => RoundAct::Cast(*round, *voter, *vote),
        CoreRecord::VoteDelegated { round, from, to } => RoundAct::Delegate(*round, *from, *to),
        CoreRecord::CutOffRecorded(c) => RoundAct::Record(c.decision),
        _ => return None,
    })
}

/// Appends `v` to the list of `p`, within the bounds. `false` when a
/// bound would be passed.
fn push<T>(map: &mut BTreeMap<ProposalId, Vec<T>>, p: ProposalId, v: T, each: usize) -> bool {
    if !map.contains_key(&p) && map.len() >= MAX_PROPOSALS {
        return false;
    }
    let list = map.entry(p).or_default();
    if list.len() >= each {
        return false;
    }
    list.push(v);
    true
}

/// Inserts `v` into `set`, within `max`. `false` when the bound would be
/// passed.
fn insert<T: Ord>(set: &mut BTreeSet<T>, v: T, max: usize) -> bool {
    if !set.contains(&v) && set.len() >= max {
        return false;
    }
    set.insert(v);
    true
}

impl Journal {
    /// Catches the journal up with the engine's ledger (module
    /// documentation). `read` answers the entries after a sequence
    /// number, or `None` when the engine serves no ledger. The first sync
    /// that gets `None` leaves the journal on its fallback for good, so
    /// the two sources never mix.
    pub(crate) fn sync(&mut self, read: impl FnOnce(Seq) -> Option<Vec<Entry<Record>>>) {
        let after = match self.source {
            Source::Commands => return,
            Source::Unset => Seq::ZERO,
            Source::Ledger(head) => head,
        };
        let Some(entries) = read(after) else {
            if self.source == Source::Unset {
                self.source = Source::Commands;
            }
            return;
        };
        let mut head = after;
        for e in &entries {
            if e.seq <= head {
                continue;
            }
            self.fold_entry(e);
            head = e.seq;
        }
        self.source = Source::Ledger(head);
    }

    /// Whether the journal folds the ledger rather than the commands of
    /// this core.
    pub(crate) fn folds_ledger(&self) -> bool {
        matches!(self.source, Source::Ledger(_))
    }

    /// Folds one ledger entry.
    fn fold_entry(&mut self, e: &Entry<Record>) {
        let Record::Core(r) = &e.record else {
            return;
        };
        let now = Timestamp::from_micros(e.at);
        match r {
            CoreRecord::Assigned(a) => {
                if !self.assignments.contains_key(&a.assignment)
                    && self.assignments.len() >= MAX_KEYS
                {
                    self.saturate();
                    return;
                }
                self.assignments.insert(a.assignment, a.proposal);
            }
            CoreRecord::PaymentRequested { request, lines, .. } => {
                self.keep_evidence(*request, lines.iter().map(|l| (l.line, &l.evidence)));
            }
            _ => {}
        }
        if let Some(act) = round_act_of_record(r) {
            self.act(act);
        }
        if let Some((p, fact)) = self.fact_of_record(r) {
            self.fold_fact(p, fact, now);
        }
    }

    /// The proposal and fact a ledger record states, if it is one the
    /// projection folds.
    fn fact_of_record(&self, r: &CoreRecord) -> Option<(ProposalId, Fact)> {
        let of = |a: &AssignmentId| self.assignments.get(a).copied();
        Some(match r {
            CoreRecord::ProposalCreated { proposal, .. } => (*proposal, Fact::Created),
            CoreRecord::PlanVersionRecorded(v) => (v.proposal, Fact::Plan(v.plan)),
            CoreRecord::Submitted { proposal, plan, .. } => (*proposal, Fact::Submitted(*plan)),
            CoreRecord::RevisionSubmitted { proposal, plan } => (*proposal, Fact::Revision(*plan)),
            CoreRecord::ScoreRecorded(s) => (
                of(&s.key.assignment)?,
                Fact::Score(s.key, s.values.0.clone()),
            ),
            CoreRecord::QuestionAsked {
                proposal,
                assignment,
                text,
            } => (*proposal, Fact::Question(*assignment, *text)),
            CoreRecord::AnswersRecorded { proposal, text } => (*proposal, Fact::Answer(*text)),
            CoreRecord::NoQuestionsRecorded {
                proposal,
                assignment,
            } => (*proposal, Fact::NoQuestions(*assignment)),
            CoreRecord::IrcReviewRecorded {
                assignment,
                verdict: fstp_domain::decision::IrcVerdict::Concern(_),
            } => (of(assignment)?, Fact::Concern),
            CoreRecord::ConflictDeclared(d) if d.conflicted && d.notifiable => {
                let p = match d.subject {
                    Declared::Proposal { proposal, .. } => proposal,
                    Declared::Assignment(a) => of(&a)?,
                };
                (p, Fact::Notifiable)
            }
            _ => return None,
        })
    }

    /// Keeps the evidence of each line of payment request `request`
    /// (lane m5/polish-access, R-PR-01, R-PR-08). A request past the bound
    /// keeps none, and its view shows no evidence rather than a wrong one.
    fn keep_evidence<'a>(
        &mut self,
        request: RequestId,
        lines: impl Iterator<Item = (LineId, &'a LineEvidence)>,
    ) {
        if self.evidence.len() < MAX_REQUESTS || self.evidence.contains_key(&request) {
            let kept = lines.take(MAX_LINES).map(|(l, e)| (l, e.clone())).collect();
            self.evidence.insert(request, kept);
        }
    }

    /// Folds a command that appended at `now`, read against the state
    /// before it (`before`), which names the proposal of an assignment.
    /// A journal that folds the ledger ignores it: the ledger holds it.
    pub(crate) fn fold(&mut self, cmd: &Command, before: &EngineState, now: Timestamp) {
        if self.folds_ledger() {
            return;
        }
        if let Command::Core(Core::RequestPayment { request, lines, .. }) = cmd {
            self.keep_evidence(*request, lines.iter().map(|l| (l.line, &l.evidence)));
        }
        match cmd {
            Command::Core(c) => self.fold_core(c, before, now),
            // R-EV-05: the plan, then its submission, as the entry holds them.
            Command::Stage2Revision(r) => {
                for c in r.commands() {
                    self.fold_core(&c, before, now);
                }
            }
            _ => {}
        }
    }

    /// Folds one core command of an appended entry.
    fn fold_core(&mut self, c: &Core, before: &EngineState, now: Timestamp) {
        let Some(p) = proposal_of(c, before) else {
            return;
        };
        if let Some(fact) = fact_of(c) {
            self.fold_fact(p, fact, now);
        }
    }

    /// Folds one fact of proposal `p`.
    fn fold_fact(&mut self, p: ProposalId, fact: Fact, now: Timestamp) {
        if self.saturated || self.lost.contains(&p) {
            return;
        }
        if !self.apply(fact, p, now) {
            self.lose(p);
        }
    }

    /// Folds a round command that appended, by `actor` (change D5). The
    /// domain accepted it, so the round exists and is open for a cast, a
    /// delegation or a record. A journal that folds the ledger ignores
    /// it: the ledger holds it.
    pub(crate) fn fold_round(&mut self, cmd: &Command, actor: AccountId) {
        if self.folds_ledger() {
            return;
        }
        if let Command::Core(c) = cmd
            && let Some(act) = round_act_of(c, actor)
        {
            self.act(act);
        }
    }

    /// Applies one round act. An act on a round the journal did not see
    /// opened is ignored, and that round stays unknown. A fold past a
    /// bound drops its round, which then reads as unknown too.
    fn act(&mut self, act: RoundAct) {
        match act {
            RoundAct::Open {
                round,
                call,
                order,
                nominated,
                rationale,
                tie_breaks,
            } => {
                // One round is open per call, so the domain superseded
                // the call's open round when it accepted this one.
                if let Some(old) = self.open_rounds.remove(&call)
                    && let Some(r) = self.rounds.get_mut(&old)
                {
                    r.status = RoundStatus::Superseded;
                }
                if self.rounds.len() >= MAX_ROUNDS {
                    return;
                }
                self.rounds.insert(
                    round,
                    RoundFacts {
                        call,
                        order,
                        nominated,
                        rationale,
                        tie_breaks,
                        status: RoundStatus::Open,
                        cast: BTreeMap::new(),
                        delegated: BTreeMap::new(),
                    },
                );
                self.open_rounds.insert(call, round);
            }
            RoundAct::Cast(round, voter, vote) => {
                self.vote(round, |r| {
                    r.cast.insert(voter, vote);
                });
            }
            RoundAct::Delegate(round, from, to) => {
                self.vote(round, |r| {
                    r.delegated.insert(from, to);
                });
            }
            RoundAct::Record(round) => {
                if let Some(r) = self.rounds.get_mut(&round) {
                    r.status = RoundStatus::Recorded;
                    if self.open_rounds.get(&r.call) == Some(&round) {
                        self.open_rounds.remove(&r.call);
                    }
                }
            }
        }
    }

    /// Applies one member's act to `round`, within the bound. Past the
    /// bound the round is dropped, so its reads fail closed.
    fn vote(&mut self, round: DecisionId, act: impl FnOnce(&mut RoundFacts)) {
        let Some(r) = self.rounds.get_mut(&round) else {
            return;
        };
        if r.cast.len().saturating_add(r.delegated.len()) >= MAX_VOTERS {
            let call = r.call;
            self.rounds.remove(&round);
            if self.open_rounds.get(&call) == Some(&round) {
                self.open_rounds.remove(&call);
            }
            return;
        }
        act(r);
    }

    /// The round `round`, if the journal folded its opening.
    pub(crate) fn round(&self, round: DecisionId) -> Option<&RoundFacts> {
        if self.saturated {
            return None;
        }
        self.rounds.get(&round)
    }

    /// The open cut-off round of `call`, if the journal folded its opening
    /// and nothing closed it since (change D5). `me.roles` lists it for
    /// the committee of the call (design section 15.0, 2026-10-31).
    pub(crate) fn open_round(&self, call: CallId) -> Option<DecisionId> {
        if self.saturated {
            return None;
        }
        self.open_rounds.get(&call).copied()
    }

    /// Folds `c` of proposal `p`. `false` when a bound would be passed.
    fn apply(&mut self, fact: Fact, p: ProposalId, now: Timestamp) -> bool {
        match fact {
            Fact::Created => insert(&mut self.created, p, MAX_PROPOSALS),
            Fact::Plan(plan) => push(&mut self.recorded, p, plan, MAX_PLANS),
            Fact::Submitted(plan) => {
                if !self.submitted.contains_key(&p) && self.submitted.len() >= MAX_PROPOSALS {
                    return false;
                }
                self.submitted.insert(p, plan);
                self.revisions.remove(&p);
                true
            }
            Fact::Revision(plan) => push(&mut self.revisions, p, plan, MAX_PLANS),
            Fact::Score(key, values) => {
                if !self.scores.contains_key(&key) && self.scores.len() >= MAX_KEYS {
                    return false;
                }
                self.scores.insert(key, values);
                true
            }
            Fact::Question(assignment, text) => push(
                &mut self.thread,
                p,
                ThreadEntry::Question {
                    assignment,
                    text,
                    at: now,
                },
                MAX_THREAD,
            ),
            Fact::Answer(text) => push(
                &mut self.thread,
                p,
                ThreadEntry::Answer { text, at: now },
                MAX_THREAD,
            ),
            Fact::Concern => {
                if !self.concerns.contains_key(&p) && self.concerns.len() >= MAX_PROPOSALS {
                    return false;
                }
                self.concerns.insert(p, now);
                true
            }
            Fact::NoQuestions(assignment) => insert(&mut self.no_questions, assignment, MAX_KEYS),
            Fact::Notifiable => insert(&mut self.notifiable, p, MAX_PROPOSALS),
        }
    }

    /// Makes every proposal and round unknown, for good.
    fn saturate(&mut self) {
        *self = Journal {
            source: self.source,
            saturated: true,
            ..Journal::default()
        };
    }

    /// Makes `p` unknown and drops what the projection held of it. When
    /// the set of lost proposals is full, every proposal becomes unknown.
    fn lose(&mut self, p: ProposalId) {
        if !insert(&mut self.lost, p, MAX_PROPOSALS) {
            self.saturate();
            return;
        }
        self.created.remove(&p);
        self.recorded.remove(&p);
        self.submitted.remove(&p);
        self.revisions.remove(&p);
        self.thread.remove(&p);
        self.notifiable.remove(&p);
        self.concerns.remove(&p);
    }

    /// Whether the projection holds the history of `p` (module
    /// documentation).
    pub(crate) fn knows(&self, p: ProposalId) -> bool {
        !self.saturated
            && !self.lost.contains(&p)
            && (self.created.contains(&p) || self.submitted.contains_key(&p))
    }

    fn known(&self, p: ProposalId) -> Result<(), Unknown> {
        if self.knows(p) { Ok(()) } else { Err(Unknown) }
    }

    /// The plan `proposal` was submitted with, if it was submitted.
    pub(crate) fn submitted_plan(
        &self,
        proposal: ProposalId,
    ) -> Result<Option<PlanVersionId>, Unknown> {
        self.known(proposal)?;
        Ok(self.submitted.get(&proposal).copied())
    }

    /// The latest plan of `proposal`, the head of its chain of versions:
    /// the plan recorded last through this core, else the submitted plan.
    /// A stage 2 revision is recorded before it is submitted, so a
    /// revision recorded and not yet submitted is the head too, as the
    /// domain's chain check reads it (R-EV-05).
    pub(crate) fn latest_plan(
        &self,
        proposal: ProposalId,
    ) -> Result<Option<PlanVersionId>, Unknown> {
        self.known(proposal)?;
        if let Some(p) = self.recorded.get(&proposal).and_then(|v| v.last()) {
            return Ok(Some(*p));
        }
        self.submitted_plan(proposal)
    }

    /// The last stage 2 revision of `proposal`, if any.
    pub(crate) fn last_revision(
        &self,
        proposal: ProposalId,
    ) -> Result<Option<PlanVersionId>, Unknown> {
        self.known(proposal)?;
        Ok(self
            .revisions
            .get(&proposal)
            .and_then(|r| r.last())
            .copied())
    }

    /// The current values of a score key. The caller reads it only for a
    /// known proposal.
    pub(crate) fn score(&self, key: &ScoreKey) -> Option<&[u8]> {
        self.scores.get(key).map(Vec::as_slice)
    }

    /// The stage 2 thread of `proposal`, oldest first.
    pub(crate) fn thread(&self, proposal: ProposalId) -> Result<&[ThreadEntry], Unknown> {
        self.known(proposal)?;
        Ok(self.thread.get(&proposal).map_or(&[], Vec::as_slice))
    }

    /// The stage 2 questions of `proposal` the team has not answered, each
    /// with its ordinal among the thread's questions (from 1) and when it
    /// was asked, oldest first (MB-Q2, decided by Daniel on 2026-11-13).
    ///
    /// Interim reading, pending Daniel: `AnswerQuestions` carries one text
    /// for all questions and names none, so an answer answers every
    /// question asked before it. A question asked after the last answer is
    /// unanswered.
    pub(crate) fn unanswered(
        &self,
        proposal: ProposalId,
    ) -> Result<Vec<(u32, Timestamp)>, Unknown> {
        let mut out = Vec::new();
        let mut n = 0u32;
        for e in self.thread(proposal)? {
            match e {
                ThreadEntry::Question { at, .. } => {
                    n = n.saturating_add(1);
                    out.push((n, *at));
                }
                ThreadEntry::Answer { .. } => out.clear(),
            }
        }
        Ok(out)
    }

    /// Whether the reviewer of `assignment` recorded "no questions". The
    /// caller reads it only for an assignment of a known proposal.
    pub(crate) fn no_questions(&self, assignment: AssignmentId) -> bool {
        self.no_questions.contains(&assignment)
    }

    /// When an IRC concern was raised on `proposal`, if one was (R-IR-02).
    pub(crate) fn concern(&self, proposal: ProposalId) -> Result<Option<Timestamp>, Unknown> {
        self.known(proposal)?;
        Ok(self.concerns.get(&proposal).copied())
    }

    /// The evidence of each line of payment request `request`, as the lead
    /// gave it, or `None` when this core did not record the request.
    pub(crate) fn line_evidence(&self, request: RequestId) -> Option<&[(LineId, LineEvidence)]> {
        self.evidence.get(&request).map(Vec::as_slice)
    }

    /// Whether a declaration raised a notifiable conflict on `proposal`.
    pub(crate) fn notifiable(&self, proposal: ProposalId) -> Result<bool, Unknown> {
        self.known(proposal)?;
        Ok(self.notifiable.contains(&proposal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(p: u128, plan: u128) -> Command {
        Command::Core(Core::Submit {
            proposal: ProposalId::from_raw(p),
            plan: PlanVersionId::from_raw(plan),
            ethics: fstp_domain::proposal::EthicsDeclaration {
                issues_declared: false,
                text: fstp_domain::id::TextRef::new(
                    fstp_domain::id::TextId::from_raw(1),
                    fstp_domain::id::ContentDigest::from_bytes([0; 32]),
                ),
            },
            notice: fstp_domain::proposal::NoticeVersion(1),
        })
    }

    /// R-SB-01, I-21: a proposal whose creation or submission this core
    /// did not fold is unknown, so no plan is derived for it and its reads
    /// fail closed.
    #[test]
    fn r_sb_01_a_proposal_recorded_elsewhere_is_unknown() {
        let mut j = Journal::default();
        let state = EngineState::genesis();
        let now = Timestamp::from_micros(1);
        let p = ProposalId::from_raw(7);
        assert_eq!(j.latest_plan(p), Err(Unknown));
        assert_eq!(j.thread(p).map(<[ThreadEntry]>::len), Err(Unknown));
        j.fold(&submit(7, 70), &state, now);
        assert_eq!(j.latest_plan(p), Ok(Some(PlanVersionId::from_raw(70))));
        assert_eq!(j.latest_plan(ProposalId::from_raw(8)), Err(Unknown));
    }

    /// R-SB-01: a fold past a bound makes its proposal unknown instead of
    /// dropping the fact.
    #[test]
    fn r_sb_01_a_fold_past_a_bound_fails_closed() {
        let mut j = Journal::default();
        let state = EngineState::genesis();
        let now = Timestamp::from_micros(1);
        let p = ProposalId::from_raw(7);
        j.fold(&submit(7, 70), &state, now);
        for raw in (100u128..).take(MAX_PLANS.saturating_add(1)) {
            let plan = PlanVersionId::from_raw(raw);
            j.fold(
                &Command::Core(Core::SubmitRevision { proposal: p, plan }),
                &state,
                now,
            );
        }
        assert_eq!(j.latest_plan(p), Err(Unknown));
        j.fold(&submit(7, 71), &state, now);
        assert_eq!(j.latest_plan(p), Err(Unknown), "a lost proposal stays lost");
    }

    fn text(n: u128) -> TextRef {
        TextRef::new(
            fstp_domain::id::TextId::from_raw(n),
            fstp_domain::id::ContentDigest::from_bytes([0; 32]),
        )
    }

    fn open(round: u128, call: u128) -> Command {
        Command::Core(Core::OpenCutOffRound {
            round: DecisionId::from_raw(round),
            call: CallId::from_raw(call),
            order: vec![ProposalId::from_raw(1), ProposalId::from_raw(2)],
            nominated: 1,
            rationale: text(1),
            tie_breaks: None,
        })
    }

    const A: AccountId = AccountId::from_raw(211);
    const B: AccountId = AccountId::from_raw(212);
    const C: AccountId = AccountId::from_raw(213);

    /// R-EV-09, P-16 NOTE 8, change D5: each ballot and delegation is
    /// folded as the acting member's own, and the round keeps what it
    /// was opened with.
    #[test]
    fn r_ev_09_journal_folds_each_members_own_ballot_and_delegation() {
        let mut j = Journal::default();
        let r = DecisionId::from_raw(9);
        j.fold_round(&open(9, 1), A);
        j.fold_round(
            &Command::Core(Core::CastBallot {
                round: r,
                vote: Vote::For,
            }),
            A,
        );
        j.fold_round(&Command::Core(Core::DelegateVote { round: r, to: A }), B);
        let facts = j.round(r).unwrap();
        assert_eq!(facts.call, CallId::from_raw(1));
        assert_eq!(facts.nominated, 1);
        assert_eq!(facts.status, RoundStatus::Open);
        assert_eq!(facts.cast.get(&A), Some(&Vote::For));
        assert_eq!(facts.cast.get(&B), None, "a delegation casts no ballot");
        assert_eq!(facts.delegated.get(&B), Some(&A));
        assert_eq!(facts.cast.len(), 1);
    }

    /// R-EV-08, change D5: opening a round of a call supersedes the call's
    /// open round, and recording the cut-off closes the round it names.
    #[test]
    fn r_ev_08_journal_opening_supersedes_and_record_closes() {
        let mut j = Journal::default();
        j.fold_round(&open(9, 1), A);
        j.fold_round(&open(10, 2), A);
        j.fold_round(&open(11, 1), B);
        let status = |j: &Journal, r| j.round(DecisionId::from_raw(r)).map(|x| x.status);
        assert_eq!(status(&j, 9), Some(RoundStatus::Superseded));
        assert_eq!(
            status(&j, 10),
            Some(RoundStatus::Open),
            "another call's round"
        );
        assert_eq!(status(&j, 11), Some(RoundStatus::Open));
        j.fold_round(
            &Command::Core(Core::RecordCutOff {
                round: DecisionId::from_raw(11),
            }),
            C,
        );
        assert_eq!(status(&j, 11), Some(RoundStatus::Recorded));
        j.fold_round(&open(12, 1), A);
        assert_eq!(
            status(&j, 11),
            Some(RoundStatus::Recorded),
            "a recorded round is never superseded"
        );
    }

    /// R-EV-08, change D5: an act on a round this core did not see opened
    /// is ignored, so the round stays unknown and its reads fail closed.
    #[test]
    fn r_ev_08_journal_ignores_acts_on_an_unknown_round() {
        let mut j = Journal::default();
        let r = DecisionId::from_raw(5);
        j.fold_round(
            &Command::Core(Core::CastBallot {
                round: r,
                vote: Vote::Against,
            }),
            A,
        );
        j.fold_round(&Command::Core(Core::RecordCutOff { round: r }), A);
        assert!(j.round(r).is_none());
    }

    /// R-EV-05, NOTE 1: a stage 2 revision recorded and not yet submitted
    /// is the head of the plan chain, so the next plan names it as the one
    /// it supersedes, as the domain's chain check reads it.
    #[test]
    fn r_ev_05_latest_plan_is_the_head_of_the_chain() {
        let mut j = Journal::default();
        let state = EngineState::genesis();
        let now = Timestamp::from_micros(1);
        let p = ProposalId::from_raw(7);
        j.fold(&submit(7, 70), &state, now);
        assert_eq!(j.latest_plan(p), Ok(Some(PlanVersionId::from_raw(70))));
        let revision = Command::Core(Core::RecordPlanVersion {
            plan: PlanVersionId::from_raw(71),
            proposal: p,
            origin: fstp_domain::proposal::PlanOrigin::Stage2Revision,
            supersedes: Some(PlanVersionId::from_raw(70)),
            tasks: Vec::new(),
            content: fstp_domain::id::ContentDigest::from_bytes([0; 32]),
        });
        j.fold(&revision, &state, now);
        assert_eq!(j.latest_plan(p), Ok(Some(PlanVersionId::from_raw(71))));
        assert_eq!(j.last_revision(p), Ok(None), "recorded, not submitted");
    }

    /// MB-Q2 (decided by Daniel on 2026-11-13), R-EV-05: the journal folds
    /// answers per question. Interim reading: `AnswerQuestions` carries one
    /// text, so an answer answers every question asked before it. Each
    /// question keeps its ordinal in the thread and its instant.
    #[test]
    fn r_ev_05_answers_fold_per_question() {
        let mut j = Journal::default();
        let state = EngineState::genesis();
        let p = ProposalId::from_raw(7);
        assert_eq!(j.unanswered(p), Err(Unknown));
        j.fold(&submit(7, 70), &state, Timestamp::from_micros(1));
        assert_eq!(j.unanswered(p), Ok(Vec::new()));
        let ask = |n: u128| {
            Command::Core(Core::AskQuestion {
                proposal: p,
                assignment: AssignmentId::from_raw(n),
                text: text(n),
            })
        };
        let answer = Command::Core(Core::AnswerQuestions {
            proposal: p,
            text: text(99),
        });
        j.fold(&ask(1), &state, Timestamp::from_micros(10));
        j.fold(&ask(2), &state, Timestamp::from_micros(20));
        assert_eq!(
            j.unanswered(p),
            Ok(vec![
                (1, Timestamp::from_micros(10)),
                (2, Timestamp::from_micros(20))
            ])
        );
        j.fold(&answer, &state, Timestamp::from_micros(30));
        assert_eq!(j.unanswered(p), Ok(Vec::new()));
        j.fold(&ask(3), &state, Timestamp::from_micros(40));
        assert_eq!(j.unanswered(p), Ok(vec![(3, Timestamp::from_micros(40))]));
    }
    /// The core record `r`, to be entry `seq` of a [`ledger`].
    fn entry(seq: u64, r: CoreRecord) -> (u64, CoreRecord) {
        (seq, r)
    }

    /// A ledger holding each record as its own entry, in order, entry `n`
    /// at instant `10 n`.
    fn ledger(records: Vec<(u64, CoreRecord)>) -> Vec<Entry<Record>> {
        use fstp_ledger::{MemStore, RecordStore as _};
        let mut store = MemStore::new();
        for (n, r) in records {
            let mut command = [0u8; 16];
            command[..8].copy_from_slice(&n.to_be_bytes());
            let at = i64::try_from(n).unwrap_or_default().saturating_mul(10);
            assert!(
                store
                    .append(
                        Seq::from_raw(n.saturating_sub(1)),
                        at,
                        command,
                        vec![Record::Core(r)]
                    )
                    .is_ok()
            );
        }
        let mut out = Vec::new();
        assert!(store.read(Seq::ZERO, usize::MAX, &mut out).is_ok());
        out
    }

    /// The ledger of a proposal recorded elsewhere: created, its plan
    /// recorded and submitted, one reviewer assigned who scored it and
    /// asked a question.
    fn elsewhere() -> Vec<Entry<Record>> {
        let p = ProposalId::from_raw(7);
        let a = AssignmentId::from_raw(3);
        let plan = PlanVersionId::from_raw(70);
        ledger(vec![
            entry(
                1,
                CoreRecord::ProposalCreated {
                    proposal: p,
                    call: CallId::from_raw(1),
                    lead: A,
                    minor: false,
                },
            ),
            entry(
                2,
                CoreRecord::PlanVersionRecorded(fstp_domain::record::PlanVersionRecorded {
                    plan,
                    proposal: p,
                    origin: fstp_domain::proposal::PlanOrigin::Submitted,
                    supersedes: None,
                    tasks: Vec::new(),
                    content: fstp_domain::id::ContentDigest::from_bytes([0; 32]),
                }),
            ),
            entry(
                3,
                CoreRecord::Submitted {
                    proposal: p,
                    plan,
                    ethics: fstp_domain::proposal::EthicsDeclaration {
                        issues_declared: false,
                        text: text(1),
                    },
                    notice: fstp_domain::proposal::NoticeVersion(1),
                },
            ),
            entry(
                4,
                CoreRecord::Assigned(fstp_domain::record::Assigned {
                    assignment: a,
                    proposal: p,
                    call: CallId::from_raw(1),
                    reviewer: B,
                    kind: fstp_domain::assignment::AssignmentKind::Reviewer,
                    handle: None,
                    by: C,
                    epoch: fstp_domain::id::VaultEpoch::GENESIS,
                }),
            ),
            entry(
                5,
                CoreRecord::ScoreRecorded(fstp_domain::record::ScoreRecorded {
                    key: key(a, plan),
                    values: fstp_domain::scoring::ScoreVector(vec![4, 5]),
                    supersedes: None,
                    reason: None,
                }),
            ),
            entry(
                6,
                CoreRecord::QuestionAsked {
                    proposal: p,
                    assignment: a,
                    text: text(2),
                },
            ),
        ])
    }

    fn key(a: AssignmentId, plan: PlanVersionId) -> ScoreKey {
        ScoreKey {
            assignment: a,
            stage: fstp_domain::scoring::Stage::One,
            plan,
        }
    }

    /// R-SB-01, R-EV-05, R-EV-06: a proposal recorded before this core
    /// started, or by another process, is known once the journal folds the
    /// ledger: its plan, its score under the assignment's key and its
    /// stage 2 thread, with the instant of each entry.
    #[test]
    fn r_sb_01_ledger_journal_knows_a_proposal_recorded_elsewhere() {
        let mut j = Journal::default();
        let p = ProposalId::from_raw(7);
        let plan = PlanVersionId::from_raw(70);
        j.sync(|after| {
            assert_eq!(after, Seq::ZERO);
            Some(elsewhere())
        });
        assert!(j.folds_ledger());
        assert_eq!(j.submitted_plan(p), Ok(Some(plan)));
        assert_eq!(j.latest_plan(p), Ok(Some(plan)));
        assert_eq!(
            j.score(&key(AssignmentId::from_raw(3), plan)),
            Some(&[4u8, 5][..])
        );
        assert_eq!(
            j.thread(p),
            Ok(&[ThreadEntry::Question {
                assignment: AssignmentId::from_raw(3),
                text: text(2),
                at: Timestamp::from_micros(60),
            }][..])
        );
        assert_eq!(j.latest_plan(ProposalId::from_raw(8)), Err(Unknown));
    }

    /// R-SB-01: each ledger entry is folded once. A later sync reads from
    /// after the last folded entry, an entry served again is skipped, and
    /// a command of this core is not folded a second time beside its
    /// record.
    #[test]
    fn r_sb_01_ledger_journal_folds_each_entry_once() {
        let mut j = Journal::default();
        let p = ProposalId::from_raw(7);
        j.sync(|_| Some(elsewhere()));
        j.sync(|after| {
            assert_eq!(after, Seq::from_raw(6));
            Some(elsewhere())
        });
        j.fold(
            &Command::Core(Core::AskQuestion {
                proposal: p,
                assignment: AssignmentId::from_raw(3),
                text: text(9),
            }),
            &EngineState::genesis(),
            Timestamp::from_micros(1),
        );
        assert_eq!(j.thread(p).map(<[ThreadEntry]>::len), Ok(1));
    }

    /// R-SB-01: an engine with no ledger leaves the journal on the
    /// commands of this core, for good.
    #[test]
    fn r_sb_01_journal_without_a_ledger_folds_commands() {
        let mut j = Journal::default();
        j.sync(|_| None);
        assert!(!j.folds_ledger());
        j.sync(|_| panic!("a journal on its fallback never reads a ledger"));
        j.fold(
            &submit(7, 70),
            &EngineState::genesis(),
            Timestamp::from_micros(1),
        );
        assert_eq!(
            j.latest_plan(ProposalId::from_raw(7)),
            Ok(Some(PlanVersionId::from_raw(70)))
        );
    }

    /// R-EV-08, R-EV-09, change D5: a round opened by another process is
    /// read from the ledger, with each member's own ballot and delegation.
    #[test]
    fn r_ev_08_ledger_journal_folds_a_round_opened_elsewhere() {
        let mut j = Journal::default();
        let r = DecisionId::from_raw(9);
        let entries = ledger(vec![
            entry(
                1,
                CoreRecord::CutOffRoundOpened {
                    round: r,
                    call: CallId::from_raw(1),
                    order: vec![ProposalId::from_raw(1)],
                    nominated: 1,
                    rationale: text(1),
                    tie_breaks: None,
                    by: A,
                },
            ),
            entry(
                2,
                CoreRecord::BallotCast {
                    round: r,
                    voter: A,
                    vote: Vote::For,
                },
            ),
            entry(
                3,
                CoreRecord::VoteDelegated {
                    round: r,
                    from: B,
                    to: A,
                },
            ),
        ]);
        j.sync(|_| Some(entries));
        let facts = j.round(r).unwrap();
        assert_eq!(facts.status, RoundStatus::Open);
        assert_eq!(facts.cast.get(&A), Some(&Vote::For));
        assert_eq!(facts.delegated.get(&B), Some(&A));
        assert_eq!(j.open_round(CallId::from_raw(1)), Some(r));
    }
}

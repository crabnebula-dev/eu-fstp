//! A projection of the commands this core executed, for the read models
//! whose data the M2 domain does not expose (design section 3.6).
//!
//! The domain's state keeps plans, submissions, scores and the stage 2
//! thread behind crate-private accessors. Its public surface gives the
//! proposal state, the assignments, the ranking view and the effective
//! score only. So [`Journal`] folds, from every command that appended
//! through this core, the members the read models show:
//!
//! - the plan versions of each proposal, in the order recorded;
//! - the plan each proposal was submitted with, and its revisions;
//! - the current values of every score key, after corrections;
//! - the stage 2 questions, with the asking assignment, and the answers;
//! - the assignments that recorded "no questions";
//! - every notifiable conflict a declaration raised (R-CF-04);
//! - when an IRC concern was raised on a proposal (R-IR-02);
//! - each cut-off round opened through this core: its call, order,
//!   position, texts and status, and each member's own ballot or
//!   delegation (change D5). A round opened elsewhere is unknown, and its
//!   reads fail closed.
//!
//! It folds only commands the domain accepted and appended, so it never
//! holds a value the ledger does not.
//!
//! # Fail closed
//!
//! The projection is complete for a proposal only when this core folded
//! its creation or its submission: from then on, every command that
//! changes the facts above is one a route reaches. Such a proposal is
//! *known*. Every read of an unknown proposal answers [`Unknown`], and
//! dispatch refuses it with `NotImplemented`. So a proposal recorded
//! before this core started, or by another process, gets no read model
//! and no derived member, never a wrong one.
//!
//! Every map is bounded. A fold that would pass a bound makes its
//! proposal unknown, and its reads then fail closed too.
//!
//! Interim, pending Daniel, the lead and lane W1b: public read accessors
//! of the domain replace this projection. Until then the cell runs one
//! API core per ledger, as the M4 cells do.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::command::{Command as Core, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, CallId, DecisionId, PlanVersionId, ProposalId, TextRef,
};
use fstp_domain::scoring::ScoreKey;
use fstp_domain::time::Timestamp;
use fstp_engine::{Command, EngineState};

/// The most proposals the projection tracks.
const MAX_PROPOSALS: usize = 100_000;

/// The most plan versions or revisions of one proposal it tracks.
const MAX_PLANS: usize = 1_000;

/// The most stage 2 entries of one proposal it tracks.
const MAX_THREAD: usize = 1_000;

/// The most score keys and "no questions" assignments it tracks.
const MAX_KEYS: usize = 1_000_000;

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

/// The projection of one cell process. See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct Journal {
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
    /// Folds a command that appended at `now`, read against the state
    /// before it (`before`), which names the proposal of an assignment.
    pub(crate) fn fold(&mut self, cmd: &Command, before: &EngineState, now: Timestamp) {
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
        if self.saturated {
            return;
        }
        let Some(p) = proposal_of(c, before) else {
            return;
        };
        if self.lost.contains(&p) {
            return;
        }
        if !self.apply(c, p, now) {
            self.lose(p);
        }
    }

    /// Folds a round command that appended, by `actor` (change D5). The
    /// domain accepted it, so the round exists and is open for a cast, a
    /// delegation or a record. A command on a round this core did not see
    /// opened is ignored, and that round stays unknown. A fold past a
    /// bound drops its round, which then reads as unknown too.
    pub(crate) fn fold_round(&mut self, cmd: &Command, actor: AccountId) {
        let Command::Core(c) = cmd else {
            return;
        };
        match c {
            Core::OpenCutOffRound {
                round,
                call,
                order,
                nominated,
                rationale,
                tie_breaks,
            } => {
                // One round is open per call, so the domain superseded
                // the call's open round when it accepted this one.
                if let Some(old) = self.open_rounds.remove(call)
                    && let Some(r) = self.rounds.get_mut(&old)
                {
                    r.status = RoundStatus::Superseded;
                }
                if self.rounds.len() >= MAX_ROUNDS {
                    return;
                }
                self.rounds.insert(
                    *round,
                    RoundFacts {
                        call: *call,
                        order: order.clone(),
                        nominated: *nominated,
                        rationale: *rationale,
                        tie_breaks: *tie_breaks,
                        status: RoundStatus::Open,
                        cast: BTreeMap::new(),
                        delegated: BTreeMap::new(),
                    },
                );
                self.open_rounds.insert(*call, *round);
            }
            Core::CastBallot { round, vote } => {
                self.vote(*round, |r| {
                    r.cast.insert(actor, *vote);
                });
            }
            Core::DelegateVote { round, to } => {
                self.vote(*round, |r| {
                    r.delegated.insert(actor, *to);
                });
            }
            Core::RecordCutOff { round } => {
                if let Some(r) = self.rounds.get_mut(round) {
                    r.status = RoundStatus::Recorded;
                    if self.open_rounds.get(&r.call) == Some(round) {
                        self.open_rounds.remove(&r.call);
                    }
                }
            }
            _ => {}
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

    /// The round `round`, if this core folded its opening.
    pub(crate) fn round(&self, round: DecisionId) -> Option<&RoundFacts> {
        if self.saturated {
            return None;
        }
        self.rounds.get(&round)
    }

    /// The open cut-off round of `call`, if this core folded its opening
    /// and nothing closed it since (change D5). `me.roles` lists it for
    /// the committee of the call (design section 15.0, 2026-10-31).
    pub(crate) fn open_round(&self, call: CallId) -> Option<DecisionId> {
        if self.saturated {
            return None;
        }
        self.open_rounds.get(&call).copied()
    }

    /// Folds `c` of proposal `p`. `false` when a bound would be passed.
    fn apply(&mut self, c: &Core, p: ProposalId, now: Timestamp) -> bool {
        match c {
            Core::CreateDraft { .. } => insert(&mut self.created, p, MAX_PROPOSALS),
            Core::RecordPlanVersion { plan, .. } => push(&mut self.recorded, p, *plan, MAX_PLANS),
            Core::Submit { plan, .. } => {
                if !self.submitted.contains_key(&p) && self.submitted.len() >= MAX_PROPOSALS {
                    return false;
                }
                self.submitted.insert(p, *plan);
                self.revisions.remove(&p);
                true
            }
            Core::SubmitRevision { plan, .. } => push(&mut self.revisions, p, *plan, MAX_PLANS),
            Core::RecordScore { key, values } | Core::CorrectScore { key, values, .. } => {
                if !self.scores.contains_key(key) && self.scores.len() >= MAX_KEYS {
                    return false;
                }
                self.scores.insert(*key, values.0.clone());
                true
            }
            Core::AskQuestion {
                assignment, text, ..
            } => push(
                &mut self.thread,
                p,
                ThreadEntry::Question {
                    assignment: *assignment,
                    text: *text,
                    at: now,
                },
                MAX_THREAD,
            ),
            Core::AnswerQuestions { text, .. } => push(
                &mut self.thread,
                p,
                ThreadEntry::Answer {
                    text: *text,
                    at: now,
                },
                MAX_THREAD,
            ),
            Core::RecordIrcReview { .. } => {
                if !self.concerns.contains_key(&p) && self.concerns.len() >= MAX_PROPOSALS {
                    return false;
                }
                self.concerns.insert(p, now);
                true
            }
            Core::RecordNoQuestions { assignment, .. } => {
                insert(&mut self.no_questions, *assignment, MAX_KEYS)
            }
            Core::DeclareConflict { .. } => insert(&mut self.notifiable, p, MAX_PROPOSALS),
            _ => true,
        }
    }

    /// Makes `p` unknown and drops what the projection held of it. When
    /// the set of lost proposals is full, every proposal becomes unknown.
    fn lose(&mut self, p: ProposalId) {
        if !insert(&mut self.lost, p, MAX_PROPOSALS) {
            *self = Journal {
                saturated: true,
                ..Journal::default()
            };
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
}

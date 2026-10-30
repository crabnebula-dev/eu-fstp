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
//! - when an IRC concern was raised on a proposal (R-IR-02).
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
use fstp_domain::id::{AssignmentId, PlanVersionId, ProposalId, TextRef};
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
        if self.saturated {
            return;
        }
        let Command::Core(c) = cmd else {
            return;
        };
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

    /// The latest plan of `proposal`: its last stage 2 revision, else the
    /// submitted plan, else the latest recorded draft plan.
    pub(crate) fn latest_plan(
        &self,
        proposal: ProposalId,
    ) -> Result<Option<PlanVersionId>, Unknown> {
        if let Some(p) = self.last_revision(proposal)? {
            return Ok(Some(p));
        }
        if let Some(p) = self.submitted_plan(proposal)? {
            return Ok(Some(p));
        }
        Ok(self.recorded.get(&proposal).and_then(|v| v.last()).copied())
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
}

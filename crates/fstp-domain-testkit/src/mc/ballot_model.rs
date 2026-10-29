//! M-BALLOT (M4 design section 8.5): 4 committee members and a chair, one
//! recused, one delegation and one round. Each counted ballot was cast by
//! its voter or its single delegate, recused members neither vote nor
//! count, and the outcome follows P-16 NOTE 8 (R-EV-09, change D5).
//!
//! Lane W1b (L-DOM) owns this file. The M4 W0 lane added it with its
//! `mod` line.
//!
//! # The universe
//!
//! Two proposals are RANKED in call 1 from genesis by production
//! commands: PR1 by L1 at 100.00 and PR2 by L2 at 75.00. The committee is
//! R1, R2, R4 and R5, with CHAIR as the committee chair. The vault relates
//! R5 to L2, so R5 recuses from the cut-off vote of call 1 (Conflict
//! declarations). R1 opens the round [`ROUND`] over PR1 then PR2 with
//! rank position 1. The model's actions are:
//!
//! - every member and the chair casts For or Against, R5 included;
//! - R4 delegates to R2 (the one delegation), and two delegations that
//!   P-16 NOTE 8 forbids: from R5 to R1 and from R1 to R5;
//! - R1 records the cut-off;
//! - R2 opens the round [`REOPENED`] of call 1 with rank position 2,
//!   which supersedes [`ROUND`] once its vote has failed (interim,
//!   pending Daniel).
//!
//! # The reference
//!
//! [`reference_accepts`] is written from `SPEC/02-domain/policy-parameters.md`
//! NOTE 8 and `roles-and-sod.md` Conflict declarations, with the D5 rules
//! of the M4 design (Q4 interim reading, pending Daniel). It reads only the
//! model's own abstract state, never a production structure:
//!
//! - members who are not recused may vote; a member casts once, and not
//!   after delegating;
//! - a member delegates once, before casting, to another member who is not
//!   recused and holds no delegated vote; a delegated vote counts with the
//!   vote its delegate casts;
//! - the quorum is more than half of the members who are not recused,
//!   delegated votes included;
//! - the cut-off is adopted with more votes for than against; on a tie the
//!   chair's own vote decides, as the casting vote;
//! - no command acts after the cut-off is recorded;
//! - a new round of the call opens only once the vote has failed: P-16
//!   would not adopt the cut-off even if every member who may vote and
//!   has not voted cast For. No command acts in [`ROUND`] after that.
//!
//! # State and production
//!
//! A state is the abstract ballot state: the ballots cast, the delegation,
//! whether the cut-off is recorded and whether a new round superseded
//! the round. Equality and hashing read only that
//! part. The production projection and the records committed since the
//! start ride along, so two histories that reach the same ballots merge.
//! Production must be a function of the ballots alone, which the
//! `two-way` property and the record checks enforce on every path the
//! checker keeps.
//!
//! Every action runs through production `queries`, `decide` and `apply`
//! over the synthetic vault, and its outcome is compared with the
//! reference in both directions. A disagreement becomes a terminal state
//! with a divergence, which the `two-way` property reports.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::decision::{Ballot, Vote};
use fstp_domain::id::{AccountId, CommandId, DecisionId};
use fstp_domain::oracle::Answers;
use fstp_domain::record::{CutOffRecorded, Record, RulesVersion};
use fstp_domain::refusal::Refusal;
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;
use fstp_mc::{Model, Property};

use crate::r#gen::policy::text;
use crate::r#gen::review::{COORDINATOR, IRC, L1, L2, O1, O2, O3, PR1, PR2, R1, R2, R4, tag};
use crate::r#gen::roster::{Backend, call};
use crate::mc::life_model::{CHAIR, IRC2, R5, Story, open_round, story_setup};
use crate::vault::{GroundTruth, Relation};

/// The state count of M-BALLOT. It was computed before production landed,
/// by enumerating the abstract states that [`reference_accepts`] admits
/// with a scratch program: 108 states before the cut-off is recorded and
/// 32 after. The superseding round added 28 states, one per state before
/// the cut-off whose vote has failed, counted from the reference by hand.
/// Without the delegation, a failed vote has three or four votes Against,
/// or two with the chair's among them: 1 + 8 + 12 = 21 states. With it,
/// R2's vote counts twice: R2 Against with R1 or the chair Against, 5
/// states, or R1 and the chair Against while R2 has not voted Against, 2
/// states, so 7. The production run must report exactly this count, because a
/// state is the abstract ballot state and production must agree with the
/// reference on every action.
pub const TRIPWIRE: usize = 168;

/// The round of the model.
pub const ROUND: DecisionId = DecisionId::from_raw(9_301);

/// The member who is recused: the vault relates R5 to L2, the lead of PR2.
pub const RECUSED: AccountId = R5;

/// Every account that may try to cast: the four members and the chair.
pub const VOTERS: [AccountId; 5] = [R1, R2, R4, R5, CHAIR];

/// The members who may vote: every voter except [`RECUSED`].
pub const ELIGIBLE: [AccountId; 4] = [R1, R2, R4, CHAIR];

/// The one delegation the universe allows: R4 to R2.
pub const DELEGATION: (AccountId, AccountId) = (R4, R2);

/// The delegations the model tries: the allowed one, one from the recused
/// member and one to it.
pub const DELEGATIONS: [(AccountId, AccountId); 3] = [DELEGATION, (R5, R1), (R1, R5)];

/// The member who opens the round and records the cut-off.
pub const RECORDER: AccountId = R1;

/// The round that supersedes [`ROUND`] once its vote has failed.
pub const REOPENED: DecisionId = DecisionId::from_raw(9_302);

/// The member who opens [`REOPENED`].
pub const REOPENER: AccountId = R2;

/// The rank position of [`REOPENED`].
pub const REOPENED_NOMINATED: u32 = 2;

/// The command id of every model command. The pure functions never read it.
const MODEL_COMMAND: CommandId = CommandId::from_bytes(*b"model:ballot:d5!");

/// One action of M-BALLOT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BallotAction {
    /// The member casts their own ballot.
    Cast(AccountId, Vote),
    /// The first member delegates their vote to the second.
    Delegate(AccountId, AccountId),
    /// [`RECORDER`] records the cut-off of [`ROUND`].
    Record,
    /// [`REOPENER`] opens [`REOPENED`] over the same order.
    Reopen,
}

/// One state of M-BALLOT. Equality and hashing read the abstract ballot
/// state only: `cast`, `delegated`, `recorded`, `reopened`, `forged` and `divergence`.
#[derive(Clone, Debug)]
pub struct BallotState {
    /// The ballot each member cast, by member.
    pub cast: BTreeMap<AccountId, Vote>,
    /// The delegation recorded, as delegator and delegate.
    pub delegated: Option<(AccountId, AccountId)>,
    /// Whether the cut-off of the round is recorded.
    pub recorded: bool,
    /// Whether [`REOPENED`] superseded the round after its vote failed.
    pub reopened: bool,
    /// Whether the teeth fault forged the cut-off. It keeps a faulty state
    /// apart from a correct one with the same ballots, so the checker
    /// checks it.
    pub forged: bool,
    /// Set when production and the reference disagree. The state is terminal.
    pub divergence: Option<String>,
    /// The production projection after the history that reached this state.
    pub core: State,
    /// Every record committed since the round opened, in order, the
    /// opening's records included.
    pub records: Vec<Record>,
}

impl PartialEq for BallotState {
    fn eq(&self, other: &BallotState) -> bool {
        self.cast == other.cast
            && self.delegated == other.delegated
            && self.recorded == other.recorded
            && self.reopened == other.reopened
            && self.forged == other.forged
            && self.divergence == other.divergence
    }
}

impl Eq for BallotState {}

impl Hash for BallotState {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.cast.hash(h);
        self.delegated.hash(h);
        self.recorded.hash(h);
        self.reopened.hash(h);
        self.forged.hash(h);
        self.divergence.hash(h);
    }
}

impl BallotState {
    /// The cut-off records of [`ROUND`] in the records committed.
    pub fn cut_offs(&self) -> Vec<&CutOffRecorded> {
        self.records
            .iter()
            .filter_map(|r| match r {
                Record::CutOffRecorded(c) if c.decision == ROUND => Some(c),
                _ => None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The reference
// ---------------------------------------------------------------------------

/// Whether `member` may vote: a committee member or the chair who is not
/// recused (P-16 NOTE 8, Conflict declarations).
pub fn may_vote(member: AccountId) -> bool {
    ELIGIBLE.contains(&member)
}

/// The ballots that count in `cast` and `delegated` (P-16 NOTE 8): every
/// ballot a member who may vote cast directly, and the delegated vote of
/// the delegator, with the vote its delegate cast, once the delegate cast.
pub fn counted(
    cast: &BTreeMap<AccountId, Vote>,
    delegated: Option<(AccountId, AccountId)>,
) -> Vec<Ballot> {
    let mut out: Vec<Ballot> = cast
        .iter()
        .filter(|(m, _)| may_vote(**m))
        .map(|(m, v)| Ballot {
            voter: *m,
            vote: *v,
            delegated_by: None,
        })
        .collect();
    if let Some((from, to)) = delegated
        && let Some(v) = cast.get(&to)
        && may_vote(from)
        && may_vote(to)
    {
        out.push(Ballot {
            voter: to,
            vote: *v,
            delegated_by: Some(from),
        });
    }
    out
}

/// Whether the ballots of `cast` and `delegated` adopt the cut-off under
/// P-16 NOTE 8: a quorum of more than half of the members who may vote,
/// delegated votes included, and more votes for than against, or a tie
/// that the chair's own vote for breaks. Abstentions are not votes cast.
pub fn adopted(
    cast: &BTreeMap<AccountId, Vote>,
    delegated: Option<(AccountId, AccountId)>,
) -> bool {
    let ballots = counted(cast, delegated);
    let represented: BTreeSet<AccountId> = ballots
        .iter()
        .map(|b| b.delegated_by.unwrap_or(b.voter))
        .collect();
    if represented.len().saturating_mul(2) <= ELIGIBLE.len() {
        return false;
    }
    let votes_for = ballots.iter().filter(|b| b.vote == Vote::For).count();
    let against = ballots.iter().filter(|b| b.vote == Vote::Against).count();
    votes_for > against || (votes_for == against && cast.get(&CHAIR) == Some(&Vote::For))
}

/// Whether the vote of the round can still pass (P-16 NOTE 8): whether the
/// cut-off is adopted once every member who may vote and has neither cast
/// nor delegated casts For. When it cannot, the vote has failed, and a
/// new round of the call may supersede the round (interim, pending Daniel).
pub fn could_pass(
    cast: &BTreeMap<AccountId, Vote>,
    delegated: Option<(AccountId, AccountId)>,
) -> bool {
    let mut best = cast.clone();
    for m in ELIGIBLE {
        if !best.contains_key(&m) && delegated.is_none_or(|(from, _)| from != m) {
            best.insert(m, Vote::For);
        }
    }
    adopted(&best, delegated)
}

/// Whether the reference accepts `action` in `s`.
pub fn reference_accepts(s: &BallotState, action: &BallotAction) -> bool {
    if s.recorded || s.reopened {
        return false;
    }
    match action {
        BallotAction::Cast(m, _) => {
            may_vote(*m)
                && !s.cast.contains_key(m)
                && s.delegated.is_none_or(|(from, _)| from != *m)
        }
        BallotAction::Delegate(from, to) => {
            may_vote(*from)
                && may_vote(*to)
                && from != to
                && !s.cast.contains_key(from)
                && s.delegated.is_none()
        }
        BallotAction::Record => adopted(&s.cast, s.delegated),
        BallotAction::Reopen => !could_pass(&s.cast, s.delegated),
    }
}

/// The record the reference requires an accepted `action` to append. A
/// recorded cut-off is checked by [`outcome_follows_p16`] instead.
fn required(action: &BallotAction) -> Option<Record> {
    match action {
        BallotAction::Cast(m, v) => Some(Record::BallotCast {
            round: ROUND,
            voter: *m,
            vote: *v,
        }),
        BallotAction::Delegate(from, to) => Some(Record::VoteDelegated {
            round: ROUND,
            from: *from,
            to: *to,
        }),
        BallotAction::Record => None,
        BallotAction::Reopen => Some(Record::CutOffRoundOpened {
            round: REOPENED,
            call: call(1),
            order: vec![PR1, PR2],
            nominated: REOPENED_NOMINATED,
            rationale: text(85_000),
            tie_breaks: None,
            by: REOPENER,
        }),
    }
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// The M-BALLOT model.
#[derive(Debug)]
pub struct BallotModel {
    /// The start state: the round open, nothing cast.
    pub start: BallotState,
    /// The vault facts.
    pub truth: GroundTruth,
    /// The instant of every model command.
    pub now: Timestamp,
}

/// The Judging bindings of M-BALLOT: the coordinator, the four committee
/// members of three organisations, the chair and two IRC members.
pub fn ballot_judges() -> Vec<(AccountId, Role, Option<fstp_domain::id::OrganisationId>)> {
    vec![
        (COORDINATOR, Role::FstpCoordinator, None),
        (R1, Role::CommitteeMember, Some(O1)),
        (R2, Role::CommitteeMember, Some(O2)),
        (R4, Role::CommitteeMember, Some(O3)),
        (R5, Role::CommitteeMember, Some(O1)),
        (CHAIR, Role::CommitteeChair, None),
        (IRC, Role::IrcMember, None),
        (IRC2, Role::IrcMember, None),
    ]
}

/// Runs `cmd` by `actor` at `now` on `core` through production `queries`,
/// `decide` and `apply`, with every answer from `truth`. Returns the next
/// projection and the records, or the refusal. A fold that refuses
/// production's own records is a harness failure.
pub fn run_core(
    core: &State,
    truth: &GroundTruth,
    now: Timestamp,
    actor: AccountId,
    cmd: &Command,
) -> Result<Result<(State, Vec<Record>), Refusal>, String> {
    let ctx = Ctx {
        now,
        actor: Actor::Account(actor),
        command: MODEL_COMMAND,
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let mut answers = Answers::new();
    let queries = match fstp_domain::queries(core, cmd, &ctx) {
        Ok(q) => q,
        Err(r) => return Ok(Err(r)),
    };
    for q in queries {
        if truth.answers(&q) {
            let a = truth.answer(&q);
            answers.insert(q, a);
        }
    }
    let records = match fstp_domain::decide(core, cmd, &ctx, &answers) {
        Ok(r) => r,
        Err(r) => return Ok(Err(r)),
    };
    let mut next = core.clone();
    for r in &records {
        fstp_domain::apply(&mut next, Seq::from_raw(1), now, r)
            .map_err(|e| format!("production refused to fold its own record {r:?}: {e}"))?;
    }
    Ok(Ok((next, records)))
}

impl BallotModel {
    /// Builds the model from genesis by production commands: PR1 and PR2
    /// RANKED in call 1, and the round opened by [`RECORDER`].
    pub fn new() -> Result<BallotModel, String> {
        let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], ballot_judges());
        let mut s = Story::new(&setup, Backend::Production, |t| {
            t.relate(tag(R5), tag(L2), Relation::CoWorker);
        })?;
        s.submit(L2, PR2)?;
        s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])?;
        s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])?;
        let truth = s.world.rev.sod.truth.clone();
        let now = s.world.now();
        let open = open_round(RECORDER, ROUND, call(1), vec![PR1, PR2], 1, false);
        let (core, records) = run_core(&s.world.rev.sod.state, &truth, now, RECORDER, &open.cmd)?
            .map_err(|r| format!("R-EV-09: the round does not open: {r}"))?;
        Ok(BallotModel {
            start: BallotState {
                cast: BTreeMap::new(),
                delegated: None,
                recorded: false,
                reopened: false,
                forged: false,
                divergence: None,
                core,
                records,
            },
            truth,
            now,
        })
    }

    /// The command of `action`, and its actor.
    pub fn command(action: &BallotAction) -> (AccountId, Command) {
        match action {
            BallotAction::Cast(m, v) => (
                *m,
                Command::CastBallot {
                    round: ROUND,
                    vote: *v,
                },
            ),
            BallotAction::Delegate(from, to) => (
                *from,
                Command::DelegateVote {
                    round: ROUND,
                    to: *to,
                },
            ),
            BallotAction::Record => (RECORDER, Command::RecordCutOff { round: ROUND }),
            BallotAction::Reopen => (
                REOPENER,
                open_round(
                    REOPENER,
                    REOPENED,
                    call(1),
                    vec![PR1, PR2],
                    REOPENED_NOMINATED,
                    false,
                )
                .cmd,
            ),
        }
    }
}

/// `s` with a divergence.
fn diverged(s: &BallotState, why: String) -> BallotState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

impl Model for BallotModel {
    type State = BallotState;
    type Action = BallotAction;

    fn init(&self) -> Vec<BallotState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &BallotState, actions: &mut Vec<BallotAction>) {
        if s.divergence.is_some() || s.recorded {
            return;
        }
        for m in VOTERS {
            actions.push(BallotAction::Cast(m, Vote::For));
            actions.push(BallotAction::Cast(m, Vote::Against));
        }
        for (from, to) in DELEGATIONS {
            actions.push(BallotAction::Delegate(from, to));
        }
        actions.push(BallotAction::Record);
        actions.push(BallotAction::Reopen);
    }

    fn step(&self, s: &BallotState, action: &BallotAction) -> Option<BallotState> {
        if s.divergence.is_some() {
            return None;
        }
        let expected = reference_accepts(s, action);
        let (actor, cmd) = BallotModel::command(action);
        let outcome = match run_core(&s.core, &self.truth, self.now, actor, &cmd) {
            Ok(o) => o,
            Err(e) => return Some(diverged(s, format!("{action:?}: {e}"))),
        };
        match (expected, outcome) {
            (false, Err(_)) => None,
            (true, Err(r)) => Some(diverged(
                s,
                format!(
                    "{action:?}: over-denial, the reference accepts, production refuses with {r}"
                ),
            )),
            (false, Ok((_, records))) => Some(diverged(
                s,
                format!(
                    "{action:?}: over-permission, the reference refuses, production records {records:?}"
                ),
            )),
            (true, Ok((core, records))) => {
                if let Some(r) = required(action)
                    && !records.contains(&r)
                {
                    return Some(diverged(
                        s,
                        format!("{action:?}: the batch lacks {r:?}: {records:?}"),
                    ));
                }
                let mut next = s.clone();
                match action {
                    BallotAction::Cast(m, v) => {
                        next.cast.insert(*m, *v);
                    }
                    BallotAction::Delegate(from, to) => next.delegated = Some((*from, *to)),
                    BallotAction::Record => next.recorded = true,
                    BallotAction::Reopen => next.reopened = true,
                }
                next.core = core;
                next.records.extend(records);
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &BallotState) -> bool {
        let exhausted = ELIGIBLE
            .iter()
            .all(|m| s.cast.contains_key(m) || s.delegated.is_some_and(|(from, _)| from == *m));
        s.divergence.is_some() || s.recorded || s.reopened || exhausted
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// R-EV-09, D5: every ballot a cut-off counts was cast by its voter in the
/// round, and every held vote was delegated by its member to that voter,
/// who cast it. No member counts twice.
pub fn counted_ballots_were_cast(s: &BallotState) -> Result<(), String> {
    for c in s.cut_offs() {
        let mut members = BTreeSet::new();
        for b in &c.ballots {
            let cast = s.records.iter().any(|r| {
                matches!(r, Record::BallotCast { round, voter, vote }
                    if *round == ROUND && *voter == b.voter && *vote == b.vote)
            });
            if !cast {
                return Err(format!("{b:?} counts, but its voter cast no such ballot"));
            }
            if let Some(from) = b.delegated_by {
                let delegated = s.records.iter().any(|r| {
                    matches!(r, Record::VoteDelegated { round, from: f, to }
                        if *round == ROUND && *f == from && *to == b.voter)
                });
                if !delegated {
                    return Err(format!(
                        "{b:?} counts, but {from:?} delegated nothing to its voter"
                    ));
                }
            }
            let member = b.delegated_by.unwrap_or(b.voter);
            if !members.insert(member) {
                return Err(format!("{member:?} counts twice"));
            }
        }
    }
    Ok(())
}

/// R-EV-09, Conflict declarations: the recused member neither casts, nor
/// delegates, nor receives a delegation, nor counts, and every cut-off
/// names it as recused.
pub fn recused_neither_votes_nor_counts(s: &BallotState) -> Result<(), String> {
    for r in &s.records {
        match r {
            Record::BallotCast { voter, .. } if *voter == RECUSED => {
                return Err("the recused member cast a ballot".to_owned());
            }
            Record::VoteDelegated { from, to, .. } if *from == RECUSED || *to == RECUSED => {
                return Err("a delegation involves the recused member".to_owned());
            }
            _ => {}
        }
    }
    for c in s.cut_offs() {
        if c.ballots
            .iter()
            .any(|b| b.voter == RECUSED || b.delegated_by == Some(RECUSED))
        {
            return Err("a ballot of the recused member counts".to_owned());
        }
        if !c.recused.contains(&RECUSED) {
            return Err(format!("the cut-off does not name {RECUSED:?} as recused"));
        }
    }
    Ok(())
}

/// P-16 NOTE 8 and D5: a recorded cut-off is adopted under the reference
/// rule over the ballots cast, counts exactly those ballots, names the
/// round as its decision and carries the M4 rules version.
pub fn outcome_follows_p16(s: &BallotState) -> Result<(), String> {
    let cut_offs = s.cut_offs();
    if s.recorded != (cut_offs.len() == 1) {
        return Err(format!(
            "recorded is {}, but the round holds {} cut-off records",
            s.recorded,
            cut_offs.len()
        ));
    }
    for c in cut_offs {
        if !adopted(&s.cast, s.delegated) {
            return Err("a cut-off is recorded that P-16 does not adopt".to_owned());
        }
        let want: BTreeSet<(AccountId, Option<AccountId>, u8)> = counted(&s.cast, s.delegated)
            .iter()
            .map(|b| (b.voter, b.delegated_by, vote_code(b.vote)))
            .collect();
        let got: BTreeSet<(AccountId, Option<AccountId>, u8)> = c
            .ballots
            .iter()
            .map(|b| (b.voter, b.delegated_by, vote_code(b.vote)))
            .collect();
        if want != got || c.ballots.len() != got.len() {
            return Err(format!(
                "the cut-off counts {:?}, the ballots cast are {want:?}",
                c.ballots
            ));
        }
        if c.recorder != RECORDER || c.rules != RulesVersion::M4 {
            return Err(format!(
                "the cut-off names recorder {:?} and rules {:?}",
                c.recorder, c.rules
            ));
        }
    }
    Ok(())
}

/// A total order code of a vote, for set comparison.
fn vote_code(v: Vote) -> u8 {
    match v {
        Vote::For => 0,
        Vote::Against => 1,
        Vote::Abstain => 2,
    }
}

/// Whether the recorded cut-off broke a tie with the chair's vote.
pub fn decided_by_casting_vote(s: &BallotState) -> bool {
    if !s.recorded {
        return false;
    }
    let ballots = counted(&s.cast, s.delegated);
    let votes_for = ballots.iter().filter(|b| b.vote == Vote::For).count();
    let against = ballots.iter().filter(|b| b.vote == Vote::Against).count();
    votes_for == against && s.cast.get(&CHAIR) == Some(&Vote::For)
}

/// R-EV-08, R-EV-09: a new round superseded the round only after its vote
/// failed, and then the round holds no cut-off and the new round's
/// opening is recorded once. Before that, no new round is opened.
pub fn superseded_only_after_failed_vote(s: &BallotState) -> Result<(), String> {
    let openings = s
        .records
        .iter()
        .filter(|r| matches!(r, Record::CutOffRoundOpened { round, .. } if *round == REOPENED))
        .count();
    if openings != usize::from(s.reopened) {
        return Err(format!(
            "reopened is {}, but {openings} openings of the new round are recorded",
            s.reopened
        ));
    }
    if s.reopened && could_pass(&s.cast, s.delegated) {
        return Err("a new round superseded a round whose vote could still pass".to_owned());
    }
    if s.reopened && !s.cut_offs().is_empty() {
        return Err("a superseded round holds a cut-off".to_owned());
    }
    Ok(())
}

/// The properties of M-BALLOT: `always("two-way")`, the three R-EV-09 and
/// P-16 checks, the superseding check, no deadlock, and the witnesses: a
/// decided round, a tie broken by the chair's casting vote, a counted
/// delegated vote, and a new round after a failed vote. They read only
/// the state, so the teeth mutant checks them too.
pub fn ballot_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = BallotState> + 'a,
{
    vec![
        Property::always_with("two-way", |s: &BallotState| match &s.divergence {
            None => Ok(()),
            Some(why) => Err(why.clone()),
        }),
        Property::always_with(
            "R-EV-09: counted ballots were cast",
            counted_ballots_were_cast,
        ),
        Property::always_with(
            "R-EV-09: recused members neither vote nor count",
            recused_neither_votes_nor_counts,
        ),
        Property::always_with("P-16 NOTE 8: outcome", outcome_follows_p16),
        Property::always_with(
            "R-EV-09: superseded only after a failed vote",
            superseded_only_after_failed_vote,
        ),
        Property::deadlock_free("deadlock"),
        Property::reachable("decided round", |s: &BallotState| s.recorded),
        Property::reachable("chair casting vote", decided_by_casting_vote),
        Property::reachable("delegated vote counted", |s: &BallotState| {
            s.recorded
                && s.cut_offs()
                    .iter()
                    .any(|c| c.ballots.iter().any(|b| b.delegated_by.is_some()))
        }),
        Property::reachable("new round after a failed vote", |s: &BallotState| {
            s.reopened
        }),
    ]
}

/// R-EV-09, Q4: each action changes only its actor's part of the round. A
/// cast changes only its member's ballot, and a delegation or the record
/// changes no ballot. So no member's session states another member's
/// vote. For [`BallotModel`] itself, whose actions it reads.
pub fn member_acts_only_for_themselves<'a>() -> Property<'a, BallotModel> {
    Property::transition(
        "R-EV-09: a member acts only for themselves",
        |a: &BallotState, act: &BallotAction, b: &BallotState| {
            if b.divergence.is_some() {
                return true;
            }
            match act {
                BallotAction::Cast(m, v) => {
                    let others = |s: &BallotState| -> BTreeMap<AccountId, Vote> {
                        s.cast
                            .iter()
                            .filter(|(k, _)| *k != m)
                            .map(|(k, x)| (*k, *x))
                            .collect()
                    };
                    others(a) == others(b) && b.cast.get(m) == Some(v)
                }
                BallotAction::Delegate(..) | BallotAction::Record | BallotAction::Reopen => {
                    a.cast == b.cast
                }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Teeth
// ---------------------------------------------------------------------------

/// The teeth fault (design 6.1): a broken engine records a cut-off that
/// counts a ballot of the recused member, which nobody cast. It is the
/// output of an alternative adapter, appended to the records the model
/// observed, never a production hook. The property
/// `R-EV-09: counted ballots were cast` must report it.
pub fn fault_uncast_ballot_counted(s: &BallotState) -> Option<BallotState> {
    if s.recorded || s.reopened || s.divergence.is_some() {
        return None;
    }
    let mut ballots = counted(&s.cast, s.delegated);
    ballots.push(Ballot {
        voter: RECUSED,
        vote: Vote::For,
        delegated_by: None,
    });
    let forged = Record::CutOffRecorded(CutOffRecorded {
        decision: ROUND,
        call: call(1),
        order: vec![PR1, PR2],
        nominated: 1,
        rationale: text(85_000),
        tie_breaks: None,
        ballots,
        recused: BTreeSet::new(),
        remaining_budget: fstp_money::Amount::zero(fstp_money::Currency::Eur),
        recorder: RECORDER,
        rules: RulesVersion::M4,
    });
    let mut next = s.clone();
    next.records.push(forged);
    next.recorded = true;
    next.forged = true;
    Some(next)
}

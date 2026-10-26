//! I-07 teeth and reference checks at the pure level
//! (`docs/handoff/m2-design.md` section 6.1).
//!
//! Each teeth test passes a deliberately broken quorum to the I-07
//! predicate as a plain function pointer. No production hook exists. One
//! broken quorum counts every score record of a valid key, so a
//! superseded score counts beside its correction. The others each drop
//! one clause of a valid score: the conflict fact, its scope to the
//! proposal, the stage, the assignment kind, the declaration, the
//! assignment's proposal, the stage's call, the void and the plan the
//! stage scores. A broken close drops the
//! NOTE 3 condition that every active assignee has a valid score. The
//! predicates must catch each of them.
//!
//! The control tests pass the references themselves, so a teeth test
//! cannot pass by a predicate that rejects everything. Hand-built scripts
//! check the reference on the cases NOTE 3 names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::id::{AccountId, AssignmentId, CallId, ProposalId, VaultEpoch};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{AssignmentReleased, ConflictDetected, Declared, Record, ScoreVoided};
use fstp_domain::scoring::{ScoreKey, Stage, VoidCause};
use fstp_domain_testkit::r#gen::scores::{Fixture, QuorumCase, Script, reviewer};
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{
    active_reviewer_assignments, current_values, i07_close_property, i07_property, plan_scorable,
    quorum_reference, reference_close, reference_quorum, reviewers_of, stage1_close_reference,
    valid_score_keys,
};
use fstp_prop::{Config, check, run};

/// A broken quorum: the valid keys, accepted when the number of score
/// records on them reaches P-03. A corrected score then counts twice.
fn superseded_counted(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records = case.script.records();
    let valid = valid_score_keys(&records, case.fixture.proposal, case.stage, case.plan);
    let counted = records
        .iter()
        .filter(|r| matches!(r, Record::ScoreRecorded(s) if valid.contains(&s.key)))
        .count();
    Ok((counted >= usize::from(case.fixture.p03)).then_some(valid))
}

/// I-07 teeth: a quorum that counts a superseded score beside its
/// correction fails the I-07 property with a counterexample.
#[test]
fn i07_teeth_superseded_score_counted_is_caught() {
    let outcome = run(
        "i07_teeth_superseded_score_counted_is_caught",
        Config::default(),
        |g| i07_property(g, superseded_counted),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07 control: the reference passes its own property.
#[test]
fn i07_teeth_control_reference_quorum_passes() {
    check("i07_teeth_control_reference_quorum_passes", |g| {
        i07_property(g, reference_quorum)
    });
}

/// A stage 1 script with `n` assigned reviewers and P-03 of `p03`.
fn base(n: u8, p03: u8) -> (Fixture, Script, Vec<AssignmentId>) {
    let fx = Fixture::numbered(1, 4, vec![30, 40, 30], 7_500, p03);
    let mut script = Script::new();
    script.open_programme(&fx).unwrap();
    let reviewers: Vec<_> = (0..n).map(reviewer).collect();
    script.bind_reviewers(&fx, &reviewers).unwrap();
    script.submit_proposal(&fx).unwrap();
    let mut assignments = Vec::new();
    for r in reviewers {
        let a = AssignmentId::from_raw(script.fresh());
        script.assign(&fx, fx.proposal, a, r).unwrap();
        assignments.push(a);
    }
    (fx, script, assignments)
}

/// The stage 1 key of `assignment` on the original plan of `fx`.
fn key(fx: &Fixture, assignment: AssignmentId) -> ScoreKey {
    ScoreKey {
        assignment,
        stage: Stage::One,
        plan: fx.plan,
    }
}

/// I-07, NOTE 3: one reviewer who scores and corrects twice is one valid
/// score, below a P-03 of 2. The current value is the last correction.
#[test]
fn i07_reference_counts_a_corrected_score_once() {
    let (fx, mut script, a) = base(2, 2);
    let k = key(&fx, a[0]);
    let s1 = script.score(k, vec![1, 1, 1], None).unwrap();
    let s2 = script.score(k, vec![2, 2, 2], Some(s1)).unwrap();
    script.score(k, vec![4, 3, 2], Some(s2)).unwrap();
    let records = script.records();
    let valid = valid_score_keys(&records, fx.proposal, Stage::One, fx.plan);
    assert_eq!(valid, [k].into_iter().collect());
    assert_eq!(
        quorum_reference(&records, fx.proposal, Stage::One, fx.plan, 2),
        None
    );
    assert_eq!(current_values(&records, k).unwrap().0, vec![4, 3, 2]);

    let k2 = key(&fx, a[1]);
    script.score(k2, vec![0, 0, 0], None).unwrap();
    let records = script.records();
    assert_eq!(
        quorum_reference(&records, fx.proposal, Stage::One, fx.plan, 2),
        Some([k, k2].into_iter().collect())
    );
}

/// I-07, NOTE 3: scores of released or conflicted reviewers never count,
/// even when no void record follows the release.
#[test]
fn i07_reference_ignores_released_and_conflicted_reviewers() {
    let (fx, mut script, a) = base(3, 1);
    for x in &a {
        script.score(key(&fx, *x), vec![3, 3, 3], None).unwrap();
    }
    script
        .push(Record::AssignmentReleased(AssignmentReleased {
            assignment: a[0],
            cause: ReleaseCause::Unassigned,
        }))
        .unwrap();
    script
        .push(Record::VaultEpochProcessed {
            epoch: VaultEpoch::from_raw(1),
        })
        .unwrap();
    script
        .push(Record::ConflictDetected(ConflictDetected {
            account: reviewer(1),
            proposal: fx.proposal,
            notifiable: false,
            epoch: VaultEpoch::from_raw(1),
        }))
        .unwrap();
    let records = script.records();
    let valid = valid_score_keys(&records, fx.proposal, Stage::One, fx.plan);
    assert_eq!(valid, [key(&fx, a[2])].into_iter().collect());
}

/// The one clause of a valid score that a broken quorum drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Drop {
    /// Conflict facts are ignored.
    Conflict,
    /// Conflict facts on any proposal count.
    ConflictScope,
    /// The stage of the key is ignored.
    Stage,
    /// Assignments of every kind count.
    Kind,
    /// Assignments awaiting their declaration count.
    Declaration,
    /// The proposal of the key's assignment is ignored.
    AssignmentProposal,
    /// Assignments of every call count after a re-entry.
    Call,
    /// Stage 1 counts the current call, not the call stage 1 ran in.
    Stage1Call,
    /// `ScoreVoided` records are ignored, so a voided score still counts.
    Void,
    /// Any plan of the proposal may hold a quorum on either stage.
    PlanOrigin,
}

/// The valid keys of the reference rule with one clause dropped, folded
/// here from raw records so that no reference code is shared. `None` when
/// the stage does not score the plan: stage 1 scores the submitted plan
/// and stage 2 a stage 2 revision (NOTE 3, NOTE 4).
fn broken_keys(case: &QuorumCase, drop: Drop) -> Option<BTreeSet<ScoreKey>> {
    let records = case.script.records();
    let proposal = case.fixture.proposal;
    let mut created = None;
    let mut call = None;
    let mut origin: Option<PlanOrigin> = None;
    let mut assignments: BTreeMap<AssignmentId, (ProposalId, CallId, AccountId, AssignmentKind)> =
        BTreeMap::new();
    let mut clear: BTreeSet<AssignmentId> = BTreeSet::new();
    let mut declared_conflict: BTreeSet<AssignmentId> = BTreeSet::new();
    let mut released: BTreeSet<AssignmentId> = BTreeSet::new();
    let mut conflicted: BTreeSet<AccountId> = BTreeSet::new();
    let mut current: BTreeMap<ScoreKey, bool> = BTreeMap::new();
    let scoped = |p: ProposalId| drop == Drop::ConflictScope || p == proposal;
    for r in &records {
        match r {
            Record::ProposalCreated {
                proposal: p,
                call: c,
                ..
            } if *p == proposal => {
                created = Some(*c);
                call = Some(*c);
            }
            Record::ReEntered {
                proposal: p,
                to_call,
                ..
            } if *p == proposal => {
                call = Some(*to_call);
            }
            Record::PlanVersionRecorded(v) if v.proposal == proposal && v.plan == case.plan => {
                origin = Some(v.origin);
            }
            Record::Assigned(a) => {
                assignments.insert(a.assignment, (a.proposal, a.call, a.reviewer, a.kind));
            }
            Record::AssignmentReleased(a) => {
                released.insert(a.assignment);
            }
            Record::ConflictDeclared(d) => match d.subject {
                Declared::Assignment(a) if d.conflicted => {
                    declared_conflict.insert(a);
                    if let Some((p, _, account, _)) = assignments.get(&a)
                        && scoped(*p)
                    {
                        conflicted.insert(*account);
                    }
                }
                Declared::Assignment(a) => {
                    clear.insert(a);
                }
                Declared::Proposal {
                    proposal: p,
                    account,
                } => {
                    if d.conflicted && scoped(p) {
                        conflicted.insert(account);
                    }
                }
            },
            Record::ConflictDetected(d) if scoped(d.proposal) => {
                conflicted.insert(d.account);
            }
            Record::ScoreRecorded(s) => {
                current.insert(s.key, true);
            }
            Record::ScoreVoided(v) if drop != Drop::Void => {
                current.insert(v.key, false);
            }
            _ => {}
        }
    }
    let wanted = match case.stage {
        Stage::One => PlanOrigin::Submitted,
        Stage::Two => PlanOrigin::Stage2Revision,
    };
    if drop != Drop::PlanOrigin && origin != Some(wanted) {
        return None;
    }
    let stage_call = match case.stage {
        Stage::One if drop != Drop::Stage1Call => created,
        _ => call,
    };
    let keys = current
        .into_iter()
        .filter(|(k, live)| *live && k.plan == case.plan)
        .filter(|(k, _)| drop == Drop::Stage || k.stage == case.stage)
        .map(|(k, _)| k)
        .filter(|k| {
            let a = k.assignment;
            assignments.get(&a).is_some_and(|(p, c, account, kind)| {
                (drop == Drop::AssignmentProposal || *p == proposal)
                    && (drop == Drop::Call || Some(*c) == stage_call)
                    && (drop == Drop::Kind || *kind == AssignmentKind::Reviewer)
                    && (drop == Drop::Declaration || clear.contains(&a))
                    && !declared_conflict.contains(&a)
                    && !released.contains(&a)
                    && (drop == Drop::Conflict || !conflicted.contains(account))
            })
        })
        .collect();
    Some(keys)
}

/// A broken quorum: [`broken_keys`] with the P-03 and one-key-per-reviewer rule.
fn broken_quorum(case: &QuorumCase, drop: Drop) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let Some(keys) = broken_keys(case, drop) else {
        return Ok(None);
    };
    let reviewers = reviewers_of(&case.script.records(), &keys);
    Ok(
        (reviewers.len() >= usize::from(case.fixture.p03) && reviewers.len() == keys.len())
            .then_some(keys),
    )
}

fn conflict_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Conflict)
}

fn conflict_unscoped(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::ConflictScope)
}

fn stage_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Stage)
}

fn kind_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Kind)
}

fn declaration_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Declaration)
}

fn assignment_proposal_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::AssignmentProposal)
}

fn call_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Call)
}

fn stage1_in_current_call(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Stage1Call)
}

fn void_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::Void)
}

fn plan_origin_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    broken_quorum(case, Drop::PlanOrigin)
}

/// I-07, NOTE 3 teeth: a quorum that ignores `ScoreVoided` fails the I-07
/// property. The generator voids scores of active, declared reviewer
/// assignments, as a complaint remedy does, so no release hides the void.
#[test]
fn i07_teeth_void_ignored_is_caught() {
    let outcome = run("i07_teeth_void_ignored_is_caught", Config::default(), |g| {
        i07_property(g, void_ignored)
    });
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// A broken stage 1 close that counts the current call after a re-entry,
/// instead of the call stage 1 ran in. Its quorum counts the current
/// call's stage 1 keys, and it needs every active assignee of the current
/// call scored. The reference's stage 2 assignment set is that call's.
fn close_in_current_call(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let Some(keys) = stage1_in_current_call(case)? else {
        return Ok(None);
    };
    let scored: BTreeSet<AssignmentId> = keys.iter().map(|k| k.assignment).collect();
    let records = case.script.records();
    let active = active_reviewer_assignments(&records, case.fixture.proposal, Stage::Two);
    Ok(active.is_subset(&scored).then_some(keys))
}

/// I-07, I-08, NOTE 8 teeth: a stage 1 close that counts the current call
/// after a re-entry, instead of the call stage 1 ran in, fails the close
/// property. That property asks for stage 1 in every case, so each
/// re-entry case tests the scope.
#[test]
fn i07_teeth_stage1_scoped_to_the_current_call_is_caught() {
    let outcome = run(
        "i07_teeth_stage1_scoped_to_the_current_call_is_caught",
        Config::default(),
        |g| i07_close_property(g, close_in_current_call),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07, NOTE 4 teeth: a stage 2 quorum on the submitted plan, which is
/// not a stage 2 revision, fails the I-07 property.
#[test]
fn i07_teeth_stage2_quorum_on_an_unrevised_plan_is_caught() {
    let outcome = run(
        "i07_teeth_stage2_quorum_on_an_unrevised_plan_is_caught",
        Config::default(),
        |g| i07_property(g, plan_origin_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07, NOTE 3 teeth: a quorum that ignores conflict facts on an
/// assignment that stays active fails the I-07 property.
#[test]
fn i07_teeth_conflict_fact_ignored_is_caught() {
    let outcome = run(
        "i07_teeth_conflict_fact_ignored_is_caught",
        Config::default(),
        |g| i07_property(g, conflict_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07 teeth: a quorum that counts conflict facts on another proposal
/// fails the I-07 property.
#[test]
fn i07_teeth_conflict_not_scoped_to_the_proposal_is_caught() {
    let outcome = run(
        "i07_teeth_conflict_not_scoped_to_the_proposal_is_caught",
        Config::default(),
        |g| i07_property(g, conflict_unscoped),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07, NOTE 4 teeth: a quorum that filters by plan but ignores the
/// stage fails the I-07 property.
#[test]
fn i07_teeth_stage_ignored_is_caught() {
    let outcome = run(
        "i07_teeth_stage_ignored_is_caught",
        Config::default(),
        |g| i07_property(g, stage_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07 teeth: a quorum that counts IRC and amendment assignments fails
/// the I-07 property.
#[test]
fn i07_teeth_assignment_kind_ignored_is_caught() {
    let outcome = run(
        "i07_teeth_assignment_kind_ignored_is_caught",
        Config::default(),
        |g| i07_property(g, kind_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07 teeth: a quorum that counts an assignment awaiting its
/// declaration fails the I-07 property (design section 2.7).
#[test]
fn i07_teeth_declaration_ignored_is_caught() {
    let outcome = run(
        "i07_teeth_declaration_ignored_is_caught",
        Config::default(),
        |g| i07_property(g, declaration_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07 teeth: a quorum that counts a key whose assignment belongs to
/// another proposal fails the I-07 property.
#[test]
fn i07_teeth_assignment_proposal_ignored_is_caught() {
    let outcome = run(
        "i07_teeth_assignment_proposal_ignored_is_caught",
        Config::default(),
        |g| i07_property(g, assignment_proposal_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07, NOTE 8 teeth: a quorum that counts assignments of the call the
/// proposal left fails the I-07 property.
#[test]
fn i07_teeth_earlier_call_counted_is_caught() {
    let outcome = run(
        "i07_teeth_earlier_call_counted_is_caught",
        Config::default(),
        |g| i07_property(g, call_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// A broken close: the I-07 quorum alone, without the NOTE 3 condition
/// that every active assignee has a valid score.
fn close_on_quorum_alone(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records = case.script.records();
    let fx = &case.fixture;
    Ok(quorum_reference(
        &records,
        fx.proposal,
        Stage::One,
        fx.plan,
        fx.p03,
    ))
}

/// I-07, NOTE 3 teeth: a stage 1 close that needs only P-03 valid scores
/// fails the close property while an active assignee is unscored.
#[test]
fn i07_teeth_close_without_every_active_assignee_is_caught() {
    let outcome = run(
        "i07_teeth_close_without_every_active_assignee_is_caught",
        Config::default(),
        |g| i07_close_property(g, close_on_quorum_alone),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

/// I-07, NOTE 3 control: the close reference passes its own property.
#[test]
fn i07_teeth_control_reference_close_passes() {
    check("i07_teeth_control_reference_close_passes", |g| {
        i07_close_property(g, reference_close)
    });
}

/// I-07, NOTE 3, design section 2.7: an assignment awaiting its
/// declaration is not active, so its score does not count and it does
/// not hold up the close. Its declaration makes it count.
#[test]
fn i07_reference_needs_a_declaration_before_a_score_counts() {
    let (fx, mut script, a) = base(1, 1);
    let pending = AssignmentId::from_raw(script.fresh());
    script
        .assign_as(
            fx.call,
            fx.proposal,
            pending,
            reviewer(5),
            AssignmentKind::Reviewer,
            false,
        )
        .unwrap();
    script.score(key(&fx, a[0]), vec![3, 3, 3], None).unwrap();
    script
        .score(key(&fx, pending), vec![4, 4, 4], None)
        .unwrap();
    let records = script.records();
    let valid = valid_score_keys(&records, fx.proposal, Stage::One, fx.plan);
    assert_eq!(valid, [key(&fx, a[0])].into_iter().collect());
    assert_eq!(
        stage1_close_reference(&records, fx.proposal, fx.plan, 1),
        Some(valid)
    );
    script.declare(pending).unwrap();
    let records = script.records();
    let valid = valid_score_keys(&records, fx.proposal, Stage::One, fx.plan);
    assert_eq!(valid.len(), 2);
}

/// I-07, NOTE 3: a complaint remedy void removes the current value of a
/// key while its assignment stays active. A fresh score on the key then
/// counts once, with the new value.
#[test]
fn i07_reference_void_removes_a_value_and_a_rescore_counts_once() {
    let (fx, mut script, a) = base(2, 2);
    let k1 = key(&fx, a[0]);
    let k2 = key(&fx, a[1]);
    script.score(k1, vec![1, 1, 1], None).unwrap();
    script.score(k2, vec![2, 2, 2], None).unwrap();
    script
        .push(Record::ScoreVoided(ScoreVoided {
            key: k1,
            cause: VoidCause::ComplaintRemedy,
        }))
        .unwrap();
    let records = script.records();
    let valid = valid_score_keys(&records, fx.proposal, Stage::One, fx.plan);
    assert_eq!(valid, [k2].into_iter().collect());
    assert_eq!(
        quorum_reference(&records, fx.proposal, Stage::One, fx.plan, 2),
        None
    );
    assert_eq!(current_values(&records, k1), None);
    script.score(k1, vec![4, 4, 4], None).unwrap();
    let records = script.records();
    assert_eq!(
        quorum_reference(&records, fx.proposal, Stage::One, fx.plan, 2),
        Some([k1, k2].into_iter().collect())
    );
    assert_eq!(current_values(&records, k1).unwrap().0, vec![4, 4, 4]);
}

/// I-07, NOTE 4: stage 2 keys on the submitted plan never form a stage 2
/// quorum, because stage 2 scores only a stage 2 revision.
#[test]
fn i07_reference_refuses_a_stage2_quorum_on_the_submitted_plan() {
    let (fx, mut script, a) = base(2, 1);
    for x in &a {
        let k = ScoreKey {
            assignment: *x,
            stage: Stage::Two,
            plan: fx.plan,
        };
        script.score(k, vec![3, 3, 3], None).unwrap();
    }
    let records = script.records();
    assert!(!plan_scorable(&records, fx.proposal, Stage::Two, fx.plan));
    assert!(plan_scorable(&records, fx.proposal, Stage::One, fx.plan));
    assert_eq!(
        valid_score_keys(&records, fx.proposal, Stage::Two, fx.plan).len(),
        2
    );
    assert_eq!(
        quorum_reference(&records, fx.proposal, Stage::Two, fx.plan, 1),
        None
    );
}

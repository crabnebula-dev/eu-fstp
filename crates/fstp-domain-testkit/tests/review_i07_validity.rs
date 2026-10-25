//! Review reproducers for lane L-SCORE: what counts as a valid score (I-07,
//! NOTE 3, design section 2.9).
//!
//! A valid score needs three things: the current value of its key, an
//! assignment active now, and no conflict fact for its account on the
//! proposal. The I-07 property must catch a quorum that drops any one of
//! them. These tests pass a quorum that drops the conflict clause.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AccountId, AssignmentId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::scoring::ScoreKey;
use fstp_domain_testkit::r#gen::scores::QuorumCase;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{i07_property, reviewers_of};
use fstp_prop::{Config, run};

/// A broken quorum: the reference rule without the conflict clause. It
/// counts the current value of a key from a reviewer assignment to the
/// proposal that is not released, whatever conflict facts exist.
fn conflict_facts_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records = case.script.records();
    let proposal = case.fixture.proposal;
    let mut assignments: BTreeMap<AssignmentId, (ProposalId, AccountId, AssignmentKind)> =
        BTreeMap::new();
    let mut released: BTreeSet<AssignmentId> = BTreeSet::new();
    let mut current: BTreeMap<ScoreKey, bool> = BTreeMap::new();
    for r in &records {
        match r {
            Record::Assigned(a) => {
                assignments.insert(a.assignment, (a.proposal, a.reviewer, a.kind));
            }
            Record::AssignmentReleased(a) => {
                released.insert(a.assignment);
            }
            Record::ScoreRecorded(s) => {
                current.insert(s.key, true);
            }
            Record::ScoreVoided(v) => {
                current.insert(v.key, false);
            }
            _ => {}
        }
    }
    let keys: BTreeSet<ScoreKey> = current
        .into_iter()
        .filter(|(k, live)| *live && k.stage == case.stage && k.plan == case.plan)
        .map(|(k, _)| k)
        .filter(|k| {
            assignments.get(&k.assignment).is_some_and(|(p, _, kind)| {
                *p == proposal
                    && *kind == AssignmentKind::Reviewer
                    && !released.contains(&k.assignment)
            })
        })
        .collect();
    let reviewers = reviewers_of(&records, &keys);
    Ok(
        (reviewers.len() >= usize::from(case.fixture.p03) && reviewers.len() == keys.len())
            .then_some(keys),
    )
}

/// I-07, NOTE 3 review: a quorum that ignores conflict facts must fail the
/// I-07 property. It fails now because every conflict in `quorum_case`
/// comes with a release of the conflicted assignment, so the release alone
/// already excludes the score. The generator needs cases with a conflict
/// fact on an assignment that is still active.
#[test]
fn review_i07_conflict_fact_without_release_is_caught() {
    let outcome = run(
        "review_i07_conflict_fact_without_release_is_caught",
        Config::default(),
        |g| i07_property(g, conflict_facts_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

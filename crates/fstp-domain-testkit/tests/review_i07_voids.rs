//! Review reproducer for lane L-SCORE: the void clause of a valid score
//! (I-07, NOTE 3, design sections 2.9 and 6.2).
//!
//! A valid score is the current value of its key. A `ScoreVoided` removes
//! that value, for example after a complaint remedy reopens the stage
//! while the assignment stays active (`VoidCause::ComplaintRemedy`). The
//! I-07 property must catch a quorum that ignores voids.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::record::Record;
use fstp_domain::scoring::ScoreKey;
use fstp_domain_testkit::r#gen::scores::QuorumCase;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{i07_property, quorum_reference};
use fstp_prop::{Config, run};

/// A broken quorum: the reference rule over the records with every
/// `ScoreVoided` removed, so a voided score still counts.
fn voids_ignored(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let records: Vec<Record> = case
        .script
        .records()
        .into_iter()
        .filter(|r| !matches!(r, Record::ScoreVoided(_)))
        .collect();
    Ok(quorum_reference(
        &records,
        case.fixture.proposal,
        case.stage,
        case.plan,
        case.fixture.p03,
    ))
}

/// I-07, NOTE 3 review: a quorum that ignores voids must fail the I-07
/// property. It passes now, because `quorum_case` voids only the scores
/// of assignments it releases in the same step. The release alone then
/// excludes the score, so the void clause is never tested on its own.
#[test]
fn review_i07_void_on_an_active_assignment_is_caught() {
    let outcome = run(
        "review_i07_void_on_an_active_assignment_is_caught",
        Config::default(),
        |g| i07_property(g, voids_ignored),
    );
    expect_prop_failure(&outcome, "I-07").unwrap();
}

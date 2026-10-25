//! I-07 pure test of the production quorum (`docs/handoff/m2-design.md`
//! sections 2.9 and 6.2).
//!
//! I-07: every scored proposal has scores from at least P-03 assigned
//! reviewers before it can leave stage 1. NOTE 3 and NOTE 4 define a
//! valid score: the current value of its key, from an assignment active
//! now, with no conflict fact for its account on the proposal. A
//! correction replaces a value and never counts twice. Stage 2 needs at
//! least P-03 valid stage 2 scores on the revised plan.
//!
//! The scenario is a list of raw records from `quorum_case`, folded into a
//! state with the public structural `apply` ([`Script::fold`]), never
//! through commands. The reference is a set computation over the same raw
//! records (`reference::scoring::valid_score_keys`).
//!
//! API this file is written against, from the design:
//! - `fstp_domain::scoring::establish_quorum(&State, ProposalId, Stage,
//!   PlanVersionId, &FrozenPolicy, &Answers) -> Result<Quorum, Refusal>`,
//!   refusing a quorum below P-03 with rule `RuleRef::I07`;
//! - `fstp_domain::scoring::judge_stage1(Quorum, &State, &FrozenPolicy)
//!   -> Result<Stage1Verdict, Refusal>`, refusing with `RuleRef::I07`
//!   while an active assignee has no valid score (NOTE 3);
//! - `Quorum::keys(&self) -> &BTreeSet<ScoreKey>`;
//! - `CallState::frozen(&self, CallId) -> Option<&FrozenPolicy>`, read
//!   through `State::calls()`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::scoring::{ScoreKey, establish_quorum, judge_stage1};
use fstp_domain_testkit::r#gen::scores::{QuorumCase, Script};
use fstp_domain_testkit::reference::scoring::{i07_close_property, i07_property, plan_scorable};
use fstp_prop::check;

/// The production quorum of a case. On a plan the stage scores, a refusal
/// by I-07 is "no quorum". On a plan it does not score, such as the
/// submitted plan in stage 2, only an `Input` and `InvalidValue` refusal
/// is "no quorum" (NOTE 4). Any other refusal, including a stub's, is an
/// error of the run.
fn production(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let script: &Script = &case.script;
    let state = script.fold()?;
    let fx = &case.fixture;
    let policy = state
        .calls()
        .frozen(fx.call)
        .ok_or_else(|| "the call has no frozen policy".to_owned())?;
    let answers = script.no_conflict_answers(fx.proposal);
    let scorable = plan_scorable(&script.records(), fx.proposal, case.stage, case.plan);
    match establish_quorum(&state, fx.proposal, case.stage, case.plan, policy, &answers) {
        Ok(q) => Ok(Some(q.keys().clone())),
        Err(r)
            if scorable && r.rule == RuleRef::I07 && r.reason != RefusalReason::NotImplemented =>
        {
            Ok(None)
        }
        Err(r)
            if !scorable && r.rule == RuleRef::Input && r.reason == RefusalReason::InvalidValue =>
        {
            Ok(None)
        }
        Err(r) => Err(format!(
            "establish_quorum refused by another rule (plan scorable: {scorable}): {r}"
        )),
    }
}

/// I-07, NOTE 3, NOTE 4: the production quorum exists exactly when at
/// least P-03 valid scores exist, and counts exactly the valid keys.
/// P-03 runs from 1 to 4, with assignment sets below, at and above it.
/// Scenarios hold corrections, voids, declared and detected conflicts,
/// releases, reassignments, noise on a second proposal, conflict facts
/// that leave an assignment active, complaint remedy voids that leave an
/// assignment active, IRC and amendment assignments, assignments awaiting
/// declaration, keys on the other stage or of another proposal's
/// assignment, re-entry into a second call, stage 2 rescoring of up to
/// three revisions, and stage 2 quorums asked on the submitted plan.
#[test]
fn i07_quorum_counts_valid_scores_once() {
    check("i07_quorum_counts_valid_scores_once", |g| {
        i07_property(g, production)
    });
}

/// The production stage 1 close of a case on the submitted plan: the
/// quorum's keys when `judge_stage1` gives a verdict. A refusal by I-07
/// from either step is "no close". Any other refusal is an error.
fn production_close(case: &QuorumCase) -> Result<Option<BTreeSet<ScoreKey>>, String> {
    let script: &Script = &case.script;
    let state = script.fold()?;
    let fx = &case.fixture;
    let policy = state
        .calls()
        .frozen(fx.call)
        .ok_or_else(|| "the call has no frozen policy".to_owned())?;
    let answers = script.no_conflict_answers(fx.proposal);
    let no_close = |r: fstp_domain::refusal::Refusal| {
        if r.rule == RuleRef::I07 && r.reason != RefusalReason::NotImplemented {
            Ok(None)
        } else {
            Err(format!("the stage 1 close refused by another rule: {r}"))
        }
    };
    let quorum =
        match establish_quorum(&state, fx.proposal, case.stage, case.plan, policy, &answers) {
            Ok(q) => q,
            Err(r) => return no_close(r),
        };
    let keys = quorum.keys().clone();
    match judge_stage1(quorum, &state, policy) {
        Ok(_) => Ok(Some(keys)),
        Err(r) => no_close(r),
    }
}

/// I-07, NOTE 3: stage 1 closes on the submitted plan exactly when at
/// least P-03 valid scores exist and every active reviewer assignment of
/// the stage 1 call has a valid score. The same scenarios as above. After
/// a re-entry, stage 1 still counts the call it ran in (NOTE 8).
#[test]
fn i07_stage1_close_needs_every_active_assignee_scored() {
    check("i07_stage1_close_needs_every_active_assignee_scored", |g| {
        i07_close_property(g, production_close)
    });
}

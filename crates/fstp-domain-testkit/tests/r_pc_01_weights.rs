//! R-PC-01 pure test of production scoring over two programmes
//! (`docs/handoff/m2-design.md` section 6.2).
//!
//! R-PC-01 AC: two programmes with different P-01 weights produce
//! different weighted scores for identical reviewer inputs. The AC is
//! false for inputs whose criterion scores are all equal, so the generator
//! draws unequal criterion totals on the two criteria whose weights differ.
//!
//! Both programmes live in one tenant ledger. The state is built from raw
//! records with the public structural `apply` ([`Script::fold`]).
//!
//! API this file is written against, from the design (as in `i08_weighted_score.rs`):
//! `establish_quorum`, `weighted_score`, and
//! `CallState::frozen(&self, CallId) -> Option<&FrozenPolicy>` through `State::calls()`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::scoring::{Stage, establish_quorum, weighted_score};
use fstp_domain::state::State;
use fstp_domain_testkit::r#gen::scores::{Fixture, Script, TwoProgrammeCase, two_programme_script};
use fstp_domain_testkit::reference::scoring::r_pc_01_property;
use fstp_money::Ratio;
use fstp_prop::check;

/// The production weighted score of the fixture's proposal in stage 1.
fn score_of(state: &State, script: &Script, fx: &Fixture) -> Result<Ratio, String> {
    let policy = state
        .calls()
        .frozen(fx.call)
        .ok_or_else(|| format!("call {:?} has no frozen policy", fx.call))?;
    let answers = script.no_conflict_answers(fx.proposal);
    let quorum = establish_quorum(state, fx.proposal, Stage::One, fx.plan, policy, &answers)
        .map_err(|r| format!("establish_quorum refused: {r}"))?;
    Ok(weighted_score(&quorum, state, policy))
}

/// Production scores of programme A and programme B in one ledger.
fn production(case: &TwoProgrammeCase) -> Result<(Ratio, Ratio), String> {
    let (a, b, script) = two_programme_script(case)?;
    let state = script.fold()?;
    Ok((
        score_of(&state, &script, &a)?,
        score_of(&state, &script, &b)?,
    ))
}

/// R-PC-01: for discriminating inputs, the two programmes' different P-01
/// weights give different production scores, each equal to the reference.
#[test]
fn r_pc_01_weights_change_scores_for_discriminating_inputs() {
    check(
        "r_pc_01_weights_change_scores_for_discriminating_inputs",
        |g| r_pc_01_property(g, production),
    );
}

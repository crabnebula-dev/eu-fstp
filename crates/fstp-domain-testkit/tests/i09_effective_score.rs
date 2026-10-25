//! I-09 pure test of the production effective score
//! (`docs/handoff/m2-design.md` sections 2.9 and 6.2).
//!
//! I-09: after stage 2, the effective score follows P-24 and references
//! exactly one plan version. P-24 is "higher of original and revised".
//! NOTE 4: the latest scored revision counts, and on a tie the original
//! plan carries forward.
//!
//! API this file is written against:
//! - `fstp_domain::scoring::effective_score_of_revisions(EffectiveScoreRule,
//!   (PlanVersionId, Ratio), &[(PlanVersionId, Option<Ratio>)]) -> EffectiveScore`,
//!   which picks the latest scored revision in production;
//! - `EffectiveScore::plan(&self) -> PlanVersionId`,
//!   `EffectiveScore::value(&self) -> Ratio` and
//!   `EffectiveScore::basis(&self) -> Basis`.
//!
//! Open obligation for lanes L-LIFE and L-MONEY. Design section 6.2 also
//! asks that a later amendment never changes the effective score record.
//! The effective score is a pure value here, so this file cannot test it.
//! `i09_m_life_s2` must check it in the state after an amendment, and the
//! L-MONEY amendment tests must check that no amendment record touches it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::policy::EffectiveScoreRule;
use fstp_domain::scoring::effective_score_of_revisions;
use fstp_domain_testkit::r#gen::scores::EffectiveCase;
use fstp_domain_testkit::reference::scoring::{EffectiveOutcome, i09_property};
use fstp_prop::check;

/// The production effective score of a case, over all its revisions.
fn production(case: &EffectiveCase) -> Result<EffectiveOutcome, String> {
    let e = effective_score_of_revisions(
        EffectiveScoreRule::HigherOfOriginalAndRevised,
        case.original,
        &case.revisions,
    );
    Ok(EffectiveOutcome {
        plan: e.plan(),
        value: e.value(),
        basis: e.basis(),
    })
}

/// I-09, P-24, NOTE 4: with an original plan and zero to three revisions,
/// the effective score is the reference maximum and names the winning
/// plan. The original wins without a scored revision and on a tie.
#[test]
fn i09_effective_score_follows_p24_and_names_one_plan() {
    check("i09_effective_score_follows_p24_and_names_one_plan", |g| {
        i09_property(g, production)
    });
}

//! I-09 control: the P-24 reference and its predicate
//! (`docs/handoff/m2-design.md` section 6.2).
//!
//! The control passes the reference itself to the I-09 predicate, so the
//! property is shown to hold for a correct implementation. Hand cases
//! check the reference on the NOTE 4 rules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::num::NonZeroU64;

use fstp_domain::decision::Basis;
use fstp_domain::id::PlanVersionId;
use fstp_domain_testkit::r#gen::scores::EffectiveCase;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{
    EffectiveOutcome, effective_reference, i09_property, reference_effective,
};
use fstp_money::Ratio;
use fstp_prop::{Config, check, run};

/// I-09 control: the reference passes its own property.
#[test]
fn i09_control_reference_effective_passes() {
    check("i09_control_reference_effective_passes", |g| {
        i09_property(g, reference_effective)
    });
}

/// The ratio `num / den`.
fn ratio(num: u64, den: u64) -> Ratio {
    Ratio::new(num, NonZeroU64::new(den).unwrap())
}

/// Plan version `n`.
fn plan(n: u128) -> PlanVersionId {
    PlanVersionId::from_raw(n)
}

/// I-09, NOTE 4: without a scored revision, on a tie, and when the latest
/// scored revision is lower, the original plan carries forward. A higher
/// latest scored revision carries forward, even when an earlier revision
/// scored higher still.
#[test]
fn i09_reference_follows_note_4() {
    let original = (plan(1), ratio(3, 4));
    let effective = |revisions: Vec<(PlanVersionId, Option<Ratio>)>| {
        effective_reference(&EffectiveCase {
            original,
            revisions,
        })
        .unwrap()
    };
    let keeps_original = EffectiveOutcome {
        plan: plan(1),
        value: ratio(3, 4),
        basis: Basis::Original,
    };
    assert_eq!(effective(vec![]), keeps_original);
    assert_eq!(effective(vec![(plan(2), None)]), keeps_original);
    assert_eq!(
        effective(vec![(plan(2), Some(ratio(6, 8)))]),
        keeps_original
    );
    assert_eq!(
        effective(vec![(plan(2), Some(ratio(1, 2)))]),
        keeps_original
    );
    assert_eq!(
        effective(vec![
            (plan(2), Some(ratio(9, 10))),
            (plan(3), Some(ratio(4, 5))),
            (plan(4), None),
        ]),
        EffectiveOutcome {
            plan: plan(3),
            value: ratio(4, 5),
            basis: Basis::Revised,
        }
    );
}

/// A broken effective score: the latest scored revision wins ties.
fn revised_on_tie(case: &EffectiveCase) -> Result<EffectiveOutcome, String> {
    let (original, o) = case.original;
    let latest = case
        .revisions
        .iter()
        .rev()
        .find_map(|(p, s)| s.map(|s| (*p, s)));
    Ok(match latest {
        Some((p, r)) if r >= o => EffectiveOutcome {
            plan: p,
            value: r,
            basis: Basis::Revised,
        },
        _ => EffectiveOutcome {
            plan: original,
            value: o,
            basis: Basis::Original,
        },
    })
}

/// A broken effective score: the best revision wins, not the latest scored one.
fn best_revision(case: &EffectiveCase) -> Result<EffectiveOutcome, String> {
    let (original, o) = case.original;
    let mut out = EffectiveOutcome {
        plan: original,
        value: o,
        basis: Basis::Original,
    };
    for (p, s) in &case.revisions {
        if let Some(s) = s
            && *s > out.value
        {
            out = EffectiveOutcome {
                plan: *p,
                value: *s,
                basis: Basis::Revised,
            };
        }
    }
    Ok(out)
}

/// I-09, NOTE 4 teeth: an effective score that lets a tied revision carry
/// forward fails the I-09 property.
#[test]
fn i09_teeth_revised_on_tie_is_caught() {
    let outcome = run(
        "i09_teeth_revised_on_tie_is_caught",
        Config::default(),
        |g| i09_property(g, revised_on_tie),
    );
    expect_prop_failure(&outcome, "I-09").unwrap();
}

/// I-09, NOTE 4 teeth: an effective score that takes the best revision
/// instead of the latest scored one fails the I-09 property.
#[test]
fn i09_teeth_best_instead_of_latest_revision_is_caught() {
    let outcome = run(
        "i09_teeth_best_instead_of_latest_revision_is_caught",
        Config::default(),
        |g| i09_property(g, best_revision),
    );
    expect_prop_failure(&outcome, "I-09").unwrap();
}

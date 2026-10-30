//! Review reproducers for lane m4shapes (contract fidelity, TH-26,
//! ADR-006). Each test fails against the code under review and passes
//! once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{Shape, reply};
use fstp_api_core::views::{CriterionScore, RankingRow};
use fstp_json::{ToJson, Value};
use fstp_money::{Amount, Currency};

/// Whether `v` fits `s`, as the generated `fitsSchema` of
/// `web/src/gen/api.ts` judges it: objects are closed, and an amount is
/// an ADR-006 EUR string.
fn fits(s: &Shape, v: &Value) -> bool {
    match (s, v) {
        (Shape::String, Value::String(_)) | (Shape::Bool, Value::Bool(_)) => true,
        (Shape::Null, Value::Null) => true,
        (Shape::Id, Value::String(t)) => !t.is_empty(),
        (Shape::Amount, Value::String(t)) => Amount::parse(t, Currency::Eur).is_ok(),
        (Shape::Int, Value::Number(_)) => true,
        (Shape::Enum(values), Value::String(t)) => values.contains(&t.as_str()),
        (Shape::Array(items), Value::Array(a)) => a.into_iter().all(|x| fits(items, x)),
        (Shape::Nullable(_), Value::Null) => true,
        (Shape::Nullable(inner), other) => fits(inner, other),
        (Shape::Object(members), Value::Object(o)) => {
            o.keys().all(|k| members.iter().any(|m| m.name == k))
                && members.iter().all(|m| match o.get(m.name) {
                    Some(x) => fits(&m.shape, x),
                    None => m.optional,
                })
        }
        _ => false,
    }
}

/// R-EV-08, ADR-006, TH-26: a call can be over-nominated, so the domain's
/// remaining budget is signed (`fstp_domain::record`, "signed because a
/// call can be over-nominated"). Dispatch spells it with
/// `Amount::to_string`, which writes a leading minus. That text is no
/// ADR-006 amount, so the served `committee.ranking` row escapes its
/// reply shape and the generated validator refuses it.
#[test]
fn review_ranking_over_nominated_remaining_budget_fits_its_shape() {
    // Budget 1000.00 with 1500.00 committed, as `ranking_view` subtracts.
    let budget = Amount::from_minor(100_000, Currency::Eur).unwrap();
    let committed = Amount::from_minor(150_000, Currency::Eur).unwrap();
    let remaining = budget.checked_sub(committed).unwrap();
    let row = RankingRow::Ranked {
        proposal: 1001,
        title: None,
        neutral_summary: None,
        rationale: None,
        effective: "80.00".to_owned(),
        criterion_scores: vec![CriterionScore {
            criterion: 1,
            weighted: "4.00".to_owned(),
        }],
        requested: "500.00".to_owned(),
        // The spelling `dispatch::ranking` uses.
        remaining_budget: remaining.to_string(),
    };
    let reply_value = Value::Array(vec![row.to_json()].into_iter().collect());
    let shape = reply("committee.ranking").expect("REPLIES has committee.ranking");
    let text = fstp_json::to_canonical(&reply_value).unwrap_or_default();
    assert!(
        fits(shape, &reply_value),
        "served committee.ranking does not fit its shape: {text}"
    );
}

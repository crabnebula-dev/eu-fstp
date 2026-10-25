//! Every rule reference of the interface names an identifier that exists in `SPEC/` (step W1c).

mod support;

use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Guard, ParamId, TRANSITIONS};

use support::{contains_token, read_all_spec};

/// The marker that defines `id` in the spec: bold for invariants, SoD rules
/// and requirements, a table row for parameters.
fn definition(id: &str) -> String {
    if id.starts_with("P-") {
        format!("| {id} |")
    } else {
        format!("**{id}**")
    }
}

/// Every `RuleRef` with a spec id, including one per parameter and every
/// guard's rule, names an identifier that `SPEC/` both mentions and defines.
/// The non-spec variants name none.
#[test]
fn spec_rule_refs_exist() {
    let spec = match read_all_spec() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };

    let mut refs: Vec<RuleRef> = RuleRef::ALL_FIXED.to_vec();
    refs.extend(ParamId::ALL.iter().map(|p| RuleRef::Param(*p)));
    for rule in TRANSITIONS {
        refs.extend(rule.guards.iter().map(|g: &Guard| g.rule()));
    }

    let mut checked = 0usize;
    for r in refs {
        match r.spec_id() {
            Some(id) => {
                assert!(
                    contains_token(&spec, id),
                    "{r:?} names {id}, which SPEC/ never mentions"
                );
                assert!(
                    spec.contains(&definition(id)),
                    "{r:?} names {id}, which SPEC/ never defines"
                );
                checked = checked.saturating_add(1);
            }
            None => assert!(
                matches!(
                    r,
                    RuleRef::Row
                        | RuleRef::Actor
                        | RuleRef::FactsIncomplete
                        | RuleRef::StaleFacts
                        | RuleRef::OracleDown
                        | RuleRef::Ledger
                        | RuleRef::Input
                        | RuleRef::NotImplemented
                ),
                "{r:?} has no spec id but is not a non-spec variant"
            ),
        }
    }
    assert!(
        checked > ParamId::ALL.len(),
        "too few spec ids were checked"
    );
}

/// The token matcher does not accept a prefix of a longer identifier, so
/// `I-1` never matches inside `I-10` and `P-0` never matches inside `P-01`.
#[test]
fn spec_rule_refs_token_match_is_exact() {
    assert!(contains_token("see I-10.", "I-10"));
    assert!(!contains_token("see I-10.", "I-1"));
    assert!(!contains_token("SoD-091", "SoD-09"));
    assert!(!contains_token("XI-01", "I-01"));
    assert!(!contains_token("R-I-01", "I-01"));
}

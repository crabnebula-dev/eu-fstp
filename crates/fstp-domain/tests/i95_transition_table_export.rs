//! I-95, R-JV-02: the exported transition table and state enum can carry one journey edge per row.
//!
//! The journey drift test (`SPEC/12-journey-ui.md` section 13) compares a
//! journey definition with `fstp_domain::rules::TRANSITIONS` and
//! `StateTag::ALL`. Its edge ids are `T-<FROM>-<TO>`, and its WITHDRAWN rule
//! stands for "any non-terminal state before GRANTED". These tests pin the
//! table properties that mapping rests on. They run against the public
//! data only and change no domain behaviour.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::rules::{Row, StateTag, TRANSITIONS};

/// I-95: each row appears exactly once, and the table has the 21 rows of
/// the split transitions table.
#[test]
fn i95_each_row_appears_once_in_the_exported_table() {
    let mut seen = BTreeSet::new();
    for rule in TRANSITIONS {
        assert!(seen.insert(rule.row), "I-95: row {:?} twice", rule.row);
    }
    assert_eq!(TRANSITIONS.len(), 21, "I-95: rows of the split table");
}

/// I-95: no two (from, to) pairs repeat, so `T-<FROM>-<TO>` maps the edges
/// one to one to the rows.
#[test]
fn i95_edge_endpoints_map_one_to_one_to_rows() {
    let mut by_pair: BTreeMap<(StateTag, StateTag), Row> = BTreeMap::new();
    for rule in TRANSITIONS.iter().filter(|r| r.row != Row::Withdraw) {
        assert_eq!(
            rule.from.len(),
            1,
            "I-95: row {:?} has one source",
            rule.row
        );
        for from in rule.from {
            if let Some(other) = by_pair.insert((*from, rule.to), rule.row) {
                panic!("I-95: rows {other:?} and {:?} share endpoints", rule.row);
            }
        }
    }
    assert_eq!(
        by_pair.len(),
        20,
        "I-95: one edge per row besides WITHDRAWN"
    );
}

/// I-95, NOTE 10: the WITHDRAWN row is the only row with several sources.
/// Its sources are the non-terminal states that GRANTED cannot reach, as
/// "any non-terminal state before GRANTED" reads on the table itself.
#[test]
fn i95_withdraw_row_is_any_nonterminal_state_before_granted() {
    let withdraw: Vec<_> = TRANSITIONS
        .iter()
        .filter(|r| r.row == Row::Withdraw)
        .collect();
    assert_eq!(withdraw.len(), 1, "I-95: one WITHDRAWN row");
    let rule = withdraw.first().unwrap();
    assert_eq!(rule.to, StateTag::Withdrawn, "I-95: WITHDRAWN row target");

    let mut after = BTreeSet::from([StateTag::Granted]);
    let mut queue = vec![StateTag::Granted];
    while let Some(at) = queue.pop() {
        for r in TRANSITIONS.iter().filter(|r| r.row != Row::Withdraw) {
            if r.from.contains(&at) && after.insert(r.to) {
                queue.push(r.to);
            }
        }
    }
    let before: BTreeSet<StateTag> = StateTag::ALL
        .into_iter()
        .filter(|s| !s.is_terminal() && !after.contains(s))
        .collect();
    let sources: BTreeSet<StateTag> = rule.from.iter().copied().collect();
    assert_eq!(sources, before, "I-95: WITHDRAWN sources");
    assert_eq!(
        sources,
        StateTag::WITHDRAWABLE.into_iter().collect(),
        "I-95: WITHDRAWABLE"
    );
}

/// I-95, R-JV-01: the exported state enum has 16 states with distinct
/// formal names, and every row names only those states.
#[test]
fn i95_state_enum_names_sixteen_distinct_states() {
    let names: BTreeSet<&str> = StateTag::ALL.iter().map(|s| s.spec_name()).collect();
    assert_eq!(names.len(), 16, "I-95: {names:?}");
    for rule in TRANSITIONS {
        assert!(StateTag::ALL.contains(&rule.to), "I-95: {:?}", rule.row);
        for from in rule.from {
            assert!(StateTag::ALL.contains(from), "I-95: {:?}", rule.row);
        }
    }
}

//! NOTE 11: GRANTED to IN_EXECUTION is the System's at the earliest milestone start date of the effective contract version (decided 2026-10-25, Q18 B).
//!
//! Lead c's plan has two milestones that start one and two days after the
//! evaluation instant. The proposal is granted from genesis by production
//! commands. `StartExecution` is refused before the earlier start date,
//! including one microsecond before it, and accepted from it. A named
//! account cannot start execution, because the row is a timer row that
//! the System records (NOTE 13).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyDraft, MoneySetup, MoneyStory, PC, T_EVAL, milestone_n, start_execution,
};
use fstp_domain_testkit::r#gen::review::after;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

const DAY: i64 = 86_400_000_000;

fn first_start() -> Timestamp {
    after(T_EVAL, DAY)
}

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts = vec![MoneyDraft {
        lead: LC,
        proposal: PC,
        minor: false,
        milestones: vec![
            (
                milestone_n(PC, 0),
                200,
                after(T_EVAL, DAY.saturating_mul(2)),
            ),
            (milestone_n(PC, 1), 200, first_start()),
        ],
        negotiate: true,
    }];
    s
}

fn story(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.grant(PC).unwrap_or_else(|e| panic!("c is granted: {e}"));
    s.refused(&start_execution(PC))
        .unwrap_or_else(|e| panic!("NOTE 11: no milestone has started yet: {e}"));
    s.at(after(first_start(), -1));
    s.refused(&start_execution(PC))
        .unwrap_or_else(|e| panic!("NOTE 11: one microsecond before the earliest start: {e}"));
    s.at(first_start());
    let mut by_pm = start_execution(PC);
    by_pm.actor = Actor::Account(STAFF_PM);
    s.refused(&by_pm)
        .unwrap_or_else(|e| panic!("NOTE 13: the System records GRANTED to IN_EXECUTION: {e}"));
    let recs = s
        .run(&start_execution(PC))
        .unwrap_or_else(|e| panic!("NOTE 11: the earliest start date is reached: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::InExecution));
    assert!(recs.iter().any(|r| matches!(
        r,
        fstp_domain::record::Record::Transitioned(t) if t.row == Row::GrantedToInExecution
    )));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// NOTE 11, R-EX-01: execution starts at the earliest milestone start date.
#[test]
fn r_ex_start_execution_at_earliest_milestone_start() {
    story(Backend::Production);
}

/// NOTE 11: the story passes on the references alone.
#[test]
fn r_ex_start_execution_story_passes_on_the_reference() {
    story(Backend::Reference);
}

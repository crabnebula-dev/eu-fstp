//! GRANTED to TERMINATED and IN_EXECUTION to TERMINATED are the programme manager's, with a reason (state-machine.md, Q18, decided 2026-10-25).
//!
//! Lead c is granted from genesis by production commands. The lead, a
//! reviewer and the System cannot terminate. The programme manager
//! terminates from GRANTED, or from IN_EXECUTION after execution starts.
//! TERMINATED is terminal, so execution cannot start afterwards.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, start_execution, terminate,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    s
}

fn story(b: Backend, started: bool) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.grant(PC).unwrap_or_else(|e| panic!("c is granted: {e}"));
    if started {
        s.run(&start_execution(PC))
            .unwrap_or_else(|e| panic!("NOTE 11: {e}"));
    }
    for actor in [
        Actor::Account(LC),
        Actor::Account(R1),
        Actor::System(SystemCause::Timeline),
    ] {
        let mut st = terminate(STAFF_PM, PC);
        st.actor = actor;
        s.refused(&st).unwrap_or_else(|e| {
            panic!("only the programme manager terminates, not {actor:?}: {e}")
        });
    }
    let recs = s
        .run(&terminate(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager terminates with a reason: {e}"));
    let row = if started {
        Row::InExecutionToTerminated
    } else {
        Row::GrantedToTerminated
    };
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::Transitioned(t) if t.row == row))
    );
    assert!(
        recs.iter()
            .any(|r| matches!(r, Record::TerminationRecorded { .. }))
    );
    assert_eq!(s.state(PC), Some(StateTag::Terminated));
    s.refused(&start_execution(PC))
        .unwrap_or_else(|e| panic!("TERMINATED is terminal: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// Q18: GRANTED to TERMINATED by the programme manager with a reason.
#[test]
fn r_ex_terminate_from_granted_by_programme_manager() {
    story(Backend::Production, false);
}

/// Q18: IN_EXECUTION to TERMINATED by the programme manager with a reason.
#[test]
fn r_ex_terminate_from_in_execution_by_programme_manager() {
    story(Backend::Production, true);
}

/// Q18: the termination stories pass on the references alone.
#[test]
fn r_ex_terminate_stories_pass_on_the_reference() {
    story(Backend::Reference, false);
    story(Backend::Reference, true);
}

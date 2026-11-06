//! State-machine NOTE 11 and NOTE 12, M5 design section 4.2: the sweep
//! issues `StartExecution` and `Complete` when `fstp_domain::due` lists
//! them, beside its D13 kinds.
//!
//! From genesis by production commands, lead c is granted 4.00 over two
//! milestones that start at `T0`. The sweep then issues `StartExecution`.
//! Once the programme manager closes both milestones and no payment
//! request is open, it issues `Complete`, and the System's run of each
//! takes the grant to IN_EXECUTION and COMPLETED.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Command as CoreCommand;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    MoneyWorld, PC, close_milestone, complete, milestone_n, start_execution,
};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};
use fstp_domain_testkit::mc::money_model::{Fact, McAction, McState, run_action};
use fstp_domain_testkit::mc::pay_model::pay_setup;
use fstp_engine::{Command, EngineState, FindingStore, sweep};

fn granted() -> MoneyWorld {
    let mut s = McState {
        world: pay_setup().world(Backend::Production).unwrap(),
        edited: false,
        cap_blocked: false,
        grant_blocked: false,
        superseded: false,
        contract_cleared: false,
        deliverables: 0,
        divergence: None,
    };
    for a in [
        McAction::Determine(PC, 0),
        McAction::Grant(PC, Fact::Contract),
    ] {
        s = run_action(&s, &a).unwrap_or_else(|| panic!("{a:?} was refused"));
        assert_eq!(s.divergence, None);
    }
    s.world
}

fn swept(w: &MoneyWorld) -> Vec<CoreCommand> {
    let state = EngineState::new(w.life.rev.sod.state.clone(), FindingStore::genesis());
    sweep::due(&state, w.now())
        .unwrap()
        .into_iter()
        .filter_map(|c| match c {
            Command::Core(c) => Some(c),
            _ => None,
        })
        .collect()
}

/// NOTE 11, NOTE 12: the sweep issues `StartExecution` for a granted grant
/// whose first milestone has started, and `Complete` once every milestone
/// is closed and no request is open.
#[test]
fn r_ex_sweep_issues_start_execution_and_complete_when_due() {
    let mut w = granted();
    assert_eq!(w.state(PC), Some(StateTag::Granted));
    assert_eq!(
        swept(&w),
        vec![CoreCommand::StartExecution { proposal: PC }],
        "NOTE 11"
    );
    w = w.must(&start_execution(PC)).unwrap();
    assert_eq!(w.state(PC), Some(StateTag::InExecution));
    assert!(
        swept(&w).is_empty(),
        "nothing is due while a milestone is open"
    );
    for n in [0, 1] {
        w = w
            .must(&close_milestone(STAFF_PM, PC, milestone_n(PC, n)).unwrap())
            .unwrap();
    }
    assert_eq!(
        swept(&w),
        vec![CoreCommand::Complete { proposal: PC }],
        "NOTE 12"
    );
    w = w.must(&complete(PC)).unwrap();
    assert_eq!(w.state(PC), Some(StateTag::Completed));
    assert!(swept(&w).is_empty());
}

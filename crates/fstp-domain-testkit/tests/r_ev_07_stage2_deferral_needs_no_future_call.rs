//! R-EV-07: a proposal without stage 2 answers within P-07 moves to the next call, with no future-call guard (NOTE 5).
//!
//! The model check runs M-LIFECYCLE from DRAFT, built from genesis. Its
//! transition property says that STAGE2 to DEFERRED happens only once P-07
//! elapsed without answers. Its witnesses are a deferral while no later
//! call is published, and a re-entry into STAGE2 once one is.
//!
//! The story checks `due` (design 3.6): it lists `ExpireStage2` from the
//! window's close and not one microsecond before, with no later call
//! published. A STAGE2 deferral then waits, and `due` lists `ReEnter` once
//! the next call is published and open.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2};
use fstp_domain_testkit::r#gen::roster::{Backend, call, publish};
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::{
    LifeModel, Story, expire, life_judges, reenter, story_setup,
};
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_STATES, lifecycle_config, r_ev_07_properties,
};

fn model(backend: Backend) {
    let model = LifeModel::new(lifecycle_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &r_ev_07_properties::<LifeModel>(),
        M_LIFECYCLE_STATES,
    ) {
        panic!("{e}");
    }
}

/// R-EV-07, NOTE 4, NOTE 5: STAGE2 to DEFERRED needs P-07 elapsed without
/// answers, and no future call.
#[test]
fn r_ev_07_stage2_deferral_needs_no_future_call() {
    model(Backend::Production);
}

/// R-EV-07: the model passes on the references alone.
#[test]
fn r_ev_07_stage2_deferral_needs_no_future_call_reference() {
    model(Backend::Reference);
}

fn due(s: &Story, now: fstp_domain::time::Timestamp) -> Vec<Command> {
    fstp_domain::due(&s.world.rev.sod.state, now)
}

/// R-EV-07, NOTE 5, NOTE 8, design 3.6: `due` lists the expiry from the
/// window's close, the deferral needs no future call, and `due` lists the
/// re-entry once the next call is published.
#[test]
fn r_ev_07_due_lists_expiry_and_reentry() {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    let end = s.world.life.window_end(PR1).unwrap();
    let before = fstp_domain::time::Timestamp::from_micros(end.micros().saturating_sub(1));
    let expiry = Command::ExpireStage2 { proposal: PR1 };
    assert!(
        !due(&s, before).contains(&expiry),
        "R-EV-07: the window is still open one microsecond before its close"
    );
    assert!(
        due(&s, end).contains(&expiry),
        "R-EV-07: due lists the expiry at the window's close"
    );
    s.at(end);
    s.run(&expire(PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
    assert!(
        due(&s, end)
            .iter()
            .all(|c| !matches!(c, Command::ReEnter { .. })),
        "NOTE 5: with no next call the deferred proposal waits"
    );
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let entry = Command::ReEnter {
        proposal: PR1,
        call: call(2),
    };
    assert!(
        due(&s, end).contains(&entry),
        "NOTE 8: due lists the re-entry once the next call is published and open"
    );
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
}

//! R-EV-07, NOTE 8, I-36: a STAGE2 deferral re-enters only once the next call has opened, and never while a former reviewer receives there.
//!
//! The stories run production commands from genesis and compare every step
//! with the lifecycle reference in both directions. Call 2 is drafted with
//! its own opening and deadline, so the clock can sit on either side of
//! the opening after the deferral.
//!
//! - NOTE 8: `ReEnter` is refused one microsecond before call 2 opens,
//!   and `due` does not list it. From the opening, `due` lists it and it
//!   takes PR1 back to STAGE2.
//! - I-36 "including after deferral": R3 reviewed PR1 in call 1, ended its
//!   committee binding and drafted a proposal in call 2 while PR1 was still
//!   in STAGE2 of call 1. After PR1 defers, its re-entry into call 2 is
//!   refused while R3 holds that Receiving binding. Once R3 withdraws its
//!   draft, PR1 re-enters.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2, R3, judge_binding, withdraw};
use fstp_domain_testkit::r#gen::roster::{Backend, call, draft, end, publish};
use fstp_domain_testkit::mc::life_model::{
    LifeWorld, Story, expire, life_judges, reenter, story_setup,
};

/// The opening of call 2 in the first story: after PR1's stage 2 window closes.
const OPENS_2: Timestamp = Timestamp::from_micros(7_000_000_000_000);
/// The deadline of call 2 in both stories: after every command.
const DEADLINE_2: Timestamp = Timestamp::from_micros(9_000_000_000_000);

/// The story with PR1 by L1 in call 1, and call 2 drafted to open at `opens`.
fn story(backend: Backend, opens: Timestamp) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut steps = setup.draft_steps().unwrap_or_else(|e| panic!("{e}"));
    for s in &mut steps {
        if let Command::DraftCall {
            call: c,
            opens: o,
            deadline,
            ..
        } = &mut s.cmd
            && *c == call(2)
        {
            *o = opens;
            *deadline = DEADLINE_2;
        }
    }
    let world = LifeWorld::from_steps(backend, setup.truth(), &steps)
        .unwrap_or_else(|e| panic!("genesis: {e}"));
    Story { world }
}

/// Whether production's `due` lists PR1's re-entry into call 2 at `now`.
/// On the references alone the production projection is not kept, so the
/// question is answered there as the expected value.
fn reentry_listed(s: &Story, now: Timestamp, expected: bool) -> bool {
    if s.world.backend() == Backend::Reference {
        return expected;
    }
    fstp_domain::due(&s.world.rev.sod.state, now).contains(&Command::ReEnter {
        proposal: PR1,
        call: call(2),
    })
}

/// Runs PR1 to STAGE2 with `reviewers`, then lets the window close and defers it.
fn deferred(s: &mut Story, reviewers: &[fstp_domain::id::AccountId], publish_first: bool) {
    let vectors: Vec<Vec<u8>> = reviewers.iter().map(|_| vec![2, 1]).collect();
    s.closed(L1, PR1, reviewers, &vectors)
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    if publish_first {
        s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    }
}

fn expire_now(s: &mut Story) {
    let end = s.world.life.window_end(PR1).unwrap();
    s.at(end);
    s.run(&expire(PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
}

fn r_ev_07_reentry_waits_for_the_next_call_to_open_on(b: Backend) {
    let mut s = story(b, OPENS_2);
    deferred(&mut s, &[R1, R2], true);
    expire_now(&mut s);
    assert!(
        s.world.now() < OPENS_2,
        "the setup defers PR1 before call 2 opens"
    );
    let before = Timestamp::from_micros(OPENS_2.micros().saturating_sub(1));
    s.at(before);
    assert!(
        !reentry_listed(&s, before, false),
        "NOTE 8: due lists no re-entry one microsecond before call 2 opens"
    );
    let early = s
        .attempt(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        early.is_none(),
        "NOTE 8: re-entry one microsecond before call 2 opens"
    );
    s.at(OPENS_2);
    assert!(
        reentry_listed(&s, OPENS_2, true),
        "NOTE 8: due lists the re-entry once call 2 opens"
    );
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("NOTE 8: re-entry at the opening of call 2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
}

fn i36_reentry_waits_while_a_former_reviewer_receives_on(b: Backend) {
    let mut s = story(b, Timestamp::from_micros(0));
    deferred(&mut s, &[R1, R2, R3], false);
    let now = s.world.now();
    s.run(&end(judge_binding(3), now))
        .unwrap_or_else(|e| panic!("R3's committee binding ends: {e}"));
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let other = ProposalId::from_raw(9_601);
    s.run(&draft(
        R3,
        other,
        call(2),
        BindingId::from_raw(9_601),
        false,
    ))
    .unwrap_or_else(|e| {
        panic!("I-36: R3 may draft in call 2 while PR1 is evaluated in call 1: {e}")
    });
    expire_now(&mut s);
    let now = s.world.now();
    assert!(
        !reentry_listed(&s, now, false),
        "I-36: due lists no re-entry while a former reviewer receives in call 2"
    );
    let barred = s
        .attempt(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        barred.is_none(),
        "I-36: PR1 re-entered call 2 while its former reviewer R3 holds a Receiving binding there"
    );
    s.run(&withdraw(R3, other))
        .unwrap_or_else(|e| panic!("R3 withdraws its draft: {e}"));
    assert!(
        reentry_listed(&s, now, true),
        "NOTE 8: due lists the re-entry once no former reviewer receives in call 2"
    );
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("NOTE 8: re-entry after the withdrawal: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
}

/// R-EV-07, NOTE 8, design 6.1: re-entry waits for the opening of the next
/// call, one microsecond before it and at it.
#[test]
fn r_ev_07_reentry_waits_for_the_next_call_to_open() {
    r_ev_07_reentry_waits_for_the_next_call_to_open_on(Backend::Production);
}

/// I-36, NOTE 8: re-entry is refused while a former reviewer holds a
/// Receiving binding in the next call, including after deferral.
#[test]
fn i36_reentry_waits_while_a_former_reviewer_receives() {
    i36_reentry_waits_while_a_former_reviewer_receives_on(Backend::Production);
}

/// R-EV-07, I-36: the stories above pass on the references alone.
#[test]
fn r_ev_07_reentry_stories_pass_on_the_reference() {
    r_ev_07_reentry_waits_for_the_next_call_to_open_on(Backend::Reference);
    i36_reentry_waits_while_a_former_reviewer_receives_on(Backend::Reference);
}

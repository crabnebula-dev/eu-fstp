//! D13, R-EV-07, NOTE 5, NOTE 8: the minimal deadline sweep of M4 cells (M4 design section 3.4).
//!
//! `fstp_engine::sweep::due` is a pure function from the engine state and
//! `now` to the due System commands. It issues `ExpireStage2` at the P-07
//! deadline and `ReEnter` once a next call is open. The cell runs it on
//! its clock as `Actor::System`, because nothing else issues these kinds
//! in an M4 cell. M6's timeline engine replaces it.
//!
//! The stories run production commands from genesis through the L-LIFE
//! world and compare every step with the lifecycle reference in both
//! directions. The sweep reads an engine state built from the world's core
//! projection and an empty finding store, as a cell's snapshot holds it.
//! Each command the sweep issues then runs as a System step, so the tests
//! also check that the System may issue it at that instant.
//!
//! Status: red while the W0 stub of `sweep::due` refuses with
//! `SweepError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command as CoreCommand;
use fstp_domain::id::ProposalId;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2};
use fstp_domain_testkit::r#gen::roster::{Backend, call, publish};
use fstp_domain_testkit::mc::life_model::{LifeWorld, Story, life_judges, story_setup, system};
use fstp_engine::{Command, EngineState, FindingStore, sweep};

/// The opening of call 2 in the re-entry story: after PR1's stage 2 window closes.
const OPENS_2: Timestamp = Timestamp::from_micros(7_000_000_000_000);
/// The deadline of call 2 in the re-entry story: after every command.
const DEADLINE_2: Timestamp = Timestamp::from_micros(9_000_000_000_000);

/// The engine state a cell's sweep reads for the story's current world.
fn engine_state(s: &Story) -> EngineState {
    EngineState::new(s.world.rev.sod.state.clone(), FindingStore::genesis())
}

/// The commands the sweep issues at `now`. The design makes the sweep
/// total, so any refusal fails the test.
fn sweep_at(s: &Story, now: Timestamp) -> Vec<Command> {
    match sweep::due(&engine_state(s), now) {
        Ok(cmds) => cmds,
        Err(e) => panic!("D13: the sweep refused at {now:?}: {e:?}"),
    }
}

/// The core command inside an engine command the sweep issued.
fn core_of(cmd: &Command) -> &CoreCommand {
    match cmd {
        Command::Core(c) => c,
        other => panic!("D13: the sweep issued a non-core command {other:?}"),
    }
}

fn expiry(proposal: ProposalId) -> Command {
    Command::Core(CoreCommand::ExpireStage2 { proposal })
}

fn reentry(proposal: ProposalId, into: u128) -> Command {
    Command::Core(CoreCommand::ReEnter {
        proposal,
        call: call(into),
    })
}

/// Runs every command the sweep issues at `now` as a System step at `now`.
fn run_sweep(s: &mut Story, now: Timestamp) {
    let cmds = sweep_at(s, now);
    s.at(now);
    for cmd in &cmds {
        s.run(&system(core_of(cmd).clone()))
            .unwrap_or_else(|e| panic!("D13: the System may issue {cmd:?} at {now:?}: {e}"));
    }
}

/// PR1 by L1 in call 1, at STAGE2 after a stage 1 close with R1 and R2.
/// Call 2 is drafted and approved but not published.
fn stage2_story() -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    s
}

/// [`stage2_story`] with call 2 drafted to open at [`OPENS_2`] and then
/// published, before PR1's stage 2 window closes.
fn reentry_story() -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut steps = setup.draft_steps().unwrap_or_else(|e| panic!("{e}"));
    for st in &mut steps {
        if let CoreCommand::DraftCall {
            call: c,
            opens,
            deadline,
            ..
        } = &mut st.cmd
            && *c == call(2)
        {
            *opens = OPENS_2;
            *deadline = DEADLINE_2;
        }
    }
    let world = LifeWorld::from_steps(Backend::Production, setup.truth(), &steps)
        .unwrap_or_else(|e| panic!("genesis: {e}"));
    let mut s = Story { world };
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR1 to STAGE2: {e}"));
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    s
}

fn micro_before(t: Timestamp) -> Timestamp {
    Timestamp::from_micros(t.micros().saturating_sub(1))
}

/// D13, R-EV-07: the sweep issues `ExpireStage2` from the P-07 deadline
/// and not one microsecond before. The System's expiry moves PR1 to
/// DEFERRED, and the sweep then issues it no more.
#[test]
fn d13_sweep_expires_stage2_at_p07() {
    let mut s = stage2_story();
    let end = s.world.life.window_end(PR1).unwrap();
    assert!(
        !sweep_at(&s, micro_before(end)).contains(&expiry(PR1)),
        "R-EV-07: the stage 2 window is open one microsecond before P-07 ends"
    );
    assert!(
        sweep_at(&s, end).contains(&expiry(PR1)),
        "R-EV-07: the sweep issues the expiry at the P-07 deadline"
    );
    run_sweep(&mut s, end);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Deferred),
        "R-EV-07: the swept expiry defers PR1"
    );
    assert!(
        !sweep_at(&s, end).contains(&expiry(PR1)),
        "D13: an applied expiry is not issued again"
    );
}

/// D13, R-EV-07, NOTE 5: a deferral needs no next call, and with no next
/// call published the sweep issues no re-entry. Once call 2 is published
/// and open, the sweep issues the re-entry and the System's `ReEnter`
/// takes PR1 back to STAGE2.
#[test]
fn d13_sweep_waits_for_a_published_next_call() {
    let mut s = stage2_story();
    let end = s.world.life.window_end(PR1).unwrap();
    run_sweep(&mut s, end);
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
    assert!(
        sweep_at(&s, end)
            .iter()
            .all(|c| !matches!(core_of(c), CoreCommand::ReEnter { .. })),
        "NOTE 5: with no next call published the deferred proposal waits"
    );
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let now = s.world.now();
    assert!(
        sweep_at(&s, now).contains(&reentry(PR1, 2)),
        "NOTE 8: the sweep issues the re-entry once call 2 is published and open"
    );
    run_sweep(&mut s, now);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Stage2),
        "R-EV-07: the swept re-entry takes PR1 back to STAGE2"
    );
}

/// D13, R-EV-07, NOTE 8: a published next call that has not opened yet
/// gets no re-entry. One microsecond before call 2 opens the sweep issues
/// none, and from the opening it issues the re-entry into call 2.
#[test]
fn d13_sweep_reenters_when_the_next_call_opens() {
    let mut s = reentry_story();
    let end = s.world.life.window_end(PR1).unwrap();
    assert!(end < OPENS_2, "the story defers PR1 before call 2 opens");
    run_sweep(&mut s, end);
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
    assert!(
        !sweep_at(&s, micro_before(OPENS_2)).contains(&reentry(PR1, 2)),
        "NOTE 8: no re-entry one microsecond before call 2 opens"
    );
    assert!(
        sweep_at(&s, OPENS_2).contains(&reentry(PR1, 2)),
        "NOTE 8: the sweep issues the re-entry when call 2 opens"
    );
    run_sweep(&mut s, OPENS_2);
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
}

/// Checks that the sweep at `now` issues only `ExpireStage2` and `ReEnter`,
/// each one a command the domain lists as due at `now`. Every due expiry
/// is issued, and a proposal with a due re-entry gets exactly one.
fn agrees_with_domain_due(s: &Story, now: Timestamp) {
    let swept = sweep_at(s, now);
    let due: Vec<CoreCommand> = fstp_domain::due(&s.world.rev.sod.state, now);
    for cmd in &swept {
        let c = core_of(cmd);
        assert!(
            matches!(
                c,
                CoreCommand::ExpireStage2 { .. } | CoreCommand::ReEnter { .. }
            ),
            "D13: the sweep issues only ExpireStage2 and ReEnter, not {c:?}"
        );
        assert!(
            due.contains(c),
            "D13: the sweep issued {c:?} at {now:?}, which is not due"
        );
    }
    for c in &due {
        match c {
            CoreCommand::ExpireStage2 { .. } => assert!(
                swept.contains(&Command::Core(c.clone())),
                "R-EV-07: the due {c:?} is missing from the sweep at {now:?}"
            ),
            CoreCommand::ReEnter { proposal, .. } => {
                let issued = swept
                    .iter()
                    .filter(|x| {
                        matches!(core_of(x), CoreCommand::ReEnter { proposal: p, .. } if p == proposal)
                    })
                    .count();
                assert_eq!(
                    issued, 1,
                    "NOTE 8: one re-entry of {proposal:?} at {now:?}, found {issued}"
                );
            }
            _ => {}
        }
    }
}

/// D13, R-EV-07: at every instant of both stories, before and at the P-07
/// deadline, after the deferral, and around the opening of call 2, the
/// sweep agrees with the domain's due System commands on its two kinds.
#[test]
fn d13_sweep_agrees_with_domain_due_on_its_two_kinds() {
    let mut s = stage2_story();
    let end = s.world.life.window_end(PR1).unwrap();
    for t in [s.world.now(), micro_before(end), end] {
        agrees_with_domain_due(&s, t);
    }
    run_sweep(&mut s, end);
    agrees_with_domain_due(&s, end);
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    agrees_with_domain_due(&s, s.world.now());

    let mut r = reentry_story();
    let end = r.world.life.window_end(PR1).unwrap();
    run_sweep(&mut r, end);
    for t in [end, micro_before(OPENS_2), OPENS_2, DEADLINE_2] {
        agrees_with_domain_due(&r, t);
    }
}

/// D13: the sweep over the empty engine state issues nothing.
#[test]
fn d13_sweep_of_genesis_issues_nothing() {
    for now in [0, 1, i64::MAX] {
        let r = sweep::due(&EngineState::genesis(), Timestamp::from_micros(now));
        assert_eq!(r, Ok(Vec::new()), "D13: genesis at {now}");
    }
}

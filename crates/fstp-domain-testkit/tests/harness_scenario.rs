//! Self-tests of the scenario builder (`docs/handoff/m2-design.md` section 6.1).
//!
//! `Scenario` builds every mid-lifecycle start state by running production
//! commands through the reference driver from an empty ledger, over a
//! synthetic vault. No model starts from a hand-built state. The scenario
//! also collects the instants of the reduced clock.
//!
//! Only the parts that need no domain lane are tested here. These
//! self-tests are deferred to the lanes that make them possible:
//! - a scenario from genesis reaches a published call (L-POL);
//! - a vault change and its `VaultChanged` run in one scenario step (L-SOD);
//! - a scenario from genesis reaches STAGE2 and NEGOTIATION (L-LIFE);
//! - every state a scenario reaches equals the replay of its ledger, over
//!   accepted commands (L-POL first).
//!
//! API this file is written against, in `fstp_domain_testkit::scenario`:
//! `Scenario::new(truth)`, `execute(cmd, ctx)`, `state()`, `entries()`,
//! `mark(instant)`, `clock()`, `ctx(now, actor)` and `drawn()`, and
//! `Clone`, `PartialEq` and `Eq` on `Scenario`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx, SystemCause, Via};
use fstp_domain::id::{CommandId, ProposalId};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::clock::ReducedClock;
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_engine::{Command, ExecError, is_reserved_command_id, replay};

/// Design 6.1: a new scenario starts at genesis with an empty ledger.
#[test]
fn harness_scenario_starts_at_genesis_with_an_empty_ledger() {
    let s = Scenario::new(GroundTruth::new()).expect("scenario");
    assert_eq!(s.state().core, State::genesis());
    let entries = s.entries().expect("entries");
    assert!(entries.is_empty());
    assert_eq!(replay(&entries), Ok(s.state().clone()));
}

/// Design 6.1: a refused step is reported to the test, records nothing and
/// leaves the state as it was. A System actor fails the Lead actor rule of
/// `Withdraw` in the dispatcher's shared checks.
#[test]
fn harness_scenario_reports_a_refused_step_and_records_nothing() {
    let mut s = Scenario::new(GroundTruth::new()).expect("scenario");
    let ctx = Ctx {
        now: Timestamp::from_micros(10),
        actor: Actor::System(SystemCause::Timeline),
        command: CommandId::from_bytes([1; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let cmd = Command::Core(CoreCommand::Withdraw {
        proposal: ProposalId::from_raw(1),
    });
    let r = s.execute(cmd, ctx);
    let wrong_actor = Refusal::new(RuleRef::Actor, RefusalReason::WrongActor);
    assert!(
        matches!(r, Err(ExecError::Refused(x)) if x == wrong_actor),
        "{r:?}"
    );
    assert!(s.entries().expect("entries").is_empty());
    assert_eq!(s.state().core, State::genesis());
}

/// Design 6.1: the scenario's reduced clock covers exactly the instants
/// marked on it, as `ReducedClock` builds them.
#[test]
fn harness_scenario_clock_covers_the_marked_instants() {
    let t = Timestamp::from_micros;
    let mut s = Scenario::new(GroundTruth::new()).expect("scenario");
    assert!(s.clock().instants().is_empty());
    for instant in [t(30), t(10), t(11)] {
        s.mark(instant);
    }
    let expected = ReducedClock::new([t(30), t(10), t(11)]);
    assert_eq!(s.clock().instants(), expected.instants());
}

/// Design 6.1: a scenario is a value that a model state can hold. A clone
/// equals the original, and `ctx` draws a fresh id each time, counted by
/// `drawn`, outside the driver's reserved namespace.
#[test]
fn harness_scenario_is_a_value_with_fresh_command_ids() {
    let mut s = Scenario::new(GroundTruth::new()).expect("scenario");
    let copy = s.clone();
    assert_eq!(copy, s);
    assert_eq!(s.drawn(), 0);
    let actor = Actor::System(SystemCause::Timeline);
    let a = s.ctx(Timestamp::from_micros(1), actor);
    let b = s.ctx(Timestamp::from_micros(1), actor);
    assert_ne!(a.command, b.command);
    assert_eq!(s.drawn(), 2);
    assert!(!is_reserved_command_id(a.command));
    assert!(!is_reserved_command_id(b.command));
    assert_ne!(copy, s);
}

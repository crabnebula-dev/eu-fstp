//! I-66, I-67, D2e: one path to an active programme (M4 design sections 3.2 and 3.4).
//!
//! The engine composes the core `ActivateProgramme` only from an approved
//! creator decision: a `Creator(ActivationApproved)` built from an
//! `ActivationClearance`, for the same programme, revision and report
//! digest. A programme with no creator records has no such decision, so
//! `fstp_engine::compose::activation` must refuse it with its own reason,
//! never with the stub's `NotImplemented`.
//!
//! The setup runs only `CreateProgramme` from genesis, so P1 exists with
//! no creator record, no grant and no activation.
//!
//! Status: red while the W0 stub of `compose::activation` refuses with
//! `ComposeError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command as CoreCommand;
use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{P1, P2, SodSetup, T0, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::compose::{self, ComposeError};
use fstp_engine::{Command, EngineState};

/// A scenario from genesis whose only command is the `CreateProgramme` of P1.
fn created() -> Scenario {
    let steps = SodSetup::one(0, &[])
        .steps()
        .unwrap_or_else(|e| panic!("{e}"));
    let first = steps
        .iter()
        .find(|s| matches!(s.cmd, CoreCommand::CreateProgramme { .. }))
        .unwrap_or_else(|| panic!("the setup creates P1"));
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    run_on(&mut s, first, T0).unwrap_or_else(|e| panic!("CreateProgramme: {e:?}"));
    assert!(s.state().core.policy().programme(P1).is_some(), "P1 exists");
    s
}

/// Whether the composition refused for a reason of its own.
fn refused_for_a_reason(r: &Result<Command, ComposeError>) -> bool {
    matches!(r, Err(e) if !matches!(e, ComposeError::NotImplemented(_)))
}

/// I-66, I-67, D2e: a programme without an approved creator decision is
/// not activated by the composition.
#[test]
fn i66_compose_activation_refuses_without_approved_creator_decision() {
    let s = created();
    let r = compose::activation(s.state(), P1);
    assert!(
        refused_for_a_reason(&r),
        "I-66: activation composed without an approved creator decision: {r:?}"
    );
}

/// I-66, D2e: no activation is composed for a programme that does not
/// exist, neither in the empty state nor beside a created programme.
#[test]
fn i66_compose_activation_refuses_unknown_programme() {
    let r = compose::activation(&EngineState::genesis(), P1);
    assert!(refused_for_a_reason(&r), "I-66: genesis: {r:?}");
    let s = created();
    let r = compose::activation(s.state(), P2);
    assert!(refused_for_a_reason(&r), "I-66: unknown programme: {r:?}");
}

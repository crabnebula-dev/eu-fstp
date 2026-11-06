//! R-PC-02, R-PC-03 and the authorisation matrix row of
//! `SPEC/07-test-plan/test-plan.md`: `EditCall` and
//! `ApproveCallPublication` judge the actor before the call's state. An
//! account outside the actor rule, or a drafter asked to approve, gets an
//! actor denial in every call state. A permitted actor gets the state
//! refusal: R-PC-02 on a published call, and the transition row on a call
//! already approved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain_testkit::r#gen::policy::{DRAFTER_1, P1, PM_A, PM_B, PM_C, PolicyWorld, STRANGER};
use fstp_engine::ExecError;
use fstp_ledger::Seq;

fn world() -> PolicyWorld {
    PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"))
}

/// The rule and reason of a refusal, or why it is none.
fn refusal(r: &Result<Seq, ExecError>) -> (RuleRef, RefusalReason) {
    match r {
        Err(ExecError::Refused(x)) => (x.rule, x.reason),
        other => panic!("not a refusal: {other:?}"),
    }
}

/// Whether `r` is an actor denial: the actor rule or the R-PC-03 drafter
/// rule.
fn actor_denial(r: &Result<Seq, ExecError>) -> bool {
    matches!(
        refusal(r),
        (RuleRef::Actor, _) | (RuleRef::Rpc03, RefusalReason::GuardFailed)
    )
}

/// R-PC-02, R-PC-03, test plan authorisation matrix row: on a published
/// call, an outsider's edit and approval, a call drafter's approval and a
/// drafting manager's approval are actor denials. A manager who may edit
/// gets R-PC-02.
#[test]
fn r_pc_02_r_pc_03_published_call_refuses_the_actor_first() {
    let mut w = world();
    assert!(w.draft(PM_A, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_C, 1).unwrap().is_ok());
    let r = w.edit_call(STRANGER, 1).unwrap();
    assert!(actor_denial(&r), "{r:?}");
    for who in [STRANGER, DRAFTER_1, PM_A] {
        let r = w.approve(who, 1);
        assert!(actor_denial(&r), "{who:?}: {r:?}");
    }
    let r = w.edit_call(PM_B, 1).unwrap();
    assert_eq!(refusal(&r), (RuleRef::Rpc02, RefusalReason::WrongState));
}

/// R-PC-03, test plan authorisation matrix row: on an approved call, an
/// outsider's and a drafter's approval are actor denials. A second
/// approval by a manager outside the drafters is a state guard, the
/// transition row, never the R-PC-03 actor rule.
#[test]
fn r_pc_03_approved_call_refuses_the_actor_first() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 2, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 2).is_ok());
    for who in [STRANGER, DRAFTER_1] {
        let r = w.approve(who, 2);
        assert!(actor_denial(&r), "{who:?}: {r:?}");
    }
    let r = w.approve(PM_C, 2);
    assert_eq!(refusal(&r), (RuleRef::Row, RefusalReason::WrongState));
}

/// R-PC-02, test plan authorisation matrix row: drafting and publishing a
/// call judge the actor first, so an outsider gets an actor denial, and
/// on a published call too.
#[test]
fn r_pc_02_draft_and_publication_refuse_the_actor_first() {
    let mut w = world();
    let r = w.draft(STRANGER, 3, P1).unwrap();
    assert!(actor_denial(&r), "{r:?}");
    assert!(w.draft(PM_A, 3, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 3).is_ok());
    assert!(w.publish(PM_C, 3).unwrap().is_ok());
    let r = w.publish(STRANGER, 3).unwrap();
    assert!(actor_denial(&r), "{r:?}");
    let r = w.publish(PM_C, 3).unwrap();
    assert_eq!(refusal(&r), (RuleRef::Rpc02, RefusalReason::WrongState));
}

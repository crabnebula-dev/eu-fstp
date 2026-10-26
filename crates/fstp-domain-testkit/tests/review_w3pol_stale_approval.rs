//! Review reproducers for lane L-POL (R-PC-03).
//!
//! The call states define DRAFT as "call text and criteria being drafted"
//! and APPROVED as approved by a person other than the drafter. A change
//! of the call text or of P-01 after the approval means the published call
//! is not the one that was approved. The reference treats that publication
//! as an open outcome (`Verdict::Either`), so no suite can catch an engine
//! that publishes on the stale approval. These tests fail until the
//! reference refuses it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{CallId, LlmConfigId};
use fstp_domain_testkit::r#gen::policy::{DRAFTER_1, P1, PM_A, PM_B, PM_C, PolicyWorld, criteria};
use fstp_domain_testkit::reference::policy::Verdict;

fn publish_cmd(w: &PolicyWorld, call: u128) -> Command {
    Command::PublishCall {
        call: CallId::from_raw(call),
        config: LlmConfigId::from_raw(w.ghost().max_config().saturating_add(1)),
        config_model: w.head(P1).unwrap().frozen.p21.primary,
    }
}

/// R-PC-03: a drafter who edits the call text after an independent
/// approval cannot publish it on that approval. The reference must refuse.
#[test]
fn review_r_pc_03_call_edit_after_approval_needs_a_new_approval() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.edit_call(DRAFTER_1, 1).unwrap().is_ok());
    let cmd = publish_cmd(&w, 1);
    let v = w
        .ghost()
        .verdict(Actor::Account(PM_A), false, &cmd)
        .unwrap();
    assert_eq!(
        v,
        Verdict::Refuse,
        "R-PC-03: publication after a text edit on the old approval is not pinned"
    );
}

/// R-PC-03: a change of P-01, the call's criteria, after an approval
/// leaves that approval stale. The reference must refuse publication on it.
#[test]
fn review_r_pc_03_criteria_edit_after_approval_needs_a_new_approval() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    let r = w
        .edit(PM_C, P1, |v| {
            v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let cmd = publish_cmd(&w, 1);
    let v = w
        .ghost()
        .verdict(Actor::Account(PM_A), false, &cmd)
        .unwrap();
    assert_eq!(
        v,
        Verdict::Refuse,
        "R-PC-03: publication after a P-01 edit on the old approval is not pinned"
    );
}

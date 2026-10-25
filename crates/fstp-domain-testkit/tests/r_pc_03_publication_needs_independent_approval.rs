//! R-PC-03: publishing a call requires approval by a person other than its drafter.
//!
//! - AC: publication by the drafter alone is rejected.
//! - AC: approval by an author of the call, or by the last author of P-01
//!   or P-09 in the policy the call freezes, is rejected.
//! - NOTE: the drafters are the call's authors plus the last authors of
//!   P-01 and P-09 in that call's policy. A person is a tenant account.
//!   Once the call is published, that set is the one at publication.
//!
//! The policy the call freezes is the head at publication, so publication
//! checks the approver against the drafters at that moment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, CallId};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::policy::criteria;
use fstp_domain_testkit::r#gen::policy::{
    ADMIN, DRAFTER_1, Focus, P1, PM_A, PM_B, PM_C, PolicyMachine, PolicyWorld, knock_outs,
};
use fstp_domain_testkit::mc::policy_model::reads;
use fstp_engine::ExecError;
use fstp_ledger::Seq;
use fstp_money::Percent;
use fstp_prop::check_machine;

fn world() -> PolicyWorld {
    PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"))
}

fn refused_by_rpc03(r: &Result<Seq, ExecError>) -> bool {
    matches!(r, Err(ExecError::Refused(x)) if x.rule == RuleRef::Rpc03)
}

/// R-PC-03: random authorship of calls, P-01 and P-09, approvals and
/// publications match the reference drafter rule.
#[test]
fn r_pc_03_publication_needs_approval_by_a_non_drafter() {
    check_machine(
        "r_pc_03_publication_needs_approval_by_a_non_drafter",
        &PolicyMachine::new(Focus::APPROVAL),
    );
}

/// R-PC-03 first AC: a programme manager who drafted the call can neither
/// publish it without approval nor approve it.
#[test]
fn r_pc_03_the_drafter_alone_cannot_publish() {
    let mut w = world();
    assert!(w.draft(PM_A, 1, P1).unwrap().is_ok());
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_rpc03(&r), "{r:?}");
    let r = w.approve(PM_A, 1);
    assert!(refused_by_rpc03(&r), "{r:?}");
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_rpc03(&r), "{r:?}");
}

/// R-PC-03 second AC: every author of the call, including an editor, is a
/// drafter and cannot approve. Another programme manager can.
#[test]
fn r_pc_03_authors_of_the_call_cannot_approve() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.edit_call(PM_B, 1).unwrap().is_ok());
    let r = w.approve(PM_B, 1);
    assert!(refused_by_rpc03(&r), "{r:?}");
    assert!(w.approve(PM_C, 1).is_ok());
    let r = w.publish(PM_A, 1).unwrap();
    assert!(r.is_ok(), "{r:?}");
}

/// R-PC-03 second AC: the last author of P-01 in the policy the call
/// freezes cannot approve.
#[test]
fn r_pc_03_the_last_author_of_p01_cannot_approve() {
    let mut w = world();
    let r = w
        .edit(PM_B, P1, |v| {
            v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    let r = w.approve(PM_B, 1);
    assert!(refused_by_rpc03(&r), "{r:?}");
    assert!(w.approve(PM_C, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
}

/// R-PC-03 second AC: the last author of P-09 in the policy the call
/// freezes cannot approve.
#[test]
fn r_pc_03_the_last_author_of_p09_cannot_approve() {
    let mut w = world();
    let r = w
        .edit(PM_B, P1, |v| v.frozen.p09 = knock_outs(3_000))
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    let r = w.approve(PM_B, 1);
    assert!(refused_by_rpc03(&r), "{r:?}");
    assert!(w.approve(PM_C, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
}

/// R-PC-03 second AC: an approver who edits P-01 after approving becomes
/// its last author in the policy the call would freeze, so publication on
/// that approval is refused.
#[test]
fn r_pc_03_an_approver_who_then_edits_p01_blocks_publication() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_C, 1).is_ok());
    let weights = [10, 20, 30];
    let r = w
        .edit(PM_C, P1, |v| v.frozen.p01 = criteria(4, weights).unwrap())
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_rpc03(&r), "{r:?}");
}

/// R-PC-03 second AC: an approver who edits the call after approving
/// becomes one of its authors, so publication on that approval is refused.
#[test]
fn r_pc_03_an_approver_who_then_edits_the_call_blocks_publication() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_C, 1).is_ok());
    assert!(w.edit_call(PM_C, 1).unwrap().is_ok());
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_rpc03(&r), "{r:?}");
}

/// R-PC-03 NOTE, reading reported to Daniel: an edit that keeps P-01 and
/// P-09 does not make its author a drafter, so that author may approve.
#[test]
fn r_pc_03_an_edit_that_keeps_p01_and_p09_makes_no_drafter() {
    let mut w = world();
    let r = w
        .edit(PM_B, P1, |v| {
            v.frozen.p02 = Percent::from_bp(5_000).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    let r = w.approve(PM_B, 1);
    assert!(r.is_ok(), "{r:?}");
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
}

/// R-PC-03 NOTE: the drafters of a published call are those of that call's
/// policy, the version it froze. A later P-01 edit makes its author a
/// drafter of an unpublished call, but not of the published one.
#[test]
fn r_pc_03_drafters_of_a_published_call_are_fixed_at_publication() {
    let mut w = world();
    for call in [1, 2] {
        assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
    }
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let at_publication: BTreeSet<AccountId> = [DRAFTER_1, ADMIN].into_iter().collect();
    let drafters = |w: &PolicyWorld, call: u128| reads::drafters(w.state(), CallId::from_raw(call));
    assert_eq!(drafters(&w, 1), Some(at_publication.clone()));
    let r = w
        .edit(PM_C, P1, |v| {
            v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(drafters(&w, 1), Some(at_publication));
    assert!(drafters(&w, 2).is_some_and(|d| d.contains(&PM_C)));
}

/// R-PC-03 with the call states, reading reported to Daniel: an approval
/// covers the call text as it was. A drafter who edits the text after an
/// independent approval sends the call back to DRAFT, so publication needs
/// a new approval. The approver may then approve the new text.
#[test]
fn r_pc_03_a_call_edit_after_approval_needs_a_new_approval() {
    let mut w = world();
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.edit_call(DRAFTER_1, 1).unwrap().is_ok());
    let r = w.publish(PM_A, 1).unwrap();
    assert!(refused_by_rpc03(&r), "{r:?}");
    assert!(w.approve(PM_B, 1).is_ok());
    let r = w.publish(PM_A, 1).unwrap();
    assert!(r.is_ok(), "{r:?}");
}

/// R-PC-03 with the call states, reading reported to Daniel: an approval
/// covers P-01 and P-09 as they were. A third manager who changes P-01 or
/// P-09 after the approval ends it, so publication needs a new approval by
/// someone who is still not a drafter.
#[test]
fn r_pc_03_a_criteria_edit_after_approval_needs_a_new_approval() {
    for p09 in [false, true] {
        let mut w = world();
        assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
        assert!(w.approve(PM_B, 1).is_ok());
        let r = w
            .edit(PM_C, P1, |v| {
                if p09 {
                    v.frozen.p09 = knock_outs(3_000);
                } else {
                    v.frozen.p01 = criteria(4, [20, 50, 30]).unwrap();
                }
            })
            .unwrap();
        assert!(r.is_ok(), "{r:?}");
        let r = w.publish(PM_A, 1).unwrap();
        assert!(refused_by_rpc03(&r), "P-09 {p09}: {r:?}");
        assert!(w.approve(PM_B, 1).is_ok(), "P-09 {p09}");
        let r = w.publish(PM_A, 1).unwrap();
        assert!(r.is_ok(), "P-09 {p09}: {r:?}");
    }
}

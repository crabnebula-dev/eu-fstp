//! R-PC-01: a tenant runs several programmes, each with its own policy parameters.
//!
//! The AC on weighted scores belongs to lane L-SCORE
//! (`r_pc_01_weights_change_scores_for_discriminating_inputs`). This file
//! covers the policy side: each programme has its own head, an edit never
//! reaches another programme, a programme manager of one programme cannot
//! edit another, and call sequence numbers count per programme.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command as CoreCommand;
use fstp_domain::id::{CallSeq, PolicyVersionId};
use fstp_domain::record::Record;
use fstp_domain_testkit::r#gen::policy::{
    DRAFTER_1, DRAFTER_2, Focus, P1, P2, PM_A, PM_B, PM_C, PM_D, PolicyMachine, PolicyWorld,
    next_version,
};
use fstp_domain_testkit::mc::policy_model::reads;
use fstp_engine::ExecError;
use fstp_money::Percent;
use fstp_prop::check_machine;

fn world() -> PolicyWorld {
    PolicyWorld::new(true).unwrap_or_else(|e| panic!("{e}"))
}

fn seq(n: u32) -> CallSeq {
    CallSeq::new(core::num::NonZeroU32::new(n).unwrap())
}

/// R-PC-01: random edits, calls and publications over two programmes,
/// including edits based on the other programme's head and edits by
/// managers of the other programme, match the reference.
#[test]
fn r_pc_01_programmes_keep_separate_policies() {
    check_machine(
        "r_pc_01_programmes_keep_separate_policies",
        &PolicyMachine::new(Focus::PROGRAMMES),
    );
}

/// R-PC-01: an edit of programme 2 leaves the head of programme 1 as it was.
#[test]
fn r_pc_01_an_edit_in_one_programme_leaves_the_other_unchanged() {
    let mut w = world();
    let p1_before = w.head(P1).unwrap();
    let r = w
        .edit(PM_D, P2, |v| {
            v.frozen.p02 = Percent::from_bp(5_000).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let p1 = reads::head(w.state(), P1).unwrap_or_else(|e| panic!("{e}"));
    let p2 = reads::head(w.state(), P2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(p1.as_ref(), Some(&p1_before));
    assert_eq!(p2.as_ref(), w.ghost().head(P2));
    assert_ne!(p1.map(|v| v.frozen.p02), p2.map(|v| v.frozen.p02));
}

/// R-PC-01: a manager of programme 1 only cannot edit programme 2, and an
/// edit based on programme 1's head cannot land in programme 2.
#[test]
fn r_pc_01_policy_edits_do_not_cross_programmes() {
    let mut w = world();
    let r = w.edit(PM_A, P2, |_| {}).unwrap();
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    let p1_head = w.head(P1).unwrap();
    let mut v = next_version(&p1_head, w.fresh_version());
    v.programme = P2;
    let cross = CoreCommand::EditPolicy {
        base: p1_head.id,
        version: Box::new(v),
    };
    let r = w.setup.run(PM_C, false, cross);
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    let r = w.edit(PM_D, P2, |_| {}).unwrap();
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(w.head(P1).unwrap().id, PolicyVersionId::from_raw(1));
}

/// R-PC-01 with P-12 NOTE 4: call sequence numbers count publications per
/// programme, from 1.
#[test]
fn r_pc_01_call_sequences_count_per_programme() {
    let mut w = world();
    for (call, programme, drafter, approver, publisher) in [
        (1, P1, DRAFTER_1, PM_B, PM_A),
        (2, P2, DRAFTER_2, PM_D, PM_C),
        (3, P1, DRAFTER_1, PM_B, PM_A),
    ] {
        assert!(w.draft(drafter, call, programme).unwrap().is_ok());
        assert!(w.approve(approver, call).is_ok());
        let r = w.publish(publisher, call).unwrap();
        assert!(r.is_ok(), "publication of call {call}: {r:?}");
    }
    let seqs: Vec<(u128, CallSeq)> = w
        .records()
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            Record::CallPublished { call, seq, .. } => Some((call.raw(), seq)),
            _ => None,
        })
        .collect();
    assert_eq!(seqs, vec![(1, seq(1)), (2, seq(1)), (3, seq(2))]);
    let p1 = reads::latest_published_seq(w.state(), P1).unwrap_or_else(|e| panic!("{e}"));
    let p2 = reads::latest_published_seq(w.state(), P2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((p1, p2), (Some(seq(2)), Some(seq(1))));
}

//! R-PC-02: a published call carries a frozen policy version (I-12).
//!
//! AC: a parameter edit after publication does not change any outcome in
//! that call. At the policy level the outcome is the frozen policy itself.
//! Outcomes of the lifecycle are covered by the W6 twin machine.
//! Publication also pins the configuration and checks it against the
//! frozen P-21 primary model (R-LA-05, P-21 NOTE 10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{CallId, LlmConfigId, PolicyVersionId};
use fstp_domain::policy::ModelRef;
use fstp_domain::record::Record;
use fstp_domain_testkit::r#gen::policy::{
    DRAFTER_1, Focus, MODEL_A, MODEL_B, MODEL_C, P1, PM_A, PM_B, PM_C, PolicyMachine, PolicyWorld,
};
use fstp_domain_testkit::mc::policy_model::{FrozenView, reads};
use fstp_engine::ExecError;
use fstp_money::Percent;
use fstp_prop::check_machine;

fn world() -> PolicyWorld {
    PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"))
}

/// Drafts call `call` and has it approved by programme manager B.
fn ready(w: &mut PolicyWorld, call: u128) {
    assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, call).is_ok());
}

fn frozen(w: &PolicyWorld, call: u128) -> Option<FrozenView> {
    reads::frozen_policy(w.state(), CallId::from_raw(call)).unwrap_or_else(|e| panic!("{e}"))
}

fn publications(w: &PolicyWorld) -> Vec<(CallId, PolicyVersionId, LlmConfigId)> {
    w.records()
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            Record::CallPublished {
                call,
                policy,
                config,
                ..
            } => Some((call, policy, config)),
            _ => None,
        })
        .collect()
}

/// R-PC-02: random publications, edits after them, call edits and wrong
/// models match the reference, and published frozen policies never change.
#[test]
fn r_pc_02_published_call_carries_frozen_version() {
    check_machine(
        "r_pc_02_published_call_carries_frozen_version",
        &PolicyMachine::new(Focus::PUBLICATION),
    );
}

/// R-PC-02: publication freezes the head version. A later edit leaves the
/// published call's frozen policy unchanged, and the next call freezes the
/// edited version.
#[test]
fn r_pc_02_publication_freezes_the_head_version() {
    let mut w = world();
    let first = w.head(P1).unwrap();
    ready(&mut w, 1);
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    assert!(frozen(&w, 1).is_some_and(|f| f.version == first.id && f.values == first.frozen));
    let r = w
        .edit(PM_C, P1, |v| {
            v.frozen.p02 = Percent::from_bp(5_000).unwrap()
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    let second = w.head(P1).unwrap();
    assert!(frozen(&w, 1).is_some_and(|f| f.version == first.id && f.values == first.frozen));
    ready(&mut w, 2);
    assert!(w.publish(PM_A, 2).unwrap().is_ok());
    assert!(frozen(&w, 2).is_some_and(|f| f.version == second.id && f.values == second.frozen));
    assert!(frozen(&w, 1).is_some_and(|f| f.version == first.id));
    let published = publications(&w);
    assert_eq!(
        published
            .iter()
            .map(|(c, v, _)| (c.raw(), *v))
            .collect::<Vec<_>>(),
        vec![(1, first.id), (2, second.id)]
    );
}

/// R-PC-02: a published call cannot be edited, approved or published again.
#[test]
fn r_pc_02_a_published_call_cannot_change() {
    let mut w = world();
    ready(&mut w, 1);
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let edited = w.edit_call(DRAFTER_1, 1).unwrap();
    assert!(matches!(edited, Err(ExecError::Refused(_))), "{edited:?}");
    let approved = w.approve(PM_C, 1);
    assert!(
        matches!(approved, Err(ExecError::Refused(_))),
        "{approved:?}"
    );
    let again = w.publish(PM_A, 1).unwrap();
    assert!(matches!(again, Err(ExecError::Refused(_))), "{again:?}");
    assert_eq!(publications(&w).len(), 1);
}

/// R-PC-02 with R-LA-05 and P-21 NOTE 10: publication pins the
/// configuration, whose model must be the frozen P-21 primary. A fallback
/// model or another model is refused. After a P-21 edit the next call needs
/// the new primary.
#[test]
fn r_pc_02_publication_checks_the_frozen_p21_primary() {
    let mut w = world();
    ready(&mut w, 1);
    for wrong in [MODEL_B, MODEL_C] {
        let r = w.publish_with(PM_A, 1, ModelRef(wrong.to_owned()));
        assert!(matches!(r, Err(ExecError::Refused(_))), "{wrong}: {r:?}");
    }
    let r = w.publish_with(PM_A, 1, ModelRef(MODEL_A.to_owned()));
    assert!(r.is_ok(), "{r:?}");
    let pinned = w.ghost().calls[&CallId::from_raw(1)]
        .published
        .as_ref()
        .unwrap()
        .config;
    assert_eq!(
        publications(&w),
        vec![(CallId::from_raw(1), PolicyVersionId::from_raw(1), pinned)]
    );
    let r = w
        .edit(PM_C, P1, |v| {
            v.frozen.p21.primary = ModelRef(MODEL_C.to_owned())
        })
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
    ready(&mut w, 2);
    let r = w.publish_with(PM_A, 2, ModelRef(MODEL_A.to_owned()));
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    let r = w.publish_with(PM_A, 2, ModelRef(MODEL_C.to_owned()));
    assert!(r.is_ok(), "{r:?}");
}

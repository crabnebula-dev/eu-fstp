//! R-EV-02, row 3: admission to stage 1 needs at least P-03 active reviewers, every active one without conflict (I-03).
//!
//! The stories run production commands from genesis and compare every step
//! with the lifecycle reference in both directions.
//!
//! - Each reviewer is of its own organisation, so I-34 holds and the P-03
//!   guard alone decides the admission. A committee binding always records
//!   an organisation (SoD-10, decided 2026-10-25).
//! - The vault answers a conflict for an active assignee at the processed
//!   epoch, before any detection. The admission is refused under I-03,
//!   since that assignee could never score and stage 1 could not close.
//!   Through the model driver every new epoch rechecks each active pair
//!   first, so this probe calls the pure engine with the answers directly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AccountId, CommandId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    Story, admit, assign_declared, life_judges, story_setup,
};

/// PR1 submitted and checked in call 1 with `reviewers`, each of its own
/// organisation.
fn checked(backend: Backend, reviewers: &[AccountId]) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.checked(L1, PR1, reviewers)
        .unwrap_or_else(|e| panic!("PR1 checked: {e}"));
    s
}

fn r_ev_02_p03_alone_decides_the_admission_on(b: Backend) {
    let mut s = checked(b, &[R1]);
    if b == Backend::Production {
        let refusal = s
            .clone()
            .world
            .rev
            .exec(&admit(PR1))
            .unwrap_or_else(|e| panic!("harness: {e}"))
            .err();
        assert_eq!(
            refusal.map(|r| r.rule),
            Some(RuleRef::Rev02),
            "R-EV-02: one reviewer is fewer than P-03 = 2"
        );
    }
    let got = s.attempt(&admit(PR1)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got.is_none(),
        "R-EV-02: admission with fewer than P-03 reviewers"
    );
    for st in assign_declared(R2, PR1, call(1), AssignmentKind::Reviewer) {
        s.run(&st).unwrap_or_else(|e| panic!("{e}"));
    }
    s.run(&admit(PR1))
        .unwrap_or_else(|e| panic!("R-EV-02: P-03 reviewers admit PR1: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage1));
}

/// R-EV-02, row 3: with I-34 holding, fewer than P-03 active reviewers
/// refuse the admission, and P-03 of them admit it.
#[test]
fn r_ev_02_p03_alone_decides_the_admission() {
    r_ev_02_p03_alone_decides_the_admission_on(Backend::Production);
}

/// R-EV-02: the story above passes on the references alone.
#[test]
fn r_ev_02_p03_alone_decides_the_admission_reference() {
    r_ev_02_p03_alone_decides_the_admission_on(Backend::Reference);
}

/// R-EV-02, I-03, row 3: two conflict-free reviewers meet P-03, but a third
/// active assignee has a vault conflict at the processed epoch. The
/// admission is refused under I-03, and admitted on the vault's answers
/// without that conflict.
#[test]
fn r_ev_02_conflicted_active_assignee_blocks_the_admission() {
    let s = checked(Backend::Production, &[R1, R2, R3]);
    let step = admit(PR1);
    let ctx = step.ctx(s.world.now(), CommandId::from_bytes(*b"r-ev-02:admit:i3"));
    let state = &s.world.rev.sod.state;
    let decide = |conflicted: bool| {
        let mut answers = Answers::new();
        for q in fstp_domain::queries(state, &step.cmd, &ctx).unwrap_or_else(|r| panic!("{r}")) {
            let mut a = s.world.rev.answer(&q);
            if conflicted && matches!(&q, Query::HasConflict { reviewer, .. } if *reviewer == R3) {
                a.holds = true;
            }
            answers.insert(q, a);
        }
        fstp_domain::decide(state, &step.cmd, &ctx, &answers)
    };
    assert!(
        decide(false).is_ok(),
        "R-EV-02: three conflict-free reviewers admit PR1"
    );
    assert_eq!(
        decide(true).err().map(|r| r.rule),
        Some(RuleRef::I03),
        "R-EV-02, I-03: an active assignee with a vault conflict blocks the admission"
    );
}

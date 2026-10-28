//! Checker reproducers for the W7 review fixes.
//!
//! Each test runs production commands from genesis and is compared with
//! the references in both directions. Each one fails on the W7 fixes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::BindingId;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, O1, O2, PR1, R1, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, P1, grant};
use fstp_domain_testkit::mc::life_model::{Story, life_judges, story_setup};

/// I-34, SoD-10 (decided 2026-10-25): each committee binding records the
/// reviewer's organisation. R1 and R3 are committee members of O1, and
/// P-39 = 2, so R1 and R3 alone cannot admit PR1. The tenant admin then
/// grants R1 a second committee binding that records O2, under a binding
/// id below R1's first one. `committee_organisation` reads the first
/// active binding by id, so R1 now counts as O2, and R1 and R3 admit PR1.
/// The count of organisations must not depend on binding ids. Either the
/// second grant with another organisation is refused, or the admission is.
#[test]
fn review_w7check_i34_second_committee_binding_cannot_change_the_reviewers_organisation() {
    let mut judges = life_judges();
    for j in &mut judges {
        if j.0 == R3 {
            j.2 = Some(O1);
        }
    }
    let setup = story_setup(vec![(L1, PR1, false)], judges);
    let mut s = Story::new(&setup, Backend::Production, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    let now = s.world.now();
    let mut g = grant(BindingId::from_raw(150), R1, P1, Role::CommitteeMember, now);
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(O2);
    }
    let granted = s
        .attempt(&g)
        .unwrap_or_else(|e| panic!("the second committee grant of R1: {e}"))
        .is_some();
    let admitted = s.to_stage1(L1, PR1, &[R1, R3]).is_ok();
    assert!(
        !(granted && admitted && s.state(PR1) == Some(StateTag::Stage1)),
        "I-34, SoD-10: R1 and R3 of O1 admitted PR1, since a second binding of R1 records O2"
    );
}

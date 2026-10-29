//! Reviewer reproducer: SoD-10, I-35 and a scheduled end (W7 fix round 1).
//!
//! SoD-10 now counts only committee bindings active beside a new one. So a
//! second committee binding of another organisation may be granted ahead,
//! to start at the instant of a scheduled end. At the System end,
//! `binding_releases` keeps every assignment of the reviewer, since the
//! account still holds a committee binding in the programme. The reviewer
//! then serves under the new organisation, which no I-35 check has seen.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::id::{AssignmentId, BindingId};
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L2, LIST_1, O1, PR2, R3, assign, handle, judge_binding, machine_accounts,
    machine_setup, records_of, review_truth, run_records, scenario_from, unassign,
};
use fstp_domain_testkit::r#gen::roster::{Flags, P1, Step, T0, end, grant};

fn t(n: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros().saturating_add(n.saturating_mul(1_000_000)))
}

/// R3 (O2) reviews PR2, whose lead declares an affiliation on O1's list.
/// R3's committee binding ends at `t(10)`, and a committee binding of R3
/// recording O1 is granted to start at `t(10)`. Once the System records
/// the end, R3 must not stay a reviewer of PR2 as a member of O1 (I-35,
/// SoD-10 "one organisation per programme"). Either the O1 grant is
/// refused, or the end releases the assignment.
#[test]
fn review_w7v2_sod10_scheduled_switch_keeps_i35() {
    let mut s = scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup: {e}"));
    let ctx = s.ctx(T0, Actor::System(SystemCause::Vault));
    s.change_vault(|v| v.declare_affiliation(L2, LIST_1), ctx)
        .unwrap_or_else(|e| panic!("vault reaction: {e:?}"));
    let a = AssignmentId::from_raw(9_031);
    run_records(
        &mut s,
        &assign(
            COORDINATOR,
            a,
            PR2,
            R3,
            AssignmentKind::Reviewer,
            Some(handle(9_031)),
        ),
        T0,
    )
    .unwrap()
    .unwrap_or_else(|r| panic!("R3 of O2 is assigned to PR2: {r}"));
    let old = judge_binding(3);
    run_records(&mut s, &end(old, t(10)), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("the scheduled end is refused: {r}"));
    let mut g = grant(
        BindingId::from_raw(950),
        R3,
        P1,
        Role::CommitteeMember,
        t(10),
    );
    if let Command::GrantRole { organisation, .. } = &mut g.cmd {
        *organisation = Some(O1);
    }
    if run_records(&mut s, &g, T0).unwrap().is_err() {
        // SoD-10 read as one organisation per programme: fixed.
        return;
    }
    let system_end = Step {
        actor: Actor::System(SystemCause::Timeline),
        flags: Flags::NONE,
        cmd: Command::EndScheduledRole { binding: old },
    };
    run_records(&mut s, &system_end, t(10))
        .unwrap()
        .unwrap_or_else(|r| panic!("the System end is refused: {r}"));
    let released = records_of(&s)
        .unwrap()
        .iter()
        .any(|r| matches!(r, Record::AssignmentReleased(x) if x.assignment == a));
    // Production itself now reads R3 as O1: released and assigned again,
    // R3 is refused under I-35.
    let _ = run_records(&mut s, &unassign(COORDINATOR, a), t(11)).unwrap();
    let fresh = run_records(
        &mut s,
        &assign(
            COORDINATOR,
            AssignmentId::from_raw(9_032),
            PR2,
            R3,
            AssignmentKind::Reviewer,
            Some(handle(9_032)),
        ),
        t(11),
    )
    .unwrap();
    assert!(
        released,
        "I-35, SoD-10: R3 stays a reviewer of PR2 as a member of O1, whose list PR2 declares on; a fresh assignment of R3 now gives {fresh:?}"
    );
}

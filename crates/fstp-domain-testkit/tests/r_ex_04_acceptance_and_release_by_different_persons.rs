//! R-EX-04, R-EX-01, I-05, SoD-04: milestone acceptance and payment release are done by different persons (payment-requests.md, the I-05 NOTE).
//!
//! Lead c is granted 4.00 over two milestones and starts execution from
//! genesis by production commands. R1, an assigned reviewer who is also a
//! payment releaser, accepts a line. R2, an assigned reviewer who is also
//! a finance approver, approves. Neither may release, and neither may
//! FINREL once it approved a second request. The release waits for the
//! acceptance and the approval (R-EX-01). REL, who holds no other role,
//! releases. An account without the releaser role cannot release.
//!
//! The I-05 NOTE names the assigned reviewers who approved a line. A
//! reviewer who approved a line at 0.00 rejected it, so R1, who only
//! rejected a line of a request, may release that request.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{LineId, RequestId};
use fstp_domain_testkit::r#gen::money::MoneyStory;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, PC, REL, accept_line, approve_payment, confirm_paid, milestone_n, release_payment,
    request_payment,
};
use fstp_domain_testkit::r#gen::review::{R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::mc::pay_model::pay_setup;
use fstp_domain_testkit::reference::payment::RequestState;

fn story(b: Backend) {
    let mut s = MoneyStory::new(&pay_setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.execute(PC)
        .unwrap_or_else(|e| panic!("c granted and in execution: {e}"));
    let r1 = RequestId::from_raw(37_001);
    let l1 = LineId::from_raw(137_001);
    s.run(&request_payment(LC, r1, PC, &[(l1, milestone_n(PC, 0), 200)]).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    s.refused(&release_payment(REL, r1))
        .unwrap_or_else(|e| panic!("R-EX-01: a release waits for acceptance: {e}"));
    s.run(&accept_line(R1, r1, l1, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("R1 accepts the line: {e}"));
    s.refused(&release_payment(REL, r1))
        .unwrap_or_else(|e| panic!("a release waits for the approval: {e}"));
    s.run(&approve_payment(R2, r1))
        .unwrap_or_else(|e| panic!("R2 approves as finance approver: {e}"));
    s.refused(&release_payment(R1, r1))
        .unwrap_or_else(|e| panic!("I-05: the acceptor does not release: {e}"));
    s.refused(&release_payment(R3, r1))
        .unwrap_or_else(|e| panic!("R3 holds no releaser role: {e}"));
    s.run(&release_payment(REL, r1))
        .unwrap_or_else(|e| panic!("I-05: a third account releases: {e}"));
    s.run(&confirm_paid(r1)).unwrap_or_else(|e| panic!("{e}"));
    let r2 = RequestId::from_raw(37_002);
    let l2 = LineId::from_raw(137_002);
    s.run(&request_payment(LC, r2, PC, &[(l2, milestone_n(PC, 1), 200)]).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&accept_line(R2, r2, l2, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("R2 accepts: {e}"));
    s.run(&approve_payment(FINREL, r2))
        .unwrap_or_else(|e| panic!("FINREL approves: {e}"));
    s.refused(&release_payment(FINREL, r2))
        .unwrap_or_else(|e| panic!("SoD-04: the approver does not release: {e}"));
    s.run(&release_payment(R1, r2))
        .unwrap_or_else(|e| panic!("I-05: R1 accepted nothing of this request: {e}"));
    assert_eq!(
        s.world.money.pay.requests.get(&r2).map(|r| r.state),
        Some(RequestState::Released)
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn rejecter_releases(b: Backend) {
    let mut s = MoneyStory::new(&pay_setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.execute(PC)
        .unwrap_or_else(|e| panic!("c granted and in execution: {e}"));
    let r = RequestId::from_raw(37_003);
    let l1 = LineId::from_raw(137_003);
    let l2 = LineId::from_raw(137_004);
    s.run(
        &request_payment(
            LC,
            r,
            PC,
            &[(l1, milestone_n(PC, 0), 200), (l2, milestone_n(PC, 1), 200)],
        )
        .unwrap(),
    )
    .unwrap_or_else(|e| panic!("c requests both milestones: {e}"));
    s.run(&accept_line(R1, r, l1, 0, true).unwrap())
        .unwrap_or_else(|e| panic!("I-60: R1 rejects the first line with a reason: {e}"));
    s.run(&accept_line(R2, r, l2, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("R2 accepts the second line: {e}"));
    s.run(&approve_payment(FINREL, r))
        .unwrap_or_else(|e| panic!("FINREL approves: {e}"));
    s.run(&release_payment(R1, r)).unwrap_or_else(|e| {
        panic!("I-05 NOTE: R1 approved no line of the request, so R1 may release: {e}")
    });
    assert_eq!(
        s.world.money.pay.requests.get(&r).map(|x| x.state),
        Some(RequestState::Released)
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-EX-04, I-05, SoD-04: acceptor, approver and releaser are different persons.
#[test]
fn r_ex_04_acceptance_and_release_by_different_persons() {
    story(Backend::Production);
}

/// R-EX-04, I-05: a reviewer who only rejected a line is no acceptor and may release.
#[test]
fn r_ex_04_i05_reviewer_who_only_rejected_may_release() {
    rejecter_releases(Backend::Production);
}

/// R-EX-04: the stories pass on the references alone.
#[test]
fn r_ex_04_story_passes_on_the_reference() {
    story(Backend::Reference);
    rejecter_releases(Backend::Reference);
}

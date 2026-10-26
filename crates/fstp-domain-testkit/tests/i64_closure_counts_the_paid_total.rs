//! I-64, I-14: at grant closure the counted amount drops to the paid total (payment-requests.md P-67, contracts.md, Q7 A).
//!
//! Leads a and b share one verified identity, under P-04 = [2.00, 4.00]
//! and P-05 = 6.00. From genesis by production commands, a is granted 4.00
//! over two milestones of 2.00 and b reaches NEGOTIATION with a plan of
//! 4.00. While a's grant counts 4.00, b's 4.00 is refused. Then a is paid
//! one milestone. When a's grant reaches COMPLETED, after the programme
//! manager closes both milestones, or TERMINATED, it counts only what was
//! paid, and b's 4.00 fits.
//!
//! A payment approved before the termination is never released after it.
//! Otherwise the paid total, which the closed grant counts, would rise
//! after b's reservation used the headroom, and the identity would hold
//! 8.00 above P-05 (I-14).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{LineId, RequestId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, LB, MoneyDraft, MoneySetup, MoneyStory, PA, PB, REL, accept_line, amount_decision,
    approve_payment, complete, confirm_paid, determine, milestone_n, release_payment,
    request_payment, terminate,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 100]);
    s.drafts = vec![
        MoneyDraft {
            lead: LA,
            proposal: PA,
            minor: false,
            milestones: vec![(milestone_n(PA, 0), 200, T0), (milestone_n(PA, 1), 200, T0)],
            negotiate: true,
        },
        MoneyDraft::one(LB, PB, 400),
    ];
    s.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    s
}

fn paid_one_milestone(b: Backend) -> MoneyStory {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.execute(PA)
        .unwrap_or_else(|e| panic!("a granted 4.00 and in execution: {e}"));
    let b4 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&b4)
        .unwrap_or_else(|e| panic!("I-14: a's 4.00 plus b's 4.00 exceeds 6.00: {e}"));
    let r = RequestId::from_raw(35_001);
    let line = LineId::from_raw(135_001);
    s.run(&request_payment(LA, r, PA, &[(line, milestone_n(PA, 0), 200)]).unwrap())
        .unwrap_or_else(|e| panic!("R-EX-01: a requests the first milestone: {e}"));
    s.run(&accept_line(R1, r, line, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("R1 accepts the line: {e}"));
    s.run(&approve_payment(FINREL, r))
        .unwrap_or_else(|e| panic!("the finance approver approves: {e}"));
    s.run(&release_payment(REL, r))
        .unwrap_or_else(|e| panic!("I-05: a third account releases: {e}"));
    s.run(&confirm_paid(r))
        .unwrap_or_else(|e| panic!("the payment port confirms: {e}"));
    s.refused(&b4)
        .unwrap_or_else(|e| panic!("I-64: before closure a's grant still counts 4.00: {e}"));
    s
}

fn completed(b: Backend) {
    let mut s = paid_one_milestone(b);
    s.refused(&complete(PA))
        .unwrap_or_else(|e| panic!("NOTE 12: COMPLETED needs every milestone closed: {e}"));
    s.close_milestones(PA)
        .unwrap_or_else(|e| panic!("NOTE 12: the programme manager closes each milestone: {e}"));
    s.run(&complete(PA))
        .unwrap_or_else(|e| panic!("NOTE 12: every milestone closed, every request terminal: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Completed));
    assert_eq!(
        s.world.money.counted(PA),
        200,
        "I-64: the closed grant counts its paid 2.00"
    );
    let b4 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&b4)
        .unwrap_or_else(|e| panic!("I-64, I-14: 2.00 paid plus 4.00 fits P-05 6.00: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn terminated(b: Backend) {
    let mut s = paid_one_milestone(b);
    s.run(&terminate(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("the programme manager terminates a's grant: {e}"));
    assert_eq!(s.state(PA), Some(StateTag::Terminated));
    assert_eq!(
        s.world.money.counted(PA),
        200,
        "I-64: the terminated grant counts its paid 2.00"
    );
    let b4 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&b4)
        .unwrap_or_else(|e| panic!("I-64, I-14: 2.00 paid plus 4.00 fits P-05 6.00: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn approved_then_terminated(b: Backend) {
    let mut s = paid_one_milestone(b);
    let r = RequestId::from_raw(35_002);
    let line = LineId::from_raw(135_002);
    s.run(&request_payment(LA, r, PA, &[(line, milestone_n(PA, 1), 200)]).unwrap())
        .unwrap_or_else(|e| panic!("a requests the second milestone: {e}"));
    s.run(&accept_line(R1, r, line, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("R1 accepts the line: {e}"));
    s.run(&approve_payment(FINREL, r))
        .unwrap_or_else(|e| panic!("the finance approver approves: {e}"));
    s.run(&terminate(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("the programme manager terminates a's grant: {e}"));
    assert_eq!(s.world.money.counted(PA), 200, "I-64: the paid 2.00 only");
    let b4 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&b4)
        .unwrap_or_else(|e| panic!("I-64, I-14: 2.00 paid plus 4.00 fits P-05 6.00: {e}"));
    s.refused(&release_payment(REL, r)).unwrap_or_else(|e| {
        panic!("I-64, I-14: a release after termination would raise a's 2.00 to 4.00: {e}")
    });
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-64, P-67: a completed grant counts only its paid total against P-05.
#[test]
fn i64_completed_grant_counts_its_paid_total() {
    completed(Backend::Production);
}

/// I-64, P-67: a terminated grant counts only its paid total against P-05.
#[test]
fn i64_terminated_grant_counts_its_paid_total() {
    terminated(Backend::Production);
}

/// I-64, I-14: a payment approved before the termination is not released after it.
#[test]
fn i64_i14_no_release_after_termination() {
    approved_then_terminated(Backend::Production);
}

/// I-64: the stories pass on the references alone.
#[test]
fn i64_stories_pass_on_the_reference() {
    completed(Backend::Reference);
    terminated(Backend::Reference);
    approved_then_terminated(Backend::Reference);
}

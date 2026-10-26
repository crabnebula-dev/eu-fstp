//! NOTE 12, O-51: COMPLETED needs every milestone closed by the programme manager and every payment request terminal, and a waiting request can be closed (payment-requests.md Milestone closure).
//!
//! Lead c is granted 4.00 over two milestones of 2.00 and starts execution
//! from genesis by production commands. A request for the first milestone
//! is paid. A second request, for the second milestone, is returned with
//! requested changes. `Complete` is refused while a milestone is open and
//! while the second request waits in CHANGES_REQUESTED. Only the programme
//! manager closes a milestone or a waiting request, each with a reason.
//! A request in SUBMITTED cannot be closed. Once both milestones are
//! closed and the waiting request is CLOSED, the System completes the
//! grant, although the second milestone was never paid (P-67).
//!
//! `CloseMilestone` and `ClosePaymentRequest` are new commands of lane
//! L-MONEY. Until the command codec knows them, the production stories
//! fail when building them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::id::{LineId, RequestId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneyDraft, MoneySetup, MoneyStory, PC, REL, accept_line, approve_payment,
    complete, confirm_paid, milestone_n, release_payment, request_changes, request_payment,
};
use fstp_domain_testkit::r#gen::review::{R1, R2};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0};
use fstp_domain_testkit::reference::money::Ext;
use fstp_domain_testkit::reference::payment::RequestState;

const PAID: RequestId = RequestId::from_raw(36_001);
const WAITING: RequestId = RequestId::from_raw(36_002);
const FRESH: RequestId = RequestId::from_raw(36_003);

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts = vec![MoneyDraft {
        lead: LC,
        proposal: PC,
        minor: false,
        milestones: vec![(milestone_n(PC, 0), 200, T0), (milestone_n(PC, 1), 200, T0)],
        negotiate: true,
    }];
    s.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    s
}

fn in_execution(b: Backend) -> MoneyStory {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.execute(PC)
        .unwrap_or_else(|e| panic!("c granted and in execution: {e}"));
    let l1 = LineId::from_raw(136_001);
    s.run(&request_payment(LC, PAID, PC, &[(l1, milestone_n(PC, 0), 200)]).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&accept_line(R1, PAID, l1, 200, false).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&approve_payment(FINREL, PAID))
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&release_payment(REL, PAID))
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&confirm_paid(PAID)).unwrap_or_else(|e| panic!("{e}"));
    let l2 = LineId::from_raw(136_002);
    s.run(&request_payment(LC, WAITING, PC, &[(l2, milestone_n(PC, 1), 100)]).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&request_changes(R2, WAITING))
        .unwrap_or_else(|e| panic!("{e}"));
    s
}

fn closed(s: &mut MoneyStory, actor: Actor, x: Ext) -> bool {
    s.ext(actor, x)
        .unwrap_or_else(|e| panic!("{x:?} by {actor:?}: {e}"))
        .is_some()
}

fn milestones(b: Backend) {
    let mut s = in_execution(b);
    let m0 = Ext::CloseMilestone {
        proposal: PC,
        milestone: milestone_n(PC, 0),
    };
    let m1 = Ext::CloseMilestone {
        proposal: PC,
        milestone: milestone_n(PC, 1),
    };
    for actor in [
        Actor::Account(LC),
        Actor::Account(R1),
        Actor::Account(FINREL),
    ] {
        assert!(
            !closed(&mut s, actor, m0),
            "NOTE 12: only the programme manager closes a milestone"
        );
    }
    assert!(
        closed(&mut s, Actor::Account(STAFF_PM), m0),
        "NOTE 12: the programme manager closes it"
    );
    assert!(
        !closed(&mut s, Actor::Account(STAFF_PM), m0),
        "a closed milestone stays closed"
    );
    s.refused(&complete(PC))
        .unwrap_or_else(|e| panic!("NOTE 12: the second milestone is open: {e}"));
    assert!(
        closed(&mut s, Actor::Account(STAFF_PM), m1),
        "P-67: an unpaid milestone may close"
    );
    s.refused(&complete(PC))
        .unwrap_or_else(|e| panic!("NOTE 12: a request waits in CHANGES_REQUESTED: {e}"));
    let waiting = Ext::ClosePaymentRequest { request: WAITING };
    assert!(
        !closed(&mut s, Actor::Account(LC), waiting),
        "O-51: the programme manager closes a request"
    );
    assert!(
        closed(&mut s, Actor::Account(STAFF_PM), waiting),
        "O-51: a waiting request closes"
    );
    assert_eq!(
        s.world.money.pay.requests.get(&WAITING).map(|r| r.state),
        Some(RequestState::Closed)
    );
    let mut by_pm = complete(PC);
    by_pm.actor = Actor::Account(STAFF_PM);
    s.refused(&by_pm)
        .unwrap_or_else(|e| panic!("NOTE 13: the System records IN_EXECUTION to COMPLETED: {e}"));
    s.run(&complete(PC))
        .unwrap_or_else(|e| panic!("NOTE 12: every milestone closed, every request terminal: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Completed));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn submitted_request_stays_open(b: Backend) {
    let mut s = in_execution(b);
    let l3 = LineId::from_raw(136_003);
    s.run(&request_payment(LC, FRESH, PC, &[(l3, milestone_n(PC, 1), 50)]).unwrap())
        .unwrap_or_else(|e| panic!("{e}"));
    let fresh = Ext::ClosePaymentRequest { request: FRESH };
    assert!(
        !closed(&mut s, Actor::Account(STAFF_PM), fresh),
        "O-51: only CHECKS_FAILED or CHANGES_REQUESTED requests close"
    );
    let paid = Ext::ClosePaymentRequest { request: PAID };
    assert!(
        !closed(&mut s, Actor::Account(STAFF_PM), paid),
        "a PAID request is terminal"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// NOTE 12, O-51, P-67: the programme manager closes milestones and a
/// waiting request, and the System then completes the grant.
#[test]
fn r_ex_milestone_closure_and_completion() {
    milestones(Backend::Production);
}

/// O-51: a submitted or paid request cannot be closed.
#[test]
fn r_ex_close_payment_request_only_while_waiting() {
    submitted_request_stays_open(Backend::Production);
}

/// NOTE 12: the stories pass on the references alone.
#[test]
fn r_ex_closure_stories_pass_on_the_reference() {
    milestones(Backend::Reference);
    submitted_request_stays_open(Backend::Reference);
}

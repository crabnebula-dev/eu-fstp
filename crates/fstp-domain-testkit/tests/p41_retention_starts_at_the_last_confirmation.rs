//! P-41 retention reminder (Daniel, 2026-11-15 late, m3-exit-audit
//! section 9): retention of a grant starts at the confirmation of its last
//! payment request and ends P-41 years later (`fstp_domain::retention`).
//!
//! Lead c is granted 4.00 over two milestones and starts execution from
//! genesis by production commands. One request is paid and confirmed at
//! `t1`. A second request waits, then closes. While the grant is open
//! there is no start. Once it is COMPLETED, retention starts at `t1`.
//! The synthetic policy holds no readable P-41, so no end is derived
//! until the programme manager sets P-41 to seven years.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use fstp_domain::command::Actor;
use fstp_domain::id::{LineId, PolicyVersionId, RequestId};
use fstp_domain::policy::OpaqueValue;
use fstp_domain::retention::{add_years, p41_years, retention_ends, retention_start};
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneyDraft, MoneySetup, MoneyStory, PC, REL, accept_line, approve_payment,
    complete, confirm_paid, milestone_n, release_payment, request_changes, request_payment,
};
use fstp_domain_testkit::r#gen::review::{R1, R2};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, T0, edit_policy};
use fstp_domain_testkit::reference::money::Ext;

const PAID: RequestId = RequestId::from_raw(41_001);
const WAITING: RequestId = RequestId::from_raw(41_002);
const DAY: i64 = 86_400_000_000;

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

/// P-41: retention starts at the last confirmation of a closed grant, and
/// ends P-41 years later once P-41 is set.
#[test]
fn p41_retention_starts_at_the_last_confirmation_of_a_closed_grant() {
    let mut s = MoneyStory::new(&setup(), Backend::Production).unwrap();
    s.execute(PC).unwrap();
    let l1 = LineId::from_raw(141_001);
    s.run(&request_payment(LC, PAID, PC, &[(l1, milestone_n(PC, 0), 200)]).unwrap())
        .unwrap();
    s.run(&accept_line(R1, PAID, l1, 200, false).unwrap())
        .unwrap();
    s.run(&approve_payment(FINREL, PAID)).unwrap();
    s.run(&release_payment(REL, PAID)).unwrap();
    let state = |s: &MoneyStory| s.world.life.rev.sod.state.clone();
    let mut confirmed = BTreeMap::new();
    assert_eq!(
        retention_start(&state(&s), PC, &confirmed),
        None,
        "an open grant has no start"
    );
    let t1 = Timestamp::from_micros(s.world.now().micros() + DAY);
    s.at(t1);
    s.run(&confirm_paid(PAID)).unwrap();
    confirmed.insert(PAID, t1);
    let l2 = LineId::from_raw(141_002);
    s.run(&request_payment(LC, WAITING, PC, &[(l2, milestone_n(PC, 1), 100)]).unwrap())
        .unwrap();
    s.run(&request_changes(R2, WAITING)).unwrap();
    assert_eq!(
        retention_start(&state(&s), PC, &confirmed),
        None,
        "IN_EXECUTION: the last payment is not known yet"
    );
    s.close_milestones(PC).unwrap();
    let waiting = Ext::ClosePaymentRequest { request: WAITING };
    assert!(s.ext(Actor::Account(STAFF_PM), waiting).unwrap().is_some());
    s.at(Timestamp::from_micros(t1.micros() + 30 * DAY));
    s.run(&complete(PC)).unwrap();
    assert_eq!(s.state(PC), Some(StateTag::Completed));
    let st = state(&s);
    assert_eq!(retention_start(&st, PC, &confirmed), Some(t1));
    assert_eq!(
        retention_start(&st, PC, &BTreeMap::new()),
        None,
        "a PAID request with no known confirmation fails closed"
    );
    let programme = fstp_domain::publicity::programme_of(&st, PC).unwrap();
    assert_eq!(p41_years(&st, programme), None, "synthetic P-41 is unset");
    assert!(retention_ends(&st, &confirmed).is_empty());

    let head = s.world.head.as_deref().unwrap().clone();
    let years = fstp_json::parse(br#"{"years":7}"#).unwrap();
    let edit = edit_policy(&head, PolicyVersionId::from_raw(41_900), |v| {
        v.live
            .opaque
            .insert(ParamId::P41, OpaqueValue::from_value(&years).unwrap());
    });
    s.run(&edit).unwrap();
    let st = state(&s);
    let seven = p41_years(&st, programme).unwrap();
    assert_eq!(seven.get(), 7);
    let ends = retention_ends(&st, &confirmed);
    assert_eq!(ends.len(), 1, "{ends:?}");
    assert_eq!(ends[0].grant, PC);
    assert_eq!(ends[0].programme, programme);
    assert_eq!(ends[0].start, t1);
    assert_eq!(Some(ends[0].end), add_years(t1, seven));
    assert!(ends[0].end.micros() >= t1.micros() + 7 * 365 * DAY);
}

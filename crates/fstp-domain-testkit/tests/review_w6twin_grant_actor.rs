//! Review reproducer for lane w6-twin: who records NEGOTIATION to GRANTED (R-LA-03, NOTE 13).
//!
//! The row's actor is "Applicant and programme manager". When the contract
//! port's EFFECTIVE fact is the last of the three grant facts, the
//! transition must still name a human, never the System. The conformance
//! test `r_la_03_no_decision_row_recorded_by_the_system_over_the_whole_lifecycle`
//! found the breach.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::record::Record;
use fstp_domain::rules::Row;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};

/// R-LA-03, NOTE 13, row NEGOTIATION to GRANTED: with the contract fact
/// last, the transition is recorded by the approving programme manager.
#[test]
fn review_w6twin_r_la_03_grant_completed_by_the_contract_port_names_a_human() {
    let mut setup = MoneySetup::sybil([400, 400, 300]);
    setup.drafts.retain(|d| d.proposal == PC);
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 3.00: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("c accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    let records = s
        .run(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("the contract port reports EFFECTIVE: {e}"));
    let actor = records
        .iter()
        .find_map(|r| match r {
            Record::Transitioned(t) if t.row == Row::NegotiationToGranted => Some(t.actor),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no NEGOTIATION to GRANTED transition in {records:#?}"));
    assert_eq!(
        actor,
        Actor::Account(STAFF_PM),
        "R-LA-03: the grant is a decision, so the approving programme manager records it"
    );
}

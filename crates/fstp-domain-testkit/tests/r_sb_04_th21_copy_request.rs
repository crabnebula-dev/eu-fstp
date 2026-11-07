//! R-SB-04 and TH-21 (M6 design reading 4 and section 6, lane L6-API):
//! a copy request is a domain command. It appends one
//! `OutboxEnqueued(CopyRequested)` that holds ids only, at most three per
//! proposal per day.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod i37_support;

use fstp_domain::command::Command;
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{L1, L2, PR1, PR2};
use i37_support::ConsentWorld;

const DAY: i64 = fstp_domain::proposal::copy::DAY_MICROS;

fn copy(
    w: &mut ConsentWorld,
    lead: fstp_domain::id::AccountId,
    p: fstp_domain::id::ProposalId,
) -> Result<Vec<Record>, RuleRef> {
    let address = text(4_000);
    match w
        .exec(
            lead,
            Command::RequestCopy {
                proposal: p,
                address,
            },
        )
        .unwrap()
    {
        Ok(entries) => Ok(entries.into_iter().map(|(_, r)| r).collect()),
        Err(r) => Err(r.rule),
    }
}

/// R-SB-04, M6 design reading 4: the lead's request appends exactly one
/// `OutboxEnqueued(CopyRequested)`, naming the proposal and the sealed
/// address text by reference. Its encoding names no member but the
/// variant's ids.
#[test]
fn r_sb_04_copy_request_appends_one_outbox_record_with_ids_only() {
    let mut w = ConsentWorld::new(false).unwrap();
    let got = copy(&mut w, L1, PR1).unwrap();
    assert_eq!(
        got,
        vec![Record::OutboxEnqueued(OutboxEvent::CopyRequested {
            proposal: PR1,
            address: text(4_000),
        })]
    );
    let json = fstp_json::ToJson::to_json(&got[0]);
    let text = fstp_json::to_canonical(&json).unwrap();
    for member in ["\"address\"", "\"proposal\"", "\"digest\"", "\"id\""] {
        assert!(text.contains(member), "{member} in {text}");
    }
    assert!(!text.contains('@'), "no address in the record: {text}");
}

/// R-SB-04: only the lead of the proposal asks for its copy.
#[test]
fn r_sb_04_only_the_lead_requests_a_copy() {
    let mut w = ConsentWorld::new(false).unwrap();
    assert_eq!(copy(&mut w, L2, PR1).unwrap_err(), RuleRef::Actor);
    assert!(w.tail.is_empty());
}

/// TH-21, R-SB-04: a fourth copy of one proposal in a day is refused, a
/// copy of another proposal is not affected, and a day after the first
/// the lead may ask again.
#[test]
fn th21_copy_requests_are_limited_per_proposal_per_day() {
    let mut w = ConsentWorld::new(false).unwrap();
    let start = w.now.micros();
    for i in 0..3 {
        w.now = Timestamp::from_micros(start + i);
        assert!(copy(&mut w, L1, PR1).is_ok(), "copy {i}");
    }
    w.now = Timestamp::from_micros(start + 10);
    assert_eq!(copy(&mut w, L1, PR1).unwrap_err(), RuleRef::Rsb04);
    assert!(copy(&mut w, L2, PR2).is_ok(), "another proposal");
    w.now = Timestamp::from_micros(start + DAY - 1);
    assert_eq!(copy(&mut w, L1, PR1).unwrap_err(), RuleRef::Rsb04);
    w.now = Timestamp::from_micros(start + DAY);
    assert!(copy(&mut w, L1, PR1).is_ok(), "a day later");
    let copies = w
        .tail
        .iter()
        .filter(|(_, r)| {
            matches!(r, Record::OutboxEnqueued(OutboxEvent::CopyRequested { proposal, .. }) if *proposal == PR1)
        })
        .count();
    assert_eq!(copies, 4);
}

/// R-SB-04: the fold keeps the submission instant the copy email names.
#[test]
fn r_sb_04_submission_instant_is_known_after_submission() {
    let w = ConsentWorld::new(false).unwrap();
    assert!(fstp_domain::proposal::copy::submitted_at(&w.state, PR1).is_some());
}

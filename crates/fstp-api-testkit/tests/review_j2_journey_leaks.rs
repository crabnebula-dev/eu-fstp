//! Review reproducers J2-R1 and J2-R2 (I-21, R-AC-01, I-93): a draft
//! withdrawn before submission keeps its route closed to staff, and the
//! team's diary holds no unpublished call drafting history.
//!
//! Each test drives `ApiCore::dispatch` on the fake cell over the I-85
//! world, where the lead holds the Receiving binding of the draft PX in
//! the open call. Every account is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{LEAD, OWNER, PX};
use fstp_json::ToJson;

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// J2-R1, I-21: after the lead withdraws the draft, the programme
/// manager of its programme is refused its route and its diary.
#[test]
fn review_i21_withdrawn_draft_route_stays_closed_to_staff() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let path = format!("/proposals/{}/withdrawal", PX.raw());
    let r = c.web(&lead, decode_route(Method::Post, &path, b"{}"));
    assert!(matches!(r, Ok(OpResult::Done { .. })), "withdraw: {r:?}");
    let owner = c.login(OWNER, LoginMethod::Passkey);
    for read in ["journey", "diary"] {
        let path = format!("/proposals/{}/{read}", PX.raw());
        match c.web(&owner, decode_route(Method::Get, &path, b"")) {
            Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "I-21", "{read}"),
            other => panic!("I-21: proposal.{read} of a withdrawn draft for staff: {other:?}"),
        }
    }
}

/// J2-R2, R-AC-01: the lead's diary holds no entry of the call's drafting
/// records, which precede publication.
#[test]
fn review_r_ac_01_team_diary_holds_no_unpublished_call_drafts() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let path = format!("/proposals/{}/diary", PX.raw());
    let text = match c.web(&lead, decode_route(Method::Get, &path, b"")) {
        Ok(OpResult::Done { body, .. }) => body.to_json().to_compact(),
        other => panic!("proposal.diary for the lead: {other:?}"),
    };
    for key in ["journey.deadline.set", "journey.deadline.moved"] {
        assert!(
            !text.contains(key),
            "R-AC-01: the team's diary holds a call drafting entry {key}: {text}"
        );
    }
}

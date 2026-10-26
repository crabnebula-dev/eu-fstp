//! NOTE 12, O-51, I-23, ADR-007: the two new commands of lane L-MONEY round trip through the command codec and refuse unknown and missing members.
//!
//! `CloseMilestone { proposal, milestone, reason }` and
//! `ClosePaymentRequest { request, reason }` are built from their JSON
//! form, as the lane scope names their fields. Each must encode back to
//! the same canonical text. A form with an unknown member, or without
//! its reason, must be refused. Until the codec knows the commands,
//! building them fails, so this test is red.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{MilestoneId, ProposalId, RequestId};
use fstp_domain_testkit::r#gen::money::{close_milestone, close_request};
use fstp_domain_testkit::r#gen::roster::STAFF_PM;
use fstp_json::{ToJson, Value, to_canonical};

fn with_member(v: &Value, name: &str, value: Option<Value>) -> Value {
    let Value::Object(o) = v else {
        panic!("a command is an object");
    };
    let mut out = fstp_json::Object::new();
    for (k, x) in o.iter() {
        if k != name {
            let _ = out.insert(k, x.clone());
        }
    }
    if let Some(x) = value {
        let _ = out.insert(name, x);
    }
    Value::Object(out)
}

fn round_trip(v: &Value) {
    let text = to_canonical(v).unwrap();
    let back = fstp_domain::codec::command_from_json(v)
        .unwrap_or_else(|e| panic!("I-23: the codec decodes {text}: {e:?}"));
    assert_eq!(
        to_canonical(&back.to_json()).unwrap(),
        text,
        "I-23: one spelling"
    );
    let extra = with_member(v, "unknown", Some(Value::String("1".to_owned())));
    assert!(
        fstp_domain::codec::command_from_json(&extra).is_err(),
        "ADR-007: an unknown member is refused"
    );
    let missing = with_member(v, "reason", None);
    assert!(
        fstp_domain::codec::command_from_json(&missing).is_err(),
        "ADR-007: a missing member is refused"
    );
}

/// NOTE 12, I-23: `CloseMilestone` round trips and refuses unknown and missing members.
#[test]
fn r_ex_close_milestone_round_trips_through_the_codec() {
    let step = close_milestone(
        STAFF_PM,
        ProposalId::from_raw(13),
        MilestoneId::from_raw(613),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    round_trip(&step.cmd.to_json());
}

/// O-51, I-23: `ClosePaymentRequest` round trips and refuses unknown and missing members.
#[test]
fn r_ex_close_payment_request_round_trips_through_the_codec() {
    let step =
        close_request(STAFF_PM, RequestId::from_raw(36_002)).unwrap_or_else(|e| panic!("{e}"));
    round_trip(&step.cmd.to_json());
}

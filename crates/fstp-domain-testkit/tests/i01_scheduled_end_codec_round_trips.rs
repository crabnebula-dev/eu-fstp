//! I-01, I-23, ADR-007: the scheduled end forms round trip through the codecs (Cooling-off NOTE, decided 2026-10-25).
//!
//! The record `BindingEndScheduled { binding, at }` and the `end` member of
//! `GrantRole` are new. Each must decode from its canonical JSON form and
//! encode back to the same bytes, since stored bytes are unique (ADR-007).
//! A form with an unknown member or without a required one is refused.
//! The stub interface does not declare either yet, so these tests reach
//! them through their JSON forms and fail until the codecs know them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::record::Record;
use fstp_domain_testkit::reference::sod::{grant_end, scheduled_end_of};
use fstp_json::{FromJson, ToJson, Value, parse, to_canonical};

/// The canonical form of a scheduled end of binding 301 at 11 s.
const RECORD: &str = r#"{"at":"11000000","binding":"301","type":"BindingEndScheduled"}"#;

/// The canonical form of a committee grant with its end at 11 s.
const GRANT: &str = r#"{"account":"103","binding":"301","confidentiality":{"digest":"0000000000000000000000000000c47d00000000000000000000000000000000","id":"50301"},"end":"11000000","organisation":"103","programme":"1","role":"CommitteeMember","second_admin":null,"start":"1000000","type":"GrantRole"}"#;

fn value(text: &str) -> Value {
    parse(text.as_bytes()).unwrap_or_else(|e| panic!("json: {e:?}"))
}

fn with(text: &str, edit: impl FnOnce(&mut fstp_json::Object)) -> Value {
    let mut v = value(text);
    edit(v.as_object_mut().unwrap_or_else(|| panic!("not an object")));
    v
}

/// I-01, I-23, ADR-007: the scheduled end record round trips, and its
/// binding and instant read back. An unknown member or a missing `at` is
/// refused.
#[test]
fn i01_scheduled_end_record_round_trips() {
    let r = Record::from_json(&value(RECORD)).unwrap_or_else(|e| {
        panic!("the record codec does not know BindingEndScheduled yet (Cooling-off NOTE): {e:?}")
    });
    assert_eq!(to_canonical(&r.to_json()).unwrap(), RECORD);
    assert_eq!(
        scheduled_end_of(&r),
        Some((
            fstp_domain::id::BindingId::from_raw(301),
            fstp_domain::time::Timestamp::from_micros(11_000_000)
        ))
    );
    let extra = with(RECORD, |o| {
        o.insert("zz", Value::String("1".to_owned()));
    });
    assert!(
        Record::from_json(&extra).is_err(),
        "an unknown member is refused"
    );
    let missing = with(RECORD, |o| {
        o.remove("at");
    });
    assert!(
        Record::from_json(&missing).is_err(),
        "a missing instant is refused"
    );
}

/// I-01, I-23, ADR-007: a `GrantRole` with an `end` round trips, and the
/// end reads back. A `GrantRole` without an end carries `"end":null`, and
/// a form without the member is refused, as for every other member.
#[test]
fn i01_grant_role_end_round_trips() {
    let c = fstp_domain::codec::command_from_json(&value(GRANT)).unwrap_or_else(|e| {
        panic!("GrantRole carries no scheduled end yet (Cooling-off NOTE): {e:?}")
    });
    assert!(matches!(c, Command::GrantRole { .. }));
    assert_eq!(to_canonical(&c.to_json()).unwrap(), GRANT);
    assert_eq!(
        grant_end(&c),
        Some(fstp_domain::time::Timestamp::from_micros(11_000_000))
    );
    let none = with(GRANT, |o| {
        o.insert("end", Value::Null);
    });
    let c = fstp_domain::codec::command_from_json(&none)
        .unwrap_or_else(|e| panic!("a GrantRole without an end: {e:?}"));
    assert_eq!(grant_end(&c), None);
    let missing = with(GRANT, |o| {
        o.remove("end");
    });
    assert!(
        fstp_domain::codec::command_from_json(&missing).is_err(),
        "a GrantRole without the end member is refused"
    );
}

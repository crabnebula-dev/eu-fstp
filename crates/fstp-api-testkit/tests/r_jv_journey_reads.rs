//! R-JV-01, R-JV-03, I-93, I-97, `SPEC/12-journey-ui.md` section 10: the
//! read operations for a proposal's route position and its diary.
//!
//! `proposal.journey` (`GET /proposals/{proposal}/journey`) gives the
//! position, the completed legs and the overlay. `proposal.diary` (`GET
//! /proposals/{proposal}/diary`) gives the diary entries the visibility
//! function lets the caller see. Both admit the proposal's team and
//! permitted staff, and both are registered in `fstp-access` with their
//! read rules, so the same authorisation and audit path applies (I-84).
//!
//! Each test drives `ApiCore::dispatch` on the fake cell over the I-85
//! world, where the lead holds the Receiving binding of the draft PX.
//! Every account and text is synthetic.
//!
//! Lane j2 test author. Red until the implementer registers and
//! dispatches the two reads: today neither operation exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{Method as RegistryMethod, op};
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{ADMIN, LEAD, OTHER, PX};
use fstp_domain::id::AccountId;
use fstp_json::{Object, ToJson, Value};

/// The canary text the lead saves in the workspace: untrusted submission
/// content that no journey reply may carry.
const CANARY: &str = "CANARY workspace text JOURNEYx7f3a9c";

/// The part of the canary every check looks for.
const CANARY_MARK: &str = "JOURNEYx7f3a9c";

/// The two reads and their routes (section 10).
fn reads() -> [(&'static str, String); 2] {
    [
        (
            "proposal.journey",
            format!("/proposals/{}/journey", PX.raw()),
        ),
        ("proposal.diary", format!("/proposals/{}/diary", PX.raw())),
    ]
}

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn read(c: &FakeCell, account: AccountId, path: &str) -> Result<OpResult, ApiError> {
    let login = c.login(account, LoginMethod::Passkey);
    c.web(&login, decode_route(Method::Get, path, b""))
}

/// R-JV-01, section 10: both reads are registered as GET routes of the
/// web channel, under the section 10 paths.
#[test]
fn r_jv_01_journey_and_diary_reads_are_registered() {
    for (name, want) in [
        ("proposal.journey", "/proposals/{proposal}/journey"),
        ("proposal.diary", "/proposals/{proposal}/diary"),
    ] {
        let spec = op(name).unwrap_or_else(|| panic!("section 10: no {name}"));
        assert_eq!(
            spec.route,
            Some((RegistryMethod::Get, want)),
            "section 10: route of {name}"
        );
        assert!(
            !spec.high_risk && !spec.binding,
            "{name} is a read: {spec:?}"
        );
    }
}

/// R-JV-01, I-93: the proposal's lead reads its route position and its
/// diary.
#[test]
fn i93_journey_reads_admit_the_team() {
    let c = cell();
    for (name, path) in reads() {
        let r = read(&c, LEAD, &path);
        assert_eq!(class(&r), Class::Done, "{name} for the lead: {r:?}");
    }
}

/// I-93, R-AC-01: a call drafter and a tenant admin, who hold no relation
/// to the draft, are refused both reads. A hidden page is never the only
/// protection.
#[test]
fn i93_journey_reads_refuse_callers_outside_the_proposal() {
    let c = cell();
    for (name, path) in reads() {
        for who in [OTHER, ADMIN] {
            let r = read(&c, who, &path);
            assert!(
                class(&r).refused(),
                "{name} for {who:?} must be refused: {r:?}"
            );
        }
    }
}

/// Whether `s` is a token: a state name, catalogue key, id, digest,
/// sequence number, time, zone or ADR-006 amount. Free text holds spaces
/// or other characters, so it never is one.
fn token(s: &str) -> bool {
    s.len() <= 96
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'+' | b'-' | b'/')
        })
}

/// Every string value of `v` that is not a token, with its path.
fn free_text(v: &Value, at: &str, out: &mut Vec<String>) {
    match v {
        Value::String(s) if !token(s) => out.push(format!("{at}: {s:?}")),
        Value::Object(o) => {
            for (k, member) in o.iter() {
                free_text(member, &format!("{at}.{k}"), out);
            }
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                free_text(item, &format!("{at}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// I-97, R-JV-11: after the lead saves a canary text in the workspace,
/// neither reply holds it, and every string in either reply is a token,
/// never free text.
#[test]
fn i97_journey_replies_hold_no_free_text() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let mut o = Object::new();
    for k in ["narrative", "summary", "title"] {
        let _ = o.insert(k, Value::from(CANARY));
    }
    let body = Value::Object(o).to_compact().into_bytes();
    let saved = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{}/workspace", PX.raw()),
            &body,
        ),
    );
    assert_eq!(class(&saved), Class::Done, "the canary save: {saved:?}");
    for (name, path) in reads() {
        let reply = match read(&c, LEAD, &path) {
            Ok(OpResult::Done { body, .. }) => body.to_json(),
            other => panic!("{name} for the lead: {other:?}"),
        };
        let text = reply.to_compact();
        assert!(
            !text.contains(CANARY_MARK),
            "I-97: {name} holds the canary: {text}"
        );
        let mut found = Vec::new();
        free_text(&reply, name, &mut found);
        assert!(found.is_empty(), "I-97: {name} holds free text: {found:#?}");
    }
}

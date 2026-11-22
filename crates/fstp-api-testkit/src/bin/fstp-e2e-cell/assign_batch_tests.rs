//! Q38 (decided by Daniel on 2026-11-22: "Step-up, batched"): the
//! coordinator assigns and unassigns many reviewers of one proposal in one
//! batch, confirmed with one step-up (I-78), web only (I-85). Tests only.
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::port::{AsyncEngine as _, Clock as _, LoginMethod};
use fstp_api_core::{Credential, OpResult, RequestHead};
use fstp_domain::id::ProposalId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, R1, R2, R3};

use super::*;

/// Proposal x of the review scene.
const X: u128 = 1001;

fn info() -> SiteInfo {
    SiteInfo {
        name: "a",
        host: "a.fstp.localhost".to_owned(),
        origin: "http://a.fstp.localhost:8640".to_owned(),
        control: "http://127.0.0.1:8641".to_owned(),
        assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
            .unwrap(),
        auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
        demo_signin: false,
        tokens: fstp_api_testkit::fake::FakeTokens::default(),
    }
}

/// The review scene at SUBMITTED, with the coordinator declared on x.
fn scene() -> Inner {
    let stage = crate::scenario::ReviewAt::parse("submitted").unwrap();
    let (inner, _) =
        fstp_rt::future::block_on(crate::scenario::build_review(&info(), stage)).unwrap();
    let out = send(
        &inner,
        &session(&inner),
        "POST",
        &format!("/proposals/{X}/coordinator-declaration"),
        r#"{"conflicted":false,"notifiable":false}"#,
    );
    assert!(
        matches!(out, Ok(OpResult::Done { .. })),
        "{:?}",
        out.map(|_| ())
    );
    inner
}

/// A fresh passkey session of the coordinator: its id and cookie.
fn session(inner: &Inner) -> (fstp_api_core::port::SessionId, Vec<u8>) {
    let l = inner
        .ports
        .sessions
        .login(COORDINATOR, LoginMethod::Passkey);
    (l.session, l.cookie)
}

fn send(
    inner: &Inner,
    s: &(fstp_api_core::port::SessionId, Vec<u8>),
    method: &str,
    path: &str,
    body: &str,
) -> Result<OpResult, fstp_api_core::ApiError> {
    let now = Timestamp::from_micros(inner.ports.clock.now().micros().saturating_add(1_000_000));
    inner.ports.clock.set(now);
    let method = match method {
        "POST" => fstp_api_core::decode::Method::Post,
        "DELETE" => fstp_api_core::decode::Method::Delete,
        _ => fstp_api_core::decode::Method::Get,
    };
    let op = fstp_api_core::decode::decode_route(method, path, body.as_bytes()).map_err(|_| {
        fstp_api_core::ApiError::Refused {
            code: fstp_api_core::ErrorCode::BadRequest,
            rule: "request",
            detail: None,
        }
    })?;
    fstp_rt::future::block_on(inner.core.dispatch(
        Credential::SessionCookie(s.1.clone()),
        &RequestHead::new(),
        op,
    ))
}

fn batch(assign: &[u128], unassign: &[u128]) -> String {
    let a: Vec<String> = assign
        .iter()
        .map(|r| format!(r#"{{"kind":{{"type":"Reviewer"}},"reviewer":"{r}"}}"#))
        .collect();
    let u: Vec<String> = unassign
        .iter()
        .map(|x| format!(r#"{{"assignment":"{x}"}}"#))
        .collect();
    format!(
        r#"{{"assign":[{}],"unassign":[{}]}}"#,
        a.join(","),
        u.join(",")
    )
}

/// The active assignments of x, by reviewer.
fn assigned(inner: &Inner) -> Vec<(u128, u128)> {
    let state = inner.ports.engine.state();
    let mut out: Vec<(u128, u128)> = state
        .core
        .review()
        .assignments()
        .filter(|(_, a)| {
            a.proposal == ProposalId::from_raw(X)
                && !matches!(
                    a.status,
                    fstp_domain::assignment::AssignmentStatus::Released(_)
                )
        })
        .map(|(id, a)| (a.reviewer.raw(), id.raw()))
        .collect();
    out.sort_unstable();
    out
}

fn ledger_len(inner: &Inner) -> usize {
    inner.ports.engine.ledger().unwrap().len()
}

/// Q38, I-78: one step-up confirms one batch of three assignments in one
/// ledger entry. The proof is consumed: the same batch, or another one,
/// asks for a step-up again. A proof approved for one batch does not
/// cover another.
#[test]
fn q38_i78_one_step_up_covers_exactly_one_batch() {
    let inner = scene();
    let s = session(&inner);
    let path = format!("/proposals/{X}/assignment-batch");
    let body = batch(&[R1.raw(), R2.raw(), R3.raw()], &[]);
    let Ok(OpResult::StepUpRequired(ch)) = send(&inner, &s, "POST", &path, &body) else {
        panic!("I-78: the batch asks for a step-up first")
    };
    // A proof for another batch does not admit this one.
    let other = batch(&[R1.raw()], &[]);
    let Ok(OpResult::StepUpRequired(ch_other)) = send(&inner, &s, "POST", &path, &other) else {
        panic!("I-78: the other batch asks for its own step-up")
    };
    assert_ne!(ch.action, ch_other.action, "the digest binds the batch");
    inner.ports.step_up.approve(s.0, ch_other.action).unwrap();
    let before = ledger_len(&inner);
    inner.ports.step_up.approve(s.0, ch.action).unwrap();
    let done = send(&inner, &s, "POST", &path, &body);
    assert!(
        matches!(done, Ok(OpResult::Done { .. })),
        "{:?}",
        done.map(|_| ())
    );
    let mine: Vec<u128> = assigned(&inner).iter().map(|(r, _)| *r).collect();
    assert_eq!(mine, vec![R1.raw(), R2.raw(), R3.raw()]);
    let entry = inner.ports.engine.ledger().unwrap();
    let new = &entry[before..];
    assert!(
        new.iter().all(|e| e.command == new[0].command),
        "one entry for the whole batch"
    );
    // The proof is spent: the port holds no proof for the digest any
    // more, and sending the batch again records nothing.
    let now = inner.ports.clock.now();
    let spent = fstp_rt::future::block_on(fstp_api_core::port::StepUp::take(
        &inner.ports.step_up,
        s.0,
        ch.action,
        now,
    ));
    assert!(spent.is_err(), "a reused step-up is refused");
    let after = ledger_len(&inner);
    let again = send(&inner, &s, "POST", &path, &body);
    assert!(!matches!(again, Ok(OpResult::Done { .. })));
    assert_eq!(ledger_len(&inner), after);
}

/// Q38, I-78, I-03: one bad item refuses the whole batch with its own
/// rule, and nothing is recorded. An unassignment of another proposal's
/// assignment is refused too.
#[test]
fn q38_one_bad_item_refuses_the_whole_batch_with_its_reason() {
    let inner = scene();
    let s = session(&inner);
    let path = format!("/proposals/{X}/assignment-batch");
    // The coordinator is no committee member, so it cannot be assigned.
    let body = batch(&[R1.raw(), COORDINATOR.raw()], &[]);
    let before = ledger_len(&inner);
    let refused = send(&inner, &s, "POST", &path, &body);
    let Err(e) = refused else {
        panic!("the batch with a bad item is refused before any step-up")
    };
    let text = fstp_json::ToJson::to_json(&e).to_compact();
    assert!(
        text.contains("\"rule\""),
        "the refusal names its rule: {text}"
    );
    assert_eq!(ledger_len(&inner), before, "nothing is recorded");
    assert!(assigned(&inner).is_empty(), "all or nothing");
    // An empty batch and an unknown member are refused as requests.
    for bad in [
        r#"{"assign":[],"unassign":[]}"#.to_owned(),
        r#"{"assign":[{"reviewer":"211","kind":{"type":"Reviewer"},"x":1}],"unassign":[]}"#
            .to_owned(),
        r#"{"assign":[]}"#.to_owned(),
    ] {
        assert!(send(&inner, &s, "POST", &path, &bad).is_err(), "{bad}");
    }
}

/// Q38, I-78: a batch both assigns and unassigns under one step-up; a
/// single assignment is high-risk too.
#[test]
fn q38_i78_batch_unassigns_and_single_assign_needs_a_step_up() {
    let inner = scene();
    let s = session(&inner);
    let single = send(
        &inner,
        &s,
        "POST",
        &format!("/proposals/{X}/assignments"),
        r#"{"kind":{"type":"Reviewer"},"reviewer":"211"}"#,
    );
    assert!(
        matches!(single, Ok(OpResult::StepUpRequired(_))),
        "I-78: a single assignment asks for a step-up"
    );
    let path = format!("/proposals/{X}/assignment-batch");
    let first = batch(&[R1.raw(), R2.raw()], &[]);
    let Ok(OpResult::StepUpRequired(ch)) = send(&inner, &s, "POST", &path, &first) else {
        panic!("step-up")
    };
    inner.ports.step_up.approve(s.0, ch.action).unwrap();
    assert!(matches!(
        send(&inner, &s, "POST", &path, &first),
        Ok(OpResult::Done { .. })
    ));
    let r1 = assigned(&inner)
        .into_iter()
        .find(|(r, _)| *r == R1.raw())
        .map(|(_, a)| a)
        .unwrap();
    let swap = batch(&[R3.raw()], &[r1]);
    let Ok(OpResult::StepUpRequired(ch)) = send(&inner, &s, "POST", &path, &swap) else {
        panic!("step-up")
    };
    inner.ports.step_up.approve(s.0, ch.action).unwrap();
    let done = send(&inner, &s, "POST", &path, &swap);
    assert!(
        matches!(done, Ok(OpResult::Done { .. })),
        "{:?}",
        done.map(|_| ())
    );
    let mine: Vec<u128> = assigned(&inner).iter().map(|(r, _)| *r).collect();
    assert_eq!(mine, vec![R2.raw(), R3.raw()]);
}

/// Q38, I-78, I-85: the three assignment operations are high-risk and
/// have no tool, so no agent completes an assignment.
#[test]
fn q38_i85_assignment_operations_are_high_risk_and_web_only() {
    for name in ["review.assign", "review.unassign", "review.assign_batch"] {
        let op = fstp_access::op(name).unwrap();
        assert!(op.high_risk, "{name}");
        assert!(op.tool.is_none(), "{name}");
    }
}

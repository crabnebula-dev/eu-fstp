//! I-32, R-PR-02, R-PR-03: the domain reads of the production checks
//! runner (ADR-026 section "Written by lane `m10/checks-runner`").
//!
//! The runner asks the domain which requests await a run, and for the
//! input of each run: the lines with the evidence the lead gave, the
//! balances the I-58 and I-31 checks judge, and P-26. These tests pin both
//! reads over the world of `m5_pay`, with the synthetic checks off.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use fstp_domain::payment::{CheckPhase, awaiting_checks, checks_input};
use fstp_domain_testkit::r#gen::money::{line_evidence, record_checks};
use fstp_domain_testkit::r#gen::roster::Backend;
use m5_pay::{ask, line_id, milestone, must, request_id, world};

fn minor(a: fstp_money::NonNegAmount) -> i64 {
    a.amount().minor()
}

/// I-32, R-PR-02: a SUBMITTED request awaits its submission run, an
/// UNDER_REVIEW request its acceptance run, and a request whose runs both
/// passed, or whose checks failed, awaits nothing.
#[test]
fn i32_awaiting_checks_lists_submission_then_acceptance() {
    let mut w = world(Backend::Production, false).unwrap();
    w.auto_checks = false;
    let state = |w: &fstp_domain_testkit::r#gen::money::MoneyWorld| w.life.rev.sod.state.clone();
    assert!(awaiting_checks(&state(&w)).is_empty());
    must(&mut w, &ask(0, 0, 50, None, None).unwrap()).unwrap();
    assert_eq!(
        awaiting_checks(&state(&w)),
        vec![(request_id(0), CheckPhase::Submission)]
    );
    let lines = [line_id(0)];
    must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Submission, &lines, false),
    )
    .unwrap();
    assert_eq!(
        awaiting_checks(&state(&w)),
        vec![(request_id(0), CheckPhase::Acceptance)]
    );
    must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Acceptance, &lines, false),
    )
    .unwrap();
    assert!(awaiting_checks(&state(&w)).is_empty());
    must(&mut w, &ask(1, 1, 50, None, None).unwrap()).unwrap();
    must(
        &mut w,
        &record_checks(request_id(1), CheckPhase::Submission, &[line_id(1)], true),
    )
    .unwrap();
    assert!(
        awaiting_checks(&state(&w)).is_empty(),
        "R-PR-02: a request in CHECKS_FAILED awaits no run"
    );
    assert_eq!(checks_input(&state(&w), request_id(1)), None);
}

/// I-32, I-58, I-31, P-34: the input of a run holds each line with the
/// evidence the lead gave, the available amount of each milestone without
/// the request itself, the contract amount, what the other requests hold,
/// and the call's P-26.
#[test]
fn i32_checks_input_holds_the_lead_evidence_and_balances() {
    let mut w = world(Backend::Production, false).unwrap();
    w.auto_checks = false;
    must(&mut w, &ask(0, 0, 50, None, None).unwrap()).unwrap();
    must(&mut w, &ask(1, 0, 30, None, None).unwrap()).unwrap();
    let s = w.life.rev.sod.state.clone();
    let input = checks_input(&s, request_id(1)).expect("request 1 awaits its submission run");
    assert_eq!(input.request, request_id(1));
    assert_eq!(input.phase, CheckPhase::Submission);
    assert_eq!(input.lines.len(), 1);
    let l = &input.lines[0];
    assert_eq!(l.line, line_id(1));
    assert_eq!(l.milestone, milestone(0));
    assert_eq!(l.amount.amount().minor(), 30);
    assert_eq!(l.evidence, line_evidence(line_id(1)));
    // Milestones of 2.00 each: request 0 holds 0.50 on milestone 0, and
    // request 1 itself is left out.
    assert_eq!(
        input.available.get(&milestone(0)).copied().map(minor),
        Some(150)
    );
    assert_eq!(
        input.available.get(&milestone(1)).copied().map(minor),
        Some(200)
    );
    assert_eq!(minor(input.contract_total), 400);
    assert_eq!(input.claimed_elsewhere.map(minor), Some(50));
    assert!(!input.licences.0.is_empty(), "P-26 of the call is read");
}

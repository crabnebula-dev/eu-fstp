//! Review reproducers for lane L-FIND-B (independent review, test strength).
//!
//! Each test fails against the lane's current working tree and passes once
//! the named defect is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{CallId, LlmConfigId, ProposalId};
use fstp_domain::refusal::RefusalReason;
use fstp_domain_testkit::r#gen::findings::{ASSESSOR, INJECTION_PHRASES, finding};
use fstp_domain_testkit::r#gen::review::{L1, PR1, after, plan_of, run_on, submit};
use fstp_domain_testkit::r#gen::roster::{T0, call};
use fstp_domain_testkit::mc::findings_model::{exec_finding, pin_scenario};
use fstp_engine::ExecError;
use fstp_findings::{Finding, FindingCommand, FindingKind};

fn f(id: u128, c: CallId, p: ProposalId, config: u128) -> Finding {
    finding(
        id,
        c,
        p,
        LlmConfigId::from_raw(config),
        FindingKind::Quality,
        INJECTION_PHRASES[0],
    )
}

/// Ledger time floor: a finding entry's time is a recorded time, so a
/// later command, core or finding, may not be before it. The core's
/// `ClockBackwards` rule says a command's time may not be before the latest
/// recorded time. Today a finding entry never raises the floor, so the
/// ledger can run backwards in time.
#[test]
fn review_finding_entry_raises_the_time_floor() {
    let (mut s, _) = pin_scenario().unwrap();
    let later = after(T0, 1_000_000);
    exec_finding(
        &mut s,
        FindingCommand::Record(f(1, call(1), PR1, 1)),
        ASSESSOR,
        later,
    )
    .unwrap()
    .unwrap();

    // A finding command before the finding entry's time.
    let r = exec_finding(
        &mut s,
        FindingCommand::Record(f(2, call(1), PR1, 1)),
        ASSESSOR,
        T0,
    )
    .unwrap();
    // A core command before the finding entry's time.
    let core = run_on(&mut s, &submit(L1, PR1, plan_of(PR1), false), T0);

    let entries = s.entries().unwrap();
    let backwards = entries.windows(2).any(|w| w[1].at < w[0].at);
    assert!(
        matches!(&r, Err(ExecError::Refused(x)) if x.reason == RefusalReason::ClockBackwards)
            && matches!(&core, Err(ExecError::Refused(x)) if x.reason == RefusalReason::ClockBackwards)
            && !backwards,
        "a command before the latest finding entry was accepted: finding {r:?}, core {core:?}, \
         ledger times {:?}",
        entries.iter().map(|e| e.at).collect::<Vec<_>>()
    );
}

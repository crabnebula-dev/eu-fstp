//! Review reproducers for lane L-FIND-B (finding routing in the engine).
//!
//! Design section 2.2: `decide` refuses a `ctx.now` earlier than the
//! latest recorded time, so the ledger is time-monotone. A finding record
//! is a recorded entry too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::LlmConfigId;
use fstp_domain_testkit::r#gen::findings::{ASSESSOR, INJECTION_PHRASES, finding};
use fstp_domain_testkit::r#gen::review::{PR1, after};
use fstp_domain_testkit::r#gen::roster::{T0, call};
use fstp_domain_testkit::mc::findings_model::{exec_finding, pin_scenario};
use fstp_engine::ExecError;
use fstp_findings::{FindingCommand, FindingKind};

const DAY: i64 = 86_400_000_000;

/// Design 2.2 (ledger time-monotone): a finding command whose time is
/// before an already recorded finding entry must be refused. Today the
/// engine compares only with the core's time floor, which finding records
/// never move, so the ledger's times go backwards.
#[test]
fn review_finding_command_before_a_recorded_finding_is_refused() {
    let (mut s, _) = pin_scenario().unwrap();
    let pin = LlmConfigId::from_raw(1);
    let late = after(T0, DAY.saturating_mul(10));
    let early = after(T0, DAY);

    let first = finding(
        501,
        call(1),
        PR1,
        pin,
        FindingKind::Quality,
        INJECTION_PHRASES[0],
    );
    exec_finding(&mut s, FindingCommand::Record(first), ASSESSOR, late)
        .unwrap()
        .expect("the first finding is stored");

    let second = finding(
        502,
        call(1),
        PR1,
        pin,
        FindingKind::Integrity,
        INJECTION_PHRASES[1],
    );
    let r = exec_finding(&mut s, FindingCommand::Record(second), ASSESSOR, early).unwrap();

    let ats: Vec<i64> = s.entries().unwrap().iter().map(|e| e.at).collect();
    let monotone = ats.windows(2).all(|w| w[0] <= w[1]);
    assert!(
        matches!(r, Err(ExecError::Refused(_))) && monotone,
        "design 2.2: a finding command at {early:?} after a finding entry at {late:?} \
         was {r:?}; ledger times {ats:?} are not monotone"
    );
}

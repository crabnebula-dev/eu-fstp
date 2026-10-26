//! I-11 and I-12 at the fold: `fstp_engine::apply` refuses a finding
//! record the engine could not have produced, as the core fold refuses a
//! forged publication record.
//!
//! The setup from genesis publishes call 1 with configuration 1 and call 2
//! with configuration 2 under a frozen P-21 whose only fallback is model B.
//! Call 3 is drafted and approved but not published. Call 9 is unknown.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::engine::FoldError;
use fstp_domain::id::{CallId, LlmConfigId};
use fstp_domain_testkit::r#gen::findings::{INJECTION_PHRASES, MODEL_C, finding, model};
use fstp_domain_testkit::r#gen::policy::MODEL_B;
use fstp_domain_testkit::r#gen::review::PR1;
use fstp_domain_testkit::r#gen::roster::call;
use fstp_domain_testkit::mc::findings_model::pin_scenario_with_fallbacks;
use fstp_engine::{EngineState, Record};
use fstp_findings::{Finding, FindingKind, FindingRecord};
use fstp_ledger::Seq;

fn start() -> EngineState {
    pin_scenario_with_fallbacks(vec![model(MODEL_B)])
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"))
        .0
        .state()
        .clone()
}

fn f(id: u128, c: CallId, config: u128) -> Finding {
    finding(
        id,
        c,
        PR1,
        LlmConfigId::from_raw(config),
        FindingKind::Accuracy,
        INJECTION_PHRASES[2],
    )
}

fn fold(state: &EngineState, r: FindingRecord) -> Result<(), FoldError> {
    let mut next = state.clone();
    let at = next.now_floor();
    fstp_engine::apply(&mut next, Seq::from_raw(1), at, &Record::Finding(r))
}

fn regenerated(c: CallId, fallback: u32, m: &str, config: u128) -> FindingRecord {
    FindingRecord::Regenerated {
        call: c,
        fallback,
        config_model: model(m),
        config: LlmConfigId::from_raw(config),
        findings: Vec::new(),
    }
}

/// I-11: a first `Recorded` of a call under a configuration other than
/// the published pin does not fold, though the store alone would take it.
#[test]
fn i11_fold_refuses_a_first_finding_off_the_published_pin() {
    let s = start();
    assert_eq!(
        fold(&s, FindingRecord::Recorded(f(1, call(1), 7))),
        Err(FoldError::Inconsistent)
    );
    assert_eq!(fold(&s, FindingRecord::Recorded(f(1, call(1), 1))), Ok(()));
}

/// I-11: a `Recorded` of an unpublished or unknown call does not fold.
#[test]
fn i11_fold_refuses_findings_of_calls_without_a_pin() {
    let s = start();
    for c in [call(3), call(9)] {
        assert_eq!(
            fold(&s, FindingRecord::Recorded(f(1, c, 1))),
            Err(FoldError::Inconsistent),
            "{c:?}"
        );
    }
}

/// I-11, I-12, P-21 NOTE 10: a `Regenerated` that names the published pin,
/// a model off the frozen list or a call without a pin does not fold.
#[test]
fn i11_fold_refuses_regenerations_the_engine_cannot_produce() {
    let s = start();
    assert_eq!(
        fold(&s, regenerated(call(1), 0, MODEL_B, 1)),
        Err(FoldError::Inconsistent),
        "the published pin"
    );
    assert_eq!(
        fold(&s, regenerated(call(1), 0, MODEL_C, 5)),
        Err(FoldError::Inconsistent),
        "a model off the frozen list"
    );
    assert_eq!(
        fold(&s, regenerated(call(3), 0, MODEL_B, 5)),
        Err(FoldError::Inconsistent),
        "an unpublished call"
    );
    assert_eq!(fold(&s, regenerated(call(1), 0, MODEL_B, 5)), Ok(()));
}

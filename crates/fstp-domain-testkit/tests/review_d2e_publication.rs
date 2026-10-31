//! Review reproducer for lane W2e: I-52, D2e (M4 design section 3.4).
//!
//! D2e says the engine composes `PublishCall` only with a recomputed clean
//! report and a `GuidePublished` record in the same entry. So a core
//! `PublishCall` that arrives through `execute` must either be refused or
//! be written with its Guide record under the same command id. Today
//! it is written alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{SodSetup, T0, call, publish, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::{ExecError, Record};

/// I-52, D2e: `execute(Core(PublishCall))` never leaves an entry whose
/// only record is the core `CallPublished`.
#[test]
fn review_i52_execute_core_publish_call_appends_no_unpaired_call_published() {
    let setup = SodSetup::one(0, &[1]);
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    for step in setup.steps().unwrap_or_else(|e| panic!("{e}")) {
        run_on(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("setup step {:?}: {e:?}", step.cmd.kind()));
    }
    let before = s.entries().unwrap_or_else(|e| panic!("{e:?}")).len();
    match run_on(&mut s, &publish(call(1)), T0) {
        Err(ExecError::Refused(_)) => {}
        Err(e) => panic!("unexpected driver error: {e:?}"),
        Ok(_) => {
            let entries = s.entries().unwrap_or_else(|e| panic!("{e:?}"));
            let last = entries.get(before..).unwrap_or_default();
            let published = last.iter().any(|e| {
                matches!(
                    e.record,
                    Record::Core(fstp_domain::Record::CallPublished { .. })
                )
            });
            let paired = last.iter().any(|e| !matches!(e.record, Record::Core(_)));
            assert!(
                !published || paired,
                "I-52, D2e: execute wrote a CallPublished with no GuidePublished in its entry"
            );
        }
    }
}

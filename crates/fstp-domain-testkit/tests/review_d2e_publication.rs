//! Review reproducer for lane W2e: I-52, D2e (M4 design section 3.4).
//!
//! D2e says the engine composes `PublishCall` only with a recomputed clean
//! report and a `GuidePublished` record in the same entry. So a core
//! `PublishCall` that arrives through `execute` must either be refused or
//! be written with its Guide record under the same command id.
//!
//! The scenario's driver decides with no shell facts (`NoEnvironment`),
//! so it has no Guide facts. The command goes to `execute` itself, not to
//! the test kit's `run_core`, which supplies synthetic Guide facts
//! (Daniel's decision of 2026-11-15).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{SodSetup, T0, call, publish, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::{Command, ExecError, Record};

/// I-52, D2e: `execute(Core(PublishCall))` never leaves an entry whose
/// `CallPublished` has no `GuidePublished` of the same call beside it.
#[test]
fn review_i52_execute_core_publish_call_appends_no_unpaired_call_published() {
    let setup = SodSetup::one(0, &[1]);
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    for step in setup.steps().unwrap_or_else(|e| panic!("{e}")) {
        run_on(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("setup step {:?}: {e:?}", step.cmd.kind()));
    }
    let before = s.entries().unwrap_or_else(|e| panic!("{e:?}")).len();
    let step = publish(call(1));
    let ctx = s.ctx(T0, step.actor);
    match s.execute(Command::Core(step.cmd.clone()), ctx) {
        Err(ExecError::Refused(_)) => {}
        Err(e) => panic!("unexpected driver error: {e:?}"),
        Ok(_) => {
            let entries = s.entries().unwrap_or_else(|e| panic!("{e:?}"));
            let last = entries.get(before..).unwrap_or_default();
            for e in last {
                if let Record::Core(fstp_domain::Record::CallPublished { call: c, .. }) = &e.record
                {
                    let paired = last.iter().any(|g| {
                        g.command == e.command
                            && matches!(
                                &g.record,
                                Record::Core(fstp_domain::Record::GuidePublished { call: gc, .. })
                                    if gc == c
                            )
                    });
                    assert!(
                        paired,
                        "I-52, D2e: execute wrote a CallPublished with no GuidePublished in its entry"
                    );
                }
            }
        }
    }
}

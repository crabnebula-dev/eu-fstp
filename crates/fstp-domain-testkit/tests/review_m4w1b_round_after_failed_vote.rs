//! Review reproducer (lane m4w1b, R-EV-08, R-EV-09, D5): a cut-off round whose vote fails can never be replaced.
//!
//! A round stays open until its cut-off is recorded or its order goes
//! stale. A vote against the cut-off makes `RecordCutOff` refuse under
//! R-EV-09, and every member has then cast. Nothing closes the round, and
//! `OpenCutOffRound` refuses while it is live, so the call's RANKED
//! proposals can never reach a cut-off. This test fails until a failed
//! vote leaves the committee a way to open a new round.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::Vote;
use fstp_domain::id::DecisionId;
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RuleRef};
use fstp_domain::state::State;
use fstp_domain_testkit::r#gen::review::{PR1, PR2, R1, R2, R4};
use fstp_domain_testkit::r#gen::roster::{Step, call};
use fstp_domain_testkit::mc::ballot_model::{BallotModel, ROUND, run_core};
use fstp_domain_testkit::mc::life_model::{cast, open_round, record_cut_off};

struct World {
    model: BallotModel,
    core: State,
}

impl World {
    fn act(&mut self, step: &Step) -> Result<Vec<Record>, Refusal> {
        let Actor::Account(actor) = step.actor else {
            panic!("a System step in a ballot story");
        };
        run_core(
            &self.core,
            &self.model.truth,
            self.model.now,
            actor,
            &step.cmd,
        )
        .unwrap_or_else(|e| panic!("harness: {e}"))
        .map(|(core, records)| {
            self.core = core;
            records
        })
    }
}

/// R-EV-08, R-EV-09, D5: after the committee votes a cut-off down, a
/// member can open a new round of the call with another rank position.
#[test]
fn review_r_ev_09_failed_vote_leaves_a_way_to_a_new_round() {
    let model = BallotModel::new().unwrap_or_else(|e| panic!("start from genesis: {e}"));
    let core = model.start.core.clone();
    let mut w = World { model, core };
    for m in [R1, R2, R4] {
        w.act(&cast(m, ROUND, Vote::Against))
            .unwrap_or_else(|r| panic!("{m:?} casts: {r}"));
    }
    let r = match w.act(&record_cut_off(R1, ROUND)) {
        Ok(records) => panic!("a cut-off voted down was recorded: {records:?}"),
        Err(r) => r,
    };
    assert_eq!(r.rule, RuleRef::Rev09, "the vote fails under P-16");
    let next = DecisionId::from_raw(9_401);
    let reopened = w.act(&open_round(R2, next, call(1), vec![PR1, PR2], 2, false));
    assert!(
        reopened.is_ok(),
        "R-EV-08: the call's RANKED proposals stay without any reachable cut-off after a failed \
         vote, since the failed round stays open and live: {reopened:?}"
    );
}

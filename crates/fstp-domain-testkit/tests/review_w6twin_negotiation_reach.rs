//! Review reproducer for lane w6-twin: the twin never runs a NEGOTIATION to DECLINED after a P-04 edit that matters (I-12).
//!
//! `check_decline` in grant.rs reads P-04 to decide the NOTE 9 failure
//! "no grant amount can keep I-13". A head read of P-04 there survives
//! every test of `i12_frozen_edits_leave_call_outcomes_unchanged`. The
//! random twin reaches NEGOTIATION in about one case in twenty-five, and
//! neither scripted witness runs `DeclineNegotiation` after a P-04 edit.
//! This test runs the twin machine exactly as the I-12 test does and
//! counts the cases where twin B's head P-04 and call 1's frozen P-04
//! disagree on the plan total when `DeclineNegotiation` runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::cell::Cell;

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::nonneg;
use fstp_domain_testkit::r#gen::roster::call;
use fstp_domain_testkit::r#gen::twin::{
    Act, TWIN_PLAN_CENTS, TwinCmd, TwinGhost, TwinMachine, TwinOutput, TwinSut,
};
use fstp_prop::{Config, Gen, StateMachine, run_machine};

/// The I-12 twin machine, counting the decisive decline commands it runs.
struct Counting {
    inner: TwinMachine,
    hits: Cell<u32>,
}

/// Whether twin B's head P-04 and call 1's frozen P-04 disagree on whether
/// the submitted plan total is a grantable amount.
fn p04_verdicts_differ(sut: &TwinSut) -> bool {
    let Ok(pair) = &sut.pair else {
        return false;
    };
    let (Ok(head), Some(frozen)) = (pair.b.head(), pair.b.frozen(call(1))) else {
        return false;
    };
    let total = nonneg(TWIN_PLAN_CENTS).unwrap();
    head.frozen.p04.contains(total).ok() != frozen.values().p04.contains(total).ok()
}

impl StateMachine for Counting {
    type Model = TwinGhost;
    type Sut = TwinSut;
    type Command = TwinCmd;
    type Output = TwinOutput;

    fn init_model(&self) -> TwinGhost {
        self.inner.init_model()
    }

    fn init_sut(&self) -> TwinSut {
        self.inner.init_sut()
    }

    fn command(&self, g: &mut Gen, m: &TwinGhost) -> TwinCmd {
        self.inner.command(g, m)
    }

    fn precondition(&self, m: &TwinGhost, c: &TwinCmd) -> bool {
        self.inner.precondition(m, c)
    }

    fn run(&self, sut: &mut TwinSut, c: &TwinCmd) -> TwinOutput {
        if let TwinCmd::Eval {
            act: Act::DeclineNegotiation,
            on: Some((_, StateTag::Negotiation)),
            ..
        } = c
            && p04_verdicts_differ(sut)
        {
            self.hits.set(self.hits.get().saturating_add(1));
        }
        self.inner.run(sut, c)
    }

    fn next_state(&self, m: &mut TwinGhost, c: &TwinCmd) {
        self.inner.next_state(m, c);
    }

    fn postcondition(&self, m: &TwinGhost, c: &TwinCmd, o: &TwinOutput) -> Result<(), String> {
        self.inner.postcondition(m, c, o)
    }

    fn invariant(&self, m: &TwinGhost, s: &TwinSut) -> Result<(), String> {
        self.inner.invariant(m, s)
    }

    fn max_commands(&self) -> usize {
        self.inner.max_commands()
    }
}

/// I-12, design 6.2 row I-12: under the I-12 test's own seed, commands and
/// cases, the twin runs `DeclineNegotiation` at least once while twin B's
/// head P-04 and the frozen P-04 disagree on the plan total. Otherwise a
/// head read of P-04 in the NOTE 9 decline check cannot be caught.
#[test]
fn review_w6twin_i12_decline_negotiation_runs_after_a_decisive_p04_edit() {
    let machine = Counting {
        inner: TwinMachine::new(120),
        hits: Cell::new(0),
    };
    let outcome = run_machine(
        "i12_frozen_edits_leave_call_outcomes_unchanged",
        Config::default().with_cases(128),
        &machine,
    );
    assert!(outcome.failure().is_none(), "the twin itself must pass");
    assert!(
        machine.hits.get() > 0,
        "no DeclineNegotiation ran while twin B's head P-04 and call 1's frozen P-04 disagree on \
         the plan total, so a head read of P-04 in check_decline survives the I-12 twin"
    );
}

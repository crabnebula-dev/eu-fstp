//! Reachability witnesses of the lane W2d machines, run on the reference
//! alone (M4 design section 8.1: "`reachable` witnesses in every model").
//!
//! Each test shows that the generator of one machine focus reaches the
//! state its machine is about from genesis, within that machine's
//! operation budget. A machine whose generator never reached it would
//! pass without testing the rule. These tests need no production code, so
//! they are green on the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use fstp_domain::rules::ParamId;
use fstp_prop::{Config, Gen, run};

use common::gens::{self, Focus, add_admin, test_env, walk};
use common::reference::{Reference, SETTABLE};
use common::vocab::{Op, Step, Verdict, acct};

const REACHED: &str = "witness reached";

/// Runs the generator of `focus` for up to `budget` operations and fails
/// with [`REACHED`] once `goal` holds. Returns whether some case reached
/// it.
fn reaches(name: &str, focus: Focus, budget: usize, goal: fn(&Reference) -> bool) -> bool {
    let outcome = run(name, Config::default(), |g: &mut Gen| {
        let mut model = Reference::new(&test_env());
        for _ in 0..budget {
            let op = gens::op(g, &model, focus);
            model.apply(&op);
            if goal(&model) {
                return Err(REACHED.to_string());
            }
        }
        Ok(())
    });
    outcome
        .failure()
        .is_some_and(|f| f.message.contains(REACHED))
}

/// R-TN-01, SoD-07: the Steps machine reaches a completed onboarding.
#[test]
fn r_tn_01_witness_steps_machine_reaches_completion() {
    assert!(reaches(
        "r_tn_01_witness_steps_machine_reaches_completion",
        Focus::Steps,
        48,
        |m| m.observed().completed
    ));
}

/// SoD-07, Q31: the Admins machine reaches a recorded self-grant approval
/// with a second admin.
#[test]
fn sod07_witness_admins_machine_reaches_an_approval() {
    assert!(reaches(
        "sod07_witness_admins_machine_reaches_an_approval",
        Focus::Admins,
        32,
        |m| m.admins().len() >= 2 && !m.observed().approvals.is_empty()
    ));
}

/// SoD-07, TH-05: the Admins machine reaches a self-grant approval that
/// its grant used.
#[test]
fn th05_witness_admins_machine_uses_an_approval() {
    assert!(reaches(
        "th05_witness_admins_machine_uses_an_approval",
        Focus::Admins,
        32,
        |m| m.observed().approvals.values().any(|a| a.used)
    ));
}

/// SoD-03: the Admins machine reaches a refused invitation of the account
/// that holds a Receiving binding. The witness is an open invitation of
/// `acct(5)` beside a second admin, so the machine has offered the
/// refused acceptance.
#[test]
fn sod03_witness_admins_machine_invites_a_receiving_account() {
    assert!(reaches(
        "sod03_witness_admins_machine_invites_a_receiving_account",
        Focus::Admins,
        32,
        |m| {
            m.admins().len() >= 2
                && m.open_invitations()
                    .iter()
                    .any(|(_, invitee)| *invitee == acct(5))
        }
    ));
}

/// P-20, R-TN-01: the Steps machine reaches a validated Payments step,
/// which needs record-only P-20.
#[test]
fn p20_witness_steps_machine_validates_payments() {
    assert!(reaches(
        "p20_witness_steps_machine_validates_payments",
        Focus::Steps,
        48,
        |m| m.is_validated(Step::Payments)
    ));
}

/// P-20, P-69 to P-72, P-74: the Settings machine reaches a state where
/// every settable parameter differs from genesis or was set.
#[test]
fn p20_p69_to_p72_p74_witness_settings_machine_changes_every_parameter() {
    fn all_changed(m: &Reference) -> bool {
        let s = m.observed().settings;
        let d = common::vocab::spec_default_settings();
        let changed = |p: ParamId| match p {
            ParamId::P20 => s.p20.is_some(),
            ParamId::P69 => s.p69 != d.p69,
            ParamId::P70 => s.p70 != d.p70,
            ParamId::P71 => s.p71_us != d.p71_us,
            ParamId::P72 => s.p72_idle_us != d.p72_idle_us,
            ParamId::P74 => s.p74 != d.p74,
            _ => false,
        };
        SETTABLE.into_iter().all(changed)
    }
    assert!(reaches(
        "p20_p69_to_p72_p74_witness_settings_machine_changes_every_parameter",
        Focus::Settings,
        32,
        all_changed
    ));
}

/// P-21: the Inference machine reaches a replaced inference record, that
/// is a second accepted record with fallbacks.
#[test]
fn p21_witness_inference_machine_replaces_a_record() {
    fn replaced(m: &Reference) -> bool {
        m.observed()
            .inference
            .is_some_and(|i| i.config.raw() != 1 && !i.fallbacks.is_empty())
    }
    assert!(reaches(
        "p21_witness_inference_machine_replaces_a_record",
        Focus::Inference,
        48,
        replaced
    ));
}

/// R-TN-01, SoD-07: a reference self-check. With a second verified admin
/// and every step walked with valid values in order, the reference
/// accepts each save and the completion, and refuses a second completion.
#[test]
fn r_tn_01_reference_accepts_the_happy_path() {
    let env = test_env();
    let mut model = Reference::new(&env);
    let mut ops: Vec<Op> = add_admin(acct(1), acct(2), 1).to_vec();
    ops.extend(walk(acct(1), &Step::ALL));
    ops.push(Op::Complete { actor: acct(1) });
    for op in &ops {
        assert_eq!(model.verdict(op), Verdict::Accepted, "{op:?}");
        model.apply(op);
    }
    assert!(model.observed().completed);
    assert_eq!(
        model.verdict(&Op::Complete { actor: acct(2) }),
        Verdict::Refused
    );
}

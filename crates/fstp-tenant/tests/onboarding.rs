//! Onboarding steps: order, fail-closed checks and completion (R-TN-01,
//! SoD-07, Q5; M4 design sections 3.5 and 13, lane W2d).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;

use common::gens::{self, Focus, add_admin, test_env, valid_input, walk};
use common::machine::TenantMachine;
use common::prod::Sut;
use common::reference::Reference;
use common::vocab::{Env, Op, Probes, Step, StepInput, Verdict, acct};
use common::{drive, setup};
use fstp_prop::{check, check_machine, prop_assert, prop_assert_eq};

/// R-TN-01: "Each step validates before the next opens. The tenant can
/// save and return at any point." Random saves of every step, with valid
/// and invalid values, interleaved with every other tenant operation. The
/// verdicts, the appended records, the validated steps and the whole
/// projection follow the reference, and a fold of the records gives the
/// same projection (Q31).
#[test]
fn r_tn_01_onboarding_steps_validate_in_order() {
    check_machine(
        "r_tn_01_onboarding_steps_validate_in_order",
        &TenantMachine {
            env: test_env(),
            focus: Focus::Steps,
            max: 48,
        },
    );
}

/// R-TN-01: after the steps before `m` validate in order, a save of any
/// later step `k` is refused, appends nothing and validates nothing. The
/// save of step `m` itself is accepted.
#[test]
fn r_tn_01_no_step_opens_before_every_earlier_step_validates() {
    check(
        "r_tn_01_no_step_opens_before_every_earlier_step_validates",
        |g| {
            let env = test_env();
            let m = g.usize_in(0..=7);
            let k = g.usize_in(m + 1..=8);
            let target = Step::ALL[k];
            g.note("validated prefix", &&Step::ALL[..m]);
            g.note("target", &target);
            let sut = setup(&env, &walk(acct(1), &Step::ALL[..m]))?;
            let mut sut = sut;
            let o = sut
                .run(&Op::SaveStep {
                    actor: acct(1),
                    step: target,
                    input: gens::step_input(g, target),
                })
                .map_err(|e| e.to_string())?;
            prop_assert_eq!(o.verdict, Verdict::Refused);
            prop_assert!(
                o.records.is_empty(),
                "a refused save appended {:?}",
                o.records
            );
            let seen = sut.observe().map_err(|e| e.to_string())?;
            prop_assert!(!seen.validated.contains(&target));
            let next = Step::ALL[m];
            let o = sut
                .run(&Op::SaveStep {
                    actor: acct(1),
                    step: next,
                    input: valid_input(next),
                })
                .map_err(|e| e.to_string())?;
            prop_assert_eq!(o.verdict, Verdict::Accepted);
            Ok(())
        },
    );
}

/// R-TN-01, "save and return": once every step validated, a save of an
/// earlier step with values that fail its checks is accepted. The step is
/// then no longer validated, and every later step refuses saves until it
/// validates again.
#[test]
fn r_tn_01_failed_return_save_closes_later_steps() {
    check("r_tn_01_failed_return_save_closes_later_steps", |g| {
        let env = test_env();
        let mut ops: Vec<Op> = add_admin(acct(1), acct(2), 1).to_vec();
        ops.extend(walk(acct(1), &Step::ALL));
        let mut sut = setup(&env, &ops)?;
        let j = g.usize_in(0..=7);
        let back = Step::ALL[j];
        let bad = match gens::step_input(g, back) {
            StepInput::Plain { .. } => StepInput::Plain { valid: false },
            StepInput::Identity { p45, .. } => StepInput::Identity {
                p18: BTreeSet::new(),
                p45,
            },
            StepInput::Inference(mut d) => {
                d.primary = String::new();
                StepInput::Inference(d)
            }
        };
        let o = sut
            .run(&Op::SaveStep {
                actor: acct(1),
                step: back,
                input: bad,
            })
            .map_err(|e| e.to_string())?;
        prop_assert_eq!(o.verdict, Verdict::Accepted);
        let seen = sut.observe().map_err(|e| e.to_string())?;
        prop_assert!(!seen.validated.contains(&back));
        let k = g.usize_in(j + 1..=8);
        let later = Step::ALL[k];
        let o = sut
            .run(&Op::SaveStep {
                actor: acct(1),
                step: later,
                input: valid_input(later),
            })
            .map_err(|e| e.to_string())?;
        prop_assert_eq!(o.verdict, Verdict::Refused);
        prop_assert!(o.records.is_empty());
        Ok(())
    });
}

/// R-TN-01 with Q5 (interim, pending Daniel): in a cell without a prober,
/// the sending domain and channel checks fail closed. Whatever operations
/// run, neither step is ever validated and onboarding never completes.
#[test]
fn r_tn_01_q5_production_never_validates_domains_or_channels() {
    check(
        "r_tn_01_q5_production_never_validates_domains_or_channels",
        |g| {
            let env = Env {
                probes: Probes::Absent,
                ..test_env()
            };
            let mut ops: Vec<Op> = add_admin(acct(1), acct(2), 1).to_vec();
            ops.extend(walk(acct(1), &Step::ALL));
            let mut model = Reference::new(&env);
            let extra = g.vec(0..=24, |g| {
                let op = gens::op(g, &model, Focus::Steps);
                model.apply(&op);
                op
            });
            ops.extend(extra);
            ops.push(Op::Complete { actor: acct(1) });
            let (sut, outs) = drive(&env, &ops).map_err(|e| e.to_string())?;
            let seen = sut.observe().map_err(|e| e.to_string())?;
            prop_assert!(!seen.validated.contains(&Step::DomainsAndEmail));
            prop_assert!(!seen.validated.contains(&Step::Channels));
            prop_assert!(!seen.completed);
            prop_assert_eq!(outs.last().map(|o| o.verdict), Some(Verdict::Refused));
            Ok(())
        },
    );
}

/// R-TN-01, Q5: a recording fake that fails every probe leaves the sending
/// domain step saved but not validated, so the Identity step stays closed.
#[test]
fn r_tn_01_q5_failing_probe_keeps_the_next_step_closed() {
    check("r_tn_01_q5_failing_probe_keeps_the_next_step_closed", |g| {
        let env = Env {
            probes: Probes::Fake { pass: false },
            ..test_env()
        };
        let mut sut = setup(&env, &walk(acct(1), &Step::ALL[..4]))?;
        let seen = sut.observe().map_err(|e| e.to_string())?;
        prop_assert!(seen.validated.contains(&Step::Branding));
        prop_assert!(!seen.validated.contains(&Step::DomainsAndEmail));
        let o = sut
            .run(&Op::SaveStep {
                actor: acct(1),
                step: Step::Identity,
                input: gens::step_input(g, Step::Identity),
            })
            .map_err(|e| e.to_string())?;
        prop_assert_eq!(o.verdict, Verdict::Refused);
        Ok(())
    });
}

/// R-TN-01, SoD-07, Q2 B (interim, pending Daniel): with every other step
/// validated, the Administrators step validates only with at least two
/// tenant admins. Completion needs every step validated and every admin,
/// at least two, verified through the vault.
#[test]
fn r_tn_01_sod07_complete_needs_two_verified_admins() {
    check("r_tn_01_sod07_complete_needs_two_verified_admins", |g| {
        let extra = g.usize_in(0..=2);
        let verified = [acct(1), acct(2), acct(3)]
            .into_iter()
            .filter(|_| g.weighted(&[3, 1]) == 0)
            .collect();
        let env = Env {
            verified,
            ..test_env()
        };
        g.note("env", &env);
        let mut ops = Vec::new();
        for (i, a) in [acct(2), acct(3)].into_iter().take(extra).enumerate() {
            ops.extend(add_admin(acct(1), a, u128::try_from(i).unwrap_or(0) + 1));
        }
        ops.extend(walk(acct(1), &Step::ALL));
        let mut sut = setup(&env, &ops)?;
        let admins: Vec<_> = [acct(1), acct(2), acct(3)]
            .into_iter()
            .take(extra + 1)
            .collect();
        let seen = sut.observe().map_err(|e| e.to_string())?;
        prop_assert_eq!(
            seen.validated.contains(&Step::Administrators),
            admins.len() >= 2
        );
        let o = sut
            .run(&Op::Complete { actor: acct(1) })
            .map_err(|e| e.to_string())?;
        let want = admins.len() >= 2 && admins.iter().all(|a| env.verified.contains(a));
        prop_assert_eq!(o.verdict == Verdict::Accepted, want);
        prop_assert_eq!(sut.observe().map_err(|e| e.to_string())?.completed, want);
        Ok(())
    });
}

/// R-TN-01: the genesis has no validated step and no completion, and the
/// first admin is the only tenant admin.
#[test]
fn r_tn_01_genesis_has_one_admin_and_no_validated_step() {
    let env = test_env();
    let seen = Sut::genesis(&env).and_then(|s| s.observe());
    assert_eq!(seen, Ok(Reference::new(&env).observed()));
}

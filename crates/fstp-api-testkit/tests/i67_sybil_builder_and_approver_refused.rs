//! I-67 with Q2 B and T-SOD-SYBIL: a second account of a builder's person
//! never approves (M4 design section 8.4, "Machine with `sybil_pair`").
//!
//! In the machine, A2 is M1's person, so every approval by A2 is refused
//! and every command is two-way against the reference. The direct
//! property makes A2 the person of a generated builder, opener A1 or
//! manager M1, and checks that A2's approval of an otherwise clean draft
//! is refused for the shared identity. Q2 B is an interim reading,
//! pending Daniel.
//!
//! The production tests are red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{ActivationMachine, Backend, Focus, attempt};
use fstp_api_testkit::reference::creator::{
    Attempt, M1, M2, RefRefusal, StepVerdict, TA, TB, clean_plan,
};
use fstp_prop::{Gen, check, check_machine, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let partner = *g.pick(&[TA, M1]);
        let second = g.bool();
        g.note("A2 is the person of", &partner);
        g.note("with M2", &second);
        let mut plan = clean_plan();
        let person = plan
            .stat
            .vault
            .person(partner)
            .ok_or_else(|| format!("the cast vault does not know {partner:?}"))?;
        plan.stat.vault = plan.stat.vault.clone().with(TB, person, true);
        if second {
            plan.managers.push(M2);
        }
        let got = attempt(backend, &Attempt::by_second_admin(plan))?;
        prop_assert_eq!(
            got.verdict,
            StepVerdict::Refused(RefRefusal::SameIdentity),
            "I-67: A2 shares a verified identity with the builder {partner:?}"
        );
        Ok(())
    }
}

/// I-67, T-SOD-SYBIL: random sequences with the Sybil pair, on production.
#[test]
fn i67_sybil_builder_and_approver_refused() {
    check_machine(
        "i67_sybil_builder_and_approver_refused",
        &ActivationMachine {
            backend: Backend::Production,
            focus: Focus::Sybil,
        },
    );
}

/// I-67, T-SOD-SYBIL: the machine on the reference alone.
#[test]
fn i67_sybil_builder_and_approver_refused_on_the_reference() {
    check_machine(
        "i67_sybil_builder_and_approver_refused_on_the_reference",
        &ActivationMachine {
            backend: Backend::Reference,
            focus: Focus::Sybil,
        },
    );
}

/// I-67, Q2 B: the approver shares a person with the opener or a manager,
/// on production.
#[test]
fn i67_sybil_builder_and_approver_refused_for_every_builder() {
    check(
        "i67_sybil_builder_and_approver_refused_for_every_builder",
        property(Backend::Production),
    );
}

/// I-67, Q2 B: the same on the reference alone.
#[test]
fn i67_sybil_builder_and_approver_refused_for_every_builder_on_the_reference() {
    check(
        "i67_sybil_builder_and_approver_refused_for_every_builder_on_the_reference",
        property(Backend::Reference),
    );
}

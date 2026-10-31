//! I-67: the approver is never a builder (M4 design section 8.4,
//! "Machine").
//!
//! Random creator, policy, grant and acknowledgement actions by every
//! cast member, with requests and approvals. After every command the
//! records equal the reference's, and `check_i67` holds: every approver
//! is a tenant admin outside the builder set computed from raw records
//! (Q1 A, interim pending Daniel), verified, and no builder's person
//! (Q2 B, interim pending Daniel). Every command is two-way against the
//! reference.
//!
//! The production test is red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{ActivationMachine, Backend, Focus};
use fstp_prop::check_machine;

/// I-67, R-PG-03: on production.
#[test]
fn i67_approver_is_never_a_builder() {
    check_machine(
        "i67_approver_is_never_a_builder",
        &ActivationMachine {
            backend: Backend::Production,
            focus: Focus::Builders,
        },
    );
}

/// I-67: the machine passes on the reference alone, which checks the
/// reference `decide` against the raw-record builder set.
#[test]
fn i67_approver_is_never_a_builder_on_the_reference() {
    check_machine(
        "i67_approver_is_never_a_builder_on_the_reference",
        &ActivationMachine {
            backend: Backend::Reference,
            focus: Focus::Builders,
        },
    );
}

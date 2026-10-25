//! I-12, policy-level machine: random `EditPolicy`, `DraftCall`, `EditCall`,
//! `ApproveCallPublication` and `PublishCall` sequences (design 6.2).
//!
//! After every step, each published call's frozen policy equals the copy
//! the reference took at publication, in the ledger and in the projection.
//! Each edit appends one version, and later calls freeze the new head. Every
//! command is compared with the reference in both directions, and every
//! step extends the ledger and replays to the state (I-23).
//!
//! The engine-wide twin `i12_frozen_edits_leave_call_outcomes_unchanged`
//! needs the lifecycle and lands in step W6.

use fstp_domain_testkit::r#gen::policy::{Focus, PolicyMachine};
use fstp_prop::check_machine;

/// I-12: every published `FrozenPolicy` equals its ghost copy forever, and
/// later calls use the new values.
#[test]
fn i12_published_frozen_policies_equal_their_ghost_copy_forever() {
    check_machine(
        "i12_published_frozen_policies_equal_their_ghost_copy_forever",
        &PolicyMachine::new(Focus::FREEZING),
    );
}

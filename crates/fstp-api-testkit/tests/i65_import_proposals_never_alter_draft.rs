//! I-65, twin machine (M4 design section 8.4).
//!
//! Both twins open the standard draft from genesis: TA opens it and
//! grants M1 and M2, and M1 saves the synthetic P-58 of 300000.00. Random
//! draft commands run on both twins: saves by managers, admins and an
//! unbound account, with valid, havoc and injection values and stale
//! bases, and the end of M2's binding. Twin B also receives
//! `RegisterDocument` and `RecordProposals` for every field, the slug
//! included, with havoc values, injection phrases and profile conflicts.
//! No proposal is ever resolved.
//!
//! After every step: both twins give the same verdict for each draft
//! command, an import command appends only import records, the creator
//! and core projections are equal, and the ledgers are equal once import
//! records are removed. Every step is two-way against the reference.
//!
//! The production test is red until lanes W2a, W2b and W2e land the
//! creator, the import store and the engine envelope.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{Backend, TwinMachine};
use fstp_prop::check_machine;

/// I-65, TH-47: unresolved import proposals never alter the draft, on
/// production.
#[test]
fn i65_import_proposals_never_alter_draft() {
    check_machine(
        "i65_import_proposals_never_alter_draft",
        &TwinMachine {
            backend: Backend::Production,
            fault: None,
        },
    );
}

/// I-65: the twin machine passes on the reference alone.
#[test]
fn i65_import_proposals_never_alter_draft_on_the_reference() {
    check_machine(
        "i65_import_proposals_never_alter_draft_on_the_reference",
        &TwinMachine {
            backend: Backend::Reference,
            fault: None,
        },
    );
}

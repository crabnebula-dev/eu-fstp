//! I-65, machine (M4 design section 8.4).
//!
//! From the standard draft, random uploads, proposal batches, saves,
//! binding ends and activations run with resolutions by programme
//! managers, by M2 after its binding ended, by tenant admins and by an
//! unbound account. Resolutions use matching, stale and forged `shown`
//! digests, confirmations of the proposed and of other values, edits to
//! valid, unchanged and invalid values, dismissals, missing conflict
//! acknowledgements and stale bases.
//!
//! After every step `check_i65` holds over the raw records: every field
//! value with `Provenance::Import` has a `ProposalResolved` of the same
//! proposal and kind, by the same account, in the same entry, and that
//! account held an active programme manager binding at that instant.
//! Every step is two-way against the reference, and replay gives the
//! state.
//!
//! The production test is red until lanes W2a, W2b and W2e land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{Backend, ResolutionMachine};
use fstp_prop::check_machine;

/// I-65, R-PG-02: every imported value has a named programme manager's
/// resolution, on production.
#[test]
fn i65_every_imported_value_has_named_pm_resolution() {
    check_machine(
        "i65_every_imported_value_has_named_pm_resolution",
        &ResolutionMachine {
            backend: Backend::Production,
        },
    );
}

/// I-65: the machine passes on the reference alone, which checks the
/// reference `decide` against the raw-record predicate.
#[test]
fn i65_every_imported_value_has_named_pm_resolution_on_the_reference() {
    check_machine(
        "i65_every_imported_value_has_named_pm_resolution_on_the_reference",
        &ResolutionMachine {
            backend: Backend::Reference,
        },
    );
}

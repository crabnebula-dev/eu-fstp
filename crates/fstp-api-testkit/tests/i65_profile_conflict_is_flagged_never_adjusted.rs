//! I-65, property (M4 design sections 3.3 and 8.4; `programme-creator.md`,
//! "Document import"): proposals that conflict with the funder profile
//! are flagged, never silently adjusted.
//!
//! The draft holds one side of I-50 and the document proposes the other.
//! Either P-58 holds a synthetic ceiling below the SuperSAFE P-05 and the
//! document proposes P-05, with 400000.00 as the fixture case (L-10
//! shape), or P-05 holds 400000.00 and the document proposes P-58.
//! Generated values fall on both sides of the bound. The recorded value
//! equals the proposal byte for byte and carries I-50 exactly when it
//! conflicts. A flagged value is refused without
//! `conflict_acknowledged`. With it, the draft takes the proposed value
//! unchanged, never the bound.
//!
//! The production test is red until lanes W2a, W2b and W2e land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{Backend, conflict_case};
use fstp_prop::check;

/// I-65, I-50, L-10: a profile conflict is flagged and never adjusted, on
/// production.
#[test]
fn i65_profile_conflict_is_flagged_never_adjusted() {
    check("i65_profile_conflict_is_flagged_never_adjusted", |g| {
        conflict_case(Backend::Production, g)
    });
}

/// I-65: the property passes on the reference alone.
#[test]
fn i65_profile_conflict_is_flagged_never_adjusted_on_the_reference() {
    check(
        "i65_profile_conflict_is_flagged_never_adjusted_on_the_reference",
        |g| conflict_case(Backend::Reference, g),
    );
}

//! I-66 with I-50 and R-PG-01 AC: "a programme with P-05 above P-58
//! cannot be activated, and the report names both values" (M4 design
//! section 8.4).
//!
//! Each case draws P-58 and P-05, with equality and off-by-one cases
//! favoured. Above the ceiling, activation is refused with
//! `CapAboveCeiling`, and the row names both values as ADR-006 strings
//! written by the reference's own formatter. At or below the ceiling,
//! no `CapAboveCeiling` row exists and the otherwise clean draft
//! activates.
//!
//! The production test is red until lane W2a lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, attempt, cap_plan, cap_strings};
use fstp_api_testkit::reference::creator::{Attempt, RefCheck, RefDetail, RefRefusal, StepVerdict};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let p58 = g.u64_in(0..=100_000_000_000);
        let p05 = match g.weighted(&[2, 2, 2, 3]) {
            0 => p58,
            1 => p58.saturating_add(1),
            2 => p58.saturating_sub(1),
            _ => g.u64_in(0..=100_000_000_000),
        };
        g.note("P-05 minor", &p05);
        g.note("P-58 minor", &p58);
        let got = attempt(backend, &Attempt::by_second_admin(cap_plan(p05, p58)))?;
        let row = got.report_at_approval.get(&RefCheck::CapAboveCeiling);
        if p05 > p58 {
            let (s05, s58) = cap_strings(p05, p58);
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Refused(RefRefusal::Failed(RefCheck::CapAboveCeiling)),
                "I-66, I-50: P-05 above P-58 must block activation and name the check"
            );
            prop_assert_eq!(
                row,
                Some(&RefDetail::Cap { p05: s05, p58: s58 }),
                "R-PG-01 AC: the report must name both values as ADR-006 strings"
            );
        } else {
            prop_assert!(
                row.is_none(),
                "a cap at or below the ceiling is not a failure: {row:?}"
            );
            prop_assert_eq!(
                got.verdict,
                StepVerdict::Accepted,
                "the clean draft activates"
            );
        }
        Ok(())
    }
}

/// I-66, I-50, R-PG-01 AC: on production.
#[test]
fn i66_r_pg_01_cap_above_ceiling_names_both_values() {
    check(
        "i66_r_pg_01_cap_above_ceiling_names_both_values",
        property(Backend::Production),
    );
}

/// I-66, I-50, R-PG-01 AC: on the reference alone.
#[test]
fn i66_r_pg_01_cap_above_ceiling_names_both_values_on_the_reference() {
    check(
        "i66_r_pg_01_cap_above_ceiling_names_both_values_on_the_reference",
        property(Backend::Reference),
    );
}

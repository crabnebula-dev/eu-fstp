//! I-93, R-JV-03, ADR-015 "Visibility", `SPEC/12-journey-ui.md` section
//! 7.2: every diary entry shown to a viewer passes one visibility
//! function, and its specification is the matrix of section 7.2.
//!
//! The reference is `fstp_domain_testkit::reference::diary`, written from
//! the spec text, with its readings listed there. The property compares
//! the production function with it for every role and entry kind, in
//! both directions: an entry the matrix hides must stay hidden, and one
//! it shows must reach the viewer.
//!
//! Lane j2 test author. The comparison is red until the implementer
//! writes the matrix: the stub hides every entry. The teeth test and the
//! "sees nothing" tests are green, since a closed stub passes them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use std::collections::BTreeMap;

use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Facts, Kind};
use fstp_prop::{Config, Gen, prop_assert, prop_assert_eq};
use j2::production_visible;

/// Cases of the matrix properties. Each case is cheap.
const CASES: u32 = 4_096;

fn config() -> Config {
    Config::default().with_cases(CASES)
}

/// I-93, R-JV-03: for random viewers, relations, P-10 options, routes and
/// entry kinds, the production function equals the section 7.2 matrix.
#[test]
fn i93_visibility_matches_the_section_7_2_matrix() {
    fstp_prop::check_with(
        "i93_visibility_matches_the_section_7_2_matrix",
        config(),
        |g: &mut Gen| {
            let f = diary::facts(g);
            let want = diary::visible(&f);
            let got = production_visible(&f);
            prop_assert_eq!(
                got,
                want,
                "I-93: {:?} reading a {:?} entry, the matrix says {want}: {f:?}",
                f.role,
                f.kind
            );
            Ok(())
        },
    );
}

/// I-93 teeth: the reference both shows and hides every kind, so the
/// comparison above is not vacuous for any kind. Deterministic sweep.
#[test]
fn i93_teeth_the_reference_shows_and_hides_every_kind() {
    let mut seen: BTreeMap<Kind, (bool, bool)> = BTreeMap::new();
    // Every kind, every role, both relation extremes.
    for kind in Kind::ALL {
        for role in Role::ALL {
            for open in [false, true] {
                let f = Facts {
                    role,
                    viewer_programme: diary::PROGRAMMES[0],
                    entry_programme: diary::PROGRAMMES[0],
                    p10: diary::P10_OPTIONS[1],
                    kind,
                    path: diary::route_to(fstp_domain::StateTag::Completed)
                        .expect("COMPLETED is reachable"),
                    transition: None,
                    team: open,
                    guardian_of: open,
                    assigned: open,
                    declared_no_conflict: open,
                    conflicted: false,
                    own: open,
                    complaint_reviewer: open,
                    sod13_barred: !open,
                };
                let v = diary::visible(&f);
                let slot = seen.entry(kind).or_insert((false, false));
                if v {
                    slot.0 = true;
                } else {
                    slot.1 = true;
                }
            }
        }
    }
    for kind in Kind::ALL {
        assert_eq!(
            seen.get(&kind),
            Some(&(true, true)),
            "the reference never shows or never hides {kind:?}"
        );
    }
}

/// I-82, I-93: a viewer never sees an entry of another programme than
/// the one their binding is in, whatever the role and relation.
#[test]
fn i93_a_viewer_sees_nothing_of_another_programme() {
    fstp_prop::check_with(
        "i93_a_viewer_sees_nothing_of_another_programme",
        config(),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.viewer_programme = diary::PROGRAMMES[0];
            f.entry_programme = diary::PROGRAMMES[1];
            prop_assert!(
                !production_visible(&f),
                "I-93: {:?} of one programme sees a {:?} entry of another",
                f.role,
                f.kind
            );
            Ok(())
        },
    );
}

/// I-93, I-03: a viewer outside the Receiving group who has a conflict
/// on the subject sees nothing of it but their own conflict entry.
#[test]
fn i93_a_conflicted_viewer_sees_only_their_own_conflict_entry() {
    fstp_prop::check_with(
        "i93_a_conflicted_viewer_sees_only_their_own_conflict_entry",
        config(),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.conflicted = true;
            let receiving = matches!(
                f.role,
                Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
            );
            let own_conflict = f.kind == Kind::Conflict && f.own;
            if !receiving && !own_conflict {
                prop_assert!(
                    !production_visible(&f),
                    "I-03: conflicted {:?} sees a {:?} entry",
                    f.role,
                    f.kind
                );
            }
            Ok(())
        },
    );
}

/// I-93, section 7.2: call drafters and tenant admins read no diary
/// entry. Tenant admins use the erasure log and the synthetic role
/// preview instead (sections 7.3 and 8.6).
#[test]
fn i93_call_drafters_and_tenant_admins_see_no_entry() {
    fstp_prop::check_with(
        "i93_call_drafters_and_tenant_admins_see_no_entry",
        config(),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.role = *g.pick(&[Role::CallDrafter, Role::TenantAdmin]);
            prop_assert!(
                !production_visible(&f),
                "I-93: {:?} sees a {:?} entry",
                f.role,
                f.kind
            );
            Ok(())
        },
    );
}

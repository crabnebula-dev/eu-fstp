//! O-57, R-CF-02, I-93, `SPEC/12-journey-ui.md` section 8.3: before
//! declaring no conflict on a proposal, an FSTP coordinator sees no
//! diary entry of it, only aggregate per-state counts with no ids,
//! titles or applicant data.
//!
//! Lane j2 test author. The counts test is red until the implementer
//! writes `state_counts`. The "no entry" test is green, since the stub
//! hides every entry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain::StateTag;
use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Kind};
use fstp_journey::visibility::state_counts;
use fstp_prop::{Config, Gen, prop_assert, prop_assert_eq};
use j2::production_visible;

/// O-57, R-CF-02: a coordinator who has not declared no conflict on the
/// proposal sees no entry of it of any kind but their own conflict
/// entry.
#[test]
fn o57_coordinator_sees_no_entry_before_declaring() {
    fstp_prop::check_with(
        "o57_coordinator_sees_no_entry_before_declaring",
        Config::default().with_cases(2_048),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.role = Role::FstpCoordinator;
            f.declared_no_conflict = false;
            if !(f.kind == Kind::Conflict && f.own) {
                prop_assert!(
                    !production_visible(&f),
                    "O-57: an undeclared coordinator sees a {:?} entry",
                    f.kind
                );
            }
            Ok(())
        },
    );
}

/// O-57: the counts are one per state that holds a proposal, and each is
/// the number of proposals in that state.
#[test]
fn o57_state_counts_match_the_positions() {
    fstp_prop::check("o57_state_counts_match_the_positions", |g: &mut Gen| {
        let states: Vec<StateTag> = g.vec(1..=40, |g| *g.pick(&StateTag::ALL));
        let got = state_counts(&states);
        prop_assert_eq!(&got, &diary::state_counts(&states), "O-57: {states:?}");
        let total: u64 = got.values().copied().sum();
        prop_assert_eq!(
            total,
            u64::try_from(states.len()).unwrap_or(u64::MAX),
            "O-57: the counts do not add up"
        );
        Ok(())
    });
}

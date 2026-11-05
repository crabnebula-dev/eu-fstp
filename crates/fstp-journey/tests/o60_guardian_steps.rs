//! O-60, I-93, `docs/design/02-voyager-route-diary.md` "Guardian steps":
//! guardian consent steps appear only to the guardian, never to the rest
//! of the team, staff or auditors.
//!
//! Lane j2 test author. The guardian's own view is red until the
//! implementer writes the matrix. The "no one else" test is green, since
//! the stub hides every entry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Kind};
use fstp_prop::{Config, Gen, prop_assert, prop_assert_eq};
use j2::production_visible;

/// O-60: no viewer but a guardian sees a guardian step, whatever their
/// relation to the proposal: not the lead, the team, staff or an auditor.
#[test]
fn o60_guardian_steps_reach_no_one_but_the_guardian() {
    fstp_prop::check_with(
        "o60_guardian_steps_reach_no_one_but_the_guardian",
        Config::default().with_cases(2_048),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.kind = Kind::GuardianStep;
            if f.role != Role::Guardian {
                prop_assert!(
                    !production_visible(&f),
                    "O-60: {:?} sees a guardian step: {f:?}",
                    f.role
                );
            }
            Ok(())
        },
    );
}

/// O-60: the guardian a step names sees it, and a guardian it does not
/// name does not.
#[test]
fn o60_the_named_guardian_sees_their_step() {
    fstp_prop::check_with(
        "o60_the_named_guardian_sees_their_step",
        Config::default().with_cases(1_024),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.role = Role::Guardian;
            f.kind = Kind::GuardianStep;
            f.entry_programme = f.viewer_programme;
            prop_assert_eq!(
                production_visible(&f),
                f.guardian_of,
                "O-60: guardian named {}",
                f.guardian_of
            );
            Ok(())
        },
    );
}

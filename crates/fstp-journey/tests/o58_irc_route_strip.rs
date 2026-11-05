//! O-58, R-IR-03, `SPEC/12-journey-ui.md` section 8.3: reviewer,
//! committee and coordinator views reuse the route map as a "where is
//! this proposal" strip. IRC members get no route strip. They see the
//! nominated proposal and its outcome only.
//!
//! Lane j2 test author. The judging-role strip and the IRC transition
//! test are red until the implementer writes them. The "no strip" test
//! is green, since the stub gives no role a strip.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Kind};
use fstp_journey::visibility::route_strip;
use fstp_prop::{Config, Gen, prop_assert_eq};
use j2::production_visible;

/// O-58: IRC members get no route strip.
#[test]
fn o58_irc_members_get_no_route_strip() {
    assert!(
        !route_strip(Role::IrcMember),
        "O-58: IRC members get a route strip"
    );
}

/// Section 8.3: committee members, committee chairs and FSTP
/// coordinators get the route strip.
#[test]
fn o58_judging_roles_other_than_irc_get_the_route_strip() {
    let mut wrong = Vec::new();
    for role in Role::ALL {
        if let Some(want) = diary::route_strip(role)
            && route_strip(role) != want
        {
            wrong.push((role, want));
        }
    }
    assert!(
        wrong.is_empty(),
        "section 8.3: (role, strip) wrong: {wrong:?}"
    );
}

/// O-58, R-IR-03: an IRC member sees the state transitions of a proposal
/// they are assigned to, and no other entry.
#[test]
fn o58_irc_members_see_only_assigned_transitions() {
    fstp_prop::check_with(
        "o58_irc_members_see_only_assigned_transitions",
        Config::default().with_cases(2_048),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.role = Role::IrcMember;
            f.entry_programme = f.viewer_programme;
            f.conflicted = false;
            let want = f.kind == Kind::StateTransition && f.assigned;
            prop_assert_eq!(
                production_visible(&f),
                want,
                "R-IR-03: an IRC member and a {:?} entry, assigned {}",
                f.kind,
                f.assigned
            );
            Ok(())
        },
    );
}

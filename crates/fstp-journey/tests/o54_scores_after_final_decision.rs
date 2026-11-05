//! O-54, I-93, ADR-015 "Decisions recorded": applicants see scores and
//! reviewer comments only after a final decision, NOT_SELECTED, DECLINED
//! or GRANTED. GRANTED is a decision, not a terminal state, so the
//! states after it keep the scores visible. An INELIGIBLE proposal has
//! no scores. A WITHDRAWN proposal had no final decision and shows none.
//!
//! Lane j2 test author. Red until the implementer writes the matrix: the
//! stub hides every score, so the "after a decision" half fails.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain::StateTag;
use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Kind};
use fstp_prop::{Config, Gen, prop_assert_eq};
use j2::production_visible;

/// The voyager roles of section 7.2.
const VOYAGERS: [Role; 2] = [Role::Applicant, Role::ApplicantTeamMember];

/// O-54: a team member sees a score or comment entry exactly when the
/// proposal's route holds NOT_SELECTED, DECLINED or GRANTED.
#[test]
fn o54_scores_reach_the_team_only_after_a_final_decision() {
    fstp_prop::check_with(
        "o54_scores_reach_the_team_only_after_a_final_decision",
        Config::default().with_cases(2_048),
        |g: &mut Gen| {
            let mut f = diary::facts(g);
            f.role = *g.pick(&VOYAGERS);
            f.kind = Kind::ReviewerScore;
            f.team = true;
            f.entry_programme = f.viewer_programme;
            let decided = f.path.iter().any(|s| {
                matches!(
                    s,
                    StateTag::NotSelected | StateTag::Declined | StateTag::Granted
                )
            });
            prop_assert_eq!(
                production_visible(&f),
                decided,
                "O-54: score on the route {:?}",
                f.path
            );
            Ok(())
        },
    );
}

/// O-54: on a route to each state, a team member sees scores in exactly
/// NOT_SELECTED, DECLINED, GRANTED, IN_EXECUTION, COMPLETED and
/// TERMINATED, and never in INELIGIBLE, WITHDRAWN or a state before a
/// decision.
#[test]
fn o54_scores_by_final_state() {
    let shown = [
        StateTag::NotSelected,
        StateTag::Declined,
        StateTag::Granted,
        StateTag::InExecution,
        StateTag::Completed,
        StateTag::Terminated,
    ];
    let mut wrong = Vec::new();
    for state in StateTag::ALL {
        let path = diary::route_to(state).expect("every state is reachable");
        for role in VOYAGERS {
            let f = diary::Facts {
                role,
                viewer_programme: diary::PROGRAMMES[0],
                entry_programme: diary::PROGRAMMES[0],
                p10: diary::P10_OPTIONS[0],
                kind: Kind::ReviewerScore,
                path: path.clone(),
                transition: None,
                team: true,
                guardian_of: false,
                assigned: false,
                declared_no_conflict: false,
                conflicted: false,
                own: false,
                complaint_reviewer: false,
                sod13_barred: false,
            };
            let want = shown.contains(&state);
            if production_visible(&f) != want {
                wrong.push((state, role, want));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "O-54: (state, role, should see) wrong: {wrong:?}"
    );
}

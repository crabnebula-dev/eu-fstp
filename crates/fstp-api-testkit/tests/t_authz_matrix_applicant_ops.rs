//! The applicant operations of the authorisation matrix, cell by cell
//! (T-AUTHZ-MATRIX, H-01, M4 design section 8.3).
//!
//! CI run 43738172717 failed cells of these operations on every channel.
//! Each test here runs the failing cells of one group of operations
//! through the reference and the direct channel, in every proposal state,
//! for every principal the state holds, under each P-10 value of the
//! SuperSAFE row. A passkey web session and a scoped MCP token are used,
//! the MCP one only where the operation has a tool and the principal has
//! an account. Each cell must agree both ways, as the full matrix
//! requires. The HTTP and MCP channels reach the same dispatch, and CI
//! runs them in the full matrix.
//!
//! Daniel's matrix answers of 2026-11-15 (night), the last table of
//! `docs/handoff/m4-design.md`, settle the four operations the previous
//! lane left open: the journey for staff and the guardian, the guardian's
//! workspace save in DRAFT, the notice acknowledgement, and the former
//! team's workspace read. No cell is left out. The follow-up answer of
//! the same night gives the guardian the route map as well. A later
//! answer that night ("if i wrote it i should be able to read it") gives
//! the former team, the guardian included, a read-only workspace read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::matrix::{self, Channel, ChannelFault, Observed};
use fstp_api_testkit::reference::authz::{
    AuthzReference, CellKey, Channel as Via, Expected, Login, P10, Policy, Session, StateProfile,
    StepUp, Who, authz_reference, feasible, target_exists,
};
use fstp_domain::StateTag;

/// One disagreement: the channel, the cell, the reference and the
/// observation.
type Disagreement = (
    &'static str,
    CellKey,
    Option<Expected>,
    Result<Observed, ChannelFault>,
);

/// Runs every cell of `ops` in every proposal state, for every feasible
/// principal but those `skip` names, and returns the cells that ran and
/// those that disagreed.
fn run(
    ops: &[&'static str],
    skip: impl Fn(&str, Who, StateTag) -> bool,
) -> (usize, Vec<Disagreement>) {
    let r: AuthzReference = authz_reference().unwrap();
    let channels: Vec<Box<dyn Channel>> = vec![matrix::direct_channel().unwrap()];
    let web = Session {
        login: Some(Login::Passkey),
        step_up: StepUp::Absent,
        channel: Via::Web,
    };
    let anonymous = Session {
        login: None,
        step_up: StepUp::Absent,
        channel: Via::Web,
    };
    let mcp = Session {
        login: Some(Login::Passkey),
        step_up: StepUp::Absent,
        channel: Via::Mcp { scope: true },
    };
    let mut n = 0usize;
    let mut bad = Vec::new();
    for mut channel in channels {
        let via = channel.name();
        for tag in StateTag::ALL {
            let state = StateProfile::Proposal(tag);
            for p10 in [P10::AssignedOnly, P10::AllCommittee, P10::OperatorStaffOnly] {
                let policy = Policy {
                    p10,
                    ..Policy::SUPERSAFE
                };
                for op in ops {
                    let spec = *r.op(op).unwrap_or_else(|| panic!("no {op}"));
                    if !target_exists(spec.target, state) {
                        continue;
                    }
                    for who in Who::ALL {
                        if !feasible(who, state) || skip(op, who, tag) {
                            continue;
                        }
                        // As the matrix builds them: a caller with no account
                        // has no session and reaches MCP through public tools
                        // only.
                        let sessions: &[Session] = if !who.account() {
                            &[anonymous]
                        } else if spec.tool.is_some() {
                            &[web, mcp]
                        } else {
                            &[web]
                        };
                        for session in sessions {
                            let cell = CellKey {
                                op,
                                who,
                                state,
                                policy,
                                session: *session,
                            };
                            n = n.saturating_add(1);
                            let e = r.expected(&cell);
                            let o = channel.observe(&cell);
                            let ok = match (&e, &o) {
                                (Some(e), Ok(o)) => matrix::agrees(*e, matrix::class_of(o)),
                                _ => false,
                            };
                            if !ok {
                                bad.push((via, cell, e, o));
                            }
                        }
                    }
                }
            }
        }
    }
    (n, bad)
}

fn report(bad: &[Disagreement]) -> String {
    bad.iter()
        .take(30)
        .map(|(via, c, e, o)| {
            format!(
                "  {via} {} {:?} {:?} {:?} {:?}: expected {e:?}, observed {o:?}\n",
                c.op, c.who, c.state, c.policy.p10, c.session.channel
            )
        })
        .collect()
}

/// I-18, `roles-and-sod.md` roles table (Guardian): only the guardian of
/// X begins the consent. Anyone else is refused as an actor before any
/// state rule, and the guardian outside IRC_REVIEW and NEGOTIATION, or
/// once X ended, by the I-18 guard. In those two states the guardian
/// reaches the vault's write page.
#[test]
fn t_authz_matrix_i18_begin_consent_is_the_guardians() {
    let (n, bad) = run(&["guardian.begin_consent"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 500, "{n}");
}

/// R-NG-01, Q23 B (M4 design section 15.0): the country, the declared
/// affiliations and the date of birth are the lead's statements, as the
/// registry admits them. Anyone else is refused as an actor, and the
/// lead outside DRAFT, or once X ended, by a guard on the target.
#[test]
fn t_authz_matrix_r_ng_01_vault_statements_are_the_leads() {
    let (n, bad) = run(
        &[
            "proposal.state_country",
            "proposal.declare_affiliations",
            "proposal.state_birth_date",
        ],
        |_, _, _| false,
    );
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1500, "{n}");
}

/// I-21, R-AC-01: a caller with no Receiving binding on X, now or ended,
/// is refused the workspace save as an actor. The team outside DRAFT is
/// refused by a guard on the target. Daniel, 2026-11-15 (night): the
/// guardian writes the application form in DRAFT, as the registry's
/// `TEAM` says. I-21 concerns operator and Judging roles only.
#[test]
fn t_authz_matrix_i21_save_workspace_refuses_outsiders_as_actors() {
    let (n, bad) = run(&["proposal.save_workspace"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
}

/// R-NG-06: only the lead acknowledges the negotiation notice, as the
/// registry says (Daniel, 2026-11-15, night). Anyone else, the team
/// member and the guardian included, is refused as an actor before the
/// state of X is read. The lead outside NEGOTIATION is refused by a
/// guard on the target.
#[test]
fn t_authz_matrix_r_ng_06_acknowledge_notice_is_the_leads() {
    let (n, bad) = run(&["negotiation.acknowledge_notice"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 500, "{n}");
}

/// T-AUTHZ-MATRIX test plan "an actor denial comes before every state or
/// input refusal", R-SB-03 and `roles-and-sod.md` Receiving bindings
/// (Daniel, 2026-11-06): a caller who never led X is refused each lead
/// command as an actor, in every state, before the command is built. The
/// former lead of a terminal X is refused by a guard on the target, since
/// no binding is revived for a command.
#[test]
fn t_authz_matrix_r_sb_03_lead_commands_actor_first_former_lead_by_guard() {
    let (n, bad) = run(
        &[
            "proposal.record_plan",
            "proposal.add_member",
            "proposal.add_guardian",
            "proposal.submit",
            "proposal.withdraw",
            "stage2.answer",
            "stage2.revise",
        ],
        |_, _, _| false,
    );
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 3000, "{n}");
}

/// `SPEC/12-journey-ui.md` sections 7.2 and 10, I-93, I-21, O-57, I-03,
/// P-10 NOTE 1 (Daniel, 2026-11-15, night). Staff read the position of X
/// as the visibility function shows them its state transition: Judging
/// roles within P-10 and their assignment, Operations roles the grant's
/// legs only, coordinators once declared free of conflict. The guardian
/// reads the full journey as a Receiving binding while X is under way.
/// The former lead and team member keep it in a terminal state.
#[test]
fn t_authz_matrix_r_jv_journey_staff_by_visibility_guardian_as_receiving() {
    let (n, bad) = run(&["proposal.journey"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
}

/// `SPEC/12-journey-ui.md` sections 7.2 and 10, I-93: the diary reads
/// with the journey's readers, and the visibility function picks its
/// entries (I-93). The guardian's diary follows the journey decision of
/// 2026-11-15 (night), and nothing else changes here.
#[test]
fn t_authz_matrix_i93_diary_readers() {
    let (n, bad) = run(&["proposal.diary"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
}

/// I-21, R-AC-01 (Daniel, 2026-11-15, night, "if i wrote it i should be
/// able to read it"): the workspace is read by the team while its
/// Receiving bindings are active. Once X ended, everyone who was on the
/// team, the lead, a team member and the guardian, keeps a read-only
/// view of the application. Nobody else reads it, and
/// `proposal.save_workspace` stays closed to the former team.
#[test]
fn t_authz_matrix_i21_get_workspace_stays_with_the_former_team() {
    let (n, bad) = run(&["proposal.get_workspace"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
    // The former team's cells, pinned: the reference admits each one and
    // the direct channel completes it.
    let r: AuthzReference = authz_reference().unwrap();
    let mut channel = matrix::direct_channel().unwrap();
    let web = Session {
        login: Some(Login::Passkey),
        step_up: StepUp::Absent,
        channel: Via::Web,
    };
    let mut pinned = 0usize;
    for tag in StateTag::ALL.into_iter().filter(|t| t.is_terminal()) {
        for who in [Who::Lead, Who::TeamMember, Who::Guardian] {
            let cell = CellKey {
                op: "proposal.get_workspace",
                who,
                state: StateProfile::Proposal(tag),
                policy: Policy::SUPERSAFE,
                session: web,
            };
            assert_eq!(r.expected(&cell), Some(Expected::Allow), "{who:?} {tag:?}");
            let o = channel.observe(&cell);
            assert!(
                matches!(o, Ok(Observed::Completed)),
                "{who:?} {tag:?}: observed {o:?}"
            );
            pinned = pinned.saturating_add(1);
        }
    }
    assert_eq!(pinned, 18);
}

/// `SPEC/12-journey-ui.md` section 8.1, O-58, R-JV-01 (Daniel,
/// 2026-11-15, night): the route map is read by the Receiving roles that
/// read the journey. The guardian sees it as part of the full journey
/// while X is under way, and the former lead and team member keep it
/// once X ended. Staff are refused, whatever they read of the journey,
/// so `proposal.journey` sets `map` exactly where this read admits.
#[test]
fn t_authz_matrix_r_jv_route_map_is_the_receiving_bindings() {
    let (n, bad) = run(&["proposal.route_map"], |_, _, _| false);
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
}

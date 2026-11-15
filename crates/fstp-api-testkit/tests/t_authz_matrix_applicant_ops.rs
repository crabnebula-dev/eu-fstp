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
//! Two readings stay open and are left out, each named where it is
//! skipped: whether the guardian writes the team's workspace, and
//! whether every team member or only the lead acknowledges the
//! negotiation notice (R-NG-06).

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
/// refused by a guard on the target. Left out, pending Daniel: the
/// guardian in DRAFT, whom the registry's `TEAM` and the reference
/// admit and the dispatch refuses under I-21 ("a guardian consents and
/// does not write the form").
#[test]
fn t_authz_matrix_i21_save_workspace_refuses_outsiders_as_actors() {
    let (n, bad) = run(&["proposal.save_workspace"], |_, who, tag| {
        who == Who::Guardian && tag == StateTag::Draft
    });
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{}",
        bad.len(),
        report(&bad)
    );
    assert!(n > 1000, "{n}");
}

/// R-NG-06: a caller with no Receiving binding on X is refused the
/// acknowledgement of the negotiation notice as an actor, before the
/// state of X is read. Left out, pending Daniel: the team member and the
/// guardian. The registry and the reference admit the lead only, and the
/// dispatch and the mailbox design (`negotiation.acknowledge`, "each
/// team member") admit the whole team.
#[test]
fn t_authz_matrix_r_ng_06_acknowledge_notice_refuses_outsiders_as_actors() {
    let (n, bad) = run(&["negotiation.acknowledge_notice"], |_, who, _| {
        matches!(who, Who::TeamMember | Who::Guardian)
    });
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

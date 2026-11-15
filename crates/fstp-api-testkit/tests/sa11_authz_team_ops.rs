//! The SA-11 operations of the authorisation matrix, cell by cell
//! (T-AUTHZ-MATRIX, H-01, M4 design section 8.3; SA-11, Daniel
//! 2026-11-15 night).
//!
//! Each test runs one operation through the reference and the direct
//! channel, in every state profile (onboarding, awaiting activation, the
//! programme and call states and the 16 proposal states), for every
//! principal the state holds. A passkey web session is used, and a scoped
//! MCP token where the operation has a tool. None of these has one. Each
//! cell must agree both ways, as the full matrix requires, so the new
//! operations agree before CI's matrix runs.
//!
//! P-10 bears on none of the four rules, so the SuperSAFE row is used.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::matrix::{self, ChannelFault, Observed};
use fstp_api_testkit::reference::authz::{
    AuthzReference, CellKey, Channel as Via, Expected, Login, Policy, Session, StateProfile,
    StepUp, Who, authz_reference, feasible, target_exists,
};

/// One disagreement: the cell, the reference and the observation.
type Disagreement = (CellKey, Option<Expected>, Result<Observed, ChannelFault>);

/// Runs every cell of `op` and returns how many ran and those that
/// disagreed.
fn run(op: &'static str) -> (usize, Vec<Disagreement>) {
    let r: AuthzReference = authz_reference().unwrap();
    let mut channel = matrix::direct_channel().unwrap();
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
    let spec = *r
        .op(op)
        .unwrap_or_else(|| panic!("no {op} in the reference"));
    let mut n = 0usize;
    let mut bad = Vec::new();
    for state in StateProfile::all() {
        if !target_exists(spec.target, state) {
            continue;
        }
        for who in Who::ALL {
            if !feasible(who, state) {
                continue;
            }
            let sessions: &[Session] = if !who.account() {
                &[anonymous]
            } else {
                &[web, mcp]
            };
            for session in sessions {
                let cell = CellKey {
                    op,
                    who,
                    state,
                    policy: Policy::SUPERSAFE,
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
                    bad.push((cell, e, o));
                }
            }
        }
    }
    (n, bad)
}

fn check(op: &'static str, at_least: usize) {
    let (n, bad) = run(op);
    let lines: String = bad
        .iter()
        .take(30)
        .map(|(c, e, o)| {
            format!(
                "  {} {:?} {:?} {:?}: expected {e:?}, observed {o:?}\n",
                c.op, c.who, c.state, c.session.channel
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} of {n} cells disagree:\n{lines}",
        bad.len()
    );
    assert!(n >= at_least, "{op}: {n} cells");
}

/// SA-11, I-86: the team page of P is read by its programme manager and
/// the tenant admins, through the web only. Anyone else is refused, and
/// before activation the setup gate refuses (ADR-021).
#[test]
fn sa11_t_authz_matrix_team_list_is_the_manager_and_the_tenant_admins() {
    check("team.list", 500);
}

/// SA-11, I-86: the member page is the tenant admins' alone, web only.
#[test]
fn sa11_t_authz_matrix_admin_members_is_the_tenant_admins() {
    check("admin.members", 500);
}

/// SA-11, I-86: every account reads its own display name, web only.
#[test]
fn sa11_t_authz_matrix_display_name_read_is_any_accounts_own() {
    check("me.display_name", 500);
}

/// SA-11, I-86: every account sets its own display name, web only, with
/// no step-up.
#[test]
fn sa11_t_authz_matrix_set_display_name_is_any_accounts_own() {
    check("me.set_display_name", 500);
}

//! The SA-12 operations of the authorisation matrix, cell by cell
//! (T-AUTHZ-MATRIX, H-01, M4 design section 8.3; SA-12, Daniel
//! 2026-11-15 night).
//!
//! SA-12: a tenant admin may take every programme set-up action of the
//! programme manager and the call drafter on the own tenant's
//! programmes, without a Drafting binding. Each test runs one operation
//! through the reference and the direct channel, in every state profile
//! (onboarding, awaiting activation, the programme and call states and
//! the 16 proposal states), for every principal the state holds. A
//! passkey web session is used, and a scoped MCP token where the
//! operation has a tool. Each cell must agree both ways, as the full
//! matrix requires.
//!
//! Each test also checks the SA-12 rule itself: once the organisation
//! is activated, neither the reference nor the cell refuses a tenant
//! admin, builder or not, as an actor or a reader. A state may still
//! refuse the act as a guard, such as a request on an active programme.
//!
//! Left out on purpose: `import.resolve`. I-65 names "a named programme
//! manager" for every imported value, and an invariant outranks SA-12
//! (`.claude/CLAUDE.md`, source of truth). The test of that operation
//! pins that a tenant admin is still refused.
//!
//! P-10 bears on none of these rules, so the SuperSAFE row is used.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::matrix::{self, ChannelFault, Observed, ObservedClass};
use fstp_api_testkit::reference::authz::{
    AuthClass, AuthzReference, CellKey, Channel as Via, Expected, Login, Policy, Session,
    StateProfile, StepUp, Who, authz_reference, feasible, target_exists,
};

/// One disagreement: the cell, the reference and the observation.
type Disagreement = (CellKey, Option<Expected>, Result<Observed, ChannelFault>);

/// The web session of a passkey login.
const WEB: Session = Session {
    login: Some(Login::Passkey),
    step_up: StepUp::Absent,
    channel: Via::Web,
};

/// What one run found: the cells run, the disagreements, and the tenant
/// admin cells after activation that either side refused as an actor or
/// a reader.
struct Run {
    n: usize,
    bad: Vec<Disagreement>,
    admin_refused: Vec<(Who, StateProfile, Option<Expected>, String)>,
    admin_cells: usize,
}

/// Runs every cell of `op`.
fn run(op: &'static str) -> Run {
    let r: AuthzReference = authz_reference().unwrap();
    let mut channel = matrix::direct_channel().unwrap();
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
    let mut out = Run {
        n: 0,
        bad: Vec::new(),
        admin_refused: Vec::new(),
        admin_cells: 0,
    };
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
                &[WEB, mcp]
            };
            for session in sessions {
                let cell = CellKey {
                    op,
                    who,
                    state,
                    policy: Policy::SUPERSAFE,
                    session: *session,
                };
                out.n = out.n.saturating_add(1);
                let e = r.expected(&cell);
                let o = channel.observe(&cell);
                let ok = match (&e, &o) {
                    (Some(e), Ok(o)) => matrix::agrees(*e, matrix::class_of(o)),
                    _ => false,
                };
                if !ok {
                    out.bad.push((cell, e, o.clone()));
                }
                let admin = matches!(who, Who::TenantAdmin | Who::TenantAdminBuilder);
                if admin && *session == WEB && !state.before_activation() {
                    out.admin_cells = out.admin_cells.saturating_add(1);
                    let refused_ref = matches!(
                        e,
                        Some(Expected::Deny(AuthClass::Actor | AuthClass::Visibility))
                    );
                    let refused_cell = match &o {
                        Ok(o) => matches!(
                            matrix::class_of(o),
                            ObservedClass::Auth(AuthClass::Actor | AuthClass::Visibility)
                        ),
                        Err(_) => true,
                    };
                    if refused_ref || refused_cell {
                        out.admin_refused.push((who, state, e, format!("{o:?}")));
                    }
                }
            }
        }
    }
    out
}

/// Checks that every cell of `op` agrees, that at least `at_least` ran,
/// and, when `admin_admitted`, the SA-12 rule for the tenant admins.
fn check(op: &'static str, at_least: usize, admin_admitted: bool) {
    let r = run(op);
    let lines: String = r
        .bad
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
        r.bad.is_empty(),
        "{} of {} cells disagree:\n{lines}",
        r.bad.len(),
        r.n
    );
    assert!(r.n >= at_least, "{op}: {} cells", r.n);
    assert!(r.admin_cells > 0, "{op}: no tenant admin cell ran");
    if admin_admitted {
        assert!(
            r.admin_refused.is_empty(),
            "SA-12: {op} refuses a tenant admin as an actor or reader: {:?}",
            r.admin_refused
        );
    } else {
        assert_eq!(
            r.admin_refused.len(),
            r.admin_cells,
            "I-65: {op} admits a tenant admin somewhere"
        );
    }
}

/// SA-12, R-PG-02: a tenant admin applies a starting point to a draft.
#[test]
fn sa12_t_authz_matrix_apply_start_admits_tenant_admins() {
    check("creator.apply_start", 500, true);
}

/// SA-12, R-PG-01: a tenant admin saves and clears draft fields, and saves
/// the knock-out criteria of an active programme.
#[test]
fn sa12_t_authz_matrix_save_fields_admits_tenant_admins() {
    check("creator.save_fields", 500, true);
}

/// SA-12, TH-49: a tenant admin accepts template narrative.
#[test]
fn sa12_t_authz_matrix_accept_narrative_admits_tenant_admins() {
    check("creator.accept_narrative", 500, true);
}

/// SA-12: a tenant admin edits narrative the draft holds.
#[test]
fn sa12_t_authz_matrix_edit_narrative_admits_tenant_admins() {
    check("creator.edit_narrative", 500, true);
}

/// SA-12, R-PG-03, I-67: a tenant admin requests activation. Approval is
/// unchanged: a non-builder admin approves, a builder admin overrides.
#[test]
fn sa12_t_authz_matrix_request_activation_admits_tenant_admins() {
    check("creator.request_activation", 500, true);
}

/// SA-12, I-65: a tenant admin uploads a document for import. The upload
/// sets no value, so I-65 does not bear on it.
#[test]
fn sa12_t_authz_matrix_import_upload_admits_tenant_admins() {
    check("import.upload", 500, true);
}

/// SA-12, I-66: a tenant admin removes an imported document. The removal
/// confirms no value, so I-65 does not bear on it.
#[test]
fn sa12_t_authz_matrix_import_remove_admits_tenant_admins() {
    check("import.remove", 500, true);
}

/// I-65 outranks SA-12: only a named programme manager confirms or edits
/// an imported value, so a tenant admin is still refused the resolution.
#[test]
fn sa12_i65_t_authz_matrix_import_resolve_stays_the_programme_managers() {
    check("import.resolve", 500, false);
}

/// SA-12: a tenant admin drafts a call of an active programme. Approval
/// and publication stay the programme manager's (R-PC-03).
#[test]
fn sa12_t_authz_matrix_call_draft_admits_tenant_admins() {
    check("call.draft", 500, true);
}

/// SA-12: a tenant admin edits a call that is not yet published.
#[test]
fn sa12_t_authz_matrix_call_edit_admits_tenant_admins() {
    check("call.edit", 300, true);
}

/// SA-12: a tenant admin lists the programme's calls, so the drafted
/// calls are reachable in the Programme editor. The list holds no
/// proposal content.
#[test]
fn sa12_t_authz_matrix_call_list_admits_tenant_admins() {
    check("call.list", 500, true);
}

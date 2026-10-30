//! Registry tests for the operations lane m4reg adds for the M4 demo
//! (M4 design sections 2.2, 3.6 and 8.3, lane scope m4reg).
//!
//! Written by the m4reg test author from the design and the demo pages,
//! before the production registry holds them. Lane m4int-a found these
//! operations called by the pages but missing from `OPS`:
//!
//! - `tenant.list_admins` and `me.get_verification` (onboarding, J0);
//! - `creator.list_programmes` and `creator.list_templates` (creator
//!   start, J1);
//! - `people.get_invitation` (invitation landing, J2);
//! - `review.assignments` (one proposal's assignments, coordinator, J5);
//! - `committee.open_round`, `committee.cast` and `committee.delegate`
//!   (the D5 ballots of J7: `OpenCutOffRound`, `CastBallot` and
//!   `DelegateVote`).
//!
//! The journey tables name the three committee operations and their
//! routes. The design names none of the six reads. Their names follow the
//! pages, and their routes sit beside the write of the same screen, as
//! the interim reading of this lane. The new `ReadKind` variants are
//! found by their `Debug` names, so these tests fail rather than fail to
//! compile while the kinds are missing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_access::{
    Classification, OPS, OpKind, OpSpec, READ_RULES, ReadKind, ReadRule, RoleOrApplicant,
    SessionNeed,
};
use fstp_domain::StateTag;
use fstp_domain::roles::Role;

use RoleOrApplicant::{Applicant as NoBinding, Role as R};

/// What one m4reg operation must be in the registry.
struct Want {
    /// The operation name the pages call.
    name: &'static str,
    /// The HTTP method.
    method: &'static str,
    /// The route below `/api/v1`.
    path: &'static str,
    /// The operation kind, as its `Debug` spells it.
    kind: &'static str,
    /// The roles through which it acts (P-74).
    acting: &'static [RoleOrApplicant],
    /// How MCP responses would classify its data.
    classification: Classification,
}

/// Every role, and an account with no binding.
const EVERY: &[RoleOrApplicant] = &[
    NoBinding,
    R(Role::ProgrammeManager),
    R(Role::CallDrafter),
    R(Role::FstpCoordinator),
    R(Role::CommitteeMember),
    R(Role::CommitteeChair),
    R(Role::IrcMember),
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
    R(Role::TenantAdmin),
    R(Role::FinanceApprover),
    R(Role::PaymentReleaser),
    R(Role::ContractSignatory),
    R(Role::Auditor),
];
const ADMIN: &[RoleOrApplicant] = &[R(Role::TenantAdmin)];
const MANAGER_OR_ADMIN: &[RoleOrApplicant] = &[R(Role::ProgrammeManager), R(Role::TenantAdmin)];
const COORDINATOR: &[RoleOrApplicant] = &[R(Role::FstpCoordinator)];
const COMMITTEE: &[RoleOrApplicant] = &[R(Role::CommitteeMember), R(Role::CommitteeChair)];

/// The one operation named `name`, or a failure naming it.
fn the_op(name: &str) -> &'static OpSpec {
    let found: Vec<&'static OpSpec> = OPS.iter().filter(|o| o.name == name).collect();
    assert_eq!(
        found.len(),
        1,
        "OPS holds {name} {} times (lane m4reg adds it once)",
        found.len()
    );
    found.first().copied().unwrap_or_else(|| unreachable!())
}

/// Checks one operation against `w`. Every m4reg operation has a web
/// route, no MCP tool and no scope, is not high-risk, and admits any
/// session strength that I-77 allows. A command's binding flag follows
/// the domain; a read is never binding.
fn check(w: &Want) {
    let o = the_op(w.name);
    assert_eq!(
        o.route.map(|(m, p)| (m.as_str(), p)),
        Some((w.method, w.path)),
        "{} route",
        w.name
    );
    assert_eq!(format!("{:?}", o.kind), w.kind, "{} kind", w.name);
    assert!(o.tool.is_none(), "{} has a tool", w.name);
    assert_eq!(o.scope, None, "{} scope", w.name);
    assert!(!o.high_risk, "{} is high-risk", w.name);
    assert_eq!(o.session, SessionNeed::Any, "{} session", w.name);
    match o.kind {
        OpKind::Command(k) => {
            assert_eq!(o.binding, k.binding_action(), "{} binding", w.name);
            assert_eq!(o.high_risk, k.high_risk(), "{} high_risk", w.name);
        }
        _ => assert!(!o.binding, "{} is a binding read", w.name),
    }
    let got: BTreeSet<RoleOrApplicant> = o.acting.iter().copied().collect();
    let want: BTreeSet<RoleOrApplicant> = w.acting.iter().copied().collect();
    assert_eq!(got, want, "{} acting", w.name);
    assert_eq!(o.classification, w.classification, "{} class", w.name);
}

/// SoD-07, design section 2.2 J0: the Administrators step lists the
/// tenant's admins and whether each verified identity, since onboarding
/// finishes only with two verified admins. Tenant admins only, beside
/// `tenant.invite_admin` on `/admin/admins`. The list names accounts, so
/// it is personal data.
#[test]
fn sod07_registry_tenant_list_admins() {
    check(&Want {
        name: "tenant.list_admins",
        method: "GET",
        path: "/admin/admins",
        kind: "Read(ListTenantAdmins)",
        acting: ADMIN,
        classification: Classification::Personal,
    });
}

/// I-86, design section 2.2 J0: the caller's own verification state,
/// beside `me.begin_verification` on `/me/verification`. It reports a
/// vault outcome to its own subject only, and never through MCP, so it
/// has no tool.
#[test]
fn i86_registry_me_get_verification() {
    check(&Want {
        name: "me.get_verification",
        method: "GET",
        path: "/me/verification",
        kind: "Read(GetMyVerification)",
        acting: EVERY,
        classification: Classification::Personal,
    });
}

/// R-PG-02, design section 2.2 J1: the clone sources of the creator start
/// page, the tenant's programmes, beside `creator.open_draft` on
/// `/programmes`. A programme manager or a tenant admin reads them.
#[test]
fn r_pg_02_registry_creator_list_programmes() {
    check(&Want {
        name: "creator.list_programmes",
        method: "GET",
        path: "/programmes",
        kind: "Read(ListProgrammes)",
        acting: MANAGER_OR_ADMIN,
        classification: Classification::Confidential,
    });
}

/// R-PG-02, R-PG-05, design section 2.2 J1: the template catalogue of the
/// creator start page, the platform's templates and the tenant's own. A
/// programme manager or a tenant admin reads it.
#[test]
fn r_pg_02_registry_creator_list_templates() {
    check(&Want {
        name: "creator.list_templates",
        method: "GET",
        path: "/templates",
        kind: "Read(ListTemplates)",
        acting: MANAGER_OR_ADMIN,
        classification: Classification::Confidential,
    });
}

/// SoD-09, design section 2.2 J2: the invitation landing, beside
/// `people.accept_invitation` on `/invitations/{invitation_token}`. The
/// link token is the only capability, never a guessable id. The invitee
/// reads it before enrolling, so every role and an account with no
/// binding act through it. It carries the invited role and the terms, so
/// it is personal data, and it has no tool.
#[test]
fn sod09_registry_people_get_invitation() {
    check(&Want {
        name: "people.get_invitation",
        method: "GET",
        path: "/invitations/{invitation_token}",
        kind: "Read(GetInvitation)",
        acting: EVERY,
        classification: Classification::Personal,
    });
    let accept = the_op("people.accept_invitation");
    let accept_params: Vec<&str> = accept
        .route
        .map(|(_, p)| fstp_access::route_params(p).collect())
        .unwrap_or_default();
    assert_eq!(
        accept_params,
        vec!["invitation_token"],
        "the landing and the acceptance name the invitation alike"
    );
}

/// R-AC-01, design section 2.2 J5: one proposal's assignments, candidates
/// and P-39 and proximity results, for the coordinator's assignment
/// screen, beside `review.assign` on `/proposals/{proposal}/assignments`.
#[test]
fn r_ac_01_registry_review_assignments() {
    check(&Want {
        name: "review.assignments",
        method: "GET",
        path: "/proposals/{proposal}/assignments",
        kind: "Read(ListProposalAssignments)",
        acting: COORDINATOR,
        classification: Classification::Confidential,
    });
}

/// R-EV-08, change D5, design section 2.2 J7: a committee member opens a
/// cut-off round of a call with the order, position, rationale and
/// tie-break, through `OpenCutOffRound`.
#[test]
fn r_ev_08_registry_committee_open_round() {
    check(&Want {
        name: "committee.open_round",
        method: "POST",
        path: "/calls/{call}/cut-off-rounds",
        kind: "Command(OpenCutOffRound)",
        acting: COMMITTEE,
        classification: Classification::Confidential,
    });
}

/// R-EV-09, change D5, design section 2.2 J7: each member casts their own
/// ballot in a round, through `CastBallot`.
#[test]
fn r_ev_09_registry_committee_cast() {
    check(&Want {
        name: "committee.cast",
        method: "POST",
        path: "/cut-off-rounds/{round}/ballot",
        kind: "Command(CastBallot)",
        acting: COMMITTEE,
        classification: Classification::Confidential,
    });
}

/// R-EV-09, P-16 NOTE 8, change D5, design section 2.2 J7: a member
/// delegates their own vote in a round, through `DelegateVote`.
#[test]
fn r_ev_09_registry_committee_delegate() {
    check(&Want {
        name: "committee.delegate",
        method: "POST",
        path: "/cut-off-rounds/{round}/delegation",
        kind: "Command(DelegateVote)",
        acting: COMMITTEE,
        classification: Classification::Confidential,
    });
}

/// The m4reg reads, by `Debug` name, with the operation that serves each.
const M4REG_READS: [(&str, &str); 6] = [
    ("ListTenantAdmins", "tenant.list_admins"),
    ("GetMyVerification", "me.get_verification"),
    ("ListProgrammes", "creator.list_programmes"),
    ("ListTemplates", "creator.list_templates"),
    ("GetInvitation", "people.get_invitation"),
    ("ListProposalAssignments", "review.assignments"),
];

/// The read named `name`, or a failure naming it.
fn kind(name: &str) -> ReadKind {
    ReadKind::ALL
        .iter()
        .copied()
        .find(|k| format!("{k:?}") == name)
        .unwrap_or_else(|| panic!("ReadKind has no {name} yet (lane m4reg)"))
}

/// The one `READ_RULES` row of `k`.
fn row(k: ReadKind) -> (ReadRule, &'static [StateTag]) {
    let rows: Vec<(ReadRule, &'static [StateTag])> = READ_RULES
        .iter()
        .filter(|(x, _, _)| *x == k)
        .map(|(_, r, s)| (*r, *s))
        .collect();
    assert_eq!(rows.len(), 1, "{k:?} has {} READ_RULES rows", rows.len());
    rows.first().copied().unwrap_or_else(|| unreachable!())
}

fn states(s: &[StateTag]) -> BTreeSet<StateTag> {
    s.iter().copied().collect()
}

/// D11, design section 3.6: each m4reg read has one `READ_RULES` row and
/// is served by its operation, whose kind is that read. A read whose
/// target is not a proposal lists every state, since the proposal state
/// does not bear on it, so no state is unjudged.
#[test]
fn d11_m4reg_reads_have_one_row_and_their_operation() {
    for (name, op_name) in M4REG_READS {
        let k = kind(name);
        let (_, open) = row(k);
        let o = the_op(op_name);
        assert_eq!(o.kind, OpKind::Read(k), "{op_name} serves {name}");
        if name != "ListProposalAssignments" {
            assert_eq!(
                states(open),
                states(&StateTag::ALL),
                "{name} opens in every state"
            );
        }
    }
}

/// SoD-07, R-AC-01, design section 3.6: the admin list is a tenant admin
/// read (`ReadRule::TenantAdmin`), as `tenant.settings` and
/// `tenant.get_step` are.
#[test]
fn sod07_list_admins_rule_is_tenant_admin() {
    let (rule, _) = row(kind("ListTenantAdmins"));
    assert_eq!(rule, ReadRule::TenantAdmin);
}

/// I-86, R-AC-01, design section 3.6: the verification state is the
/// caller's own object (`ReadRule::Own`), so it never reports another
/// account's vault outcome.
#[test]
fn i86_own_verification_rule_is_own() {
    let (rule, _) = row(kind("GetMyVerification"));
    assert_eq!(rule, ReadRule::Own);
}

/// R-AC-01, I-21, R-EV-01, design section 3.6: the assignment view is the
/// FSTP coordinator's (`ReadRule::Holder(FstpCoordinator)`), open from
/// SUBMITTED on. A draft is the team's alone until it is submitted, and
/// a knocked-out proposal receives no further review (R-EV-01), so DRAFT
/// and INELIGIBLE are closed (interim reading, see `ASSIGNABLE`).
#[test]
fn r_ac_01_assignment_view_rule_and_states() {
    let (rule, open) = row(kind("ListProposalAssignments"));
    assert_eq!(rule, ReadRule::Holder(Role::FstpCoordinator));
    let want: BTreeSet<StateTag> = StateTag::ALL
        .iter()
        .copied()
        .filter(|s| !matches!(s, StateTag::Draft | StateTag::Ineligible))
        .collect();
    assert_eq!(states(open), want, "ListProposalAssignments states");
}

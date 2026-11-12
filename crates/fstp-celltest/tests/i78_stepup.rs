//! I-78: no high-risk action completes without a phishing-resistant
//! step-up within P-71 (design section 14.4, T-AU-STEPUP, R-LG-03).
//!
//! Lane W1b wrote these tests before the production code. They are red
//! until the gate and the cell fold (lane W2c), the store catalogue (lane
//! W2e) and the tripwire count (lane W4) land. `i78_high_risk_table_*`
//! lives in `w0_high_risk_table.rs` (lane W0). The compile-fail twins
//! `i78_route_without_risk_class_does_not_compile` and
//! `i78_stepup_proof_cannot_be_built_outside_the_gate` are doctests in
//! `fstp_celltest::reference::auth`. The I-78 test
//! `sod_07_self_grant_needs_second_admin_approval_of_the_same_digest` of
//! design section 14.4 lives here, over a production cell. The route
//! table check over production waits for `fstp-cell` to expose its table
//! (lane W3a).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_auth::{AuthCommand, AuthRecord};
use fstp_cell::routes::RiskClass;
use fstp_cell_core::gate::{
    self, Action, Deny, HIGH_RISK_TABLE, HighRiskAction, LoginPolicy, ReadAction, StepUpView,
};
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_celltest::mc::auth_model::http::production_routes;
use fstp_celltest::mc::auth_model::{ProdCell, ProdError, credential_of, prod_session};
use fstp_celltest::mc::stepup_model::{
    Mutant, Production, Reference, StepUpBackend, StepUpDefect, StepUpModel, ids, login_policy_p71,
    prod_action_digest, prod_self_grant_digest, properties,
};
use fstp_celltest::mc::tripwires::{M_STEPUP, NOT_MEASURED, tripwire};
use fstp_celltest::reference::auth::{
    self as r, ROUTES, RefAdmin, RefMethod, RefRisk, RefRoster, RefSelfGrantApproval,
    RefSelfGrantDeny, RefSession,
};
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{AccountId, AssignmentId, BindingId, ProposalId, RequestId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, ADMIN, ADMIN_2, B, P1, SodSetup, T0, call, end, grant, publish, reinstate,
};
use fstp_domain_testkit::harness::teeth::{expect_unreachable, expect_violation};
use fstp_mc::{Config, check, explore};
use fstp_prop::{Gen, prop_assert_eq};

mod pg_store;

// ---------------------------------------------------------------------------
// Helpers.

fn bound() -> Config {
    assert_ne!(
        M_STEPUP, NOT_MEASURED,
        "the M-STEPUP tripwire is not recorded yet (lane W4); \
         i78_m_stepup_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_STEPUP))
}

fn passes<B: StepUpBackend>(backend: B) {
    let model = StepUpModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-STEPUP did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn outcome_of<B: StepUpBackend>(
    backend: B,
) -> fstp_mc::Outcome<
    fstp_celltest::mc::stepup_model::StepUpState,
    fstp_celltest::mc::stepup_model::StepUpAction,
> {
    let model = StepUpModel::new(backend);
    let props = properties(&model);
    check(&model, &props, &bound())
}

fn caught<B: StepUpBackend>(backend: B, id: &str) {
    let outcome = outcome_of(backend);
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn witness_lost<B: StepUpBackend>(backend: B, id: &str) {
    let outcome = outcome_of(backend);
    if let Err(e) = expect_unreachable(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-STEPUP production backend: {e}"))
}

fn cell() -> ProdCell {
    ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"))
}

/// The id of a step-up the ledger granted to [`admin_session`] for
/// `digest`, asserted at [`NOW`] with a passkey and user verification
/// (design section 8.4). `ProdCell::grant_stepup` runs the route check and
/// production records `StepUpGranted`, so the gate meets the step-up in
/// the ledger. ADMIN registers its first passkey once, before the first
/// grant.
fn granted(cell: &mut ProdCell, digest: [u8; 32]) -> [u8; 16] {
    let credential = credential_of(ADMIN, 0);
    if !cell.state().auth().has_any_credential(ADMIN) {
        cell.register_passkey(ADMIN, credential.clone(), T0)
            .unwrap_or_else(|e| panic!("ADMIN's passkey: {e}"));
    }
    match cell.grant_stepup(
        &prod_session(&admin_session()),
        &credential,
        digest,
        true,
        NOW,
    ) {
        Ok(Ok(id)) => id,
        Ok(Err(deny)) => panic!("the step-up route refused: {deny:?}"),
        Err(e) => panic!("the step-up was not granted: {e}"),
    }
}

const NOW: Timestamp = Timestamp::from_micros(3_000_000_000);

fn admin_session() -> RefSession {
    RefSession {
        id: [0x51; 16],
        account: ADMIN,
        method: RefMethod::Passkey,
        device: Some(0),
        started: NOW,
        last_used: NOW,
        ended: None,
    }
}

fn policy(p71: i64) -> LoginPolicy {
    LoginPolicy {
        stepup_freshness_us: p71,
    }
}

fn core(cmd: fstp_domain::Command) -> CellCommand {
    CellCommand::Engine(fstp_engine::Command::Core(cmd))
}

/// The commands of `HIGH_RISK_TABLE` that M3 can build, by table name.
///
/// Gaps: `AddPasskey` has no command of its own, so `RegisterCredential`
/// stands in. `ChangeLoginMethods` is `RevokeCredential`, the device
/// removal of R-LG-04.
fn m3_command(name: &str) -> Option<CellCommand> {
    let setup = SodSetup::one(2, &[1]).steps().ok()?;
    let c = match name {
        "GrantRole" => {
            core(grant(BindingId::from_raw(4_001), A, P1, Role::CommitteeMember, T0).cmd)
        }
        "EndRole" => core(end(BindingId::from_raw(11), T0).cmd),
        "ReinstateBinding" => core(reinstate(BindingId::from_raw(11)).cmd),
        "GrantTenantAdmin" => {
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN_2 })
        }
        "EndTenantAdmin" => CellCommand::Tenant(TenantCommand::EndTenantAdmin { account: ADMIN_2 }),
        "ApproveSelfGrant" => CellCommand::Tenant(TenantCommand::ApproveSelfGrant {
            grant_digest: [0x77; 32],
        }),
        "SetLoginPolicy" => CellCommand::Tenant(TenantCommand::SetLoginPolicy {
            policy: b"{}".to_vec(),
        }),
        "Assign" => core(fstp_domain::Command::Assign {
            assignment: AssignmentId::from_raw(1),
            proposal: ProposalId::from_raw(1),
            reviewer: A,
            kind: AssignmentKind::Reviewer,
            handle: None,
        }),
        "Unassign" => core(fstp_domain::Command::Unassign {
            assignment: AssignmentId::from_raw(1),
        }),
        "AddPasskey" => CellCommand::Auth(AuthCommand::RegisterCredential {
            account: ADMIN,
            credential: vec![0x5E, 1],
        }),
        "ChangeLoginMethods" => CellCommand::Auth(AuthCommand::RevokeCredential {
            account: ADMIN,
            credential: vec![0x5E, 0],
        }),
        "ApprovePayment" => core(fstp_domain::Command::ApprovePayment {
            request: RequestId::from_raw(1),
        }),
        "ReleasePayment" => core(fstp_domain::Command::ReleasePayment {
            request: RequestId::from_raw(1),
            record_file: fstp_domain::id::ContentDigest::from_bytes([0; 32]),
        }),
        "CreateProgramme" => core(setup.first()?.cmd.clone()),
        "ActivateProgramme" => core(setup.get(1)?.cmd.clone()),
        "PublishCall" => core(publish(call(1)).cmd),
        "ApproveBreakGlass" => CellCommand::Ops(OpsCommand::ApproveBreakGlass {
            request: [0x42; 16],
        }),
        "ApproveRecovery" => CellCommand::Auth(AuthCommand::ApproveRecovery { case: [0x7C; 16] }),
        _ => return None,
    };
    Some(c)
}

/// Table entries with no M3 route in design section 8.7. Each names the
/// milestone or reason. The sweep asserts that the reference route table
/// routes none of them.
const NOT_ROUTED_IN_M3: [(&str, &str); 7] = [
    ("TenantExport", "M9 export"),
    ("VaultExport", "M9 export"),
    ("ChangeBankDetails", "M5 payments"),
    ("PublishTemplate", "M4 templates"),
    ("LinkDevice", "no M3 route"),
    ("DesktopSignIn", "no M3 route"),
    ("ChangeEmail", "no M3 route"),
];

/// Table entries that M3 routes but the stubs give no action for. The
/// sweep fails on them until the stubs gain the action (lane W1b gap).
const M3_GAPS: [(&str, &str); 1] = [(
    "IdentityDownload",
    "POST /api/v1/vault-tickets with download scope",
)];

/// Whether `d` is the refusal a fault must get. Each fault names its own
/// `Deny` variant, so a refusal for another reason, such as a missing
/// permission, does not hide a missing step-up rule.
type Expect = fn(&Deny) -> bool;

/// The step-up faults of the sweep, each with the session and step-up it
/// offers and the refusal it must get.
///
/// Reading: design section 5.4 has no variant for a consumed step-up, so
/// a consumed one may be refused as any step-up refusal. The other faults
/// map to the variant design section 5.4 names for them.
fn faulty(
    id: [u8; 16],
    digest: [u8; 32],
    other: [u8; 32],
    p71: i64,
) -> Vec<(&'static str, RefSession, Option<StepUpView>, Expect)> {
    let s = admin_session();
    let good = StepUpView {
        id,
        session: s.id,
        action_digest: digest,
        asserted_at: NOW,
        strong: true,
        consumed: false,
    };
    let stale_at = Timestamp::from_micros(NOW.micros() - p71 - 1);
    let mut magic = s;
    magic.method = RefMethod::MagicLink;
    magic.account = B;
    let required: Expect = |d| matches!(d, Deny::StepUpRequired(_));
    let stale: Expect = |d| *d == Deny::StepUpStale;
    let mismatch: Expect = |d| *d == Deny::StepUpMismatch;
    let weak: Expect = |d| *d == Deny::StepUpFromWeakMethod;
    let magic_rule: Expect = |d| *d == Deny::MagicLinkSessionHighRisk;
    let any_stepup: Expect = |d| {
        matches!(
            d,
            Deny::StepUpRequired(_)
                | Deny::StepUpStale
                | Deny::StepUpMismatch
                | Deny::StepUpFromWeakMethod
        )
    };
    vec![
        ("none", s, None, required),
        (
            "P-71 plus 1 µs old",
            s,
            Some(StepUpView {
                asserted_at: stale_at,
                ..good.clone()
            }),
            stale,
        ),
        (
            "another command's digest",
            s,
            Some(StepUpView {
                action_digest: other,
                ..good.clone()
            }),
            mismatch,
        ),
        (
            "consumed",
            s,
            Some(StepUpView {
                consumed: true,
                ..good.clone()
            }),
            any_stepup,
        ),
        (
            "another session's",
            s,
            Some(StepUpView {
                session: [0x52; 16],
                ..good.clone()
            }),
            mismatch,
        ),
        (
            "a passkey without UV",
            s,
            Some(StepUpView {
                strong: false,
                ..good.clone()
            }),
            weak,
        ),
        (
            "from a magic-link session",
            magic,
            Some(StepUpView {
                session: magic.id,
                ..good
            }),
            magic_rule,
        ),
    ]
}

// ---------------------------------------------------------------------------
// M-STEPUP.

/// I-78, M-STEPUP over production: `gate::admit` over a production cell.
#[test]
fn i78_m_stepup() {
    passes(production());
}

/// I-78, M-STEPUP over the reference: every property and witness holds.
#[test]
fn i78_m_stepup_on_the_reference() {
    passes(Reference);
}

/// I-78, design section 14.1: the recorded tripwire count is the measured
/// state count of M-STEPUP over the reference.
#[test]
fn i78_m_stepup_tripwire_records_the_measured_count() {
    let space = explore(&StepUpModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-STEPUP over the reference did not finish"
    );
    assert_eq!(
        M_STEPUP,
        space.len(),
        "record the measured M-STEPUP count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

// ---------------------------------------------------------------------------
// The sweep.

/// I-78, R-LG-03: every high-risk command of `HIGH_RISK_TABLE` is refused
/// with no step-up, a step-up P-71 plus 1 µs old, another command's
/// digest, a consumed one, another session's, a passkey without UV, and
/// from a magic-link session. Each refusal must be the step-up refusal
/// for that fault. A fresh valid step-up passes the gate.
///
/// The step-up digest is production's own
/// `SHA-256(canonical(command) || command_id)`, through
/// `prod_action_digest`, and the gate checks it under the command id
/// through `gate::admit_command`.
#[test]
fn i78_every_high_risk_route_and_command_needs_a_fresh_step_up() {
    let names: BTreeSet<&str> = HIGH_RISK_TABLE.iter().map(|e| e.command).collect();
    let later: BTreeSet<&str> = NOT_ROUTED_IN_M3.iter().map(|(n, _)| *n).collect();
    let gaps: BTreeSet<&str> = M3_GAPS.iter().map(|(n, _)| *n).collect();
    for name in &later {
        let class = r::high_risk_of(name).unwrap_or_else(|| panic!("{name} is not high-risk"));
        assert!(
            !ROUTES.iter().any(|x| x.risk == RefRisk::HighRisk(class)),
            "{name} is routed in M3 but listed as not routed"
        );
    }
    let missing: BTreeSet<&str> = names
        .iter()
        .copied()
        .filter(|n| !later.contains(n) && m3_command(n).is_none())
        .collect();
    let unlisted: Vec<&&str> = missing.difference(&gaps).collect();
    assert!(
        unlisted.is_empty(),
        "high-risk entries with no M3 action, not listed as gaps: {unlisted:?}"
    );

    let mut cell = cell();
    let p71 = r::P71_DEFAULT_US;
    let command_id = [0xC0; 16];
    for name in names.iter().filter(|n| !later.contains(*n)) {
        let Some(cmd) = m3_command(name) else {
            continue;
        };
        let digest = prod_action_digest(&cmd, command_id).unwrap_or_else(|e| panic!("{e}"));
        let other = r::action_digest(b"another command", command_id);
        let id = granted(&mut cell, digest);
        for (fault, s, u, expect) in faulty(id, digest, other, p71) {
            let got = gate::admit_command(
                cell.state(),
                &prod_session(&s),
                Action::Command(cmd.clone()),
                command_id,
                u.as_ref(),
                NOW,
                &policy(p71),
            );
            match got {
                Err(Deny::NotImplemented(op)) => panic!("{op} is NotImplemented"),
                Err(d) => assert!(
                    expect(&d),
                    "{name} with a step-up that is {fault} was refused for another reason: {d:?}"
                ),
                Ok(_) => panic!("{name} with a step-up that is {fault} was admitted"),
            }
        }
        let fresh = StepUpView {
            id,
            session: admin_session().id,
            action_digest: digest,
            asserted_at: NOW,
            strong: true,
            consumed: false,
        };
        let got = gate::admit_command(
            cell.state(),
            &prod_session(&admin_session()),
            Action::Command(cmd.clone()),
            command_id,
            Some(&fresh),
            NOW,
            &policy(p71),
        );
        assert!(
            got.is_ok(),
            "{name} with a fresh valid step-up was refused: {got:?}"
        );
    }
    assert!(
        missing.is_empty(),
        "M3 routes these high-risk actions, but the stubs give no action for them: {missing:?}"
    );
}

/// I-78, design section 8.4: `HighRiskAction::of` classifies every M3
/// command as the reference table does, and a read as needing no step-up.
#[test]
fn i78_high_risk_of_matches_reference() {
    let mut cases: Vec<(String, Action)> = HIGH_RISK_TABLE
        .iter()
        .filter_map(|e| m3_command(e.command).map(|c| (e.command.to_owned(), Action::Command(c))))
        .collect();
    cases.push((
        "GrantStepUp".to_owned(),
        Action::Command(CellCommand::Auth(AuthCommand::GrantStepUp {
            session: [1; 16],
            action_digest: [2; 32],
        })),
    ));
    cases.push((
        "EndBreakGlass".to_owned(),
        Action::Command(CellCommand::Ops(OpsCommand::EndBreakGlass {
            grant: [3; 16],
        })),
    ));
    cases.push(("ReadAudit".to_owned(), Action::Read(ReadAction::ReadAudit)));
    for (name, action) in cases {
        let want = r::high_risk_of(&name).map(|c| format!("{c:?}"));
        match HighRiskAction::of(&action) {
            Err(Deny::NotImplemented(op)) => panic!("{op} is NotImplemented"),
            Err(d) => panic!("{name}: HighRiskAction::of refused with {d:?}"),
            Ok(got) => assert_eq!(got.map(|c| format!("{c:?}")), want, "{name}"),
        }
    }
}

/// I-78: every route class of the reference route table that needs a
/// step-up names an action of `HIGH_RISK_TABLE` (design section 8.7).
#[test]
fn i78_reference_high_risk_routes_name_table_actions() {
    let table: BTreeSet<String> = HIGH_RISK_TABLE
        .iter()
        .map(|e| format!("{:?}", e.action))
        .collect();
    for route in ROUTES {
        if let RefRisk::HighRisk(class) = route.risk {
            assert!(
                table.contains(&format!("{class:?}")),
                "{} {} needs {class:?}, which HIGH_RISK_TABLE lacks",
                route.method,
                route.path
            );
        }
    }
}

/// I-78, design section 8.7: every route of the production cell carries
/// the risk class of the section 8.7 table, and every auth and API route
/// it serves is in that table. A high-risk route names the same action;
/// every other class is `RiskClass::Normal`.
///
/// Reading: `POST /api/v1/commands` and `POST /api/v1/vault-tickets` are
/// classified per command and per scope through `HighRiskAction::of`, so
/// their route class is `Normal`.
///
/// Gap: `fstp-cell` exposes no route table yet, so `production_routes`
/// refuses with `ROUTE_TABLE_SEAM` (lane W3a).
#[test]
fn i78_production_routes_have_the_section_8_7_risk_classes() {
    let routes = production_routes().unwrap_or_else(|e| panic!("{e}"));
    let parts: Vec<(&str, &str, RiskClass)> = routes.iter().map(|x| x.parts()).collect();
    for want in ROUTES {
        let got = parts
            .iter()
            .find(|(m, p, _)| *m == want.method && *p == want.path)
            .map(|(_, _, risk)| *risk)
            .unwrap_or_else(|| panic!("production has no route {} {}", want.method, want.path));
        match (want.risk, got) {
            (RefRisk::HighRisk(class), RiskClass::HighRisk(action)) => assert_eq!(
                format!("{action:?}"),
                format!("{class:?}"),
                "{} {}",
                want.method,
                want.path
            ),
            (RefRisk::HighRisk(class), RiskClass::Normal) => panic!(
                "{} {} is Normal in production but needs {class:?}",
                want.method, want.path
            ),
            (_, RiskClass::HighRisk(action)) => panic!(
                "{} {} needs {action:?} in production but is not high risk in section 8.7",
                want.method, want.path
            ),
            (_, RiskClass::Normal) => {}
        }
    }
    for (method, path, _) in &parts {
        let served = path.starts_with("/auth/") || path.starts_with("/api/");
        assert!(
            !served
                || ROUTES
                    .iter()
                    .any(|x| x.method == *method && x.path == *path),
            "production serves {method} {path}, which section 8.7 does not list"
        );
    }
}

// ---------------------------------------------------------------------------
// SoD-07.

/// The tenant admins of the SoD-07 tests: admin1 and admin2.
fn two_admins() -> RefRoster {
    RefRoster {
        bindings: Vec::new(),
        admins: vec![
            RefAdmin {
                account: ADMIN,
                end: None,
            },
            RefAdmin {
                account: ADMIN_2,
                end: None,
            },
        ],
    }
}

/// admin1's grant of finance approver to its own account, starting at `at`.
fn self_grant(at: Timestamp) -> CellCommand {
    core(
        grant(
            BindingId::from_raw(7_001),
            ADMIN,
            P1,
            Role::FinanceApprover,
            at,
        )
        .cmd,
    )
}

/// I-78, SoD-07, TH-05, design section 5.1: a tenant admin's grant to its
/// own account commits only with an unused, unexpired approval by a
/// different current tenant admin of the same grant digest. One approval
/// admits exactly one grant: its batch records `SelfGrantApprovalUsed`,
/// and the same grant does not commit again.
///
/// Each leg also asserts the reference rule's verdict, so the test and
/// `admit_self_grant` agree.
///
/// Gap: production's digest needs `prod_self_grant_digest`, which refuses
/// with `SELF_GRANT_DIGEST_SEAM` (lane W2c).
#[test]
fn sod_07_self_grant_needs_second_admin_approval_of_the_same_digest() {
    let grant_id = [0xD7; 16];
    let approved_at = T0;
    let fresh_at = Timestamp::from_micros(T0.micros() + r::MINUTE_US);
    let stale_at = Timestamp::from_micros(T0.micros() + r::P71_DEFAULT_US + 1);
    let digest_at = |at: Timestamp| {
        prod_self_grant_digest(&self_grant(at), grant_id).unwrap_or_else(|e| panic!("{e}"))
    };
    let other_digest = |at: Timestamp| {
        let other = core(grant(BindingId::from_raw(7_002), ADMIN, P1, Role::Auditor, at).cmd);
        prod_self_grant_digest(&other, grant_id).unwrap_or_else(|e| panic!("{e}"))
    };
    type Leg = (&'static str, Vec<(AccountId, [u8; 32])>, Timestamp, bool);
    let legs: Vec<Leg> = vec![
        ("no approval", Vec::new(), fresh_at, false),
        (
            "an approval of another digest",
            vec![(ADMIN_2, other_digest(fresh_at))],
            fresh_at,
            false,
        ),
        (
            "an approval by the grantor",
            vec![(ADMIN, digest_at(fresh_at))],
            fresh_at,
            false,
        ),
        (
            "an approval older than P-71",
            vec![(ADMIN_2, digest_at(stale_at))],
            stale_at,
            false,
        ),
        (
            "a valid approval",
            vec![(ADMIN_2, digest_at(fresh_at))],
            fresh_at,
            true,
        ),
    ];
    for (leg, approvals, at, admitted) in legs {
        let digest = digest_at(at);
        let reference: Vec<RefSelfGrantApproval> = approvals
            .iter()
            .map(|(approver, d)| RefSelfGrantApproval {
                approver: *approver,
                grant_digest: *d,
                stepup_at: approved_at,
                used: false,
            })
            .collect();
        let verdict = r::admit_self_grant(
            &two_admins(),
            ADMIN,
            ADMIN,
            digest,
            &reference,
            at,
            r::P71_DEFAULT_US,
        );
        assert_eq!(verdict.is_ok(), admitted, "{leg}: the reference disagrees");

        let mut cell = cell();
        cell.exec_tenant_admin_grant(ADMIN, ADMIN_2, T0)
            .unwrap_or_else(|e| panic!("{leg}: {e}"));
        for (approver, d) in &approvals {
            let approve = CellCommand::Tenant(TenantCommand::ApproveSelfGrant { grant_digest: *d });
            match cell.exec(approve, *approver, approved_at) {
                Err(ProdError::NotImplemented(op)) => panic!("{leg}: {op} is NotImplemented"),
                // An approval the cell refuses up front is no approval.
                Ok(_) | Err(ProdError::Refused(_)) => {}
            }
        }
        let got = cell.exec_with_id(self_grant(at), ADMIN, at, grant_id);
        match (got, admitted) {
            (Err(ProdError::NotImplemented(op)), _) => panic!("{leg}: {op} is NotImplemented"),
            (Err(ProdError::Refused(_)), false) => {}
            (Ok(batch), false) => panic!("{leg}: the self-grant committed: {batch:?}"),
            (Err(ProdError::Refused(why)), true) => {
                panic!("{leg}: the self-grant was refused: {why}")
            }
            (Ok(batch), true) => {
                let used = batch
                    .iter()
                    .filter(|x| {
                        matches!(
                            x,
                            CellRecord::Tenant(TenantRecord::SelfGrantApprovalUsed { grant_digest })
                                if *grant_digest == digest
                        )
                    })
                    .count();
                assert_eq!(used, 1, "{leg}: SelfGrantApprovalUsed in {batch:?}");
                match cell.exec_with_id(self_grant(at), ADMIN, at, grant_id) {
                    Err(ProdError::NotImplemented(op)) => {
                        panic!("{leg}: {op} is NotImplemented")
                    }
                    Err(ProdError::Refused(_)) => {}
                    Ok(again) => assert!(
                        again.is_empty(),
                        "{leg}: one approval admitted a second grant: {again:?}"
                    ),
                }
            }
        }
    }
}

/// I-78, SoD-07, design section 5.1: the reference rule refuses a
/// self-grant with no approval, another digest, the grantor's approval, a
/// non-admin's approval, an approval older than P-71 or a used one, and
/// admits one with a valid approval. A grant to another account needs none.
#[test]
fn i78_sod_07_reference_self_grant_approval_rule() {
    let digest = [0x71; 32];
    let now = Timestamp::from_micros(T0.micros() + r::MINUTE_US);
    let valid = RefSelfGrantApproval {
        approver: ADMIN_2,
        grant_digest: digest,
        stepup_at: T0,
        used: false,
    };
    let check = |approvals: &[RefSelfGrantApproval], at: Timestamp| {
        r::admit_self_grant(
            &two_admins(),
            ADMIN,
            ADMIN,
            digest,
            approvals,
            at,
            r::P71_DEFAULT_US,
        )
    };
    let p71_old = Timestamp::from_micros(T0.micros() + r::P71_DEFAULT_US);
    let stale = Timestamp::from_micros(p71_old.micros() + 1);
    type Case = (
        &'static str,
        Vec<RefSelfGrantApproval>,
        Timestamp,
        Result<Option<usize>, RefSelfGrantDeny>,
    );
    let cases: Vec<Case> = vec![
        ("none", Vec::new(), now, Err(RefSelfGrantDeny::NoApproval)),
        (
            "another digest",
            vec![RefSelfGrantApproval {
                grant_digest: [0x72; 32],
                ..valid
            }],
            now,
            Err(RefSelfGrantDeny::OtherDigest),
        ),
        (
            "the grantor",
            vec![RefSelfGrantApproval {
                approver: ADMIN,
                ..valid
            }],
            now,
            Err(RefSelfGrantDeny::ApproverIsGrantor),
        ),
        (
            "not an admin",
            vec![RefSelfGrantApproval {
                approver: A,
                ..valid
            }],
            now,
            Err(RefSelfGrantDeny::ApproverNotAdmin),
        ),
        ("P-71 old", vec![valid], p71_old, Ok(Some(0))),
        (
            "P-71 plus 1 µs old",
            vec![valid],
            stale,
            Err(RefSelfGrantDeny::Expired),
        ),
        (
            "used",
            vec![RefSelfGrantApproval {
                used: true,
                ..valid
            }],
            now,
            Err(RefSelfGrantDeny::Used),
        ),
        ("valid", vec![valid], now, Ok(Some(0))),
    ];
    for (name, approvals, at, want) in cases {
        assert_eq!(check(&approvals, at), want, "{name}");
    }
    assert_eq!(
        r::admit_self_grant(&two_admins(), ADMIN, A, digest, &[], now, r::P71_DEFAULT_US),
        Ok(None),
        "a grant to another account needs no approval"
    );
}

// ---------------------------------------------------------------------------
// Logging, P-71 and the database.

/// I-78: a step-up is logged with the action digest it authorises: the
/// batch of `GrantStepUp` records `StepUpGranted` with that digest.
#[test]
fn i78_stepup_logged_with_action_digest() {
    let mut cell = cell();
    let digest = r::action_digest(b"ReleasePayment#1", [0xC0; 16]);
    let cmd = CellCommand::Auth(AuthCommand::GrantStepUp {
        session: admin_session().id,
        action_digest: digest,
    });
    let batch = cell.exec(cmd, ADMIN, NOW).unwrap_or_else(|e| panic!("{e}"));
    let logged = batch.iter().any(|x| {
        matches!(
            x,
            fstp_cell_core::CellRecord::Auth(AuthRecord::StepUpGranted { action_digest, .. })
                if *action_digest == digest
        )
    });
    assert!(
        logged,
        "no StepUpGranted with the action digest in {batch:?}"
    );
}

/// I-78, P-71 "may only shorten": `SetLoginPolicy` with a tenant P-71
/// above the default is refused, and one at or below it is accepted, as
/// `validate_p71` says (design section 8.4, ADR-008).
///
/// Gap: the canonical login policy form is not defined, so
/// `login_policy_p71` refuses with `POLICY_SEAM` for now.
#[test]
fn i78_tenant_p71_above_the_default_is_refused() {
    let values = [
        1,
        r::MINUTE_US,
        r::P71_DEFAULT_US - 1,
        r::P71_DEFAULT_US,
        r::P71_DEFAULT_US + 1,
        2 * r::P71_DEFAULT_US,
        0,
        -1,
    ];
    for v in values {
        let mut cell = cell();
        let policy = login_policy_p71(v).unwrap_or_else(|e| panic!("{e}"));
        let cmd = CellCommand::Tenant(TenantCommand::SetLoginPolicy { policy });
        let got = match cell.exec(cmd, ADMIN, NOW) {
            Ok(_) => true,
            Err(ProdError::Refused(_)) => false,
            Err(e @ ProdError::NotImplemented(_)) => panic!("{e}"),
        };
        assert_eq!(
            got,
            r::validate_p71(v).is_ok(),
            "SetLoginPolicy with a tenant P-71 of {v} µs"
        );
    }
}

/// I-78, P-71 "may only shorten": the gate admits a step-up exactly when
/// its age is at most the smaller of the tenant value and the default.
#[test]
fn i78_p71_may_only_shorten() {
    let mut cell = cell();
    let cmd = m3_command("ReleasePayment").unwrap_or_else(|| panic!("no ReleasePayment"));
    let digest = prod_action_digest(&cmd, [0xC0; 16]).unwrap_or_else(|e| panic!("{e}"));
    let id = granted(&mut cell, digest);
    fstp_prop::check("i78_p71_may_only_shorten", |g: &mut Gen| {
        let tenant = g.i64_in(1..=2 * r::P71_DEFAULT_US);
        let limit = r::effective_p71(Some(tenant));
        let age = match g.u8_in(0..=2) {
            0 => limit + g.i64_in(-1..=1),
            1 => r::P71_DEFAULT_US + g.i64_in(-1..=1),
            _ => g.i64_in(0..=2 * r::P71_DEFAULT_US),
        }
        .max(0);
        let u = StepUpView {
            id,
            session: admin_session().id,
            action_digest: digest,
            asserted_at: Timestamp::from_micros(NOW.micros() - age),
            strong: true,
            consumed: false,
        };
        let got = gate::admit_command(
            cell.state(),
            &prod_session(&admin_session()),
            Action::Command(cmd.clone()),
            [0xC0; 16],
            Some(&u),
            NOW,
            &policy(tenant),
        );
        if let Err(Deny::NotImplemented(op)) = got {
            return Err(format!("{op} is NotImplemented"));
        }
        prop_assert_eq!(
            got.is_ok(),
            age <= limit,
            "tenant P-71 {tenant} µs, age {age} µs"
        );
        Ok(())
    });
}

/// I-78, design section 4.2: the database refuses a second consumption of
/// a step-up through the primary key of `auth_log.stepup_consumed`.
///
/// The writer of a cell database granted the production plan inserts one
/// consumption, then the same challenge again. The second insert fails
/// with SQLSTATE 23505 and the table keeps one row (lane F-STORE).
#[test]
fn i78_database_refuses_a_second_step_up_consumption() {
    let t = fstp_pgstore::CATALOGUE
        .iter()
        .find(|t| t.schema == "auth_log" && t.name == "stepup_consumed");
    let t = t.unwrap_or_else(|| {
        panic!("fstp_pgstore::CATALOGUE lists no auth_log.stepup_consumed (lane W2e)")
    });
    let first = t.columns.first().map(|c| c.name);
    assert_eq!(
        first,
        Some("challenge_id"),
        "the key column of {}.{}",
        t.schema,
        t.name
    );
    let db = pg_store::prod_db();
    let command = pg_store::fresh16();
    let entry = fstp_audit::chain::StoredEntry {
        seq: 1,
        at: 1_000,
        command,
        schema: 1,
        key_ix: 0,
        body: vec![0xA5; 40],
    };
    let seed = pg_store::insert_entries_sql(&command, 1_000, std::slice::from_ref(&entry));
    db.psql_as("writer", &seed)
        .unwrap_or_else(|e| panic!("the writer's ledger row: {e:?}"));
    let insert = format!(
        "INSERT INTO auth_log.stepup_consumed (challenge_id, ledger_seq) VALUES ('{}', 1);",
        pg_store::uuid_text(&pg_store::fresh16())
    );
    assert_eq!(
        db.state_as("writer", &insert),
        None,
        "I-78: the first consumption"
    );
    assert_eq!(
        db.state_as("writer", &insert).as_deref(),
        Some("23505"),
        "I-78: a second consumption of one challenge"
    );
    assert_eq!(
        db.count("SELECT count(*) FROM auth_log.stepup_consumed;"),
        1,
        "I-78: the rows of one challenge"
    );
}

/// I-78, ADR-007: the ledger-writing role holds INSERT and SELECT only on
/// the `auth_log` tables, so no update can undo a consumption.
///
/// The cell database is granted the production plan. The writer holds
/// exactly SELECT and INSERT on each `auth_log` table, no column grant,
/// and no privilege beyond SELECT and INSERT on any table. Its UPDATE,
/// DELETE and TRUNCATE fail with SQLSTATE 42501 (lane F-STORE).
#[test]
fn i78_writer_role_holds_insert_and_select_only() {
    let tables: BTreeSet<&str> = fstp_pgstore::CATALOGUE
        .iter()
        .filter(|t| t.schema == "auth_log")
        .map(|t| t.name)
        .collect();
    assert_eq!(
        tables,
        BTreeSet::from(["stepup_consumed", "session_end"]),
        "fstp_pgstore::CATALOGUE must list both auth_log tables (lane W2e)"
    );
    let db = pg_store::prod_db();
    let writer = db.role("writer");
    let grants: Vec<(String, String)> = pg_store::table_grants(&db)
        .into_iter()
        .filter(|(r, _, _)| *r == writer)
        .map(|(_, o, p)| (o, p))
        .collect();
    for table in &tables {
        let object = format!("auth_log.{table}");
        let held: BTreeSet<&str> = grants
            .iter()
            .filter(|(o, _)| *o == object)
            .map(|(_, p)| p.as_str())
            .collect();
        assert_eq!(
            held,
            BTreeSet::from(["INSERT", "SELECT"]),
            "I-78: the writer's privileges on {object}"
        );
    }
    let beyond: Vec<&(String, String)> = grants
        .iter()
        .filter(|(_, p)| p != "SELECT" && p != "INSERT")
        .collect();
    assert!(
        beyond.is_empty(),
        "I-78: the writer holds more than INSERT and SELECT: {beyond:?}"
    );
    let columns: Vec<_> = pg_store::column_grants(&db)
        .into_iter()
        .filter(|(r, _, _)| *r == writer)
        .collect();
    assert!(
        columns.is_empty(),
        "I-78: the writer holds column grants: {columns:?}"
    );
    for (table, key) in [
        ("auth_log.stepup_consumed", "challenge_id"),
        ("auth_log.session_end", "session_id"),
    ] {
        for stmt in [
            format!("UPDATE {table} SET {key} = {key};"),
            format!("DELETE FROM {table};"),
            format!("TRUNCATE {table};"),
        ] {
            assert_eq!(
                db.state_as("writer", &stmt).as_deref(),
                Some("42501"),
                "I-78: the writer ran {stmt}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Teeth.

/// I-78 teeth: a step-up accepted 1 µs past P-71 is caught.
#[test]
fn i78_teeth_stale_step_up_accepted_is_caught() {
    caught(
        Mutant::new(production(), StepUpDefect::StaleAccepted),
        ids::I78,
    );
}

/// I-78 teeth: the same defect is caught on the reference.
#[test]
fn i78_teeth_stale_step_up_accepted_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, StepUpDefect::StaleAccepted),
        ids::I78,
    );
}

/// I-78 teeth: `>=` for staleness refuses a step-up exactly P-71 old, so
/// the witness at P-71 disappears.
#[test]
fn i78_teeth_step_up_exactly_p71_old_refused_is_caught() {
    witness_lost(
        Mutant::new(production(), StepUpDefect::FreshAtP71Refused),
        ids::W_AT_P71,
    );
}

/// I-78 teeth: the same defect is caught on the reference.
#[test]
fn i78_teeth_step_up_exactly_p71_old_refused_is_caught_on_the_reference() {
    witness_lost(
        Mutant::new(Reference, StepUpDefect::FreshAtP71Refused),
        ids::W_AT_P71,
    );
}

/// I-78 teeth: a batch that does not consume its step-up is caught.
#[test]
fn i78_teeth_consumption_dropped_is_caught() {
    caught(
        Mutant::new(production(), StepUpDefect::ConsumptionDropped),
        ids::I78_SINGLE_USE,
    );
}

/// I-78 teeth: the same defect is caught on the reference.
#[test]
fn i78_teeth_consumption_dropped_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, StepUpDefect::ConsumptionDropped),
        ids::I78_SINGLE_USE,
    );
}

/// I-78 teeth: a digest compared by command kind only is caught.
#[test]
fn i78_teeth_digest_compared_by_kind_is_caught() {
    caught(
        Mutant::new(production(), StepUpDefect::DigestComparedByKind),
        ids::I78,
    );
}

/// I-78 teeth: the same defect is caught on the reference.
#[test]
fn i78_teeth_digest_compared_by_kind_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, StepUpDefect::DigestComparedByKind),
        ids::I78,
    );
}

/// I-78 teeth, design section 8.3: a gate that lets a magic-link session
/// add a passkey to its own account is caught.
#[test]
fn i78_teeth_magic_link_session_adds_passkey_is_caught() {
    caught(
        Mutant::new(production(), StepUpDefect::MagicLinkRuleDropped),
        ids::I78,
    );
}

/// I-78 teeth: the same defect is caught on the reference.
#[test]
fn i78_teeth_magic_link_session_adds_passkey_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, StepUpDefect::MagicLinkRuleDropped),
        ids::I78,
    );
}

// ---------------------------------------------------------------------------
// The reference itself.

/// I-78, SoD-08, design section 8.6: a break-glass grant admits only the
/// staff member it names, only for reads in its scope and window, and
/// never a command. Staff accounts hold no role in the cell.
#[test]
fn i78_sod_08_reference_break_glass_admits_only_the_named_staff_member() {
    let approved_at = NOW;
    let g = r::RefBreakGlass {
        staff: r::RefStaff(7),
        scope: vec![r::RefRead::Audit],
        approved_at,
        until: Timestamp::from_micros(NOW.micros() + r::HOUR_US),
        ended: None,
    };
    let t = Timestamp::from_micros(NOW.micros() + 1);
    let read = r::RefStaffRequest::Read(r::RefRead::Audit);
    assert!(r::admit_break_glass(
        &g,
        read,
        true,
        Some(r::RefStaff(7)),
        t
    ));
    assert!(
        !r::admit_break_glass(&g, read, true, Some(r::RefStaff(8)), t),
        "another staff member"
    );
    assert!(
        !r::admit_break_glass(&g, read, true, None, t),
        "an assertion that does not verify"
    );
    assert!(
        !r::admit_break_glass(
            &g,
            r::RefStaffRequest::Command,
            true,
            Some(r::RefStaff(7)),
            t
        ),
        "a command"
    );
    assert!(r::BREAK_GLASS_ROLES.is_empty(), "staff hold no role");
    let roster = r::RefRoster {
        bindings: vec![r::RefBinding {
            account: B,
            role: Role::Applicant,
            end: None,
            suspended: false,
            voided: false,
        }],
        admins: Vec::new(),
    };
    assert!(r::sod08_staff_hold_no_role(&roster, &[A], t));
    assert!(
        !r::sod08_staff_hold_no_role(&roster, &[B], t),
        "a staff account with a Receiving binding"
    );
}

/// I-78, P-71: the reference refuses a tenant P-71 above the default and
/// takes the default in its place.
#[test]
fn i78_reference_p71_may_only_shorten() {
    assert!(r::validate_p71(r::P71_DEFAULT_US).is_ok());
    assert!(r::validate_p71(r::P71_DEFAULT_US + 1).is_err());
    assert!(r::validate_p71(0).is_err());
    assert_eq!(
        r::effective_p71(Some(r::P71_DEFAULT_US + 1)),
        r::P71_DEFAULT_US
    );
    assert_eq!(r::effective_p71(Some(r::MINUTE_US)), r::MINUTE_US);
}

/// I-78: the reference digest binds the command id, and the challenge
/// binds cell, session and digest.
#[test]
fn i78_reference_digest_binds_command_id_and_challenge_binds_session() {
    let d1 = r::action_digest(b"GrantRole", [1; 16]);
    let d2 = r::action_digest(b"GrantRole", [2; 16]);
    assert_ne!(d1, d2);
    let c1 = r::stepup_challenge(&[9; 16], [1; 16], d1, b"n");
    let c2 = r::stepup_challenge(&[9; 16], [2; 16], d1, b"n");
    assert_ne!(c1, c2);
}

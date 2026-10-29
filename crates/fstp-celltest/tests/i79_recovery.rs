//! I-79: an account holding any role outside Receiving is never recovered
//! by email alone (design section 14.4, T-AU-RECOVERY).
//!
//! Lane W1b wrote these tests before the production code. They are red
//! until `fstp_auth::recovery` (lane W2b), the recovery routes (lane W3a)
//! and the tripwire count (lane W4) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::recovery::{RecoveryPath, recovery_path};
use fstp_celltest::mc::auth_model::RosterChange;
use fstp_celltest::mc::auth_model::http::{AuthClient, CaseRef, Cookie, one_cell_world};
use fstp_celltest::mc::recover_model::{
    IX_A, IX_ADMIN1, IX_ADMIN2, IX_B, Mutant, Production, RecoverAction, RecoverBackend,
    RecoverDefect, RecoverModel, RecoverState, Reference, Variant, VaultAnswer, account, ids,
    prod_holdings, prod_mode, properties, ref_path,
};
use fstp_celltest::mc::tripwires::{M_RECOVER, NOT_MEASURED, tripwire};
use fstp_celltest::reference::auth::{
    self as r, RefApproval, RefDeployment, RefEvidence, RefHoldings, RefPath, RefRoster,
};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, B};
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::{Config, Model, check, explore};
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

fn bound() -> Config {
    assert_ne!(
        M_RECOVER, NOT_MEASURED,
        "the M-RECOVER tripwire is not recorded yet (lane W4); \
         i79_m_recover_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_RECOVER))
}

fn passes<B: RecoverBackend>(backend: B) {
    let model = RecoverModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-RECOVER did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn caught<B: RecoverBackend>(backend: B, id: &str) {
    let model = RecoverModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn production() -> Production {
    Production::new()
        .unwrap_or_else(|e| panic!("M-RECOVER production backend: {e} (NotImplemented)"))
}

const ALL_HOLDINGS: [RefHoldings; 3] = [
    RefHoldings::ReceivingOnly,
    RefHoldings::Management,
    RefHoldings::TenantAdmin,
];

/// A world with admin1 enrolled, a holding committee member, and admin2
/// a tenant admin in the two-admin variant. Returns the client and admin1's
/// session cookie.
fn seeded<'w>(
    client: &AuthClient<'w>,
    variant: Variant,
) -> Result<std::collections::BTreeMap<u8, Cookie>, String> {
    let e = |x: fstp_celltest::NotImplemented| x.to_string();
    for who in [ADMIN, ADMIN_2, A, B] {
        if !client.enrol(who).map_err(e)? {
            return Err(format!("{who:?} could not enrol"));
        }
    }
    let mut cookies = std::collections::BTreeMap::new();
    let admin = client
        .login(ADMIN, r::RefMethod::Passkey)
        .map_err(e)?
        .ok_or("admin1 cannot log in")?;
    let cm = RosterChange::Grant {
        account: A,
        role: Role::CommitteeMember,
        until: None,
    };
    if !client.roster(&admin, cm).map_err(e)? {
        return Err("the committee grant to a was refused".to_owned());
    }
    if variant == Variant::TwoAdmins
        && !client
            .roster(&admin, RosterChange::GrantAdmin { account: ADMIN_2 })
            .map_err(e)?
    {
        return Err("the tenant admin grant to admin2 was refused".to_owned());
    }
    cookies.insert(IX_ADMIN1, admin);
    for (ix, who) in [(IX_ADMIN2, ADMIN_2), (IX_A, A)] {
        if let Some(c) = client.login(who, r::RefMethod::Passkey).map_err(e)? {
            cookies.insert(ix, c);
        }
    }
    Ok(cookies)
}

// ---------------------------------------------------------------------------
// M-RECOVER.

/// I-79, M-RECOVER over production: `fstp_auth::recovery`.
#[test]
fn i79_m_recover() {
    passes(production());
}

/// I-79, M-RECOVER over the reference: every property and witness holds.
#[test]
fn i79_m_recover_on_the_reference() {
    passes(Reference);
}

/// I-79, design section 14.1: the recorded tripwire count is the measured
/// state count of M-RECOVER over the reference.
#[test]
fn i79_m_recover_tripwire_records_the_measured_count() {
    let space = explore(&RecoverModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-RECOVER over the reference did not finish"
    );
    assert_eq!(
        M_RECOVER,
        space.len(),
        "record the measured M-RECOVER count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

// ---------------------------------------------------------------------------
// Production against the reference.

/// I-79, design section 8.5: `recovery_path` equals the reference path for
/// every holding, number of other admins and deployment.
#[test]
fn i79_recovery_path_matches_reference() {
    fstp_prop::check("i79_recovery_path_matches_reference", |g: &mut Gen| {
        let h = *g.pick(&ALL_HOLDINGS);
        let others = g.usize_in(0..=3);
        let mode = *g.pick(&[RefDeployment::Saas, RefDeployment::SelfHosted]);
        let want = r::recovery_path(h, others, mode);
        match recovery_path(prod_holdings(h), others, prod_mode(mode)) {
            Err(fstp_auth::AuthError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
            Ok(got) => {
                prop_assert_eq!(
                    ref_path(got),
                    want,
                    "{h:?}, {others} other admins, {mode:?}"
                );
                Ok(())
            }
        }
    });
}

/// I-79, Q15: the sole tenant admin of a SaaS cell needs an operator
/// ticket with two staff approvals, and the completion is shown to the
/// tenant. A self-hosted cell's sole admin needs the host console.
#[test]
fn i79_sole_admin_needs_operator_ticket_shown_to_tenant() {
    let saas = recovery_path(
        prod_holdings(RefHoldings::TenantAdmin),
        0,
        prod_mode(RefDeployment::Saas),
    );
    let hosted = recovery_path(
        prod_holdings(RefHoldings::TenantAdmin),
        0,
        prod_mode(RefDeployment::SelfHosted),
    );
    assert_eq!(saas, Ok(RecoveryPath::OperatorProcess), "SaaS sole admin");
    assert_eq!(
        hosted,
        Ok(RecoveryPath::HostConsole),
        "self-hosted sole admin"
    );

    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world
        .cell(0)
        .unwrap_or_else(|| panic!("the world has no cell 0"));
    let client = AuthClient::new(cell);
    let cookies = seeded(&client, Variant::SoleAdminSaas).unwrap_or_else(|e| panic!("{e}"));
    let case = client
        .recovery(ADMIN)
        .unwrap()
        .unwrap_or_else(|| panic!("no case"));
    assert!(client.recovery_email(&case).unwrap());
    assert!(
        !client.recovery_ticket(&case, false).unwrap(),
        "one staff member twice"
    );
    assert!(
        client.recovery_complete(&case).unwrap().is_none(),
        "email alone"
    );
    assert!(
        client.recovery_ticket(&case, true).unwrap(),
        "two staff members"
    );
    let fresh = client.recovery_complete(&case).unwrap();
    let fresh = fresh.unwrap_or_else(|| panic!("the ticketed recovery did not complete"));
    let audit = client.audit_view(&fresh).unwrap();
    assert!(
        !audit.is_empty(),
        "the operator recovery is not in the tenant's audit view"
    );
    let old = cookies
        .get(&IX_ADMIN1)
        .unwrap_or_else(|| panic!("no admin1 cookie"));
    assert!(
        !client.admitted(old).unwrap(),
        "the old admin1 session survived recovery"
    );
}

/// I-79, ADR-008: an approval is refused when the approver is the holder,
/// is not a current tenant admin, gives no step-up, or shares the holder's
/// identity, and when the vault cannot answer. A valid one is accepted.
#[test]
fn i79_approver_differs_steps_up_and_is_not_the_same_identity() {
    let holder = A;
    let ok = RefApproval {
        approver: ADMIN_2,
        approver_admin: true,
        stepup_ok: true,
        same_identity: Some(false),
        both_verified: true,
    };
    let cases = [
        ("valid", ok, true),
        ("self", RefApproval { approver: A, ..ok }, false),
        (
            "not an admin",
            RefApproval {
                approver_admin: false,
                ..ok
            },
            false,
        ),
        (
            "no step-up",
            RefApproval {
                stepup_ok: false,
                ..ok
            },
            false,
        ),
        (
            "same identity",
            RefApproval {
                same_identity: Some(true),
                ..ok
            },
            false,
        ),
        (
            "vault down",
            RefApproval {
                same_identity: None,
                ..ok
            },
            false,
        ),
        (
            "vault down, so the verification is unknown too",
            RefApproval {
                same_identity: None,
                both_verified: false,
                ..ok
            },
            false,
        ),
        (
            "not both verified, so the identity check does not apply",
            RefApproval {
                same_identity: Some(false),
                both_verified: false,
                ..ok
            },
            true,
        ),
    ];
    for (what, a, want) in cases {
        assert_eq!(
            r::approve_recovery(holder, &a).is_ok(),
            want,
            "reference: {what}"
        );
        let got = production().approve(holder, &a);
        assert_eq!(got, Ok(want), "production: {what}");
    }
}

/// I-79, Q15: completing a recovery revokes every earlier credential and
/// ends every session of the account.
#[test]
fn i79_completion_revokes_every_credential_and_ends_every_session() {
    let world = one_cell_world().unwrap_or_else(|e| panic!("{e}"));
    let cell = world
        .cell(0)
        .unwrap_or_else(|| panic!("the world has no cell 0"));
    let client = AuthClient::new(cell);
    let cookies = seeded(&client, Variant::TwoAdmins).unwrap_or_else(|e| panic!("{e}"));
    let old = cookies
        .get(&IX_A)
        .unwrap_or_else(|| panic!("no session of a"));
    let admin2 = cookies
        .get(&IX_ADMIN2)
        .unwrap_or_else(|| panic!("no session of admin2"));
    let devices_before = client.devices(old).unwrap().unwrap_or_default();
    let case = client
        .recovery(A)
        .unwrap()
        .unwrap_or_else(|| panic!("no case"));
    assert!(client.recovery_email(&case).unwrap());
    assert!(client.recovery_approve(&case, admin2, true).unwrap());
    let fresh = client.recovery_complete(&case).unwrap();
    let fresh = fresh.unwrap_or_else(|| panic!("the approved recovery did not complete"));
    assert!(
        !client.admitted(old).unwrap(),
        "an earlier session survived"
    );
    let devices_after = client.devices(&fresh).unwrap().unwrap_or_default();
    assert_ne!(
        devices_after, devices_before,
        "an earlier credential survived"
    );
}

// ---------------------------------------------------------------------------
// The HTTP machine.

/// I-79 over HTTP: requests, email proofs, approvals with and without a
/// step-up, operator tickets, the committee grant racing b's open email
/// recovery, and completions, compared step by step with M-RECOVER over
/// the reference. The host console runs outside HTTP, so the machine
/// takes the SaaS variants only.
#[test]
fn i79_non_receiving_never_recovered_by_email_alone() {
    let model = RecoverModel::new(Reference);
    fstp_prop::check(
        "i79_non_receiving_never_recovered_by_email_alone",
        |g: &mut Gen| {
            let e = |x: fstp_celltest::NotImplemented| x.to_string();
            let init: Vec<RecoverState> = model
                .init()
                .into_iter()
                .filter(|s| s.variant != Variant::SoleAdminSelfHosted)
                .collect();
            let mut s = g.pick(&init).clone();
            let world = one_cell_world().map_err(|x| x.to_string())?;
            let cell = world.cell(0).ok_or("the world has no cell 0")?;
            let client = AuthClient::new(cell);
            client
                .set_clock(fstp_celltest::mc::recover_model::NOW)
                .map_err(e)?;
            let mut cookies = seeded(&client, s.variant)?;
            let mut cases: Vec<CaseRef> = Vec::new();
            for _ in 0..g.usize_in(1..=10) {
                let mut actions = Vec::new();
                model.actions(&s, &mut actions);
                // The host console runs outside HTTP, and the vault faults
                // of an approval are the vault lane's, so this machine
                // takes neither.
                actions.retain(|a| {
                    !matches!(
                        a,
                        RecoverAction::Console(_)
                            | RecoverAction::Approve(
                                _,
                                _,
                                _,
                                VaultAnswer::Same | VaultAnswer::Down
                            )
                    )
                });
                let a = *g.pick(&actions);
                let next = model.step(&s, &a);
                let got = match a {
                    RecoverAction::Request(h) => {
                        let c = client.recovery(account(h)).map_err(e)?;
                        let made = c.is_some();
                        if let Some(c) = c {
                            cases.push(c);
                        }
                        made
                    }
                    RecoverAction::Email(i) => match pick(&cases, i) {
                        Some(c) => client.recovery_email(&c).map_err(e)?,
                        None => false,
                    },
                    RecoverAction::Approve(i, approver, stepup, _) => {
                        match (pick(&cases, i), cookies.get(&approver)) {
                            (Some(c), Some(k)) => {
                                client.recovery_approve(&c, k, stepup).map_err(e)?
                            }
                            _ => false,
                        }
                    }
                    RecoverAction::Ticket(i, two) => match pick(&cases, i) {
                        Some(c) => client.recovery_ticket(&c, two).map_err(e)?,
                        None => false,
                    },
                    RecoverAction::GrantB => {
                        let admin = cookies.get(&IX_ADMIN1).ok_or("no admin1 session")?;
                        let change = RosterChange::Grant {
                            account: B,
                            role: Role::CommitteeMember,
                            until: None,
                        };
                        client.roster(admin, change).map_err(e)?
                    }
                    RecoverAction::Complete(i) => match pick(&cases, i) {
                        Some(c) => match client.recovery_complete(&c).map_err(e)? {
                            // Completion ends every session of the holder (Q15),
                            // so its later requests use the fresh cookie.
                            Some(fresh) => {
                                if let Some(case) = s.cases.get(usize::from(i)) {
                                    cookies.insert(case.holder, fresh);
                                }
                                true
                            }
                            None => false,
                        },
                        None => false,
                    },
                    RecoverAction::Console(_) => continue,
                };
                let want = next.as_ref().is_some_and(|t| t != &s);
                prop_assert_eq!(got, want, "{a:?} in {s:?}");
                if let Some(t) = next {
                    s = t;
                }
            }
            Ok(())
        },
    );
}

fn pick(cases: &[CaseRef], i: u8) -> Option<CaseRef> {
    cases.get(usize::from(i)).cloned()
}

// ---------------------------------------------------------------------------
// Teeth.

/// I-79 teeth: a path checked at request time only is caught by the
/// committee grant that races b's open email recovery.
#[test]
fn i79_teeth_path_checked_at_request_only_is_caught() {
    caught(
        Mutant::new(production(), RecoverDefect::PathCheckedAtRequestOnly),
        ids::I79,
    );
}

/// I-79 teeth: the same defect is caught on the reference.
#[test]
fn i79_teeth_path_checked_at_request_only_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, RecoverDefect::PathCheckedAtRequestOnly),
        ids::I79,
    );
}

/// I-79 teeth, design section 8.5: an approval check that ignores the
/// step-up is caught.
#[test]
fn i79_teeth_approval_without_step_up_is_caught() {
    caught(
        Mutant::new(production(), RecoverDefect::ApprovalIgnoresStepUp),
        ids::TWO_WAY,
    );
}

/// I-79 teeth: the same defect is caught on the reference.
#[test]
fn i79_teeth_approval_without_step_up_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, RecoverDefect::ApprovalIgnoresStepUp),
        ids::TWO_WAY,
    );
}

/// I-79 teeth, design section 8.5: an operator ticket check that accepts
/// one staff member twice is caught.
#[test]
fn i79_teeth_one_staff_ticket_is_caught() {
    caught(
        Mutant::new(production(), RecoverDefect::TicketAcceptsOneStaff),
        ids::TWO_WAY,
    );
}

/// I-79 teeth: the same defect is caught on the reference.
#[test]
fn i79_teeth_one_staff_ticket_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, RecoverDefect::TicketAcceptsOneStaff),
        ids::TWO_WAY,
    );
}

/// I-79 teeth, Q15: a completion that revokes no credential and ends no
/// session is caught, from the backend's own completion records.
#[test]
fn i79_teeth_completion_revokes_nothing_is_caught() {
    caught(
        Mutant::new(production(), RecoverDefect::CompletionRevokesNothing),
        ids::I79_SHOWN,
    );
}

/// I-79 teeth: the same defect is caught on the reference.
#[test]
fn i79_teeth_completion_revokes_nothing_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, RecoverDefect::CompletionRevokesNothing),
        ids::I79_SHOWN,
    );
}

// ---------------------------------------------------------------------------
// The reference itself.

/// I-79: over every holding, admin count, deployment and evidence, the
/// reference never completes a recovery of an account outside Receiving
/// on email proof alone.
#[test]
fn i79_reference_never_completes_non_receiving_by_email_alone() {
    let now = Timestamp::from_micros(1);
    for h in ALL_HOLDINGS {
        for second_admin in [false, true] {
            for mode in [RefDeployment::Saas, RefDeployment::SelfHosted] {
                let mut roster = RefRoster::default();
                roster.admins.push(r::RefAdmin {
                    account: ADMIN,
                    end: None,
                });
                if second_admin {
                    roster.admins.push(r::RefAdmin {
                        account: ADMIN_2,
                        end: None,
                    });
                }
                let holder = match h {
                    RefHoldings::TenantAdmin => ADMIN,
                    _ => A,
                };
                if h == RefHoldings::Management {
                    roster.bindings.push(r::RefBinding {
                        account: A,
                        role: Role::CommitteeMember,
                        end: None,
                        suspended: false,
                        voided: false,
                    });
                }
                let email_only = RefEvidence {
                    email: true,
                    ..RefEvidence::default()
                };
                let done = r::complete_recovery(&roster, holder, &email_only, mode, now);
                let outside = roster.holdings(holder, now) != RefHoldings::ReceivingOnly;
                assert!(
                    !(outside && done.is_ok()),
                    "{h:?}, second admin {second_admin}, {mode:?}: completed by email alone"
                );
                if !outside {
                    assert_eq!(done, Ok(RefPath::EmailThenPasskey));
                }
            }
        }
    }
}

/// The constant used by the machine to name b, so a renumbering shows here.
#[test]
fn i79_model_accounts_are_the_design_universe() {
    assert_eq!(account(IX_ADMIN1), ADMIN);
    assert_eq!(account(IX_ADMIN2), ADMIN_2);
    assert_eq!(account(IX_A), A);
    assert_eq!(account(IX_B), B);
}

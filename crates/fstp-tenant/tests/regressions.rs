//! Regression tests of review round 1 of lane W2d (M4 design section 3.5).
//! Each test drives the production API directly, with every answer the
//! shell would give stated in the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, ProgrammeId, TextId, TextRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    AgreementVersions, ApprovalId, BankInterface, BrandingPackage, CellKind, DomainName, GrantRef,
    InferenceDefault, InvitationId, Milestone, OnboardingStep, PaymentMode, ProbeOutcome, RpMode,
    SettingValue, StepFailure, StepOutcome, StepStatus, StepValues, TenantAnswers, TenantCommand,
    TenantCtx, TenantQuery, TenantRecord, TenantRefusal, TenantState, Token, TokenDigest,
    VerifyMethod, decide, queries,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);
const D1: TokenDigest = TokenDigest::from_bytes([0x11; 32]);
const D2: TokenDigest = TokenDigest::from_bytes([0x22; 32]);
const RECORDED: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn ctx(actor: AccountId, at: Timestamp) -> TenantCtx {
    TenantCtx {
        actor,
        via: Via::Web,
        at,
    }
}

/// What the shell answers in a test.
#[derive(Clone, Copy)]
struct Shell {
    agreements: Option<AgreementVersions>,
    receiving: Option<bool>,
}

const SHELL: Shell = Shell {
    agreements: Some(RECORDED),
    receiving: Some(false),
};

/// The state, the records it folded, and the shell.
struct Tenant {
    first: AccountId,
    cell: CellKind,
    state: TenantState,
    ledger: Vec<TenantRecord>,
    shell: Shell,
}

impl Tenant {
    fn new(cell: CellKind) -> Tenant {
        Tenant {
            first: acct(1),
            cell,
            state: TenantState::genesis(acct(1), cell),
            ledger: Vec::new(),
            shell: SHELL,
        }
    }

    /// Runs `cmd` as `actor` at `at`. Every prober check passes and every
    /// admin is verified. The control plane and Receiving answers come
    /// from `self.shell`.
    fn run_at(
        &mut self,
        actor: AccountId,
        at: Timestamp,
        cmd: &TenantCommand,
    ) -> Result<Vec<TenantRecord>, TenantRefusal> {
        let mut answers = TenantAnswers::new();
        for q in queries(&self.state, cmd) {
            match q {
                TenantQuery::AdminVerified(a) => answers.verified(a, true),
                TenantQuery::Probe(k) => answers.probe(k, ProbeOutcome::Passed),
                TenantQuery::Agreements => {
                    if let Some(v) = self.shell.agreements {
                        answers.agreements(v);
                    }
                }
                TenantQuery::HoldsReceiving(a) => {
                    if let Some(h) = self.shell.receiving {
                        answers.holds_receiving(a, h);
                    }
                }
            }
        }
        let recs = decide(&self.state, &ctx(actor, at), cmd, &answers)?;
        self.state.apply_all(&recs).unwrap();
        self.ledger.extend(recs.iter().cloned());
        let replayed = TenantState::replay(self.first, self.cell, &self.ledger).unwrap();
        assert_eq!(replayed, self.state, "a fold of the ledger differs (Q31)");
        Ok(recs)
    }

    fn run(
        &mut self,
        actor: AccountId,
        cmd: &TenantCommand,
    ) -> Result<Vec<TenantRecord>, TenantRefusal> {
        self.run_at(actor, T0, cmd)
    }

    fn save(&mut self, values: StepValues) -> Result<Vec<TenantRecord>, TenantRefusal> {
        let cmd = TenantCommand::SaveStep {
            values,
            base: self.state.revision(),
        };
        self.run(acct(1), &cmd)
    }

    fn set(&mut self, value: SettingValue) {
        self.run(acct(1), &TenantCommand::SetSetting { value })
            .unwrap();
    }

    fn invite(&mut self, invitation: u128, invitee: AccountId, digest: TokenDigest) {
        self.run(
            acct(1),
            &TenantCommand::InviteAdmin {
                invitation: InvitationId::from_raw(invitation),
                invitee,
                token_digest: digest,
            },
        )
        .unwrap();
    }

    fn accept(
        &mut self,
        actor: AccountId,
        invitation: u128,
        digest: TokenDigest,
    ) -> Result<Vec<TenantRecord>, TenantRefusal> {
        self.run(
            actor,
            &TenantCommand::AcceptAdminInvitation {
                invitation: InvitationId::from_raw(invitation),
                token_digest: digest,
            },
        )
    }
}

fn validated(recs: &[TenantRecord]) -> bool {
    recs.iter()
        .any(|r| matches!(r, TenantRecord::StepValidated { .. }))
}

fn organisation() -> StepValues {
    StepValues::Organisation {
        data_protection_contact: TextRef::new(
            TextId::from_raw(1),
            ContentDigest::from_bytes([0x5a; 32]),
        ),
        signatories: [acct(1)].into_iter().collect(),
    }
}

fn agreements(v: u32) -> StepValues {
    StepValues::Agreements {
        saas_terms: v,
        dpa: v,
        sub_processors: v,
    }
}

fn identity(p45: RpMode) -> StepValues {
    StepValues::Identity {
        p18: [VerifyMethod::EudiWallet].into_iter().collect(),
        p45,
    }
}

fn inference() -> StepValues {
    StepValues::Inference(InferenceDefault {
        provider: Token::new("synthetic-provider").unwrap(),
        primary: Token::new("model-a").unwrap(),
        fallbacks: Vec::new(),
    })
}

fn payments(bank_interface: BankInterface) -> StepValues {
    StepValues::Payments { bank_interface }
}

/// Every step value of a valid walk, in order, for a cell of kind `cell`.
fn walk_values(cell: CellKind, t: &TenantState) -> Vec<StepValues> {
    let mut v = vec![organisation()];
    if cell == CellKind::Saas {
        v.push(agreements(1));
    }
    v.extend([
        StepValues::Branding {
            package: BrandingPackage::Default,
        },
        StepValues::DomainsAndEmail {
            sending_domain: DomainName::new("mail.example.org").unwrap(),
        },
        identity(RpMode::TenantRegistration),
        inference(),
        payments(BankInterface::NotConnected),
        StepValues::Channels {
            matrix_homeserver: None,
            whatsapp: false,
        },
        StepValues::Administrators {
            admins: t.admins().clone(),
        },
    ]);
    v
}

/// A tenant with a second admin, P-20 record-only and every step it goes
/// through validated.
fn onboarded(cell: CellKind) -> Tenant {
    let mut t = Tenant::new(cell);
    t.invite(1, acct(2), D1);
    t.accept(acct(2), 1, D1).unwrap();
    t.set(SettingValue::P20(PaymentMode::RecordOnly));
    for values in walk_values(cell, &t.state.clone()) {
        let step = values.step();
        let recs = t.save(values).unwrap();
        assert!(validated(&recs), "{step:?} did not validate");
    }
    t
}

/// SoD-07, Q31, `authentication.md` (granting tenant admin is high-risk):
/// an admin invitation names its invitee and the digest of its token.
/// Another account is refused, even with the digest read from the ledger,
/// and the invitee is refused with a wrong token. The invitee with the
/// right token becomes the admin, once.
#[test]
fn sod07_q31_invitation_is_taken_only_by_its_invitee_with_its_token() {
    let mut t = Tenant::new(CellKind::Saas);
    t.invite(1, acct(2), D1);
    assert_eq!(
        t.accept(acct(3), 1, D1),
        Err(TenantRefusal::InvitationMismatch)
    );
    assert_eq!(
        t.accept(acct(2), 1, D2),
        Err(TenantRefusal::InvitationMismatch)
    );
    assert!(!t.state.is_admin(acct(2)) && !t.state.is_admin(acct(3)));
    assert!(t.accept(acct(2), 1, D1).is_ok());
    assert!(t.state.is_admin(acct(2)));
    assert_eq!(
        t.accept(acct(2), 1, D1),
        Err(TenantRefusal::InvitationNotOpen)
    );
}

/// SoD-07, Q31: the fold checks the invitee again. A ledger whose
/// `AdminAdded` names another account than the invitation's invitee does
/// not replay.
#[test]
fn sod07_q31_fold_refuses_admin_added_for_another_account() {
    let ledger = [
        TenantRecord::AdminInvited {
            invitation: InvitationId::from_raw(1),
            invitee: acct(2),
            token_digest: D1,
            by: acct(1),
        },
        TenantRecord::AdminAdded {
            account: acct(9),
            invitation: InvitationId::from_raw(1),
        },
    ];
    let r = TenantState::replay(acct(1), CellKind::Saas, &ledger);
    assert_eq!(
        r.err().map(|e| e.0),
        Some(TenantRefusal::InvitationMismatch)
    );
}

/// SoD-03, `Ctx::binds_tenant_admin`: a tenant admin counts as holding
/// Operations in every programme, so an account that holds a Receiving
/// binding never takes an admin invitation. Without an answer the
/// acceptance fails closed (Q5).
#[test]
fn sod03_receiving_account_cannot_become_tenant_admin() {
    let mut t = Tenant::new(CellKind::Saas);
    t.invite(1, acct(2), D1);
    assert_eq!(
        queries(
            &t.state,
            &TenantCommand::AcceptAdminInvitation {
                invitation: InvitationId::from_raw(1),
                token_digest: D1,
            }
        ),
        vec![TenantQuery::HoldsReceiving(acct(2))]
    );
    t.shell.receiving = Some(true);
    assert_eq!(t.accept(acct(2), 1, D1), Err(TenantRefusal::HoldsReceiving));
    t.shell.receiving = None;
    assert_eq!(t.accept(acct(2), 1, D1), Err(TenantRefusal::AnswerMissing));
    assert!(!t.state.is_admin(acct(2)));
    t.shell.receiving = Some(false);
    assert!(t.accept(acct(2), 1, D1).is_ok());
}

/// R-TN-01, Q22, Q5: the Agreements step validates only when the control
/// plane confirms the saved versions. No answer and other versions both
/// leave it not validated, with the failure recorded.
#[test]
fn r_tn_01_q22_agreements_validate_only_on_control_plane_confirmation() {
    let mut t = Tenant::new(CellKind::Saas);
    assert!(validated(&t.save(organisation()).unwrap()));
    let outcome = |recs: &[TenantRecord]| match &recs[0] {
        TenantRecord::StepSaved { outcome, .. } => *outcome,
        other => panic!("{other:?}"),
    };
    t.shell.agreements = None;
    let recs = t.save(agreements(1)).unwrap();
    assert_eq!(
        outcome(&recs),
        StepOutcome::Failed(StepFailure::AgreementsNotRecorded)
    );
    t.shell.agreements = Some(RECORDED);
    let recs = t.save(agreements(2)).unwrap();
    assert_eq!(
        outcome(&recs),
        StepOutcome::Failed(StepFailure::AgreementsNotRecorded)
    );
    assert_eq!(
        t.state.status(OnboardingStep::Agreements),
        StepStatus::Saved
    );
    assert!(!t.state.is_open(OnboardingStep::Branding));
    assert!(validated(&t.save(agreements(1)).unwrap()));
    assert!(t.state.is_open(OnboardingStep::Branding));
}

/// R-TN-01, `programme-creator.md` ("skipped for self-hosted"), interim
/// pending Daniel: a self-hosted cell skips the Agreements step. It shows
/// as skipped, refuses saves, asks the control plane nothing, and
/// onboarding completes without it.
#[test]
fn r_tn_01_self_hosted_cell_skips_agreements() {
    let mut t = Tenant::new(CellKind::SelfHosted);
    assert_eq!(
        t.state.status(OnboardingStep::Agreements),
        StepStatus::Skipped
    );
    assert!(validated(&t.save(organisation()).unwrap()));
    assert!(t.state.is_open(OnboardingStep::Branding));
    assert_eq!(t.save(agreements(1)), Err(TenantRefusal::StepSkipped));
    let cmd = TenantCommand::SaveStep {
        values: agreements(1),
        base: t.state.revision(),
    };
    assert!(!queries(&t.state, &cmd).contains(&TenantQuery::Agreements));
    let mut t = onboarded(CellKind::SelfHosted);
    assert!(!t.state.validated().contains(&OnboardingStep::Agreements));
    assert!(t.run(acct(1), &TenantCommand::Complete).is_ok());
    assert!(t.state.onboarded());
}

/// P-45 (`policy-parameters.md`: "self-hosted cells use tenant
/// registration only"): in a self-hosted cell the Identity step does not
/// validate with CrabNebula as intermediary, and the fold refuses a
/// ledger that claims it did. A SaaS cell accepts either mode.
#[test]
fn p45_self_hosted_cell_refuses_crabnebula_intermediary() {
    let mut t = Tenant::new(CellKind::SelfHosted);
    for values in [
        organisation(),
        StepValues::Branding {
            package: BrandingPackage::Default,
        },
        StepValues::DomainsAndEmail {
            sending_domain: DomainName::new("mail.example.org").unwrap(),
        },
    ] {
        assert!(validated(&t.save(values).unwrap()));
    }
    let recs = t.save(identity(RpMode::CrabNebulaIntermediary)).unwrap();
    assert!(!validated(&recs));
    assert_eq!(t.state.defaults().p45, None);
    let forged: Vec<TenantRecord> = t.ledger[..t.ledger.len() - 1]
        .iter()
        .cloned()
        .chain([TenantRecord::StepSaved {
            values: identity(RpMode::CrabNebulaIntermediary),
            by: acct(1),
            outcome: StepOutcome::Validated,
        }])
        .collect();
    assert_eq!(
        TenantState::replay(acct(1), CellKind::SelfHosted, &forged)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::Inconsistent)
    );
    assert!(validated(
        &t.save(identity(RpMode::TenantRegistration)).unwrap()
    ));
    let saas = TenantState::replay(acct(1), CellKind::Saas, &[]).unwrap();
    assert!(
        fstp_tenant::rules::values_check(&identity(RpMode::CrabNebulaIntermediary), &saas).is_ok()
    );
}

/// Walks a SaaS tenant up to the open Payments step.
fn to_payments() -> Tenant {
    let mut t = Tenant::new(CellKind::Saas);
    let values = walk_values(CellKind::Saas, &t.state.clone());
    for v in values.into_iter().take(6) {
        assert!(validated(&t.save(v).unwrap()));
    }
    assert!(t.state.is_open(OnboardingStep::Payments));
    t
}

/// R-TN-01, P-20 (`programme-creator.md`: "Payment mode (P-20), bank
/// interface where execution mode is used"): the Payments step shows why
/// it does not validate. P-20 unset is its own failure. Execution mode
/// waits for the bank interface of M5. Record-only mode validates.
#[test]
fn p20_payments_step_needs_record_only_mode_in_m4() {
    let mut t = to_payments();
    assert!(!validated(
        &t.save(payments(BankInterface::NotConnected)).unwrap()
    ));
    assert_eq!(t.state.status(OnboardingStep::Payments), StepStatus::Saved);
    t.set(SettingValue::P20(PaymentMode::Execution));
    assert!(!validated(
        &t.save(payments(BankInterface::NotConnected)).unwrap()
    ));
    assert_eq!(
        t.state.status(OnboardingStep::Payments),
        StepStatus::Unavailable {
            milestone: Milestone::M5
        }
    );
    t.set(SettingValue::P20(PaymentMode::RecordOnly));
    assert!(!validated(
        &t.save(payments(BankInterface::Connect)).unwrap()
    ));
    assert!(validated(
        &t.save(payments(BankInterface::NotConnected)).unwrap()
    ));
}

/// R-TN-01, P-20: a change of P-20 to execution mode after the Payments
/// step validated leaves the step not validated, closes the later steps
/// and shows the M5 wait. A fold of the ledger agrees (checked in every
/// run).
#[test]
fn p20_change_to_execution_unvalidates_payments() {
    let mut t = to_payments();
    t.set(SettingValue::P20(PaymentMode::RecordOnly));
    assert!(validated(
        &t.save(payments(BankInterface::NotConnected)).unwrap()
    ));
    assert!(t.state.is_open(OnboardingStep::Channels));
    t.set(SettingValue::P20(PaymentMode::Execution));
    assert!(!t.state.validated().contains(&OnboardingStep::Payments));
    assert!(!t.state.is_open(OnboardingStep::Channels));
    assert_eq!(
        t.state.status(OnboardingStep::Payments),
        StepStatus::Unavailable {
            milestone: Milestone::M5
        }
    );
}

/// R-TN-01, P-20: the fold checks the Payments rule again. A ledger that
/// claims a validated Payments save while P-20 is unset does not replay.
#[test]
fn p20_fold_refuses_validated_payments_without_p20() {
    let t = to_payments();
    let mut forged = t.ledger.clone();
    forged.push(TenantRecord::StepSaved {
        values: payments(BankInterface::NotConnected),
        by: acct(1),
        outcome: StepOutcome::Validated,
    });
    assert_eq!(
        TenantState::replay(acct(1), CellKind::Saas, &forged)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::Inconsistent)
    );
}

fn self_grant() -> GrantRef {
    GrantRef {
        grantee: acct(1),
        programme: ProgrammeId::from_raw(1),
        role: Role::ProgrammeManager,
    }
}

fn approve(t: &mut Tenant, approval: u128, at: Timestamp) {
    t.run_at(
        acct(2),
        at,
        &TenantCommand::ApproveSelfGrant {
            approval: ApprovalId::from_raw(approval),
            grant: self_grant(),
        },
    )
    .unwrap();
}

fn use_approval(
    t: &mut Tenant,
    actor: AccountId,
    approval: u128,
    grant: GrantRef,
    at: Timestamp,
) -> Result<Vec<TenantRecord>, TenantRefusal> {
    t.run_at(
        actor,
        at,
        &TenantCommand::UseSelfGrantApproval {
            approval: ApprovalId::from_raw(approval),
            grant,
        },
    )
}

fn with_second_admin() -> Tenant {
    let mut t = Tenant::new(CellKind::Saas);
    t.invite(1, acct(2), D1);
    t.accept(acct(2), 1, D1).unwrap();
    t
}

/// SoD-07, TH-05: one approval admits one self-grant. The grantee uses it
/// for exactly the approved grant. Another grant, another account and a
/// second use are refused.
#[test]
fn th05_sod07_approval_is_used_once_for_its_grant() {
    let mut t = with_second_admin();
    approve(&mut t, 7, T0);
    let other = GrantRef {
        role: Role::CallDrafter,
        ..self_grant()
    };
    assert_eq!(
        use_approval(&mut t, acct(1), 7, other, T0),
        Err(TenantRefusal::ApprovalNotOpen)
    );
    assert_eq!(
        use_approval(&mut t, acct(2), 7, self_grant(), T0),
        Err(TenantRefusal::ApprovalNotOpen)
    );
    assert!(use_approval(&mut t, acct(1), 7, self_grant(), T0).is_ok());
    assert!(t.state.approvals()[&ApprovalId::from_raw(7)].used);
    assert_eq!(
        use_approval(&mut t, acct(1), 7, self_grant(), T0),
        Err(TenantRefusal::ApprovalNotOpen)
    );
    assert_eq!(
        use_approval(&mut t, acct(1), 8, self_grant(), T0),
        Err(TenantRefusal::ApprovalNotOpen)
    );
}

/// SoD-07, TH-05 (interim, pending Daniel, as M3 builds it): an approval
/// lapses P-71 after it was given. With P-71 shortened to one minute, a
/// use at the last instant passes and one microsecond later is refused.
#[test]
fn th05_sod07_approval_expires_after_p71() {
    let mut t = with_second_admin();
    t.set(SettingValue::P71 { us: 60_000_000 });
    approve(&mut t, 7, T0);
    approve(&mut t, 8, T0);
    let end = Timestamp::from_micros(T0.micros() + 60_000_000);
    let late = Timestamp::from_micros(end.micros() + 1);
    assert_eq!(
        t.state.approvals()[&ApprovalId::from_raw(7)].expires_at,
        end
    );
    assert_eq!(
        use_approval(&mut t, acct(1), 7, self_grant(), late),
        Err(TenantRefusal::ApprovalExpired)
    );
    assert!(use_approval(&mut t, acct(1), 8, self_grant(), end).is_ok());
}

/// SoD-07, TH-05: the fold checks a use again. A ledger that uses an
/// approval twice, or after it lapsed, does not replay.
#[test]
fn th05_fold_refuses_reused_or_lapsed_approval() {
    let mut t = with_second_admin();
    approve(&mut t, 7, T0);
    let used = TenantRecord::SelfGrantApprovalUsed {
        approval: ApprovalId::from_raw(7),
        by: acct(1),
        at: T0,
    };
    let mut twice = t.ledger.clone();
    twice.extend([used.clone(), used]);
    assert_eq!(
        TenantState::replay(acct(1), CellKind::Saas, &twice)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::ApprovalNotOpen)
    );
    let mut lapsed = t.ledger.clone();
    lapsed.push(TenantRecord::SelfGrantApprovalUsed {
        approval: ApprovalId::from_raw(7),
        by: acct(1),
        at: Timestamp::from_micros(T0.micros() + 300_000_001),
    });
    assert_eq!(
        TenantState::replay(acct(1), CellKind::Saas, &lapsed)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::ApprovalExpired)
    );
}

/// R-TN-01, SoD-07: `completed` is history and `onboarded` is the current
/// answer. After completion, a failed return save leaves a step not
/// validated: `completed` stays true and `onboarded` turns false until
/// the step validates again.
#[test]
fn r_tn_01_completed_is_history_and_onboarded_is_current() {
    let mut t = onboarded(CellKind::Saas);
    assert!(!t.state.onboarded());
    assert!(t.run(acct(1), &TenantCommand::Complete).is_ok());
    assert!(t.state.completed() && t.state.onboarded());
    let bad = StepValues::Branding {
        package: BrandingPackage::WhiteLabel,
    };
    assert!(!validated(&t.save(bad).unwrap()));
    assert!(t.state.completed());
    assert!(!t.state.onboarded());
    let good = StepValues::Branding {
        package: BrandingPackage::Default,
    };
    assert!(validated(&t.save(good).unwrap()));
    assert!(t.state.onboarded());
}

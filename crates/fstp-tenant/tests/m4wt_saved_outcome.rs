//! Lane m4tenant: the step view shows the outcome of each step's latest
//! save (R-TN-01: "the tenant can save and return at any point"). Before
//! this lane the state kept that outcome without a public read, so the
//! onboarding read model could not name why a save did not validate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, ContentDigest, TextId, TextRef};
use fstp_tenant::{
    BankInterface, BrandingPackage, CellKind, Milestone, OnboardingStep, PaymentMode, SettingValue,
    StepFailure, StepOutcome, StepValues, TenantRecord, TenantState,
};

const A1: AccountId = AccountId::from_raw(1);

fn validated(values: StepValues) -> [TenantRecord; 2] {
    let step = values.step();
    [
        TenantRecord::StepSaved {
            values,
            by: A1,
            outcome: StepOutcome::Validated,
        },
        TenantRecord::StepValidated { step, by: A1 },
    ]
}

fn p20(mode: PaymentMode) -> TenantRecord {
    TenantRecord::SettingChanged {
        value: SettingValue::P20(mode),
        by: A1,
    }
}

/// R-TN-01: a failed save keeps its outcome, a validating save replaces
/// it, and a P-20 change that the saved Payments values no longer meet
/// shows as the Payments outcome. A step never saved has none.
#[test]
fn r_tn_01_saved_outcome_names_the_latest_save_of_each_step() {
    let mut s = TenantState::genesis(A1, CellKind::SelfHosted);
    assert_eq!(s.saved_outcome(OnboardingStep::Organisation), None);
    let failed = StepOutcome::Failed(StepFailure::InvalidValues);
    let org = |signatories: Vec<AccountId>| StepValues::Organisation {
        data_protection_contact: TextRef::new(
            TextId::from_raw(1),
            ContentDigest::from_bytes([1; 32]),
        ),
        signatories: signatories.into_iter().collect(),
    };
    s.apply(&TenantRecord::StepSaved {
        values: org(Vec::new()),
        by: A1,
        outcome: failed,
    })
    .unwrap();
    assert_eq!(s.saved_outcome(OnboardingStep::Organisation), Some(failed));
    s.apply_all(&validated(org(vec![A1]))).unwrap();
    assert_eq!(
        s.saved_outcome(OnboardingStep::Organisation),
        Some(StepOutcome::Validated)
    );

    for step in [
        StepValues::Branding {
            package: BrandingPackage::Default,
        },
        StepValues::DomainsAndEmail {
            sending_domain: fstp_tenant::DomainName::new("mail.e2e.invalid").unwrap(),
        },
        StepValues::Identity {
            p18: [fstp_tenant::VerifyMethod::EudiWallet]
                .into_iter()
                .collect(),
            p45: fstp_tenant::RpMode::TenantRegistration,
        },
        StepValues::Inference(fstp_tenant::InferenceDefault {
            provider: fstp_tenant::Token::new("p").unwrap(),
            primary: fstp_tenant::Token::new("m").unwrap(),
            fallbacks: Vec::new(),
        }),
    ] {
        s.apply_all(&validated(step)).unwrap();
    }
    s.apply(&p20(PaymentMode::RecordOnly)).unwrap();
    s.apply_all(&validated(StepValues::Payments {
        bank_interface: BankInterface::NotConnected,
    }))
    .unwrap();
    assert_eq!(
        s.saved_outcome(OnboardingStep::Payments),
        Some(StepOutcome::Validated)
    );
    s.apply(&p20(PaymentMode::Execution)).unwrap();
    assert_eq!(
        s.saved_outcome(OnboardingStep::Payments),
        Some(StepOutcome::Failed(StepFailure::Unavailable(Milestone::M5)))
    );
}

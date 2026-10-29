//! Review reproducers for lane W2d (independent review, spec, security and
//! robustness lens). Each test fails against the code under review and
//! passes once the named defect is fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeSet;

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, TextId, TextRef};
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    AgreementVersions, CellKind, InvitationId, StepOutcome, StepValues, TenantAnswers,
    TenantCommand, TenantCtx, TenantQuery, TenantRecord, TenantState, TokenDigest, decide,
    decode_record, encode_record, queries,
};

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

const AT: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);

fn web(a: AccountId) -> TenantCtx {
    TenantCtx {
        actor: a,
        via: Via::Web,
        at: AT,
    }
}

/// Runs `cmd` as `ctx`, answering every query with "no" (the vault, the
/// control plane and the prober have nothing, and nobody holds a
/// Receiving binding), and folds the records on acceptance.
fn run(
    s: &mut TenantState,
    ctx: TenantCtx,
    cmd: &TenantCommand,
) -> Result<Vec<TenantRecord>, fstp_tenant::TenantRefusal> {
    let mut answers = TenantAnswers::new();
    for q in queries(s, cmd) {
        match q {
            TenantQuery::AdminVerified(a) => answers.verified(a, false),
            TenantQuery::HoldsReceiving(a) => answers.holds_receiving(a, false),
            TenantQuery::Probe(_) | TenantQuery::Agreements => {}
        }
    }
    let recs = decide(s, &ctx, cmd, &answers)?;
    s.apply_all(&recs).unwrap();
    Ok(recs)
}

const SECRET: u128 = 0x5eed_0000_0000_0000_0000_0000_0000_0042;

/// The digest of the invitation token, which only the shell and the
/// invitee's ceremony know the preimage of.
const TOKEN_DIGEST: TokenDigest = TokenDigest::from_bytes([0x6b; 32]);

/// SoD-07, Q31, R-LG-03 (granting tenant admin is high-risk): the admin
/// invitation is the bearer value that makes its holder a tenant admin,
/// and the `AdminInvited` ledger body stores it in clear. An account that
/// can read the ledger or the audit trail (an Auditor, an export, a
/// backup) but was never invited must not become a tenant admin with it.
#[test]
fn review_invitation_read_from_ledger_does_not_make_reader_admin() {
    let a1 = acct(1);
    let reader = acct(9);
    let mut s = TenantState::genesis(a1, CellKind::Saas);
    let recs = run(
        &mut s,
        web(a1),
        &TenantCommand::InviteAdmin {
            invitation: InvitationId::from_raw(SECRET),
            invitee: acct(2),
            token_digest: TOKEN_DIGEST,
        },
    )
    .unwrap();
    // The reader sees only the stored ledger body.
    let stored = encode_record(&recs[0]).unwrap();
    let Ok(TenantRecord::AdminInvited {
        invitation,
        token_digest,
        ..
    }) = decode_record(&stored)
    else {
        panic!("not an AdminInvited record");
    };
    let taken = run(
        &mut s,
        web(reader),
        &TenantCommand::AcceptAdminInvitation {
            invitation,
            token_digest,
        },
    );
    assert!(
        taken.is_err() && !s.is_admin(reader),
        "an account that only read the ledger became a tenant admin"
    );
}

/// I-85, I-78: granting tenant admin is a high-risk action
/// (`authentication.md`), and `AdminAdded` is the record that completes
/// it. A high-risk action cannot complete through MCP, so taking an admin
/// invitation through MCP is refused.
#[test]
fn review_accept_admin_invitation_via_mcp_is_refused() {
    let a1 = acct(1);
    let a2 = acct(2);
    let mut s = TenantState::genesis(a1, CellKind::Saas);
    run(
        &mut s,
        web(a1),
        &TenantCommand::InviteAdmin {
            invitation: InvitationId::from_raw(SECRET),
            invitee: a2,
            token_digest: TOKEN_DIGEST,
        },
    )
    .unwrap();
    let via_mcp = TenantCtx {
        actor: a2,
        via: Via::Mcp,
        at: AT,
    };
    let taken = run(
        &mut s,
        via_mcp,
        &TenantCommand::AcceptAdminInvitation {
            invitation: InvitationId::from_raw(SECRET),
            token_digest: TOKEN_DIGEST,
        },
    );
    assert!(
        taken.is_err() && !s.is_admin(a2),
        "a tenant admin grant completed through MCP"
    );
}

/// R-TN-01, Q22, Q5: agreement acceptance is recorded in the control
/// plane, not typed into the cell. A save of the Agreements step that
/// names versions nobody accepted, with no control plane answer, must not
/// validate the step (fail closed), or the step is skippable.
#[test]
fn review_agreements_step_does_not_validate_on_client_claimed_versions() {
    let a1 = acct(1);
    let mut s = TenantState::genesis(a1, CellKind::Saas);
    let org = StepValues::Organisation {
        data_protection_contact: TextRef::new(
            TextId::from_raw(1),
            ContentDigest::from_bytes([0x5a; 32]),
        ),
        signatories: [a1].into_iter().collect::<BTreeSet<_>>(),
    };
    let save_org = TenantCommand::SaveStep {
        values: org,
        base: s.revision(),
    };
    let recs = run(&mut s, web(a1), &save_org).unwrap();
    assert!(
        recs.iter()
            .any(|r| matches!(r, TenantRecord::StepValidated { .. }))
    );
    let claimed = TenantCommand::SaveStep {
        values: StepValues::Agreements {
            saas_terms: 4_000_000,
            dpa: 4_000_000,
            sub_processors: 4_000_000,
        },
        base: s.revision(),
    };
    let recs = run(&mut s, web(a1), &claimed);
    let validated = recs.is_ok_and(|r| {
        r.iter().any(|x| {
            matches!(
                x,
                TenantRecord::StepSaved {
                    outcome: StepOutcome::Validated,
                    ..
                }
            )
        })
    });
    assert!(
        !validated,
        "the Agreements step validated on versions only the client asserted"
    );
}

/// Walks Organisation to Inference with valid values and a passing
/// prober, so the Payments step is open.
fn walk_to_payments(a1: AccountId) -> TenantState {
    use fstp_tenant::{
        BrandingPackage, DomainName, InferenceDefault, ProbeOutcome, RpMode, Token, VerifyMethod,
    };
    let mut s = TenantState::genesis(a1, CellKind::Saas);
    let steps = [
        StepValues::Organisation {
            data_protection_contact: TextRef::new(
                TextId::from_raw(1),
                ContentDigest::from_bytes([0x5a; 32]),
            ),
            signatories: [a1].into_iter().collect(),
        },
        StepValues::Agreements {
            saas_terms: 1,
            dpa: 1,
            sub_processors: 1,
        },
        StepValues::Branding {
            package: BrandingPackage::Default,
        },
        StepValues::DomainsAndEmail {
            sending_domain: DomainName::new("mail.example.org").unwrap(),
        },
        StepValues::Identity {
            p18: [VerifyMethod::EudiWallet].into_iter().collect(),
            p45: RpMode::TenantRegistration,
        },
        StepValues::Inference(InferenceDefault {
            provider: Token::new("synthetic-provider").unwrap(),
            primary: Token::new("model-a").unwrap(),
            fallbacks: Vec::new(),
        }),
    ];
    for values in steps {
        let cmd = TenantCommand::SaveStep {
            values,
            base: s.revision(),
        };
        let mut answers = TenantAnswers::new();
        for q in queries(&s, &cmd) {
            match q {
                TenantQuery::Probe(k) => answers.probe(k, ProbeOutcome::Passed),
                // The control plane recorded the versions this walk saves.
                TenantQuery::Agreements => answers.agreements(AgreementVersions {
                    saas_terms: 1,
                    dpa: 1,
                    sub_processors: 1,
                }),
                _ => {}
            }
        }
        let recs = decide(&s, &web(a1), &cmd, &answers).unwrap();
        assert!(
            recs.iter()
                .any(|r| matches!(r, TenantRecord::StepValidated { .. }))
        );
        s.apply_all(&recs).unwrap();
    }
    s
}

fn payments_validates(s: &mut TenantState, a1: AccountId) -> bool {
    let cmd = TenantCommand::SaveStep {
        values: StepValues::Payments {
            bank_interface: fstp_tenant::BankInterface::NotConnected,
        },
        base: s.revision(),
    };
    run(s, web(a1), &cmd).is_ok_and(|r| {
        r.iter()
            .any(|x| matches!(x, TenantRecord::StepValidated { .. }))
    })
}

/// R-TN-01, P-20 (`programme-creator.md`: the Payments step captures
/// "Payment mode (P-20), bank interface where execution mode is used"):
/// with P-20 set to execution and no bank interface, the Payments step
/// does not validate.
#[test]
fn review_payments_execution_mode_needs_bank_interface() {
    let a1 = acct(1);
    let mut s = walk_to_payments(a1);
    run(
        &mut s,
        web(a1),
        &TenantCommand::SetSetting {
            value: fstp_tenant::SettingValue::P20(fstp_tenant::PaymentMode::Execution),
        },
    )
    .unwrap();
    assert!(
        !payments_validates(&mut s, a1),
        "Payments validated in execution mode without a bank interface"
    );
}

/// R-TN-01, P-20: the Payments step captures the payment mode. While no
/// tenant admin has chosen P-20 (the spec gives no default), the step
/// does not validate, so onboarding never completes with P-20 unset.
#[test]
fn review_payments_step_needs_p20_chosen() {
    let a1 = acct(1);
    let mut s = walk_to_payments(a1);
    assert_eq!(s.settings().p20, None);
    assert!(
        !payments_validates(&mut s, a1),
        "Payments validated while P-20 was never chosen"
    );
}

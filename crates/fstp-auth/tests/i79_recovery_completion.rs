//! I-79 over the lane W2b production API: the approval by a second
//! tenant admin, the operator ticket and the completion (ADR-008
//! "Recovery", design section 8.5, Q15).
//!
//! Lane W2b implementer. The oracles are written from ADR-008 and
//! `authentication.md`, not from the production predicates.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::recovery::{
    Approval, ApprovalDeny, Case, Deployment, Evidence, IdentityFacts, OperatorTicket,
    RecoveryDeny, RecoveryPath, Revocation, StaffRef, TICKET_CONTEXT, TicketDeny, VaultDown,
    accept_ticket, approve, complete, decide, request, verify_ticket,
};
use fstp_auth::stepup::StepUpDeny;
use fstp_auth::{AuthRecord, RosterView, TenantView};
use fstp_domain::id::AccountId;
use fstp_prop::{Gen, check, prop_assert};
use fstp_webauthn::{CoseKey, NewCredential};

const fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

const ADMIN_1: AccountId = acct(1);
const ADMIN_2: AccountId = acct(2);
const MEMBER: AccountId = acct(3);
const APPLICANT: AccountId = acct(4);
const CASE: [u8; 16] = [0xCA; 16];

fn admins(list: &[AccountId]) -> TenantView {
    TenantView {
        admins: list.to_vec(),
    }
}

fn management(list: &[AccountId]) -> RosterView {
    RosterView {
        management: list.to_vec(),
    }
}

fn ok_approval() -> Approval {
    Approval {
        approver: ADMIN_2,
        approver_admin: true,
        stepup: Ok(()),
        identity: Ok(IdentityFacts {
            both_verified: true,
            same_identity: false,
        }),
    }
}

/// I-79, ADR-008: an approval is refused when the approver is the holder,
/// is not a tenant admin, gives no step-up or shares the holder's
/// identity, and when the vault is down. A valid one is accepted.
#[test]
fn i79_approval_needs_another_admin_step_up_and_distinct_identity() {
    let ok = ok_approval();
    assert_eq!(approve(MEMBER, &ok), Ok(()));
    let cases = [
        (
            Approval {
                approver: MEMBER,
                ..ok
            },
            Err(ApprovalDeny::SelfApproval),
        ),
        (
            Approval {
                approver_admin: false,
                ..ok
            },
            Err(ApprovalDeny::NotAdmin),
        ),
        (
            Approval {
                stepup: Err(StepUpDeny::Stale),
                ..ok
            },
            Err(ApprovalDeny::StepUp(StepUpDeny::Stale)),
        ),
        (
            Approval {
                identity: Ok(IdentityFacts {
                    both_verified: true,
                    same_identity: true,
                }),
                ..ok
            },
            Err(ApprovalDeny::SameIdentity),
        ),
        (
            Approval {
                identity: Err(VaultDown),
                ..ok
            },
            Err(ApprovalDeny::VaultDown),
        ),
        (
            Approval {
                identity: Ok(IdentityFacts {
                    both_verified: false,
                    same_identity: true,
                }),
                ..ok
            },
            Ok(()),
        ),
    ];
    for (a, want) in cases {
        assert_eq!(approve(MEMBER, &a), want, "{a:?}");
    }
}

/// I-79, `Approval::new`: the approver's admin status is read from the
/// tenant view at approval.
#[test]
fn i79_approval_reads_admin_status_from_the_tenant_view() {
    let a = Approval::new(ADMIN_2, &admins(&[ADMIN_1]), Ok(()), Err(VaultDown));
    assert!(!a.approver_admin);
    let b = Approval::new(ADMIN_2, &admins(&[ADMIN_2]), Ok(()), Err(VaultDown));
    assert!(b.approver_admin);
}

/// The control-plane key of these tests and a ticket for `case` by
/// `staff`, signed under it, with the last byte flipped when `tamper`.
struct Signer {
    key: fstp_crypto::composite::CompositeSigningKey,
}

impl Signer {
    fn new() -> Signer {
        Signer {
            key: fstp_crypto::composite::generate().unwrap(),
        }
    }

    fn public(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().to_vec()
    }

    fn ticket(&self, case: [u8; 16], staff: [u8; 2], tamper: bool) -> Vec<u8> {
        let t = OperatorTicket {
            case,
            staff_1: StaffRef([staff[0]; 16]),
            staff_2: StaffRef([staff[1]; 16]),
        };
        let sig = self
            .key
            .sign_with_context(&t.message(), TICKET_CONTEXT)
            .unwrap()
            .to_bytes();
        let mut b = fstp_auth::codec::encode_operator_ticket(&t, &sig).unwrap();
        if tamper {
            *b.last_mut().unwrap() ^= 1;
        }
        b
    }
}

/// I-79, ADR-008: an operator ticket needs a valid composite signature
/// under the pinned key, this case's reference and two staff members.
#[test]
fn i79_operator_ticket_needs_signature_case_and_two_staff() {
    let s = Signer::new();
    let pk = s.public();
    assert!(accept_ticket(&s.ticket(CASE, [1, 2], false), CASE, &pk).is_ok());
    assert_eq!(
        accept_ticket(&s.ticket(CASE, [1, 2], true), CASE, &pk),
        Err(TicketDeny::Signature)
    );
    assert_eq!(
        accept_ticket(&s.ticket([0xCB; 16], [1, 2], false), CASE, &pk),
        Err(TicketDeny::OtherCase)
    );
    assert_eq!(
        accept_ticket(&s.ticket(CASE, [1, 1], false), CASE, &pk),
        Err(TicketDeny::OneStaff)
    );
    let other = Signer::new();
    assert_eq!(
        accept_ticket(&s.ticket(CASE, [1, 2], false), CASE, &other.public()),
        Err(TicketDeny::Signature)
    );
    assert!(matches!(
        verify_ticket(&[0; 10], &pk),
        Err(TicketDeny::Malformed(_))
    ));
}

fn case(holder: AccountId, evidence: Evidence) -> Case {
    Case {
        case: CASE,
        holder,
        requested: RecoveryPath::EmailThenPasskey,
        evidence,
    }
}

const EMAIL: Evidence = Evidence {
    email: true,
    approval: None,
    ticket: None,
    host_console: false,
};

/// I-79: the request records the path at request time.
#[test]
fn i79_request_records_the_request_time_path() {
    let r = request(
        CASE,
        MEMBER,
        &management(&[MEMBER]),
        &admins(&[ADMIN_1]),
        Deployment::Saas,
    );
    assert_eq!(
        r,
        AuthRecord::RecoveryRequested {
            case: CASE,
            account: MEMBER,
            path: RecoveryPath::SecondAdmin,
        }
    );
}

/// I-79, design section 8.5: the completion recomputes the path, so a
/// role granted during an open email recovery makes that recovery fail.
#[test]
fn i79_grant_during_email_recovery_makes_it_fail() {
    let c = case(APPLICANT, EMAIL);
    let tenant = admins(&[ADMIN_1]);
    assert_eq!(
        decide(&c, &management(&[]), &tenant, Deployment::Saas),
        Ok(RecoveryPath::EmailThenPasskey)
    );
    assert_eq!(
        decide(&c, &management(&[APPLICANT]), &tenant, Deployment::Saas),
        Err(RecoveryDeny::PathNotSatisfied(RecoveryPath::SecondAdmin))
    );
}

/// I-79: no account outside Receiving at completion completes on email
/// proof alone, for any views and deployment.
#[test]
fn i79_email_alone_never_completes_outside_receiving() {
    check(
        "i79_email_alone_never_completes_outside_receiving",
        |g: &mut Gen| {
            let pool = [ADMIN_1, ADMIN_2, MEMBER, APPLICANT];
            let roster = management(&g.vec(0..=4, |g| *g.pick(&pool)));
            let tenant = admins(&g.vec(0..=3, |g| *g.pick(&pool)));
            let holder = *g.pick(&pool);
            let mode = *g.pick(&[Deployment::Saas, Deployment::SelfHosted]);
            let outside = roster.management.contains(&holder) || tenant.admins.contains(&holder);
            let got = decide(&case(holder, EMAIL), &roster, &tenant, mode);
            prop_assert!(
                !(outside && got.is_ok()),
                "{holder:?} completed by email alone: {roster:?} {tenant:?}"
            );
            Ok(())
        },
    );
}

/// I-79, design section 8.5: a second-admin completion needs the email
/// proof and an approval whose approver is still a tenant admin.
#[test]
fn i79_second_admin_completion_needs_a_current_admin_approver() {
    let e = Evidence {
        approval: Some(ok_approval()),
        ..EMAIL
    };
    let roster = management(&[MEMBER]);
    let mode = Deployment::Saas;
    assert_eq!(
        decide(
            &case(MEMBER, e),
            &roster,
            &admins(&[ADMIN_1, ADMIN_2]),
            mode
        ),
        Ok(RecoveryPath::SecondAdmin)
    );
    assert!(decide(&case(MEMBER, e), &roster, &admins(&[ADMIN_1]), mode).is_err());
    let no_email = Evidence { email: false, ..e };
    assert!(
        decide(
            &case(MEMBER, no_email),
            &roster,
            &admins(&[ADMIN_1, ADMIN_2]),
            mode
        )
        .is_err()
    );
}

/// I-79, Q15: a sole SaaS admin completes with email proof and a valid
/// operator ticket for the case; a self-hosted sole admin with the host
/// console.
#[test]
fn i79_sole_admin_completes_by_operator_ticket_or_host_console() {
    let s = Signer::new();
    let pk = s.public();
    let t = verify_ticket(&s.ticket(CASE, [1, 2], false), &pk).unwrap();
    let one = verify_ticket(&s.ticket(CASE, [1, 1], false), &pk).unwrap();
    let tenant = admins(&[ADMIN_1]);
    let roster = management(&[]);
    let ticketed = Evidence {
        ticket: Some(t),
        ..EMAIL
    };
    assert_eq!(
        decide(&case(ADMIN_1, ticketed), &roster, &tenant, Deployment::Saas),
        Ok(RecoveryPath::OperatorProcess)
    );
    let one_staff = Evidence {
        ticket: Some(one),
        ..EMAIL
    };
    assert!(
        decide(
            &case(ADMIN_1, one_staff),
            &roster,
            &tenant,
            Deployment::Saas
        )
        .is_err()
    );
    let console = Evidence {
        host_console: true,
        ..Evidence::default()
    };
    assert_eq!(
        decide(
            &case(ADMIN_1, console),
            &roster,
            &tenant,
            Deployment::SelfHosted
        ),
        Ok(RecoveryPath::HostConsole)
    );
    assert!(decide(&case(ADMIN_1, console), &roster, &tenant, Deployment::Saas).is_err());
}

/// I-79, Q15: a completion revokes every earlier credential, ends every
/// session, registers the new passkey and is shown to the tenant on the
/// operator and host console paths only.
#[test]
fn i79_completion_records_revoke_every_credential_and_end_every_session() {
    let creds = [vec![1u8; 8], vec![2u8; 8]];
    let sessions = [[3u8; 16], [4u8; 16]];
    let new = NewCredential {
        id: vec![9; 8],
        key: CoseKey::Ed25519 { x: [9; 32] },
        sign_count: 0,
        user_verified: true,
    };
    let r = Revocation {
        credentials: &creds,
        sessions: &sessions,
        new_credential: &new,
    };
    let c = case(APPLICANT, EMAIL);
    let records = complete(&c, &management(&[]), &admins(&[]), Deployment::Saas, &r).unwrap();
    for cred in &creds {
        assert!(records.contains(&AuthRecord::CredentialRevoked {
            account: APPLICANT,
            credential: cred.clone(),
        }));
    }
    for s in sessions {
        assert!(records.contains(&AuthRecord::SessionEnded { session: s }));
    }
    assert!(records.contains(&AuthRecord::CredentialRegistered {
        account: APPLICANT,
        credential: vec![9; 8],
        key: CoseKey::Ed25519 { x: [9; 32] },
        user_verified: true,
    }));
    assert!(records.contains(&AuthRecord::RecoveryCompleted {
        case: CASE,
        account: APPLICANT,
        path: RecoveryPath::EmailThenPasskey,
        shown_to_tenant: false,
    }));
    for p in RecoveryPath::ALL {
        let shown = matches!(p, RecoveryPath::OperatorProcess | RecoveryPath::HostConsole);
        assert_eq!(p.shown_to_tenant(), shown, "{p:?}");
    }
}

//! I-79 over the lane W2b production API: the new passkey of a recovery
//! and the kind of an operator ticket (ADR-008 "Recovery", "User
//! verification", design sections 8.1, 8.5 and 9.1).
//!
//! Lane W2b implementer, fix round 2. The oracles are written from
//! ADR-008 and WebAuthn Level 2 section 7.1 step 22.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod passkey;

use fstp_auth::ceremony::{EnrolDeny, Registration};
use fstp_auth::recovery::{
    Approval, Case, Deployment, Evidence, IdentityFacts, OperatorTicket, RecoveryDeny,
    RecoveryPath, Revocation, StaffRef, TICKET_CONTEXT, TicketDeny, TicketKind, accept_ticket,
    check_ticket, complete, new_passkey, verify_ticket_as,
};
use fstp_auth::{RosterView, TenantView};
use fstp_domain::id::AccountId;
use fstp_webauthn::{CoseKey, NewCredential, WebAuthnError};

const ADMIN_1: AccountId = AccountId::from_raw(1);
const ADMIN_2: AccountId = AccountId::from_raw(2);
const APPLICANT: AccountId = AccountId::from_raw(4);
const CASE: [u8; 16] = [0xCA; 16];
const CHALLENGE: [u8; 32] = [0x3D; 32];

fn tenant(list: &[AccountId]) -> TenantView {
    TenantView {
        admins: list.to_vec(),
    }
}

fn no_id(_: &[u8]) -> bool {
    false
}

/// The evidence that completes `path` for `holder`, with `ticket` for
/// the operator path.
fn evidence(
    path: RecoveryPath,
    tenant: &TenantView,
    ticket: Option<Vec<u8>>,
    pk: &[u8],
) -> Evidence {
    let approval = Approval::new(
        ADMIN_2,
        tenant,
        Ok(()),
        Ok(IdentityFacts {
            both_verified: false,
            same_identity: false,
        }),
    );
    Evidence {
        email: path != RecoveryPath::HostConsole,
        approval: (path == RecoveryPath::SecondAdmin).then_some(approval),
        ticket: ticket.map(|b| accept_ticket(&b, CASE, pk).unwrap()),
        host_console: path == RecoveryPath::HostConsole,
    }
}

fn signed_ticket(key: &fstp_crypto::composite::CompositeSigningKey, context: &[u8]) -> Vec<u8> {
    let t = OperatorTicket {
        case: CASE,
        staff_1: StaffRef([1; 16]),
        staff_2: StaffRef([2; 16]),
    };
    let sig = key
        .sign_with_context(&t.message(), context)
        .unwrap()
        .to_bytes();
    fstp_auth::codec::encode_operator_ticket(&t, &sig).unwrap()
}

/// I-79, ADR-008 "User verification": every completion path but
/// `EmailThenPasskey` refuses a new passkey without UV, and the
/// `EmailThenPasskey` path accepts one. Regression for a tenant admin
/// recovered with a passkey that gave no user verification.
#[test]
fn i79_completion_requires_uv_on_every_path_but_email() {
    let key = fstp_crypto::composite::generate().unwrap();
    let pk = key.public_key().to_bytes().to_vec();
    let no_uv = NewCredential {
        id: vec![0x09; 16],
        key: CoseKey::Ed25519 { x: [0x03; 32] },
        sign_count: 0,
        user_verified: false,
    };
    let r = Revocation {
        credentials: &[],
        sessions: &[],
        new_credential: &no_uv,
    };
    let roster = RosterView::default();
    let cases = [
        (
            RecoveryPath::SecondAdmin,
            tenant(&[ADMIN_1, ADMIN_2]),
            Deployment::Saas,
        ),
        (
            RecoveryPath::OperatorProcess,
            tenant(&[ADMIN_1]),
            Deployment::Saas,
        ),
        (
            RecoveryPath::HostConsole,
            tenant(&[ADMIN_1]),
            Deployment::SelfHosted,
        ),
    ];
    for (path, t, mode) in cases {
        let ticket =
            (path == RecoveryPath::OperatorProcess).then(|| signed_ticket(&key, TICKET_CONTEXT));
        let c = Case {
            case: CASE,
            holder: ADMIN_1,
            requested: path,
            evidence: evidence(path, &t, ticket, &pk),
        };
        assert_eq!(
            complete(&c, &roster, &t, mode, &r),
            Err(RecoveryDeny::NoUserVerification(path)),
            "{path:?}"
        );
        assert!(path.uv_required());
    }
    let t = tenant(&[ADMIN_1]);
    let c = Case {
        case: CASE,
        holder: APPLICANT,
        requested: RecoveryPath::EmailThenPasskey,
        evidence: evidence(RecoveryPath::EmailThenPasskey, &t, None, &pk),
    };
    assert!(complete(&c, &roster, &t, Deployment::Saas, &r).is_ok());
    assert!(!RecoveryPath::EmailThenPasskey.uv_required());
}

/// I-79, ADR-008, WebAuthn Level 2 section 7.1 step 22: the recovery
/// passkey ceremony takes its UV rule from the path recomputed from the
/// views, and refuses a credential id that is registered already.
#[test]
fn i79_recovery_passkey_takes_uv_from_the_path_and_needs_a_fresh_id() {
    let pk = passkey::Passkey::new(0x51);
    let rp = passkey::rp();
    let without_uv = pk.register(&CHALLENGE, false);
    let with_uv = pk.register(&CHALLENGE, true);
    let reg = |r| Registration {
        response: r,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let roster = RosterView::default();
    let t = tenant(&[ADMIN_1, ADMIN_2]);
    let admin_case = Case {
        case: CASE,
        holder: ADMIN_1,
        requested: RecoveryPath::EmailThenPasskey,
        evidence: Evidence::default(),
    };
    // The request-time path says email, but the views say SecondAdmin.
    assert_eq!(
        new_passkey(
            &reg(&without_uv),
            &admin_case,
            &roster,
            &t,
            Deployment::Saas,
            &no_id
        ),
        Err(RecoveryDeny::Passkey(EnrolDeny::Registration(
            WebAuthnError::UserVerification
        )))
    );
    assert!(
        new_passkey(
            &reg(&with_uv),
            &admin_case,
            &roster,
            &t,
            Deployment::Saas,
            &no_id
        )
        .is_ok()
    );
    let applicant_case = Case {
        holder: APPLICANT,
        ..admin_case
    };
    assert!(
        new_passkey(
            &reg(&without_uv),
            &applicant_case,
            &roster,
            &t,
            Deployment::Saas,
            &no_id
        )
        .is_ok()
    );
    let id = pk.id.clone();
    let taken = move |x: &[u8]| x == id.as_slice();
    assert_eq!(
        new_passkey(
            &reg(&with_uv),
            &admin_case,
            &roster,
            &t,
            Deployment::Saas,
            &taken
        ),
        Err(RecoveryDeny::Passkey(EnrolDeny::CredentialRegistered))
    );
}

/// I-79, design section 9.1: a ticket of another kind never completes a
/// recovery. A break-glass ticket does not verify as a recovery ticket,
/// and one verified as break-glass fails `check_ticket`.
#[test]
fn i79_operator_ticket_of_another_kind_is_refused() {
    let key = fstp_crypto::composite::generate().unwrap();
    let pk = key.public_key().to_bytes().to_vec();
    let bg = signed_ticket(&key, TicketKind::BreakGlass.context());
    assert_eq!(accept_ticket(&bg, CASE, &pk), Err(TicketDeny::Signature));
    let v = verify_ticket_as(&bg, &pk, TicketKind::BreakGlass).unwrap();
    assert_eq!(v.kind(), TicketKind::BreakGlass);
    assert_eq!(check_ticket(&v, CASE), Err(TicketDeny::OtherKind));
    assert_ne!(
        TicketKind::Recovery.context(),
        TicketKind::BreakGlass.context()
    );
    assert_eq!(TICKET_CONTEXT, TicketKind::Recovery.context());
}

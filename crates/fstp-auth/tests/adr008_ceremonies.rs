//! The first-passkey ceremonies and magic links (ADR-008 "Ceremonies and
//! the first passkey", "Magic links", design section 8.3, G10, Q15, Q35).
//!
//! Lane W2b implementer. Synthetic tokens only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod passkey;

use fstp_auth::ceremony::{
    CredentialIndex, EnrolDeny, INVITATION_US, Invitation, InvitationProof, Issuer, MagicDeny,
    MagicLink, Registration, admit_add_passkey, admit_invitation, admit_magic_link,
    admit_self_registration, enrol_add_passkey, enrol_by_invitation, enrol_by_self_registration,
    invitation_records, issue_invitation, may_issue_magic_link, split_token_digest, token_digest,
};
use fstp_auth::codec::Token;
use fstp_auth::recovery::Deployment;
use fstp_auth::stepup::StepUpDeny;
use fstp_auth::{AuthRecord, EnabledMethods, HOUR_US, Method, SessionView};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_webauthn::{CoseKey, NewCredential, WebAuthnError};

const T0: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);
const WHO: AccountId = AccountId::from_raw(5);
const TOKEN: Token = Token([0x7A; 32]);

/// Provisioning of a cell with no first admin and no open first-admin
/// invitation.
const PROVISIONING: Issuer = Issuer::Provisioning {
    first_admin_enrolled: false,
    invitation_open: false,
};

/// A credential index in which no id is registered.
fn no_id(_: &[u8]) -> bool {
    false
}

/// The index of [`no_id`].
const NONE: &dyn CredentialIndex = &no_id;

const fn at(us: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros() + us)
}

fn invitation(first_admin: bool, split: bool, digest: [u8; 32]) -> Invitation {
    Invitation {
        id: [0x1D; 16],
        account: WHO,
        token_digest: digest,
        first_admin,
        split,
        issued_at: T0,
        consumed: false,
    }
}

/// ADR-008 "Constants": an invitation is valid for 72 hours, inclusive,
/// and refused one microsecond later.
#[test]
fn adr008_invitation_valid_for_72_hours() {
    assert_eq!(INVITATION_US, 72 * HOUR_US);
    let inv = invitation(false, false, token_digest(&TOKEN));
    let proof = InvitationProof::Token(TOKEN);
    assert_eq!(
        admit_invitation(&inv, &proof, false, at(INVITATION_US)),
        Ok(())
    );
    assert_eq!(
        admit_invitation(&inv, &proof, false, at(INVITATION_US + 1)),
        Err(EnrolDeny::InvitationExpired)
    );
    assert_eq!(
        admit_invitation(&inv, &proof, false, at(-1)),
        Err(EnrolDeny::InvitationExpired)
    );
}

/// ADR-008: an invitation is single use, and the token must match.
#[test]
fn adr008_invitation_single_use_with_its_token() {
    let inv = invitation(false, false, token_digest(&TOKEN));
    let used = Invitation {
        consumed: true,
        ..inv
    };
    assert_eq!(
        admit_invitation(&used, &InvitationProof::Token(TOKEN), false, T0),
        Err(EnrolDeny::InvitationConsumed)
    );
    assert_eq!(
        admit_invitation(&inv, &InvitationProof::Token(Token([0; 32])), false, T0),
        Err(EnrolDeny::InvitationToken)
    );
}

/// Q35, ADR-008 "First admin delivery": the first admin's enrolment needs
/// both halves, in order, and records `FirstAdminEnrolled`.
#[test]
fn adr008_first_admin_needs_both_halves() {
    let a = Token([0xA1; 32]);
    let b = Token([0xB2; 32]);
    let inv = invitation(true, true, split_token_digest(&a, &b));
    assert_eq!(
        admit_invitation(&inv, &InvitationProof::Halves(a, b), false, T0),
        Ok(())
    );
    assert_eq!(
        admit_invitation(&inv, &InvitationProof::Halves(b, a), false, T0),
        Err(EnrolDeny::InvitationToken)
    );
    assert_eq!(
        admit_invitation(&inv, &InvitationProof::Token(a), false, T0),
        Err(EnrolDeny::InvitationShape)
    );
    let records = invitation_records(&inv, &new_credential());
    assert!(records.contains(&AuthRecord::FirstAdminEnrolled { account: WHO }));
    assert!(records.contains(&AuthRecord::InvitationConsumed { invitation: inv.id }));
}

/// ADR-008: a tenant admin issues an invitation only with a valid
/// step-up, and never the first admin's. Only provisioning issues the
/// first admin's.
#[test]
fn adr008_invitation_issuers() {
    let d = token_digest(&TOKEN);
    let admin = |stepup| Issuer::TenantAdmin {
        admin: true,
        stepup,
    };
    for mode in [Deployment::Saas, Deployment::SelfHosted] {
        assert_eq!(
            issue_invitation(admin(Ok(())), mode, [1; 16], WHO, d, true),
            Ok(AuthRecord::InvitationIssued {
                invitation: [1; 16],
                account: WHO,
                token_digest: d,
                first_admin: false,
                split: false,
            })
        );
        assert_eq!(
            issue_invitation(
                admin(Err(StepUpDeny::Required)),
                mode,
                [1; 16],
                WHO,
                d,
                true
            ),
            Err(EnrolDeny::InvitationIssuer)
        );
        assert_eq!(
            issue_invitation(
                Issuer::TenantAdmin {
                    admin: false,
                    stepup: Ok(())
                },
                mode,
                [1; 16],
                WHO,
                d,
                true
            ),
            Err(EnrolDeny::InvitationIssuer)
        );
    }
}

/// Q35, ADR-008 "First admin delivery": provisioning's first-admin
/// invitation is split on a SaaS cell and a single token on a self-hosted
/// cell. Both record `FirstAdminEnrolled` at enrolment. Regression for a
/// SaaS first admin issued unsplit, and a self-hosted one without the
/// record.
#[test]
fn adr008_first_admin_split_on_saas_only() {
    let d = token_digest(&TOKEN);
    let issued = |mode| issue_invitation(PROVISIONING, mode, [1; 16], WHO, d, true);
    assert_eq!(
        issued(Deployment::Saas),
        Ok(AuthRecord::InvitationIssued {
            invitation: [1; 16],
            account: WHO,
            token_digest: d,
            first_admin: true,
            split: true,
        })
    );
    assert_eq!(
        issued(Deployment::SelfHosted),
        Ok(AuthRecord::InvitationIssued {
            invitation: [1; 16],
            account: WHO,
            token_digest: d,
            first_admin: true,
            split: false,
        })
    );
    // A SaaS first admin never enrols with one token.
    let saas = invitation(true, true, d);
    assert_eq!(
        admit_invitation(&saas, &InvitationProof::Token(TOKEN), false, T0),
        Err(EnrolDeny::InvitationShape)
    );
    // A self-hosted first admin enrols with one token and is recorded.
    let hosted = invitation(true, false, d);
    assert_eq!(
        admit_invitation(&hosted, &InvitationProof::Token(TOKEN), false, T0),
        Ok(())
    );
    let records = invitation_records(&hosted, &new_credential());
    assert!(records.contains(&AuthRecord::FirstAdminEnrolled { account: WHO }));
}

/// `authentication.md` "First passkey", ADR-008: an invitation enrols the
/// first passkey of a new account only. An existing account, or one that
/// holds a passkey at enrolment, is refused, so an invitation never
/// stands in for `AddPasskey` or recovery.
#[test]
fn adr008_invitation_is_for_a_new_account_only() {
    let d = token_digest(&TOKEN);
    let admin = Issuer::TenantAdmin {
        admin: true,
        stepup: Ok(()),
    };
    assert_eq!(
        issue_invitation(admin, Deployment::Saas, [1; 16], WHO, d, false),
        Err(EnrolDeny::InviteeNotNew)
    );
    assert_eq!(
        issue_invitation(PROVISIONING, Deployment::SelfHosted, [1; 16], WHO, d, false),
        Err(EnrolDeny::InviteeNotNew)
    );
    let inv = invitation(false, false, d);
    assert_eq!(
        admit_invitation(&inv, &InvitationProof::Token(TOKEN), true, T0),
        Err(EnrolDeny::InviteeNotNew)
    );
}

/// A verified new credential, as `verify_new_passkey` returns it.
fn new_credential() -> NewCredential {
    NewCredential {
        id: vec![0xCC; 8],
        key: CoseKey::Ed25519 { x: [0xCC; 32] },
        sign_count: 0,
        user_verified: true,
    }
}

const CHALLENGE: [u8; 32] = [0x3C; 32];

/// Design section 4.2, ADR-008 "User verification": an invitation
/// enrolment verifies the registration through `fstp-webauthn` and
/// records the credential's public key and UV flag. A replay of the
/// record rebuilds the stored credential, which then verifies a login.
#[test]
fn adr008_invitation_enrolment_records_the_verified_key() {
    let key = passkey::Passkey::new(0x42);
    let rp = passkey::rp();
    let response = key.register(&CHALLENGE, true);
    let reg = Registration {
        response: &response,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let inv = invitation(false, false, token_digest(&TOKEN));
    let records = enrol_by_invitation(
        &inv,
        &InvitationProof::Token(TOKEN),
        false,
        true,
        &reg,
        NONE,
        T0,
    )
    .unwrap();
    let registered = AuthRecord::CredentialRegistered {
        account: WHO,
        credential: key.id.clone(),
        key: key.key(),
        user_verified: true,
    };
    assert!(records.contains(&registered), "{records:?}");

    let bytes = fstp_auth::codec::encode_auth_record(&registered).unwrap();
    let replayed = fstp_auth::codec::decode_auth_record(&bytes).unwrap();
    let (owner, stored) = replayed.stored_credential(0).unwrap();
    assert_eq!(owner, WHO);
    let login = [0x77; 32];
    let ok = fstp_auth::session::verify_passkey_login(
        true,
        &EnabledMethods::default(),
        &key.assert(&login, 1, true),
        &stored,
        &rp,
        login,
    );
    assert!(ok.is_ok(), "{ok:?}");
}

/// ADR-008 "User verification": a holder's or the first admin's first
/// passkey needs UV, and a registration over another challenge is
/// refused. An applicant's passkey without UV enrols, and the record says
/// so.
#[test]
fn adr008_enrolment_requires_uv_for_holders_and_records_it_for_applicants() {
    let key = passkey::Passkey::new(0x43);
    let rp = passkey::rp();
    let no_uv = key.register(&CHALLENGE, false);
    let reg = Registration {
        response: &no_uv,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let inv = invitation(false, false, token_digest(&TOKEN));
    let proof = InvitationProof::Token(TOKEN);
    assert_eq!(
        enrol_by_invitation(&inv, &proof, false, true, &reg, NONE, T0),
        Err(EnrolDeny::Registration(WebAuthnError::UserVerification))
    );
    let first = invitation(true, false, token_digest(&TOKEN));
    assert_eq!(
        enrol_by_invitation(&first, &proof, false, false, &reg, NONE, T0),
        Err(EnrolDeny::Registration(WebAuthnError::UserVerification))
    );
    let other = Registration {
        challenge: [0; 32],
        ..reg
    };
    assert!(matches!(
        enrol_by_invitation(&inv, &proof, false, false, &other, NONE, T0),
        Err(EnrolDeny::Registration(_))
    ));
    assert_eq!(
        enrol_by_self_registration(WHO, true, true, true, &reg, NONE),
        Ok(AuthRecord::CredentialRegistered {
            account: WHO,
            credential: key.id.clone(),
            key: key.key(),
            user_verified: false,
        })
    );
    assert_eq!(
        enrol_by_self_registration(WHO, false, true, true, &reg, NONE),
        Err(EnrolDeny::SelfRegistration)
    );
}

/// ADR-008, I-78: `AddPasskey` verifies the registration too, with UV for
/// a holder, and registers the key for the session's own account.
#[test]
fn adr008_add_passkey_verifies_the_registration() {
    let key = passkey::Passkey::new(0x44);
    let rp = passkey::rp();
    let uv = key.register(&CHALLENGE, true);
    let no_uv = key.register(&CHALLENGE, false);
    let s = SessionView {
        id: [1; 16],
        account: WHO,
        method: Method::Passkey,
        started: T0,
        last_used: T0,
    };
    let reg = |r| Registration {
        response: r,
        rp: &rp,
        challenge: CHALLENGE,
    };
    assert_eq!(
        enrol_add_passkey(true, &s, Ok(()), true, &reg(&uv), NONE),
        Ok(AuthRecord::CredentialRegistered {
            account: WHO,
            credential: key.id.clone(),
            key: key.key(),
            user_verified: true,
        })
    );
    assert_eq!(
        enrol_add_passkey(true, &s, Ok(()), true, &reg(&no_uv), NONE),
        Err(EnrolDeny::Registration(WebAuthnError::UserVerification))
    );
    assert_eq!(
        enrol_add_passkey(false, &s, Ok(()), true, &reg(&uv), NONE),
        Err(EnrolDeny::AddPasskey)
    );
}

/// ADR-008: self-registration is only for a new Receiving account with
/// email proof in the same ceremony.
#[test]
fn adr008_self_registration_rule() {
    assert_eq!(admit_self_registration(true, true, true), Ok(()));
    for (n, r, e) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        assert_eq!(
            admit_self_registration(n, r, e),
            Err(EnrolDeny::SelfRegistration)
        );
    }
}

/// ADR-008, I-78: `AddPasskey` needs an existing passkey, a strong session
/// and a step-up. A magic-link session never adds one.
#[test]
fn adr008_add_passkey_needs_passkey_strong_session_and_step_up() {
    let s = |m| SessionView {
        id: [1; 16],
        account: WHO,
        method: m,
        started: T0,
        last_used: T0,
    };
    assert_eq!(admit_add_passkey(true, &s(Method::Passkey), Ok(())), Ok(()));
    assert!(admit_add_passkey(false, &s(Method::Passkey), Ok(())).is_err());
    assert!(admit_add_passkey(true, &s(Method::MagicLink), Ok(())).is_err());
    assert!(admit_add_passkey(true, &s(Method::Passkey), Err(StepUpDeny::Stale)).is_err());
}

fn link() -> MagicLink {
    MagicLink {
        account: WHO,
        token_digest: token_digest(&TOKEN),
        issued_at: T0,
        consumed: false,
    }
}

/// I-77, ADR-008 "Magic links": a holder never gets a magic link, and a
/// tenant that does not enable them sends none.
#[test]
fn i77_magic_link_refused_to_holders_and_where_disabled() {
    let on = EnabledMethods {
        methods: vec![Method::MagicLink],
    };
    assert_eq!(may_issue_magic_link(false, &on), Ok(()));
    assert_eq!(may_issue_magic_link(true, &on), Err(MagicDeny::Holder));
    assert_eq!(
        may_issue_magic_link(false, &EnabledMethods::default()),
        Err(MagicDeny::Disabled)
    );
    assert_eq!(
        admit_magic_link(true, &on, &link(), &TOKEN, T0, 10),
        Err(MagicDeny::Holder)
    );
}

/// ADR-008 "Magic links": a link is single use, needs its token and lives
/// for the given lifetime.
#[test]
fn adr008_magic_link_single_use_with_its_token() {
    let on = EnabledMethods {
        methods: vec![Method::MagicLink],
    };
    assert_eq!(
        admit_magic_link(false, &on, &link(), &TOKEN, at(10), 10),
        Ok(())
    );
    assert_eq!(
        admit_magic_link(false, &on, &link(), &TOKEN, at(11), 10),
        Err(MagicDeny::Expired)
    );
    assert_eq!(
        admit_magic_link(false, &on, &link(), &Token([0; 32]), T0, 10),
        Err(MagicDeny::Token)
    );
    let used = MagicLink {
        consumed: true,
        ..link()
    };
    assert_eq!(
        admit_magic_link(false, &on, &used, &TOKEN, T0, 10),
        Err(MagicDeny::Consumed)
    );
}

/// ADR-008 "Ceremonies and the first passkey", design section 8.3:
/// provisioning issues the first admin's invitation, in the singular. It
/// refuses once `FirstAdminEnrolled` is recorded, and while another
/// first-admin invitation is open. Regression for a repeated provisioning
/// run that minted a further tenant-admin enrolment without tenant
/// approval.
#[test]
fn adr008_provisioning_issues_only_while_the_cell_has_no_first_admin() {
    let d = token_digest(&TOKEN);
    for (first_admin_enrolled, invitation_open) in [(true, false), (false, true), (true, true)] {
        let issuer = Issuer::Provisioning {
            first_admin_enrolled,
            invitation_open,
        };
        for mode in [Deployment::Saas, Deployment::SelfHosted] {
            assert_eq!(
                issue_invitation(issuer, mode, [1; 16], WHO, d, true),
                Err(EnrolDeny::InvitationIssuer),
                "{first_admin_enrolled} {invitation_open} {mode:?}"
            );
        }
    }
    assert!(issue_invitation(PROVISIONING, Deployment::Saas, [1; 16], WHO, d, true).is_ok());
}

/// ADR-008 "Ceremonies and the first passkey", WebAuthn Level 2 section
/// 7.1 step 22: every enrolment ceremony refuses a credential id that is
/// registered already, to any account. Regression for a self-registrant
/// who registered a victim admin's public credential id under their own
/// key.
#[test]
fn adr008_enrolment_refuses_a_registered_credential_id() {
    let key = passkey::Passkey::new(0x45);
    let rp = passkey::rp();
    let response = key.register(&CHALLENGE, true);
    let reg = Registration {
        response: &response,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let victim = key.id.clone();
    let taken = move |id: &[u8]| id == victim.as_slice();
    let inv = invitation(false, false, token_digest(&TOKEN));
    assert_eq!(
        enrol_by_invitation(
            &inv,
            &InvitationProof::Token(TOKEN),
            false,
            true,
            &reg,
            &taken,
            T0
        ),
        Err(EnrolDeny::CredentialRegistered)
    );
    assert_eq!(
        enrol_by_self_registration(WHO, true, true, true, &reg, &taken),
        Err(EnrolDeny::CredentialRegistered)
    );
    let s = SessionView {
        id: [1; 16],
        account: WHO,
        method: Method::Passkey,
        started: T0,
        last_used: T0,
    };
    assert_eq!(
        enrol_add_passkey(true, &s, Ok(()), true, &reg, &taken),
        Err(EnrolDeny::CredentialRegistered)
    );
    // Another id still enrols.
    let other = |id: &[u8]| id == [0u8; 4].as_slice();
    assert!(enrol_by_self_registration(WHO, true, true, true, &reg, &other).is_ok());
}

//! First-passkey ceremonies and magic links (ADR-008 "Ceremonies and the
//! first passkey", "Magic links", design section 8.3, G10, Q15, Q35).
//!
//! A first passkey is accepted only inside an invitation, a
//! self-registration of a new Receiving account, or a recovery
//! completion ([`crate::recovery::complete`]). An ordinary strong session
//! adds a further passkey only as the high-risk action `AddPasskey`, and a
//! magic-link session never does.
//!
//! Every new passkey goes through `fstp_webauthn::verify_registration`
//! ([`verify_new_passkey`]). Its record carries the verified public key
//! and the UV flag, so the ledger holds both (design section 4.2). Every
//! ceremony then refuses a credential id that is registered already
//! ([`check_new_id`]), since `fstp-webauthn` is stateless.
//!
//! Tokens are 32 random bytes drawn by the shell, and only their SHA-256
//! digest is stored. Every digest comparison runs in constant time.

use fstp_crypto::{Sha256, constant_time_eq, sha256};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_webauthn::{
    NewCredential, RegistrationExpect, RegistrationResponse, RelyingParty, WebAuthnError,
    verify_registration,
};

use crate::codec::Token;
use crate::recovery::Deployment;
use crate::stepup::StepUpDeny;
use crate::{AuthRecord, EnabledMethods, HOUR_US, Method, SessionView, within};

/// The invitation lifetime: 72 hours (ADR-008 constant with no P- id,
/// interim pending Daniel, Q37).
pub const INVITATION_US: i64 = 72 * HOUR_US;

/// The domain separation prefix of the split first-admin token digest.
pub const FIRST_ADMIN_PREFIX: &[u8] = b"fstp-first-admin-v1";

/// The stored digest of a token: SHA-256 of its 32 bytes.
pub fn token_digest(t: &Token) -> [u8; 32] {
    sha256(&t.0)
}

/// The stored digest of the split first-admin token (Q35): SHA-256 over
/// the prefix and both halves. Enrolment needs both halves.
pub fn split_token_digest(first: &Token, second: &Token) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FIRST_ADMIN_PREFIX);
    h.update(&first.0);
    h.update(&second.0);
    h.finish()
}

/// Why an enrolment ceremony is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolDeny {
    /// The invitation was issued without a tenant admin's valid step-up,
    /// or provisioning issued it while the cell has a first admin or an
    /// open first-admin invitation.
    InvitationIssuer,
    /// The invitation was used already.
    InvitationConsumed,
    /// The invitation is older than 72 hours, or dated after `now`.
    InvitationExpired,
    /// The token, or one of the two halves, does not match.
    InvitationToken,
    /// A split first-admin token was given as one token, or the reverse.
    InvitationShape,
    /// The invited account is not new, or it holds a passkey. Such an
    /// account adds a further passkey only as `AddPasskey`, and an
    /// account without one gets its first through recovery
    /// (`authentication.md` "First passkey").
    InviteeNotNew,
    /// The self-registration is not of a new Receiving account with email
    /// proof in the same ceremony.
    SelfRegistration,
    /// `AddPasskey` without an existing passkey, outside a phishing-resistant
    /// session, or without a valid step-up.
    AddPasskey,
    /// The registration did not verify, or it gave no user verification
    /// where ADR-008 requires it.
    Registration(WebAuthnError),
    /// The new credential id is registered already, to this account or
    /// another (WebAuthn Level 2 section 7.1 step 22).
    CredentialRegistered,
}

/// A registration response and what it must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration<'a> {
    /// The browser's response.
    pub response: &'a RegistrationResponse,
    /// The relying party: the exact cell host.
    pub rp: &'a RelyingParty,
    /// The single-use challenge of the ceremony.
    pub challenge: [u8; 32],
}

/// Verifies a new passkey through `fstp_webauthn::verify_registration`.
///
/// `uv_required` is true when the account holds a management role, or
/// will hold one as the first tenant admin (ADR-008 "User
/// verification"). An applicant passkey requests UV, and the returned
/// credential records whether it was given.
pub fn verify_new_passkey(
    reg: &Registration<'_>,
    uv_required: bool,
) -> Result<NewCredential, EnrolDeny> {
    let expect = RegistrationExpect {
        rp: reg.rp.clone(),
        challenge: reg.challenge,
        user_verification: uv_required,
    };
    let cred = verify_registration(reg.response, &expect).map_err(EnrolDeny::Registration)?;
    if uv_required && !cred.user_verified {
        return Err(EnrolDeny::Registration(WebAuthnError::UserVerification));
    }
    Ok(cred)
}

/// The cell's index of registered credential ids. The shell answers it
/// from the `CredLookup` HMAC of the id (design section 4.2), over every
/// account and including revoked credentials.
///
/// A closure `Fn(&[u8]) -> bool` is an index.
pub trait CredentialIndex {
    /// Whether a credential with `id` is registered already.
    fn is_registered(&self, id: &[u8]) -> bool;
}

impl<F: Fn(&[u8]) -> bool> CredentialIndex for F {
    fn is_registered(&self, id: &[u8]) -> bool {
        self(id)
    }
}

/// Refuses a new credential whose id is registered already (WebAuthn
/// Level 2 section 7.1 step 22). Credential ids are not secret, so
/// without this check a crafted authenticator could register another
/// account's id under its own key.
pub fn check_new_id(cred: &NewCredential, known: &dyn CredentialIndex) -> Result<(), EnrolDeny> {
    if known.is_registered(&cred.id) {
        Err(EnrolDeny::CredentialRegistered)
    } else {
        Ok(())
    }
}

/// [`verify_new_passkey`], then [`check_new_id`].
pub fn verify_fresh_passkey(
    reg: &Registration<'_>,
    uv_required: bool,
    known: &dyn CredentialIndex,
) -> Result<NewCredential, EnrolDeny> {
    let cred = verify_new_passkey(reg, uv_required)?;
    check_new_id(&cred, known)?;
    Ok(cred)
}

/// Who issues an invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issuer {
    /// Provisioning, for a cell's first tenant admin. It issues only while
    /// the cell has no first admin and no other provisioning invitation is
    /// open.
    Provisioning {
        /// Whether `FirstAdminEnrolled` is recorded in the cell.
        first_admin_enrolled: bool,
        /// Whether a first-admin invitation is unused and within its 72
        /// hours. An expired one does not block a new invitation.
        invitation_open: bool,
    },
    /// A tenant admin, with the outcome of their step-up.
    TenantAdmin {
        /// Whether the issuer is a current tenant admin.
        admin: bool,
        /// The outcome of [`crate::stepup::admit_step_up`].
        stepup: Result<(), StepUpDeny>,
    },
}

/// An invitation as the fold holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The invitation id.
    pub id: [u8; 16],
    /// The invited account.
    pub account: AccountId,
    /// The stored token digest.
    pub token_digest: [u8; 32],
    /// Whether it is the first tenant admin's invitation.
    pub first_admin: bool,
    /// Whether the token is drawn as two halves: the first admin's
    /// invitation of a SaaS cell (Q35).
    pub split: bool,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// Whether an enrolment used it.
    pub consumed: bool,
}

/// What the invitee presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationProof {
    /// One token.
    Token(Token),
    /// The two halves of the split first-admin token, in order.
    Halves(Token, Token),
}

/// The record of an invitation, when `issuer` may issue it (ADR-008
/// "Ceremonies and the first passkey", "First admin delivery").
///
/// - Provisioning issues only the first tenant admin's invitation, and
///   only while no `FirstAdminEnrolled` is recorded and no first-admin
///   invitation is open (ADR-008 "Ceremonies and the first passkey").
///   Its enrolment records `FirstAdminEnrolled`. On a SaaS cell its token is
///   split into two halves (Q35), so `token_digest` is a
///   [`split_token_digest`]. A self-hosted cell's first admin has one
///   token, which `fstp-cell first-admin` prints.
/// - A tenant admin issues any other invitation, with a step-up. It is
///   never split.
/// - `invitee_new` is true when the invitation creates the account: no
///   record names it before, other than invitations that no enrolment
///   used. An existing account is refused. It adds a further passkey only
///   as `AddPasskey`, or gets its first through recovery.
pub fn issue_invitation(
    issuer: Issuer,
    mode: Deployment,
    id: [u8; 16],
    account: AccountId,
    token_digest: [u8; 32],
    invitee_new: bool,
) -> Result<AuthRecord, EnrolDeny> {
    let first_admin = match issuer {
        Issuer::Provisioning {
            first_admin_enrolled,
            invitation_open,
        } => {
            if first_admin_enrolled || invitation_open {
                return Err(EnrolDeny::InvitationIssuer);
            }
            true
        }
        Issuer::TenantAdmin { admin, stepup } => {
            if !admin || stepup.is_err() {
                return Err(EnrolDeny::InvitationIssuer);
            }
            false
        }
    };
    if !invitee_new {
        return Err(EnrolDeny::InviteeNotNew);
    }
    Ok(AuthRecord::InvitationIssued {
        invitation: id,
        account,
        token_digest,
        first_admin,
        split: first_admin && mode == Deployment::Saas,
    })
}

/// The invitation rule at `now`: unused, at most 72 hours old, the
/// invitee holds no passkey, and the presented token or halves match the
/// stored digest.
pub fn admit_invitation(
    inv: &Invitation,
    proof: &InvitationProof,
    invitee_has_passkey: bool,
    now: Timestamp,
) -> Result<(), EnrolDeny> {
    if inv.consumed {
        return Err(EnrolDeny::InvitationConsumed);
    }
    if !within(inv.issued_at, now, INVITATION_US) {
        return Err(EnrolDeny::InvitationExpired);
    }
    if invitee_has_passkey {
        return Err(EnrolDeny::InviteeNotNew);
    }
    let digest = match (proof, inv.split) {
        (InvitationProof::Token(t), false) => token_digest(t),
        (InvitationProof::Halves(a, b), true) => split_token_digest(a, b),
        (InvitationProof::Token(_), true) | (InvitationProof::Halves(..), false) => {
            return Err(EnrolDeny::InvitationShape);
        }
    };
    if !constant_time_eq(&digest, &inv.token_digest) {
        return Err(EnrolDeny::InvitationToken);
    }
    Ok(())
}

/// The records of an enrolment through `inv` with the verified new
/// passkey `credential`: the invitation consumed, the credential
/// registered, and `FirstAdminEnrolled` for the first admin's invitation.
pub fn invitation_records(inv: &Invitation, credential: &NewCredential) -> Vec<AuthRecord> {
    let mut out = vec![
        AuthRecord::InvitationConsumed { invitation: inv.id },
        AuthRecord::registration(inv.account, credential),
    ];
    if inv.first_admin {
        out.push(AuthRecord::FirstAdminEnrolled {
            account: inv.account,
        });
    }
    out
}

/// The invitation ceremony: [`admit_invitation`], then
/// [`verify_fresh_passkey`] against `known`, then [`invitation_records`].
///
/// User verification is required when `holdings` is true or the
/// invitation is the first admin's.
pub fn enrol_by_invitation(
    inv: &Invitation,
    proof: &InvitationProof,
    invitee_has_passkey: bool,
    holdings: bool,
    reg: &Registration<'_>,
    known: &dyn CredentialIndex,
    now: Timestamp,
) -> Result<Vec<AuthRecord>, EnrolDeny> {
    admit_invitation(inv, proof, invitee_has_passkey, now)?;
    let cred = verify_fresh_passkey(reg, holdings || inv.first_admin, known)?;
    Ok(invitation_records(inv, &cred))
}

/// The self-registration rule: a new account, holding Receiving roles
/// only, whose email was proven earlier in the same ceremony.
pub const fn admit_self_registration(
    new_account: bool,
    receiving_only: bool,
    email_proven: bool,
) -> Result<(), EnrolDeny> {
    if new_account && receiving_only && email_proven {
        Ok(())
    } else {
        Err(EnrolDeny::SelfRegistration)
    }
}

/// The self-registration ceremony with a passkey:
/// [`admit_self_registration`], then [`verify_fresh_passkey`] without
/// required UV (an applicant passkey), then the registration record.
pub fn enrol_by_self_registration(
    account: AccountId,
    new_account: bool,
    receiving_only: bool,
    email_proven: bool,
    reg: &Registration<'_>,
    known: &dyn CredentialIndex,
) -> Result<AuthRecord, EnrolDeny> {
    admit_self_registration(new_account, receiving_only, email_proven)?;
    let cred = verify_fresh_passkey(reg, false, known)?;
    Ok(AuthRecord::registration(account, &cred))
}

/// The `AddPasskey` rule: the account has a passkey already, the session
/// is phishing resistant, and the step-up passed.
pub fn admit_add_passkey(
    has_passkey: bool,
    session: &SessionView,
    stepup: Result<(), StepUpDeny>,
) -> Result<(), EnrolDeny> {
    if has_passkey && session.method.phishing_resistant() && stepup.is_ok() {
        Ok(())
    } else {
        Err(EnrolDeny::AddPasskey)
    }
}

/// `AddPasskey` for the session's own account: [`admit_add_passkey`],
/// then [`verify_fresh_passkey`] with UV required for a holder, then the
/// registration record.
pub fn enrol_add_passkey(
    has_passkey: bool,
    session: &SessionView,
    stepup: Result<(), StepUpDeny>,
    holdings: bool,
    reg: &Registration<'_>,
    known: &dyn CredentialIndex,
) -> Result<AuthRecord, EnrolDeny> {
    admit_add_passkey(has_passkey, session, stepup)?;
    let cred = verify_fresh_passkey(reg, holdings, known)?;
    Ok(AuthRecord::registration(session.account, &cred))
}

// ---------------------------------------------------------------------------
// Magic links.

/// Why a magic link is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MagicDeny {
    /// The account holds a role outside Receiving (I-77).
    Holder,
    /// The tenant does not enable magic links (P-70).
    Disabled,
    /// The presented token does not match.
    Token,
    /// The link was used already.
    Consumed,
    /// The link is older than its lifetime, or dated after `now`.
    Expired,
}

/// A magic link as the cell stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MagicLink {
    /// The account.
    pub account: AccountId,
    /// The stored token digest.
    pub token_digest: [u8; 32],
    /// When it was issued.
    pub issued_at: Timestamp,
    /// Whether a consumption used it.
    pub consumed: bool,
}

/// Whether the cell may send a magic link to an account: only to one that
/// holds no role outside Receiving, and only where the tenant enables
/// magic links. `POST /auth/magic/request` answers the same either way.
pub fn may_issue_magic_link(holdings: bool, enabled: &EnabledMethods) -> Result<(), MagicDeny> {
    if holdings {
        return Err(MagicDeny::Holder);
    }
    if !enabled.offers(Method::MagicLink) {
        return Err(MagicDeny::Disabled);
    }
    Ok(())
}

/// The rule of `POST /auth/magic/consume` at `now`. The holdings are read
/// again at consumption, so a grant after the request refuses the link.
///
/// The magic-link lifetime is not set by the design (ADR-008 open point
/// "Unset lifetimes"), so the caller passes `lifetime_us`. ADR-008 fixes
/// it by amendment before W2b merges. This function then takes the
/// constant in place of the parameter.
pub fn admit_magic_link(
    holdings: bool,
    enabled: &EnabledMethods,
    link: &MagicLink,
    presented: &Token,
    now: Timestamp,
    lifetime_us: i64,
) -> Result<(), MagicDeny> {
    may_issue_magic_link(holdings, enabled)?;
    if !constant_time_eq(&token_digest(presented), &link.token_digest) {
        return Err(MagicDeny::Token);
    }
    if link.consumed {
        return Err(MagicDeny::Consumed);
    }
    if !within(link.issued_at, now, lifetime_us) {
        return Err(MagicDeny::Expired);
    }
    Ok(())
}

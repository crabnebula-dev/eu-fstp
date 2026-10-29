//! Account recovery (I-79, ADR-008 "Recovery", design section 8.5, Q15).
//!
//! | Holdings | Other tenant admins | Deployment | Path |
//! | --- | --- | --- | --- |
//! | Receiving only, or none | any | any | `EmailThenPasskey` |
//! | Management or tenant admin | at least one | any | `SecondAdmin` |
//! | Management or tenant admin | none | SaaS | `OperatorProcess` |
//! | Management or tenant admin | none | self-hosted | `HostConsole` |
//!
//! Reading, shared with the W1b reference: an account outside Receiving
//! with no tenant admin to approve takes the operator path, as a sole
//! tenant admin does. I-79 forbids email alone, and no second admin
//! exists.
//!
//! [`complete`] recomputes the path from the holdings at completion, so a
//! role granted during an open email recovery makes it fail. It also
//! refuses a new passkey without user verification on every path but
//! `EmailThenPasskey`. [`new_passkey`] verifies that passkey, with the
//! UV rule of the recomputed path and a fresh credential id. Completion
//! revokes every credential and ends every session of the account.
//!
//! Open, ADR-008 "Unset lifetimes" (fixed by amendment before W2b
//! merges): a recovery case, the `SecondAdmin` one-time enrolment token
//! and an operator ticket have no lifetime in the design. So [`decide`]
//! checks no case age, [`Evidence`] holds no enrolment token, and a
//! ticket carries no expiry. This lane does not invent the constants.

use fstp_domain::id::AccountId;
use fstp_webauthn::NewCredential;

use crate::ceremony::{CredentialIndex, EnrolDeny, Registration, check_new_id, verify_new_passkey};
use crate::codec::{CodecError, decode_operator_ticket};
use crate::stepup::StepUpDeny;
use crate::{AuthError, AuthRecord, RosterView, TenantView};

/// The recovery path an account must take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryPath {
    /// Receiving roles only, or no role: email proof, then a new passkey.
    EmailThenPasskey,
    /// Another tenant admin approves with a step-up.
    SecondAdmin,
    /// The sole tenant admin of a SaaS cell: an operator ticket.
    OperatorProcess,
    /// The sole tenant admin of a self-hosted cell: a host console command.
    HostConsole,
}

impl RecoveryPath {
    /// Every path.
    pub const ALL: [RecoveryPath; 4] = [
        RecoveryPath::EmailThenPasskey,
        RecoveryPath::SecondAdmin,
        RecoveryPath::OperatorProcess,
        RecoveryPath::HostConsole,
    ];

    /// Whether a completion by this path is shown in the tenant's audit
    /// view as `authentication.md` requires: the operator and host console
    /// paths.
    pub const fn shown_to_tenant(self) -> bool {
        matches!(
            self,
            RecoveryPath::OperatorProcess | RecoveryPath::HostConsole
        )
    }

    /// Whether the new passkey of a completion by this path must give
    /// user verification (ADR-008 "User verification", design section
    /// 8.1). Every path but `EmailThenPasskey` recovers a management
    /// account or a tenant admin.
    pub const fn uv_required(self) -> bool {
        !matches!(self, RecoveryPath::EmailThenPasskey)
    }
}

/// The role holdings that decide the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holdings {
    /// Receiving roles only, or no role.
    ReceivingOnly,
    /// A role outside Receiving.
    Management,
    /// The tenant admin role.
    TenantAdmin,
}

impl Holdings {
    /// The holdings class of `a` in the views.
    pub fn of(roster: &RosterView, tenant: &TenantView, a: AccountId) -> Holdings {
        if tenant.is_admin(a) {
            Holdings::TenantAdmin
        } else if roster.management.contains(&a) {
            Holdings::Management
        } else {
            Holdings::ReceivingOnly
        }
    }
}

/// How the cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deployment {
    /// Hosted by CrabNebula.
    Saas,
    /// Self-hosted.
    SelfHosted,
}

/// The path of the table above. The designed signature is infallible.
/// The `Result` is kept from the W0 API and is always `Ok`.
pub const fn recovery_path(
    holdings: Holdings,
    other_admins: usize,
    mode: Deployment,
) -> Result<RecoveryPath, AuthError> {
    Ok(path_of(holdings, other_admins, mode))
}

/// The path of the table above.
pub const fn path_of(holdings: Holdings, other_admins: usize, mode: Deployment) -> RecoveryPath {
    match (holdings, other_admins, mode) {
        (Holdings::ReceivingOnly, _, _) => RecoveryPath::EmailThenPasskey,
        (_, 0, Deployment::Saas) => RecoveryPath::OperatorProcess,
        (_, 0, Deployment::SelfHosted) => RecoveryPath::HostConsole,
        (_, _, _) => RecoveryPath::SecondAdmin,
    }
}

/// The path for `a` in the views.
pub fn path_for(
    roster: &RosterView,
    tenant: &TenantView,
    a: AccountId,
    mode: Deployment,
) -> RecoveryPath {
    path_of(Holdings::of(roster, tenant, a), tenant.others(a), mode)
}

/// The record that opens case `case` for `account` (`POST /auth/recovery`).
pub fn request(
    case: [u8; 16],
    account: AccountId,
    roster: &RosterView,
    tenant: &TenantView,
    mode: Deployment,
) -> AuthRecord {
    AuthRecord::RecoveryRequested {
        case,
        account,
        path: path_for(roster, tenant, account, mode),
    }
}

// ---------------------------------------------------------------------------
// Approval by a second tenant admin.

/// The vault answered that the identity check could not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VaultDown;

/// The vault's answers for an approval: whether both accounts are
/// verified, and `SameIdentityAsAny` for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityFacts {
    /// Whether both approver and holder are verified, so the identity
    /// check applies.
    pub both_verified: bool,
    /// Whether approver and holder share an identity.
    pub same_identity: bool,
}

/// An approval of a recovery, as the facts it is decided on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approval {
    /// The approving account.
    pub approver: AccountId,
    /// Whether the approver was a current tenant admin at approval.
    pub approver_admin: bool,
    /// The outcome of [`crate::stepup::admit_step_up`] for the approval.
    pub stepup: Result<(), StepUpDeny>,
    /// The vault's answers, or the outage that refuses the approval.
    pub identity: Result<IdentityFacts, VaultDown>,
}

impl Approval {
    /// The approval by `approver`, whose admin status is read from
    /// `tenant` at approval.
    pub fn new(
        approver: AccountId,
        tenant: &TenantView,
        stepup: Result<(), StepUpDeny>,
        identity: Result<IdentityFacts, VaultDown>,
    ) -> Approval {
        Approval {
            approver,
            approver_admin: tenant.is_admin(approver),
            stepup,
            identity,
        }
    }
}

/// Why a recovery approval is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDeny {
    /// The approver is the account holder.
    SelfApproval,
    /// The approver is not a current tenant admin.
    NotAdmin,
    /// The approval has no valid step-up.
    StepUp(StepUpDeny),
    /// Approver and holder are both verified and share an identity.
    SameIdentity,
    /// The vault could not answer, so the approval fails closed.
    VaultDown,
}

/// The approval rule for the recovery of `holder` (I-79, ADR-008).
///
/// A vault outage refuses the approval whatever else holds. Whether both
/// accounts are verified is itself a vault fact, so the cell cannot know
/// it while the vault does not answer.
pub fn approve(holder: AccountId, a: &Approval) -> Result<(), ApprovalDeny> {
    if a.approver == holder {
        return Err(ApprovalDeny::SelfApproval);
    }
    if !a.approver_admin {
        return Err(ApprovalDeny::NotAdmin);
    }
    a.stepup.map_err(ApprovalDeny::StepUp)?;
    match a.identity {
        Err(VaultDown) => Err(ApprovalDeny::VaultDown),
        Ok(f) if f.both_verified && f.same_identity => Err(ApprovalDeny::SameIdentity),
        Ok(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Operator tickets (`OperatorProcess`).

/// The kind of an operator ticket, as `fstp_cp_proto::TicketKind` names
/// it (design section 9.1). Each kind signs under its own composite
/// context, so a ticket of one kind never verifies as another.
///
/// Open, for the lead: design section 9.1 carries `kind` and `issued_at`
/// beside the signature but no staff references, while ADR-008 asks for
/// two staff approvals. This crate signs the case and both staff
/// references, and binds the kind through the context. `issued_at` joins
/// the signed bytes once ADR-008 "Unset lifetimes" sets a ticket
/// lifetime. The first-admin verification ticket of ADR-008 gets its own
/// kind once its mechanism is fixed by amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketKind {
    /// The recovery of a sole tenant admin (`OperatorProcess`).
    Recovery,
    /// Break-glass access (SoD-08).
    BreakGlass,
}

impl TicketKind {
    /// The composite signature context of a ticket of this kind.
    pub const fn context(self) -> &'static [u8] {
        match self {
            TicketKind::Recovery => b"fstp-operator-ticket-recovery-v1",
            TicketKind::BreakGlass => b"fstp-operator-ticket-break-glass-v1",
        }
    }
}

/// The composite signature context of a recovery operator ticket: the
/// context of [`TicketKind::Recovery`].
pub const TICKET_CONTEXT: &[u8] = TicketKind::Recovery.context();

/// An opaque reference to one operator staff member. It is no cell
/// account (SoD-08).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StaffRef(pub [u8; 16]);

/// An operator ticket: two staff approvals for one case reference. It
/// names only the cell's opaque case reference, never an account (I-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperatorTicket {
    /// The case reference.
    pub case: [u8; 16],
    /// The first staff approval.
    pub staff_1: StaffRef,
    /// The second staff approval.
    pub staff_2: StaffRef,
}

/// The length of the signed part of a ticket.
pub const TICKET_MESSAGE_LEN: usize = 48;

impl OperatorTicket {
    /// The bytes the control plane signs: `case || staff_1 || staff_2`.
    pub fn message(&self) -> [u8; TICKET_MESSAGE_LEN] {
        let mut out = [0u8; TICKET_MESSAGE_LEN];
        let (case, rest) = out.split_at_mut(16);
        let (s1, s2) = rest.split_at_mut(16);
        case.copy_from_slice(&self.case);
        s1.copy_from_slice(&self.staff_1.0);
        s2.copy_from_slice(&self.staff_2.0);
        out
    }
}

/// A ticket whose composite signature verified under the pinned control
/// plane key, with the kind whose context it verified under. Only
/// [`verify_ticket_as`] builds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedTicket {
    ticket: OperatorTicket,
    kind: TicketKind,
}

impl VerifiedTicket {
    /// The ticket.
    pub const fn ticket(&self) -> &OperatorTicket {
        &self.ticket
    }

    /// The kind the signature verified as.
    pub const fn kind(&self) -> TicketKind {
        self.kind
    }
}

/// Why an operator ticket is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketDeny {
    /// The bytes are not one ticket.
    Malformed(CodecError),
    /// The composite signature did not verify under the pinned key.
    Signature,
    /// The ticket names another case.
    OtherCase,
    /// The two approvals are by one staff member.
    OneStaff,
    /// The ticket is of another kind than a recovery.
    OtherKind,
}

/// Decodes `bytes` and verifies the ticket's composite signature under
/// `pinned_key`, the control plane's composite public key, in the context
/// of `kind` (ADR-008, I-90). Both halves must verify.
pub fn verify_ticket_as(
    bytes: &[u8],
    pinned_key: &[u8],
    kind: TicketKind,
) -> Result<VerifiedTicket, TicketDeny> {
    let signed = decode_operator_ticket(bytes).map_err(TicketDeny::Malformed)?;
    fstp_crypto::composite::verify_with_context(
        pinned_key,
        &signed.ticket.message(),
        kind.context(),
        &signed.signature,
    )
    .map_err(|_| TicketDeny::Signature)?;
    Ok(VerifiedTicket {
        ticket: signed.ticket,
        kind,
    })
}

/// [`verify_ticket_as`] for a recovery ticket.
pub fn verify_ticket(bytes: &[u8], pinned_key: &[u8]) -> Result<VerifiedTicket, TicketDeny> {
    verify_ticket_as(bytes, pinned_key, TicketKind::Recovery)
}

/// The checks after the signature: the ticket is a recovery ticket, it
/// names `case`, and its two approvals are by two different staff members.
pub fn check_ticket(t: &VerifiedTicket, case: [u8; 16]) -> Result<(), TicketDeny> {
    if t.kind != TicketKind::Recovery {
        return Err(TicketDeny::OtherKind);
    }
    if t.ticket.case != case {
        return Err(TicketDeny::OtherCase);
    }
    if t.ticket.staff_1 == t.ticket.staff_2 {
        return Err(TicketDeny::OneStaff);
    }
    Ok(())
}

/// [`verify_ticket`], then [`check_ticket`].
pub fn accept_ticket(
    bytes: &[u8],
    case: [u8; 16],
    pinned_key: &[u8],
) -> Result<VerifiedTicket, TicketDeny> {
    let t = verify_ticket(bytes, pinned_key)?;
    check_ticket(&t, case)?;
    Ok(t)
}

// ---------------------------------------------------------------------------
// Completion.

/// What a recovery case gathered before completion. The approval and the
/// ticket are kept as the facts they were accepted on, so the completion
/// checks them again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The email proof.
    pub email: bool,
    /// The accepted approval, if any.
    pub approval: Option<Approval>,
    /// The accepted operator ticket, if any.
    pub ticket: Option<VerifiedTicket>,
    /// A host console command run as root with custody access.
    pub host_console: bool,
}

impl Evidence {
    /// Whether the case may take an approval or an operator ticket: the
    /// email proof comes first (design section 8.5).
    pub const fn may_take_approval_or_ticket(&self) -> bool {
        self.email
    }
}

/// One open recovery case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Case {
    /// The case reference.
    pub case: [u8; 16],
    /// The account to recover.
    pub holder: AccountId,
    /// The path computed at request time. The completion does not trust
    /// it: it recomputes the path.
    pub requested: RecoveryPath,
    /// The evidence so far.
    pub evidence: Evidence,
}

/// Why a recovery completion is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryDeny {
    /// The evidence does not complete the path recomputed at completion.
    PathNotSatisfied(RecoveryPath),
    /// The new passkey gave no user verification, and the path recomputed
    /// at completion requires it ([`RecoveryPath::uv_required`]).
    NoUserVerification(RecoveryPath),
    /// The new passkey did not pass [`new_passkey`]: its registration did
    /// not verify, or its credential id is registered already.
    Passkey(EnrolDeny),
}

/// Whether the evidence completes `path` for case `c`, with `tenant` the
/// tenant admins at completion. An approver must still be a tenant admin
/// at completion, and the approval and the ticket must still pass their
/// checks.
fn completes(path: RecoveryPath, c: &Case, tenant: &TenantView) -> bool {
    let e = &c.evidence;
    match path {
        RecoveryPath::EmailThenPasskey => e.email,
        RecoveryPath::SecondAdmin => {
            e.email
                && e.approval
                    .is_some_and(|a| approve(c.holder, &a).is_ok() && tenant.is_admin(a.approver))
        }
        RecoveryPath::OperatorProcess => {
            e.email && e.ticket.is_some_and(|t| check_ticket(&t, c.case).is_ok())
        }
        RecoveryPath::HostConsole => e.host_console,
    }
}

/// The completion decision (I-79): the path recomputed from the views at
/// completion, when the evidence completes it.
pub fn decide(
    c: &Case,
    roster: &RosterView,
    tenant: &TenantView,
    mode: Deployment,
) -> Result<RecoveryPath, RecoveryDeny> {
    let path = path_for(roster, tenant, c.holder, mode);
    if completes(path, c, tenant) {
        Ok(path)
    } else {
        Err(RecoveryDeny::PathNotSatisfied(path))
    }
}

/// What a completion revokes and enrols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation<'a> {
    /// Every credential id of the account.
    pub credentials: &'a [Vec<u8>],
    /// Every live session of the account.
    pub sessions: &'a [[u8; 16]],
    /// The new passkey, as [`new_passkey`] verified it. UV is required
    /// unless the path is `EmailThenPasskey`, and [`complete`] checks it
    /// again against the path it recomputes.
    pub new_credential: &'a NewCredential,
}

/// The new passkey of a recovery of case `c`: the path recomputed from
/// the views, then [`verify_new_passkey`] with UV required by that path,
/// then [`check_new_id`] against the cell's credential index
/// (WebAuthn Level 2 section 7.1 step 22).
///
/// The shell calls it before [`complete`], with the same views, and
/// passes the result as [`Revocation::new_credential`].
pub fn new_passkey(
    reg: &Registration<'_>,
    c: &Case,
    roster: &RosterView,
    tenant: &TenantView,
    mode: Deployment,
    known: &dyn CredentialIndex,
) -> Result<NewCredential, RecoveryDeny> {
    let path = path_for(roster, tenant, c.holder, mode);
    let cred = verify_new_passkey(reg, path.uv_required()).map_err(RecoveryDeny::Passkey)?;
    check_new_id(&cred, known).map_err(RecoveryDeny::Passkey)?;
    Ok(cred)
}

/// The records of a completion of case `case` for `holder` by `path`
/// (Q15): every credential revoked, every session ended, the new passkey
/// registered and the completion, shown to the tenant for the operator
/// and host console paths.
pub fn completion_records(
    case: [u8; 16],
    holder: AccountId,
    path: RecoveryPath,
    r: &Revocation<'_>,
) -> Vec<AuthRecord> {
    let mut out = Vec::with_capacity(
        r.credentials
            .len()
            .saturating_add(r.sessions.len())
            .saturating_add(2),
    );
    out.extend(r.credentials.iter().map(|c| AuthRecord::CredentialRevoked {
        account: holder,
        credential: c.clone(),
    }));
    out.extend(
        r.sessions
            .iter()
            .map(|s| AuthRecord::SessionEnded { session: *s }),
    );
    out.push(AuthRecord::registration(holder, r.new_credential));
    out.push(AuthRecord::RecoveryCompleted {
        case,
        account: holder,
        path,
        shown_to_tenant: path.shown_to_tenant(),
    });
    out
}

/// Completes a recovery: [`decide`], then the UV rule of the recomputed
/// path on the new passkey, then [`completion_records`].
///
/// The UV rule is checked here as well as in [`new_passkey`]. So a role
/// granted between the two calls cannot let a passkey without UV in.
pub fn complete(
    c: &Case,
    roster: &RosterView,
    tenant: &TenantView,
    mode: Deployment,
    r: &Revocation<'_>,
) -> Result<Vec<AuthRecord>, RecoveryDeny> {
    let path = decide(c, roster, tenant, mode)?;
    if path.uv_required() && !r.new_credential.user_verified {
        return Err(RecoveryDeny::NoUserVerification(path));
    }
    Ok(completion_records(c.case, c.holder, path, r))
}

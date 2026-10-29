//! M-RECOVER (design section 14.2, I-79). Lane W1b owns this file.
//!
//! The universe: accounts admin1, admin2, a (committee member) and b
//! (applicant). Email recovery, approval by a tenant admin with or
//! without a valid step-up and under each vault answer, a committee grant
//! to b racing b's open recovery, an operator ticket in a single-admin SaaS
//! variant and a host console command in a single-admin self-hosted
//! variant.
//!
//! The model runs over a [`RecoverBackend`]: [`Reference`],
//! [`Production`] (`fstp_auth::recovery`) or a [`Mutant`] with one seeded
//! defect. Every decision the model records comes from the backend: the
//! path, the approval and ticket checks, the completion and what the
//! completion did. The properties judge those decisions by the reference.

use fstp_auth::recovery::{self as prod, Deployment, Holdings, RecoveryPath};
use fstp_domain::id::AccountId;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, B};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::reference::auth::{
    self as r, RefAdmin, RefApproval, RefBinding, RefCompletion, RefDeployment, RefEvidence,
    RefHoldings, RefPath, RefRoster, RefTicket,
};

/// The instant of every step of the universe.
pub const NOW: Timestamp = Timestamp::from_micros(4_000_000_000);

/// The accounts, in model order: admin1, admin2, a, b.
pub const ACCOUNTS: [AccountId; 4] = [ADMIN, ADMIN_2, A, B];

/// The index of admin1.
pub const IX_ADMIN1: u8 = 0;
/// The index of admin2.
pub const IX_ADMIN2: u8 = 1;
/// The index of a.
pub const IX_A: u8 = 2;
/// The index of b.
pub const IX_B: u8 = 3;

/// The account at index `i`.
pub fn account(i: u8) -> AccountId {
    ACCOUNTS.get(usize::from(i)).copied().unwrap_or(ADMIN)
}

/// A variant of the universe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Variant {
    /// Two tenant admins, SaaS.
    TwoAdmins,
    /// admin1 is the sole tenant admin, SaaS.
    SoleAdminSaas,
    /// admin1 is the sole tenant admin, self-hosted.
    SoleAdminSelfHosted,
}

impl Variant {
    /// The deployment.
    pub const fn mode(self) -> RefDeployment {
        match self {
            Variant::SoleAdminSelfHosted => RefDeployment::SelfHosted,
            Variant::TwoAdmins | Variant::SoleAdminSaas => RefDeployment::Saas,
        }
    }
}

/// The vault's answer to `SameIdentityAsAny` for an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultAnswer {
    /// Both verified, different identities.
    Distinct,
    /// Both verified, one identity.
    Same,
    /// The vault could not answer, so the cell does not know whether both
    /// are verified either.
    Down,
}

impl VaultAnswer {
    /// Every answer.
    pub const ALL: [VaultAnswer; 3] = [VaultAnswer::Distinct, VaultAnswer::Same, VaultAnswer::Down];

    /// The `(same_identity, both_verified)` facts of the answer.
    pub const fn facts(self) -> (Option<bool>, bool) {
        match self {
            VaultAnswer::Distinct => (Some(false), true),
            VaultAnswer::Same => (Some(true), true),
            VaultAnswer::Down => (None, false),
        }
    }
}

/// The approval of `approver` under `roster`, with or without a valid
/// step-up, under the vault answer `v`.
pub fn approval(
    roster: &RefRoster,
    approver: AccountId,
    stepup_ok: bool,
    v: VaultAnswer,
) -> RefApproval {
    let (same_identity, both_verified) = v.facts();
    RefApproval {
        approver,
        approver_admin: roster.is_admin(approver, NOW),
        stepup_ok,
        same_identity,
        both_verified,
    }
}

/// The operator ticket of the universe, with two staff members or with
/// one staff member twice.
pub const fn ticket(two_staff: bool) -> RefTicket {
    RefTicket {
        staff_1: 1,
        staff_2: if two_staff { 2 } else { 1 },
        case_matches: true,
        signature_ok: true,
    }
}

// ---------------------------------------------------------------------------
// Backends.

/// The decisions M-RECOVER asks of a backend.
pub trait RecoverBackend {
    /// The path at request time.
    fn path(
        &self,
        h: RefHoldings,
        other_admins: usize,
        mode: RefDeployment,
    ) -> Result<RefPath, NotImplemented>;

    /// Whether the approval of `holder`'s recovery is accepted.
    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented>;

    /// Whether an operator ticket is accepted.
    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented>;

    /// The path a completion took, or `None` when it is refused.
    /// `requested` is the path computed at request time.
    fn complete(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        requested: RefPath,
        e: &RefEvidence,
        mode: RefDeployment,
        now: Timestamp,
    ) -> Result<Option<RefPath>, NotImplemented>;

    /// What the completion of `holder`'s recovery by `path` did, as its
    /// records show it.
    ///
    /// The default reports a completion that revoked nothing, ended
    /// nothing and showed nothing. A backend that does not report its
    /// records is no evidence of revocation, so `I-79-shown` fails closed.
    /// [`Reference`], [`Production`] and [`Mutant`] override it.
    fn completion(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        path: RefPath,
        now: Timestamp,
    ) -> Result<RefCompletion, NotImplemented> {
        let _ = (roster, holder, path, now);
        Ok(RefCompletion::NOTHING)
    }
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl RecoverBackend for Reference {
    fn path(
        &self,
        h: RefHoldings,
        other_admins: usize,
        mode: RefDeployment,
    ) -> Result<RefPath, NotImplemented> {
        Ok(r::recovery_path(h, other_admins, mode))
    }

    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        Ok(r::approve_recovery(holder, a).is_ok())
    }

    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        Ok(r::ticket_ok(t))
    }

    fn complete(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        _requested: RefPath,
        e: &RefEvidence,
        mode: RefDeployment,
        now: Timestamp,
    ) -> Result<Option<RefPath>, NotImplemented> {
        Ok(r::complete_recovery(roster, holder, e, mode, now).ok())
    }

    fn completion(
        &self,
        _roster: &RefRoster,
        _holder: AccountId,
        path: RefPath,
        _now: Timestamp,
    ) -> Result<RefCompletion, NotImplemented> {
        Ok(r::completion_of(path))
    }
}

/// The seam of [`Production::approve`]: the stubs have no recovery
/// approval check. Lane W2b adds `ApproveRecovery` (design section 8.5)
/// as a pure check over the approver, the step-up and the vault answer,
/// and this backend then calls it. The harness owns this seam.
pub const APPROVE_SEAM: &str = "fstp_celltest::mc::recover_model::Production::approve: the stubs have no ApproveRecovery check (design section 8.5, lane W2b)";

/// The seam of [`Production::ticket`]: `ApplyOperatorTicket` carries a
/// byte form the stubs do not define, and no ticket check exists. Lane
/// W2b adds the check over a decoded ticket, and this backend then calls
/// it. The harness owns this seam.
pub const TICKET_SEAM: &str = "fstp_celltest::mc::recover_model::Production::ticket: the stubs define no operator ticket form or check (design section 8.5, lane W2b)";

/// The seam of [`Production::complete`] and [`Production::completion`]:
/// `fstp_auth::recovery::complete` takes only a path. It sees neither the
/// roster at completion, the request-time path nor the evidence, so it
/// cannot make the decision of design section 8.5. Its records have no
/// credential revocation and no tenant-visible entry either. Lane W2b
/// widens the API, and this backend then passes the request-time path and
/// the evidence and takes the decision from production. The harness owns
/// this seam.
pub const COMPLETE_SEAM: &str = "fstp_celltest::mc::recover_model::Production::complete: fstp_auth::recovery::complete takes no roster, request-time path or evidence, and its records name no revocation (design section 8.5, lane W2b)";

/// The production backend: `fstp_auth::recovery`.
///
/// Only `recovery_path` exists in the production API. The approval, the
/// ticket and the completion refuse with the named seams
/// [`APPROVE_SEAM`], [`TICKET_SEAM`] and [`COMPLETE_SEAM`]. No reference
/// logic stands in for production.
#[derive(Clone, Copy, Debug)]
pub struct Production {
    _probe: (),
}

/// The production holdings of reference holdings.
pub const fn prod_holdings(h: RefHoldings) -> Holdings {
    match h {
        RefHoldings::ReceivingOnly => Holdings::ReceivingOnly,
        RefHoldings::Management => Holdings::Management,
        RefHoldings::TenantAdmin => Holdings::TenantAdmin,
    }
}

/// The production deployment of a reference deployment.
pub const fn prod_mode(m: RefDeployment) -> Deployment {
    match m {
        RefDeployment::Saas => Deployment::Saas,
        RefDeployment::SelfHosted => Deployment::SelfHosted,
    }
}

/// The reference path of a production path.
pub const fn ref_path(p: RecoveryPath) -> RefPath {
    match p {
        RecoveryPath::EmailThenPasskey => RefPath::EmailThenPasskey,
        RecoveryPath::SecondAdmin => RefPath::SecondAdmin,
        RecoveryPath::OperatorProcess => RefPath::OperatorProcess,
        RecoveryPath::HostConsole => RefPath::HostConsole,
    }
}

/// The production path of a reference path.
pub const fn prod_path(p: RefPath) -> RecoveryPath {
    match p {
        RefPath::EmailThenPasskey => RecoveryPath::EmailThenPasskey,
        RefPath::SecondAdmin => RecoveryPath::SecondAdmin,
        RefPath::OperatorProcess => RecoveryPath::OperatorProcess,
        RefPath::HostConsole => RecoveryPath::HostConsole,
    }
}

fn auth_ni(e: fstp_auth::AuthError) -> NotImplemented {
    match e {
        fstp_auth::AuthError::NotImplemented(op) => NotImplemented::new(op),
    }
}

impl Production {
    /// The production backend, once `recovery_path` answers.
    pub fn new() -> Result<Production, NotImplemented> {
        let p = Production { _probe: () };
        p.path(RefHoldings::ReceivingOnly, 1, RefDeployment::Saas)?;
        Ok(p)
    }
}

impl RecoverBackend for Production {
    fn path(
        &self,
        h: RefHoldings,
        other_admins: usize,
        mode: RefDeployment,
    ) -> Result<RefPath, NotImplemented> {
        prod::recovery_path(prod_holdings(h), other_admins, prod_mode(mode))
            .map(ref_path)
            .map_err(auth_ni)
    }

    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        let _ = (holder, a);
        Err(NotImplemented::new(APPROVE_SEAM))
    }

    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        let _ = t;
        Err(NotImplemented::new(TICKET_SEAM))
    }

    fn complete(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        requested: RefPath,
        e: &RefEvidence,
        mode: RefDeployment,
        now: Timestamp,
    ) -> Result<Option<RefPath>, NotImplemented> {
        let _ = (roster, holder, requested, e, mode, now);
        Err(NotImplemented::new(COMPLETE_SEAM))
    }

    fn completion(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        path: RefPath,
        now: Timestamp,
    ) -> Result<RefCompletion, NotImplemented> {
        let _ = (roster, holder, path, now);
        Err(NotImplemented::new(COMPLETE_SEAM))
    }
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoverDefect {
    /// The path is checked at request time only, never at completion.
    PathCheckedAtRequestOnly,
    /// The approval check ignores the step-up.
    ApprovalIgnoresStepUp,
    /// The ticket check accepts one staff member twice.
    TicketAcceptsOneStaff,
    /// The completion revokes no credential and ends no session.
    CompletionRevokesNothing,
}

/// `inner` with one seeded defect.
#[derive(Clone, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: RecoverDefect,
}

impl<B: RecoverBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: RecoverDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }
}

impl<B: RecoverBackend> RecoverBackend for Mutant<B> {
    fn path(
        &self,
        h: RefHoldings,
        other_admins: usize,
        mode: RefDeployment,
    ) -> Result<RefPath, NotImplemented> {
        self.inner.path(h, other_admins, mode)
    }

    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        if self.defect == RecoverDefect::ApprovalIgnoresStepUp {
            let forged = RefApproval {
                stepup_ok: true,
                ..*a
            };
            return self.inner.approve(holder, &forged);
        }
        self.inner.approve(holder, a)
    }

    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        if self.defect == RecoverDefect::TicketAcceptsOneStaff {
            let forged = RefTicket {
                staff_2: t.staff_1.wrapping_add(1),
                ..*t
            };
            return self.inner.ticket(&forged);
        }
        self.inner.ticket(t)
    }

    fn complete(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        requested: RefPath,
        e: &RefEvidence,
        mode: RefDeployment,
        now: Timestamp,
    ) -> Result<Option<RefPath>, NotImplemented> {
        let got = self
            .inner
            .complete(roster, holder, requested, e, mode, now)?;
        match self.defect {
            RecoverDefect::PathCheckedAtRequestOnly => {
                // The inner backend was asked once, so a stub still halts the run.
                Ok(
                    r::evidence_completes(requested, e, holder, &roster.admins_at(now))
                        .then_some(requested),
                )
            }
            RecoverDefect::ApprovalIgnoresStepUp
            | RecoverDefect::TicketAcceptsOneStaff
            | RecoverDefect::CompletionRevokesNothing => Ok(got),
        }
    }

    fn completion(
        &self,
        roster: &RefRoster,
        holder: AccountId,
        path: RefPath,
        now: Timestamp,
    ) -> Result<RefCompletion, NotImplemented> {
        let got = self.inner.completion(roster, holder, path, now)?;
        if self.defect == RecoverDefect::CompletionRevokesNothing {
            return Ok(RefCompletion {
                credentials_revoked: false,
                sessions_ended: false,
                ..got
            });
        }
        Ok(got)
    }
}

// ---------------------------------------------------------------------------
// The model.

/// One recovery case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Case {
    /// The holder's index.
    pub holder: u8,
    /// The path at request time.
    pub requested: RefPath,
    /// The evidence so far.
    pub evidence: RefEvidence,
    /// Whether the case completed.
    pub completed: bool,
}

/// A completed recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Done {
    /// The holder's index.
    pub holder: u8,
    /// The path the completion took.
    pub path: RefPath,
    /// The evidence it completed with.
    pub evidence: RefEvidence,
    /// What the backend's completion did.
    pub completion: RefCompletion,
}

/// The state of M-RECOVER.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RecoverState {
    /// The variant.
    pub variant: Variant,
    /// Whether b holds a committee binding: the grant that races b's recovery.
    pub b_granted: bool,
    /// The cases, in request order.
    pub cases: Vec<Case>,
    /// The completed recoveries, in order.
    pub done: Vec<Done>,
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

/// The most cases of a run.
pub const MAX_CASES: usize = 2;

impl RecoverState {
    /// The roster now.
    pub fn roster(&self) -> RefRoster {
        let mut roster = RefRoster {
            bindings: vec![RefBinding {
                account: A,
                role: Role::CommitteeMember,
                end: None,
                suspended: false,
                voided: false,
            }],
            admins: vec![RefAdmin {
                account: ADMIN,
                end: None,
            }],
        };
        if self.variant == Variant::TwoAdmins {
            roster.admins.push(RefAdmin {
                account: ADMIN_2,
                end: None,
            });
        }
        if self.b_granted {
            roster.bindings.push(RefBinding {
                account: B,
                role: Role::CommitteeMember,
                end: None,
                suspended: false,
                voided: false,
            });
        }
        roster
    }

    /// The case at index `i`, if it is open.
    pub fn open(&self, i: u8) -> Option<&Case> {
        self.cases.get(usize::from(i)).filter(|c| !c.completed)
    }
}

/// An action of M-RECOVER.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoverAction {
    /// `POST /auth/recovery` for the holder.
    Request(u8),
    /// The email proof of the case.
    Email(u8),
    /// An approval of the case by the approver, with or without a valid
    /// step-up, under a vault answer.
    Approve(u8, u8, bool, VaultAnswer),
    /// An operator ticket for the case, with two staff or with one twice.
    Ticket(u8, bool),
    /// The host console command for the case.
    Console(u8),
    /// The committee grant to b.
    GrantB,
    /// `POST /auth/recovery/{case}/complete`.
    Complete(u8),
}

/// The approvals the universe offers per case: each candidate approver
/// with a valid step-up and distinct identities, then admin2 without a
/// step-up, sharing an identity, and with the vault down.
pub const APPROVALS: [(u8, bool, VaultAnswer); 6] = [
    (IX_ADMIN1, true, VaultAnswer::Distinct),
    (IX_ADMIN2, true, VaultAnswer::Distinct),
    (IX_A, true, VaultAnswer::Distinct),
    (IX_ADMIN2, false, VaultAnswer::Distinct),
    (IX_ADMIN2, true, VaultAnswer::Same),
    (IX_ADMIN2, true, VaultAnswer::Down),
];

/// M-RECOVER over a backend.
#[derive(Clone, Debug)]
pub struct RecoverModel<B> {
    backend: B,
}

impl<B: RecoverBackend> RecoverModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> RecoverModel<B> {
        RecoverModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn evidence_step(
        &self,
        s: &RecoverState,
        i: u8,
        f: impl FnOnce(&Case) -> Result<Option<RefEvidence>, NotImplemented>,
    ) -> Option<RecoverState> {
        let c = *s.open(i)?;
        let mut next = s.clone();
        match f(&c) {
            Err(e) => next.halt = Some(e.operation),
            Ok(None) => return None,
            Ok(Some(e)) => {
                if e == c.evidence {
                    return None;
                }
                if let Some(slot) = next.cases.get_mut(usize::from(i)) {
                    slot.evidence = e;
                }
            }
        }
        Some(next)
    }
}

impl<B: RecoverBackend> Model for RecoverModel<B> {
    type State = RecoverState;
    type Action = RecoverAction;

    fn init(&self) -> Vec<RecoverState> {
        [
            Variant::TwoAdmins,
            Variant::SoleAdminSaas,
            Variant::SoleAdminSelfHosted,
        ]
        .into_iter()
        .map(|variant| RecoverState {
            variant,
            b_granted: false,
            cases: Vec::new(),
            done: Vec::new(),
            halt: None,
        })
        .collect()
    }

    fn actions(&self, s: &RecoverState, out: &mut Vec<RecoverAction>) {
        if s.halt.is_some() {
            return;
        }
        // A request that the model's bounds prune is not offered: no more
        // than MAX_CASES cases, and no second open case of one holder.
        // Design section 8.5 has neither rule, so a request with no step
        // never stands for a refusal by the cell in the I-79 HTTP machine.
        if s.cases.len() < MAX_CASES {
            for h in [IX_ADMIN1, IX_A, IX_B] {
                if !s.cases.iter().any(|c| c.holder == h && !c.completed) {
                    out.push(RecoverAction::Request(h));
                }
            }
        }
        out.push(RecoverAction::GrantB);
        for i in 0..MAX_CASES {
            let Ok(i) = u8::try_from(i) else { continue };
            out.push(RecoverAction::Email(i));
            for (approver, stepup, vault) in APPROVALS {
                out.push(RecoverAction::Approve(i, approver, stepup, vault));
            }
            out.push(RecoverAction::Ticket(i, true));
            out.push(RecoverAction::Ticket(i, false));
            out.push(RecoverAction::Console(i));
            out.push(RecoverAction::Complete(i));
        }
    }

    fn step(&self, s: &RecoverState, a: &RecoverAction) -> Option<RecoverState> {
        let roster = s.roster();
        let mode = s.variant.mode();
        match *a {
            RecoverAction::Request(h) => {
                if s.cases.len() >= MAX_CASES
                    || s.cases.iter().any(|c| c.holder == h && !c.completed)
                {
                    return None;
                }
                let holder = account(h);
                let mut next = s.clone();
                match self.backend.path(
                    roster.holdings(holder, NOW),
                    roster.other_admins(holder, NOW),
                    mode,
                ) {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(requested) => next.cases.push(Case {
                        holder: h,
                        requested,
                        evidence: RefEvidence::default(),
                        completed: false,
                    }),
                }
                Some(next)
            }
            RecoverAction::GrantB => {
                if s.b_granted {
                    return None;
                }
                let mut next = s.clone();
                next.b_granted = true;
                Some(next)
            }
            RecoverAction::Email(i) => self.evidence_step(s, i, |c| {
                Ok(Some(RefEvidence {
                    email: true,
                    ..c.evidence
                }))
            }),
            RecoverAction::Approve(i, approver, stepup_ok, vault) => {
                self.evidence_step(s, i, |c| {
                    if !r::may_take_approval_or_ticket(&c.evidence) {
                        return Ok(None);
                    }
                    let a = approval(&roster, account(approver), stepup_ok, vault);
                    let ok = self.backend.approve(account(c.holder), &a)?;
                    Ok(ok.then_some(RefEvidence {
                        approval: Some(a),
                        ..c.evidence
                    }))
                })
            }
            RecoverAction::Ticket(i, two_staff) => {
                if mode != RefDeployment::Saas {
                    return None;
                }
                self.evidence_step(s, i, |c| {
                    if !r::may_take_approval_or_ticket(&c.evidence) {
                        return Ok(None);
                    }
                    let t = ticket(two_staff);
                    let ok = self.backend.ticket(&t)?;
                    Ok(ok.then_some(RefEvidence {
                        ticket: Some(t),
                        ..c.evidence
                    }))
                })
            }
            RecoverAction::Console(i) => {
                if mode != RefDeployment::SelfHosted {
                    return None;
                }
                self.evidence_step(s, i, |c| {
                    Ok(Some(RefEvidence {
                        host_console: true,
                        ..c.evidence
                    }))
                })
            }
            RecoverAction::Complete(i) => {
                let c = *s.open(i)?;
                let holder = account(c.holder);
                let mut next = s.clone();
                let done = self
                    .backend
                    .complete(&roster, holder, c.requested, &c.evidence, mode, NOW)
                    .and_then(|got| match got {
                        None => Ok(None),
                        Some(path) => self
                            .backend
                            .completion(&roster, holder, path, NOW)
                            .map(|completion| Some((path, completion))),
                    });
                match done {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => return None,
                    Ok(Some((path, completion))) => {
                        if let Some(slot) = next.cases.get_mut(usize::from(i)) {
                            slot.completed = true;
                        }
                        next.done.push(Done {
                            holder: c.holder,
                            path,
                            evidence: c.evidence,
                            completion,
                        });
                    }
                }
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &RecoverState) -> bool {
        s.halt.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-RECOVER.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-79: no account outside Receiving at completion is recovered by
    /// email alone, nor on an approval or ticket that the reference refuses.
    pub const I79: &str = "I-79";
    /// I-79 shown (Q15): a completion revokes every credential and ends
    /// every session, and an operator or console completion is shown to
    /// the tenant. Read from the backend's completion records.
    pub const I79_SHOWN: &str = "I-79-shown";
    /// Two-way: every path, approval, ticket and completion decision
    /// equals the reference's.
    pub const TWO_WAY: &str = "two-way";
    /// Witness: b recovered by email.
    pub const W_B_BY_EMAIL: &str = "witness-b-recovered-by-email";
    /// Witness: a recovered with admin2's approval.
    pub const W_A_BY_ADMIN2: &str = "witness-a-recovered-with-admin2-approval";
    /// Witness: the sole SaaS admin recovered by an operator ticket.
    pub const W_SOLE_TICKET: &str = "witness-sole-admin-recovered-by-operator-ticket";
    /// Witness: the sole self-hosted admin recovered by the host console.
    pub const W_SOLE_CONSOLE: &str = "witness-sole-admin-recovered-by-host-console";
    /// Witness: b's email recovery is open with email proof after the grant.
    pub const W_RACE: &str = "witness-grant-races-open-email-recovery";
}

/// Why the completion `d` breaks I-79 in the state `t` after it.
fn i79_breach(t: &RecoverState, d: &Done) -> Option<String> {
    let roster = t.roster();
    let holder = account(d.holder);
    let outside = roster.holdings(holder, NOW) != RefHoldings::ReceivingOnly;
    if !outside {
        return None;
    }
    let e = d.evidence;
    let approved = e.approval.is_some_and(|a| {
        r::approve_recovery(holder, &a).is_ok() && roster.is_admin(a.approver, NOW)
    });
    let sole = roster.other_admins(holder, NOW) == 0;
    let ticketed = e.ticket.is_some_and(|x| r::ticket_ok(&x));
    let operator = sole && ticketed && t.variant.mode() == RefDeployment::Saas;
    let console = sole && e.host_console && t.variant.mode() == RefDeployment::SelfHosted;
    if (e.email && approved) || (e.email && operator) || console {
        None
    } else {
        Some(format!(
            "I-79: account {} outside Receiving recovered with {e:?}",
            d.holder
        ))
    }
}

/// The two-way check of the approval and ticket decisions in one state:
/// every approval shape the universe can build, for every holder, and
/// every ticket shape.
fn two_way_checks<B: RecoverBackend>(m: &RecoverModel<B>, s: &RecoverState) -> Result<(), String> {
    let roster = s.roster();
    for h in [IX_ADMIN1, IX_ADMIN2, IX_A, IX_B] {
        let holder = account(h);
        for approver in [IX_ADMIN1, IX_ADMIN2, IX_A, IX_B] {
            for stepup in [true, false] {
                for vault in VaultAnswer::ALL {
                    let a = approval(&roster, account(approver), stepup, vault);
                    let want = r::approve_recovery(holder, &a).is_ok();
                    if let Ok(got) = m.backend().approve(holder, &a)
                        && got != want
                    {
                        return Err(format!(
                            "two-way: approval of {h}'s recovery by {approver} ({a:?}) is {got}, reference {want}"
                        ));
                    }
                }
            }
        }
    }
    for t in [
        ticket(true),
        ticket(false),
        RefTicket {
            case_matches: false,
            ..ticket(true)
        },
        RefTicket {
            signature_ok: false,
            ..ticket(true)
        },
    ] {
        let want = r::ticket_ok(&t);
        if let Ok(got) = m.backend().ticket(&t)
            && got != want
        {
            return Err(format!("two-way: ticket {t:?} is {got}, reference {want}"));
        }
    }
    Ok(())
}

/// The two-way check of one state.
fn two_way<B: RecoverBackend>(m: &RecoverModel<B>, s: &RecoverState) -> Result<(), String> {
    let roster = s.roster();
    let mode = s.variant.mode();
    for h in [IX_ADMIN1, IX_ADMIN2, IX_A, IX_B] {
        let holder = account(h);
        let hold = roster.holdings(holder, NOW);
        let others = roster.other_admins(holder, NOW);
        let want = r::recovery_path(hold, others, mode);
        if let Ok(got) = m.backend().path(hold, others, mode)
            && got != want
        {
            return Err(format!(
                "two-way: path of {h} is {got:?}, reference {want:?}"
            ));
        }
    }
    two_way_checks(m, s)?;
    for c in s.cases.iter().filter(|c| !c.completed) {
        let holder = account(c.holder);
        let want = r::complete_recovery(&roster, holder, &c.evidence, mode, NOW).ok();
        if let Ok(got) = m
            .backend()
            .complete(&roster, holder, c.requested, &c.evidence, mode, NOW)
            && got != want
        {
            return Err(format!(
                "two-way: completion of {c:?} is {got:?}, reference {want:?}"
            ));
        }
    }
    Ok(())
}

/// Every property of M-RECOVER.
pub fn properties<'a, B: RecoverBackend>(
    m: &'a RecoverModel<B>,
) -> Vec<Property<'a, RecoverModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &RecoverState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::transition_with(
            ids::I79,
            |s: &RecoverState, _a: &RecoverAction, t: &RecoverState| {
                if t.done.len() <= s.done.len() {
                    return Ok(());
                }
                match t.done.last().and_then(|d| i79_breach(t, d)) {
                    None => Ok(()),
                    Some(why) => Err(why),
                }
            },
        ),
        Property::always_with(ids::I79_SHOWN, |s: &RecoverState| {
            match s
                .done
                .iter()
                .find(|d| !r::completion_ok(d.path, &d.completion))
            {
                None => Ok(()),
                Some(d) => Err(format!(
                    "I-79-shown: completion {d:?} did not revoke everything or was not shown"
                )),
            }
        }),
        Property::always_with(ids::TWO_WAY, move |s: &RecoverState| two_way(m, s)),
        Property::reachable(ids::W_B_BY_EMAIL, |s: &RecoverState| {
            s.done
                .iter()
                .any(|d| d.holder == IX_B && d.path == RefPath::EmailThenPasskey)
        }),
        Property::reachable(ids::W_A_BY_ADMIN2, |s: &RecoverState| {
            s.done.iter().any(|d| {
                d.holder == IX_A && d.evidence.approval.is_some_and(|a| a.approver == ADMIN_2)
            })
        }),
        Property::reachable(ids::W_SOLE_TICKET, |s: &RecoverState| {
            s.done
                .iter()
                .any(|d| d.holder == IX_ADMIN1 && d.path == RefPath::OperatorProcess)
        }),
        Property::reachable(ids::W_SOLE_CONSOLE, |s: &RecoverState| {
            s.done
                .iter()
                .any(|d| d.holder == IX_ADMIN1 && d.path == RefPath::HostConsole)
        }),
        Property::reachable(ids::W_RACE, |s: &RecoverState| {
            s.b_granted
                && s.cases.iter().any(|c| {
                    c.holder == IX_B
                        && !c.completed
                        && c.requested == RefPath::EmailThenPasskey
                        && c.evidence.email
                })
        }),
    ]
}

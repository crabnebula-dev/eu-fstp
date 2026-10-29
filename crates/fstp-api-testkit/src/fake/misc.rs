//! The smaller fakes: accounts, the pre-check provider, the recovery and
//! break-glass approvals, the prober, the tenant configuration and the
//! outbox.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    Accounts, ApprovalId, BreakGlass, BreakGlassId, DisplayHandle, InvitationLink, InviteKind,
    NoticePage, Outbox, Page, PortError, Precheck, ProbeKind, ProbeOutcome, Prober, Recovery,
    RecoveryId, SecondAdminApproval, StepUpProof, StepUpRef, TenantConfig, TenantSettings,
};
use fstp_domain::id::AccountId;

use super::lock;

/// Invitations and pseudonymous display handles. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeAccounts {
    invited: Arc<Mutex<usize>>,
}

impl FakeAccounts {
    /// How many invitations were made.
    pub fn invited(&self) -> usize {
        *lock(&self.invited)
    }
}

impl Accounts for FakeAccounts {
    async fn invite(&self, kind: InviteKind) -> Result<InvitationLink, PortError> {
        let _ = kind;
        let mut n = lock(&self.invited);
        *n = n.saturating_add(1);
        Ok(InvitationLink(format!("/fake/invitations/{n}")))
    }

    /// A handle made from the raw account id, never an email.
    async fn display_handle(&self, a: AccountId) -> Result<DisplayHandle, PortError> {
        Ok(DisplayHandle(format!("person-{:x}", a.raw())))
    }
}

/// The e2e cell's pre-check provider. M7 defines its methods (Q38).
#[derive(Clone, Copy, Debug, Default)]
pub struct FakePrecheck;

impl Precheck for FakePrecheck {}

/// Records every recovery approval. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeRecovery {
    approvals: Arc<Mutex<Vec<(AccountId, RecoveryId, StepUpRef)>>>,
}

impl FakeRecovery {
    /// Every approval: approver, case and the step-up it consumed.
    pub fn approvals(&self) -> Vec<(AccountId, RecoveryId, StepUpRef)> {
        lock(&self.approvals).clone()
    }
}

impl Recovery for FakeRecovery {
    async fn approve(
        &self,
        approver: AccountId,
        r: RecoveryId,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        lock(&self.approvals).push((approver, r, proof.step_up));
        Ok(())
    }
}

/// One break-glass decision: approver, request, verdict and step-up.
pub type Decision = (AccountId, BreakGlassId, bool, StepUpRef);

/// Records every break-glass decision. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeBreakGlass {
    decisions: Arc<Mutex<Vec<Decision>>>,
}

impl FakeBreakGlass {
    /// Every decision: approver, request, verdict and the step-up.
    pub fn decisions(&self) -> Vec<Decision> {
        lock(&self.decisions).clone()
    }
}

impl BreakGlass for FakeBreakGlass {
    async fn decide(
        &self,
        approver: AccountId,
        b: BreakGlassId,
        approve: bool,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        lock(&self.decisions).push((approver, b, approve, proof.step_up));
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Probes {
    outcomes: BTreeMap<ProbeKind, ProbeOutcome>,
    seen: Vec<ProbeKind>,
}

/// A recording prober (`test-plan.md`: recording fakes for channels).
/// Every probe passes unless a test sets its outcome. Cloning shares it.
#[derive(Clone, Debug, Default)]
pub struct FakeProber {
    state: Arc<Mutex<Probes>>,
}

impl FakeProber {
    /// Sets the outcome of every later probe of `kind`.
    pub fn set(&self, kind: ProbeKind, outcome: ProbeOutcome) {
        lock(&self.state).outcomes.insert(kind, outcome);
    }

    /// Every probe run, in order.
    pub fn seen(&self) -> Vec<ProbeKind> {
        lock(&self.state).seen.clone()
    }
}

impl Prober for FakeProber {
    async fn probe(&self, p: ProbeKind) -> ProbeOutcome {
        let mut s = lock(&self.state);
        s.seen.push(p);
        s.outcomes.get(&p).copied().unwrap_or(ProbeOutcome::Pass)
    }
}

/// The tenant configuration: the attested admin set and the second-admin
/// approvals (Q31). Cloning shares them.
#[derive(Clone)]
pub struct FakeTenant {
    settings: Arc<TenantSettings>,
    admins: Arc<Mutex<BTreeSet<AccountId>>>,
    approvals: Arc<Mutex<BTreeMap<ApprovalId, SecondAdminApproval>>>,
}

impl std::fmt::Debug for FakeTenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTenant")
            .field("admins", &*lock(&self.admins))
            .finish_non_exhaustive()
    }
}

impl FakeTenant {
    /// The configuration with `settings` and the admin set `admins`.
    pub fn new(settings: Arc<TenantSettings>, admins: BTreeSet<AccountId>) -> FakeTenant {
        FakeTenant {
            settings,
            admins: Arc::new(Mutex::new(admins)),
            approvals: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Whether the attested admin set holds `a`.
    pub fn holds_admin(&self, a: AccountId) -> bool {
        lock(&self.admins).contains(&a)
    }

    /// Records a second-admin approval (SoD-07).
    pub fn record_approval(&self, approval: SecondAdminApproval) {
        lock(&self.approvals).insert(approval.approval, approval);
    }
}

impl TenantConfig for FakeTenant {
    fn settings(&self) -> Arc<TenantSettings> {
        self.settings.clone()
    }

    fn is_tenant_admin(&self, a: AccountId) -> bool {
        self.holds_admin(a)
    }

    async fn approval(&self, id: ApprovalId) -> Result<SecondAdminApproval, PortError> {
        lock(&self.approvals)
            .get(&id)
            .copied()
            .ok_or(PortError::Refused)
    }
}

/// The in-app notice list. Cloning shares it.
#[derive(Clone)]
pub struct FakeOutbox {
    notices: Arc<dyn Fn(AccountId, Page) -> NoticePage + Send + Sync>,
}

impl std::fmt::Debug for FakeOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeOutbox(..)")
    }
}

impl FakeOutbox {
    /// The outbox whose pages `notices` builds.
    pub fn new(notices: Arc<dyn Fn(AccountId, Page) -> NoticePage + Send + Sync>) -> FakeOutbox {
        FakeOutbox { notices }
    }
}

impl Outbox for FakeOutbox {
    fn notices(&self, a: AccountId, page: Page) -> NoticePage {
        (self.notices)(a, page)
    }
}

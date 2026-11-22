//! The smaller fakes: accounts, the pre-check provider, the recovery and
//! break-glass approvals, the prober, the tenant configuration and the
//! outbox.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    Accounts, ApprovalId, BreakGlass, BreakGlassId, DisplayHandle, InvitationLink, InviteKind,
    NoticePage, Outbox, Page, PortError, ProbeKind, ProbeOutcome, Prober, Recovery, RecoveryId,
    SecondAdminApproval, StepUpProof, StepUpRef, TenantConfig, TenantSettings,
};
use fstp_domain::id::AccountId;

use super::lock;

/// Invitations and pseudonymous display handles. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeAccounts {
    invited: Arc<Mutex<usize>>,
    names: Arc<Mutex<BTreeMap<AccountId, String>>>,
    /// Every invitation M3 received, oldest first (lane inv).
    kinds: Arc<Mutex<Vec<InviteKind>>>,
    /// The login email index of the cell, by account (SA-11).
    logins: Arc<Mutex<BTreeMap<AccountId, String>>>,
    /// The flagging events of disabled passkeys (ADR-008, 2026-11-19).
    disabled: Arc<Mutex<Vec<(AccountId, u64)>>>,
}

impl FakeAccounts {
    /// Sets the disabled passkeys the port lists: owner and ordinal.
    pub fn set_disabled_passkeys(&self, flags: Vec<(AccountId, u64)>) {
        *lock(&self.disabled) = flags;
    }

    /// How many invitations were made.
    pub fn invited(&self) -> usize {
        *lock(&self.invited)
    }

    /// Every invitation M3 received, oldest first, with its email and
    /// link token (J2, lane inv). Only M3 sees these, so a test reads the
    /// token here, never from a reply or the ledger.
    pub fn invitations(&self) -> Vec<InviteKind> {
        lock(&self.kinds).clone()
    }

    /// The link token, in its link spelling, of the newest invitation M3
    /// received for `email`.
    pub fn token_for(&self, email: &str) -> Option<String> {
        lock(&self.kinds).iter().rev().find_map(|k| match k {
            InviteKind::ProgrammeRole {
                email: e, token, ..
            } if e == email => Some(token.hex()),
            InviteKind::ProgrammeRole { .. } | InviteKind::TenantAdmin { .. } => None,
        })
    }

    /// Gives `a` the pseudonymous display handle `handle`, such as the
    /// synthetic label of a committee member. Never an email.
    pub fn name(&self, a: AccountId, handle: &str) {
        lock(&self.names).insert(a, handle.to_owned());
    }

    /// Records `email` as the login email of `a`, as the cell's login
    /// email index holds it (SA-11). Synthetic addresses only.
    pub fn set_login_email(&self, a: AccountId, email: &str) {
        lock(&self.logins).insert(a, email.to_owned());
    }

    /// The name [`FakeAccounts::name`] gave `a`, if any. Only the demo
    /// vault page reads it, on the vault origin (ADR-023).
    pub fn name_of(&self, a: AccountId) -> Option<String> {
        lock(&self.names).get(&a).cloned()
    }
}

impl Accounts for FakeAccounts {
    /// Records the invitation as M3 would before mailing it, and answers
    /// the landing link `/app/invitation#<token>` (J2).
    async fn invite(&self, kind: InviteKind) -> Result<InvitationLink, PortError> {
        let link = match &kind {
            InviteKind::ProgrammeRole { token, .. } => {
                format!("/app/invitation#{}", token.hex())
            }
            // SoD-07, ADR-026 record of lane L18: the M3 enrolment page.
            InviteKind::TenantAdmin { token, .. } => format!("/auth/invite#{}", token.hex()),
        };
        lock(&self.kinds).push(kind);
        let mut n = lock(&self.invited);
        *n = n.saturating_add(1);
        Ok(InvitationLink(link))
    }

    /// The handle given by [`FakeAccounts::name`], else one made from the
    /// raw account id. Never an email.
    async fn display_handle(&self, a: AccountId) -> Result<DisplayHandle, PortError> {
        if let Some(n) = lock(&self.names).get(&a) {
            return Ok(DisplayHandle(n.clone()));
        }
        Ok(DisplayHandle(format!("person-{:x}", a.raw())))
    }

    /// The login email [`FakeAccounts::set_login_email`] recorded.
    async fn login_email(&self, a: AccountId) -> Result<Option<String>, PortError> {
        Ok(lock(&self.logins).get(&a).cloned())
    }

    /// The events [`FakeAccounts::set_disabled_passkeys`] set.
    fn disabled_passkeys(&self) -> Vec<(AccountId, u64)> {
        lock(&self.disabled).clone()
    }
}

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
    absent: BTreeSet<ProbeKind>,
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
        let mut s = lock(&self.state);
        s.outcomes.insert(kind, outcome);
        s.absent.remove(&kind);
    }

    /// Marks the probe of `kind` as absent: no prober exists for it (Q5).
    /// The creator environment then reports it absent. `set` clears it.
    pub fn set_absent(&self, kind: ProbeKind) {
        lock(&self.state).absent.insert(kind);
    }

    /// Whether the probe of `kind` is absent.
    pub fn is_absent(&self, kind: ProbeKind) -> bool {
        lock(&self.state).absent.contains(&kind)
    }

    /// Every probe run, in order.
    pub fn seen(&self) -> Vec<ProbeKind> {
        lock(&self.state).seen.clone()
    }

    /// Runs one probe now and records it, as `Prober::probe` does. The
    /// engine port's creator environment, which is synchronous, runs the
    /// probes of an approval here (design 3.2 "Fresh probes").
    pub fn run(&self, p: ProbeKind) -> ProbeOutcome {
        let mut s = lock(&self.state);
        s.seen.push(p);
        s.outcomes.get(&p).copied().unwrap_or(ProbeOutcome::Pass)
    }

    /// The outcome the next probe of `p` would give, without running it.
    pub fn outcome(&self, p: ProbeKind) -> ProbeOutcome {
        lock(&self.state)
            .outcomes
            .get(&p)
            .copied()
            .unwrap_or(ProbeOutcome::Pass)
    }
}

impl Prober for FakeProber {
    async fn probe(&self, p: ProbeKind) -> ProbeOutcome {
        self.run(p)
    }
}

/// The tenant configuration: the attested admin set and the second-admin
/// approvals (Q31). Cloning shares them.
#[derive(Clone)]
pub struct FakeTenant {
    settings: Arc<TenantSettings>,
    admins: Arc<Mutex<BTreeSet<AccountId>>>,
    approvals: Arc<Mutex<BTreeMap<ApprovalId, SecondAdminApproval>>>,
    /// The port's answer whether the organisation is activated, for a
    /// cell whose ledger holds no tenant part (ADR-021). Shared by clones.
    active: Arc<std::sync::atomic::AtomicBool>,
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
            active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Sets the port's answer whether the organisation is activated, for
    /// a cell whose ledger holds no tenant part (ADR-021). A new port
    /// answers yes: it stands for the attested tenant of the worlds from
    /// before the tenant part, as its attested admin set does. The e2e
    /// cell sets it to no, so a scene must activate through onboarding.
    pub fn set_organisation_active(&self, active: bool) {
        self.active
            .store(active, std::sync::atomic::Ordering::SeqCst);
    }

    /// The attested admin set.
    pub fn admins(&self) -> BTreeSet<AccountId> {
        lock(&self.admins).clone()
    }

    /// The shared attested admin set, which the engine port's creator
    /// environment reads (`shell.rs`).
    pub fn admin_set(&self) -> Arc<Mutex<BTreeSet<AccountId>>> {
        self.admins.clone()
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

    fn organisation_active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::SeqCst)
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

    /// The fake cell has no delivery log yet (M6 lane L6-DEMO wires the
    /// sink), so the log is empty.
    fn deliveries(
        &self,
        _page: Page,
    ) -> impl std::future::Future<
        Output = Result<Vec<fstp_api_core::views::DeliveryRow>, fstp_api_core::port::PortError>,
    > + Send {
        std::future::ready(Ok(Vec::new()))
    }

    /// The fake cell runs no timeline yet (lane L6-DEMO), so it is empty.
    fn timeline(
        &self,
        _programme: fstp_domain::id::ProgrammeId,
    ) -> impl std::future::Future<
        Output = Result<Vec<fstp_api_core::views::TimelineRow>, fstp_api_core::port::PortError>,
    > + Send {
        std::future::ready(Ok(Vec::new()))
    }
}

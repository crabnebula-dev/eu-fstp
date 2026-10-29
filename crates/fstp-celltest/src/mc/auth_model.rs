//! M-AUTH (design section 14.2, I-77). Lane W1b owns this file.
//!
//! The universe: accounts a, b, admin1 and admin2. Passkeys and magic
//! links. Grants and ends of committee member (a) and finance approver
//! (b), one tenant admin grant (admin2), one scheduled end with ticks one
//! microsecond before and after its instant, two logins each, and one
//! credential revocation (a's passkey).
//!
//! The universe also holds one conflict-of-interest suspension of a's
//! committee binding (I-06), which ends a's sessions and still holds
//! (design sections 5.1 and 8.2).
//!
//! The model runs over an [`AuthBackend`]. [`Reference`] answers from
//! `reference::auth`. [`Production`] drives `fstp-auth` for logins, and
//! `fstp-cell-core` from genesis through [`ProdCell`] for holdings,
//! sessions (`gate::admit` over the cell roster) and the batches of roster
//! changes. [`Mutant`] seeds one defect into another backend for the
//! teeth tests. Every property reads the reference rules, and every batch
//! a backend records is compared with the reference's, so a backend
//! defect shows as a property failure.
//!
//! A backend that answers `NotImplemented` halts the run in a state that
//! only the `backend-answers` property reports. No I-77 property counts a
//! stub refusal as a pass or as a violation.
//!
//! This file also holds [`ProdCell`], the production cell driver from
//! genesis that M-STEPUP, M-RECOVER and the I-77 to I-79 tests share.

use fstp_auth::SessionView;
use fstp_auth::{AuthCommand, EnabledMethods, LoginDeny, Method, SessionLifetimes};
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, ReadAction};
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellRefusal, CellState, FoldError};
use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::oracle::Answers;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, ADMIN, ADMIN_2, B, P1, SodSetup, Step, T0, add_staff, end, grant, grant_until,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::reference::auth::{
    self as r, RefAdmin, RefBinding, RefEnabled, RefLifetimes, RefMethod, RefRoster, RefSession,
};

// ---------------------------------------------------------------------------
// The production cell driver.

/// Why the production cell did not run a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProdError {
    /// A production operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
    /// Production refused the command. The text is its refusal.
    Refused(String),
}

impl From<NotImplemented> for ProdError {
    fn from(e: NotImplemented) -> ProdError {
        ProdError::NotImplemented(e.operation)
    }
}

impl std::fmt::Display for ProdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProdError::NotImplemented(op) => {
                write!(f, "{op} is not implemented yet (NotImplemented)")
            }
            ProdError::Refused(why) => write!(f, "production refused: {why}"),
        }
    }
}

fn refusal(e: CellRefusal) -> ProdError {
    match e {
        CellRefusal::NotImplemented(op) => ProdError::NotImplemented(op),
        CellRefusal::Domain(d) => ProdError::Refused(format!("{d:?}")),
    }
}

fn fold(e: FoldError) -> ProdError {
    match e {
        FoldError::NotImplemented(op) => ProdError::NotImplemented(op),
        FoldError::Engine(f) => ProdError::Refused(format!("fold: {f:?}")),
    }
}

/// The synthetic vault of the auth models: staff, a and b, each with its
/// own verified identity. No pair shares an identity.
pub fn auth_truth() -> GroundTruth {
    let mut truth = GroundTruth::new();
    add_staff(&mut truth);
    truth.set_identity(A, IdentityTag::new(1_101));
    truth.set_identity(B, IdentityTag::new(1_102));
    truth.verify(A);
    truth.verify(B);
    truth
}

/// The operation a [`ProdCell`] cannot run yet: building the
/// `fstp_ledger::Entry` values that `fstp_cell_core::apply` folds.
/// `fstp-celltest` has no `fstp-ledger` dependency, and only the lead
/// edits its manifest (lane W1b gap).
pub const FOLD_SEAM: &str =
    "ProdCell::fold: fstp-celltest has no fstp-ledger dependency to build Entry<CellRecord> (lead)";

/// The seam of [`ProdCell::suspend_for_conflict`]: a conflict-of-interest
/// suspension is the vault reaction `VaultChanged`, a system command.
/// `CellCtx` carries an account actor only, and the reaction's facts need
/// the vault seeding of design section 6.9 (lanes W2c and W2d). The
/// harness owns this seam.
pub const SUSPEND_SEAM: &str = "fstp_celltest::mc::auth_model::ProdCell::suspend_for_conflict: CellCtx has no system actor for the VaultChanged reaction that suspends a binding (design sections 5.1 and 6.9, lanes W2c and W2d)";

/// The seam of [`ProdCell::open_session`] and of every production batch
/// that must name sessions: sessions are operational rows, not ledger
/// records (design section 4.2), and `decide` sees no session list. So a
/// production batch cannot name the sessions it ends (lane W2c). The
/// harness owns this seam.
pub const SESSIONS_SEAM: &str = "fstp_celltest::mc::auth_model::ProdCell::open_session: fstp_cell_core::decide sees no session rows, so a batch cannot name the sessions it ends (design sections 4.2 and 5.1, lane W2c)";

/// The seam of a production session check under lifetimes other than the
/// P-72 defaults, closed by lane W2c: the gate reads P-72 from the tenant
/// fold, whose form is `fstp_cell_core::tenant::TenantLoginPolicy`.
/// [`Production::session_in`] sets the lifetimes with `SetLoginPolicy` by
/// the tenant admin. The constant stays for the suites that name it.
pub const P72_SEAM: &str = "fstp_celltest::mc::auth_model::Production::session_in: the gate reads P-72 from the tenant fold, whose login policy form is not defined (lane W2c)";

/// The credential id the auth models give device `device` of `account`.
pub fn credential_of(account: AccountId, device: u8) -> Vec<u8> {
    let raw = account.raw().to_be_bytes();
    let mut out = vec![0x5E, device];
    out.extend_from_slice(&raw);
    out
}

/// One batch a [`ProdCell`] appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appended {
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The records.
    pub batch: Vec<CellRecord>,
}

/// A production cell from genesis: `fstp_cell_core::replay` of an empty
/// ledger, then `queries`, `decide`, an append and `apply` for each
/// command. No state is built by hand (design section 14.1).
#[derive(Clone, Debug)]
pub struct ProdCell {
    log: Vec<Appended>,
    state: CellState,
    truth: GroundTruth,
    drawn: u128,
}

impl ProdCell {
    /// The empty cell over `truth`.
    pub fn genesis(truth: GroundTruth) -> Result<ProdCell, ProdError> {
        let state = fstp_cell_core::replay(&[]).map_err(fold)?;
        Ok(ProdCell {
            log: Vec::new(),
            state,
            truth,
            drawn: 0,
        })
    }

    /// The cell with tenant admin `ADMIN` and programme `P1` with its
    /// staff, as `SodSetup::one` builds it.
    ///
    /// Gap: the stubs have no first-admin enrolment command, so the
    /// first `GrantTenantAdmin` is run by `ADMIN` itself.
    pub fn bootstrapped() -> Result<ProdCell, ProdError> {
        let mut cell = ProdCell::genesis(auth_truth())?;
        let t = fstp_domain_testkit::r#gen::roster::T0;
        cell.exec_tenant_admin_grant(ADMIN, ADMIN, t)?;
        let steps = SodSetup::one(2, &[]).steps().map_err(ProdError::Refused)?;
        for s in steps {
            cell.exec_step(&s, t)?;
        }
        Ok(cell)
    }

    /// The folded state.
    pub fn state(&self) -> &CellState {
        &self.state
    }

    /// Every batch appended, in order.
    pub fn log(&self) -> &[Appended] {
        &self.log
    }

    /// The next command id: a counter, so ids never repeat.
    pub fn draw(&mut self) -> [u8; 16] {
        self.drawn = self.drawn.saturating_add(1);
        self.drawn.to_be_bytes()
    }

    /// Runs `cmd` by `actor` at `at` and returns the batch it appended.
    pub fn exec(
        &mut self,
        cmd: CellCommand,
        actor: AccountId,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        self.run(cmd, actor, at, None)
    }

    /// Runs `cmd` by `actor` at `at` under the command id `command`, and
    /// returns the batch it appended. A digest bound to a command id, such
    /// as the SoD-07 grant digest, needs the id known in advance.
    ///
    /// Gap: `CellCtx` carries no command id, so `decide` cannot see it
    /// yet (lane W2c). The id still names the appended batch.
    pub fn exec_with_id(
        &mut self,
        cmd: CellCommand,
        actor: AccountId,
        at: Timestamp,
        command: [u8; 16],
    ) -> Result<Vec<CellRecord>, ProdError> {
        self.run(cmd, actor, at, Some(command))
    }

    fn run(
        &mut self,
        cmd: CellCommand,
        actor: AccountId,
        at: Timestamp,
        id: Option<[u8; 16]>,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let x = CellCtx {
            actor,
            at: at.micros(),
        };
        let qs = fstp_cell_core::queries(&self.state, &cmd, &x).map_err(refusal)?;
        let mut answers = Answers::new();
        for q in qs {
            let a = self.truth.answer(&q);
            answers.insert(q, a);
        }
        let batch = fstp_cell_core::decide(&self.state, &cmd, &x, &answers).map_err(refusal)?;
        if batch.is_empty() {
            return Ok(batch);
        }
        let command = match id {
            Some(c) => c,
            None => self.draw(),
        };
        self.fold(at, command, &batch)?;
        self.log.push(Appended {
            at: at.micros(),
            command,
            batch: batch.clone(),
        });
        Ok(batch)
    }

    /// Appends `batch` and folds it into the state. A seam until the lead
    /// adds `fstp-ledger` to this crate: it refuses with [`FOLD_SEAM`].
    fn fold(
        &mut self,
        at: Timestamp,
        command: [u8; 16],
        batch: &[CellRecord],
    ) -> Result<(), ProdError> {
        let _ = (at, command, batch, &mut self.state);
        Err(ProdError::NotImplemented(FOLD_SEAM))
    }

    /// Runs an M2 roster step of `fstp-domain-testkit` as a cell command.
    pub fn exec_step(&mut self, s: &Step, at: Timestamp) -> Result<Vec<CellRecord>, ProdError> {
        let actor = match s.actor {
            Actor::Account(a) => a,
            Actor::System(_) => {
                return Err(ProdError::Refused(
                    "a system step has no account".to_owned(),
                ));
            }
        };
        let cmd = CellCommand::Engine(fstp_engine::Command::Core(s.cmd.clone()));
        self.exec(cmd, actor, at)
    }

    /// Runs `GrantTenantAdmin` of `account` by `actor`.
    pub fn exec_tenant_admin_grant(
        &mut self,
        actor: AccountId,
        account: AccountId,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let cmd = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin {
            account,
        });
        self.exec(cmd, actor, at)
    }

    /// Suspends `account`'s binding `binding` for a conflict of interest
    /// at `at`, as the vault reaction does (I-06), and returns the batch.
    /// Refuses with [`SUSPEND_SEAM`] until the cell can run the reaction.
    pub fn suspend_for_conflict(
        &mut self,
        account: AccountId,
        binding: BindingId,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let _ = (account, binding, at, &mut self.state);
        Err(ProdError::NotImplemented(SUSPEND_SEAM))
    }

    /// Opens session `s` in the cell, as a login does, so that later
    /// batches can end it. Refuses with [`SESSIONS_SEAM`] until `decide`
    /// sees session rows.
    pub fn open_session(&mut self, s: &SessionView) -> Result<(), ProdError> {
        let _ = (s, &mut self.state);
        Err(ProdError::NotImplemented(SESSIONS_SEAM))
    }
}

/// The session ids that `SessionEnded` records of `batch` name.
pub fn sessions_ended_in(batch: &[CellRecord]) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = batch
        .iter()
        .filter_map(|r| match r {
            CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }) => Some(*session),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// The production method of a reference method.
pub const fn prod_method(m: RefMethod) -> Method {
    match m {
        RefMethod::Passkey => Method::Passkey,
        RefMethod::EudiWallet => Method::EudiWallet,
        RefMethod::Opaque => Method::Opaque,
        RefMethod::MagicLink => Method::MagicLink,
    }
}

/// The production methods a reference tenant setting enables.
pub fn prod_enabled(e: RefEnabled) -> EnabledMethods {
    let mut methods = vec![Method::Passkey];
    if e.magic_link {
        methods.push(Method::MagicLink);
    }
    if e.eudi_wallet {
        methods.push(Method::EudiWallet);
    }
    if e.opaque {
        methods.push(Method::Opaque);
    }
    EnabledMethods { methods }
}

/// The production session view of a reference session.
pub fn prod_session(s: &RefSession) -> SessionView {
    SessionView {
        id: s.id,
        account: s.account,
        method: prod_method(s.method),
        started: s.started,
        last_used: s.last_used,
    }
}

/// The production lifetimes of reference lifetimes.
pub const fn prod_lifetimes(p: RefLifetimes) -> SessionLifetimes {
    SessionLifetimes {
        idle_us: p.idle_us,
        absolute_us: p.absolute_us,
    }
}

// ---------------------------------------------------------------------------
// Backends.

/// A roster change of M-AUTH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RosterChange {
    /// Grant `role` to `account`, with an optional scheduled end.
    Grant {
        /// The account.
        account: AccountId,
        /// The role.
        role: Role,
        /// The scheduled end.
        until: Option<Timestamp>,
    },
    /// End `account`'s binding of `role` now.
    End {
        /// The account.
        account: AccountId,
        /// The role.
        role: Role,
    },
    /// Grant the tenant admin role to `account`.
    GrantAdmin {
        /// The account.
        account: AccountId,
    },
}

/// The decisions M-AUTH asks of a backend.
pub trait AuthBackend {
    /// Whether `a` holds a management role at `now`.
    fn holds(
        &self,
        roster: &RefRoster,
        a: AccountId,
        now: Timestamp,
    ) -> Result<bool, NotImplemented>;

    /// Whether a login of a holder (`holds`) with `m` is admitted. M-AUTH
    /// logins give user verification.
    fn login(&self, holds: bool, m: RefMethod, enabled: RefEnabled)
    -> Result<bool, NotImplemented>;

    /// Whether session `s` is admitted at `now`, given the holding and
    /// the binding-end fact already evaluated.
    fn session(
        &self,
        holds: bool,
        s: &RefSession,
        binding_ended: bool,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented>;

    /// The sessions the batch of `change` ends. `None` when the backend
    /// refuses the change.
    fn batch_ends(
        &self,
        change: RosterChange,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented>;

    /// Whether session `s` is admitted at `now` under `roster`. The model
    /// asks this one. The default evaluates the holding and the binding
    /// end by the reference and asks [`AuthBackend::session`].
    /// [`Production`] overrides it to ask the gate over the cell roster.
    fn session_in(
        &self,
        roster: &RefRoster,
        s: &RefSession,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        let holds = roster.holds_management(s.account, now);
        let ended = roster.binding_ended_between(s.account, s.started, now);
        self.session(holds, s, ended, now, p72)
    }

    /// The sessions the vault reaction ends that suspends `account`'s
    /// binding of `role` for a conflict of interest (I-06, design section
    /// 5.1). `None` when the backend refuses it. The default is the
    /// reference rule; [`Production`] and [`Mutant`] override it.
    fn suspension_ends(
        &self,
        account: AccountId,
        role: Role,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        Reference.suspension_ends(account, role, before, sessions, now)
    }

    /// The sessions the batch that revokes `account`'s credential on
    /// `device` ends. `None` when the backend refuses it. The default is
    /// the reference rule; [`Production`] and [`Mutant`] override it.
    fn revocation_ends(
        &self,
        account: AccountId,
        device: u8,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        Reference.revocation_ends(account, device, before, sessions, now)
    }
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

fn sorted(mut ids: Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    ids.sort();
    ids.dedup();
    ids
}

impl AuthBackend for Reference {
    fn holds(
        &self,
        roster: &RefRoster,
        a: AccountId,
        now: Timestamp,
    ) -> Result<bool, NotImplemented> {
        Ok(roster.holds_management(a, now))
    }

    fn login(
        &self,
        holds: bool,
        m: RefMethod,
        enabled: RefEnabled,
    ) -> Result<bool, NotImplemented> {
        Ok(r::admit_login(holds, m, true, enabled).is_ok())
    }

    fn session(
        &self,
        holds: bool,
        s: &RefSession,
        binding_ended: bool,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        Ok(r::admit_session(holds, s, binding_ended, now, p72).is_ok())
    }

    fn batch_ends(
        &self,
        change: RosterChange,
        _before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let out = match change {
            RosterChange::Grant { account, role, .. } if r::is_management_role(role) => {
                r::ended_by_grant(sessions, account, now)
            }
            RosterChange::Grant { .. } => Vec::new(),
            RosterChange::GrantAdmin { account } => r::ended_by_grant(sessions, account, now),
            RosterChange::End { account, .. } => r::ended_by_binding_end(sessions, account, now),
        };
        Ok(Some(sorted(out)))
    }

    fn suspension_ends(
        &self,
        account: AccountId,
        _role: Role,
        _before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        Ok(Some(sorted(r::ended_by_suspension(sessions, account, now))))
    }

    fn revocation_ends(
        &self,
        account: AccountId,
        device: u8,
        _before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        Ok(Some(sorted(r::ended_by_credential_revocation(
            sessions, account, device, now,
        ))))
    }
}

/// The production backend: `fstp_auth::admit_method` for logins, and
/// `fstp_cell_core` from genesis for holdings, sessions and batches.
///
/// Holdings and sessions come from `gate::admit` over a production cell
/// that replays the roster (design section 5.4 step 2), never from a
/// holding the reference evaluated. A holding is read as the gate's
/// refusal of a fresh magic-link session as `WeakSessionForRole`.
///
/// Gaps against design sections 4.2, 5.1 and 8.2, reported by lane W1b:
/// `decide` sees no session rows, so a batch that must end sessions
/// refuses with [`SESSIONS_SEAM`]; a suspension refuses with
/// [`SUSPEND_SEAM`].
#[derive(Clone, Debug)]
pub struct Production {
    _probe: (),
}

fn login_ni(e: LoginDeny) -> Result<bool, NotImplemented> {
    match e {
        LoginDeny::NotImplemented(op) => Err(NotImplemented::new(op)),
        LoginDeny::WeakMethodForRole | LoginDeny::MethodDisabled => Ok(false),
    }
}

fn prod_ni(e: ProdError) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
    match e {
        ProdError::NotImplemented(op) => Err(NotImplemented::new(op)),
        ProdError::Refused(_) => Ok(None),
    }
}

/// The step-up policy the production gate is asked under: the P-71 default.
const GATE_POLICY: LoginPolicy = LoginPolicy {
    stepup_freshness_us: r::P71_DEFAULT_US,
};

/// Whether the gate's answer to a read in a session admits the session.
///
/// Reading: `NotPermitted` comes after the session checks of design
/// section 5.4 steps 1 and 2, so it counts as an admitted session. Every
/// other refusal counts as a refused session.
fn session_admitted<T>(got: Result<T, Deny>) -> Result<bool, NotImplemented> {
    match got {
        Ok(_) | Err(Deny::NotPermitted) => Ok(true),
        Err(Deny::NotImplemented(op)) => Err(NotImplemented::new(op)),
        Err(_) => Ok(false),
    }
}

/// Whether any of `sessions` belongs to `account`.
fn of_account(sessions: &[RefSession], account: AccountId) -> bool {
    sessions.iter().any(|s| s.account == account)
}

impl Production {
    /// The production backend, once each production operation it drives
    /// answers. Refuses with the first stub it meets.
    pub fn new() -> Result<Production, NotImplemented> {
        let p = Production { _probe: () };
        let roster = RefRoster::default();
        let now = T0;
        p.holds(&roster, A, now)?;
        p.login(false, RefMethod::Passkey, RefEnabled::default())?;
        let s = RefSession {
            id: [0; 16],
            account: A,
            method: RefMethod::Passkey,
            device: Some(0),
            started: now,
            last_used: now,
            ended: None,
        };
        p.session_in(&roster, &s, now, RefLifetimes::DEFAULT)?;
        Ok(p)
    }
}

/// The binding id M-AUTH gives `account`'s binding of `role`.
pub fn binding_of(account: AccountId, role: Role) -> BindingId {
    let r = match role {
        Role::CommitteeMember => 1,
        Role::FinanceApprover => 2,
        _ => 3,
    };
    BindingId::from_raw(
        account
            .raw()
            .saturating_mul(10)
            .saturating_add(r)
            .saturating_add(1_000),
    )
}

impl Production {
    /// Replays `roster` into a bootstrapped production cell at `now`.
    fn cell_for(&self, roster: &RefRoster, now: Timestamp) -> Result<ProdCell, ProdError> {
        let mut cell = ProdCell::bootstrapped()?;
        for g in &roster.admins {
            if g.account != ADMIN {
                cell.exec_tenant_admin_grant(ADMIN, g.account, T0)?;
            }
        }
        for b in &roster.bindings {
            let id = binding_of(b.account, b.role);
            let step = match b.end {
                Some(e) if e.micros() > now.micros() => {
                    grant_until(id, b.account, P1, b.role, T0, e).map_err(ProdError::Refused)?
                }
                _ => grant(id, b.account, P1, b.role, T0),
            };
            cell.exec_step(&step, T0)?;
            if b.suspended {
                cell.suspend_for_conflict(b.account, id, T0)?;
            }
            if let Some(e) = b.end.filter(|e| e.micros() <= now.micros()) {
                cell.exec_step(&end(id, e), e)?;
            }
        }
        Ok(cell)
    }

    /// The ended ids of `batch`, or [`SESSIONS_SEAM`] when the account
    /// had sessions the cell cannot know.
    fn ends_of(
        &self,
        batch: Result<Vec<CellRecord>, ProdError>,
        sessions: &[RefSession],
        account: AccountId,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        match batch {
            Err(e) => prod_ni(e),
            Ok(_) if of_account(sessions, account) => Err(NotImplemented::new(SESSIONS_SEAM)),
            Ok(b) => Ok(Some(sessions_ended_in(&b))),
        }
    }
}

impl AuthBackend for Production {
    fn holds(
        &self,
        roster: &RefRoster,
        a: AccountId,
        now: Timestamp,
    ) -> Result<bool, NotImplemented> {
        let cell = match self.cell_for(roster, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e).map(|_| false),
        };
        let probe = SessionView {
            id: [0xB0; 16],
            account: a,
            method: Method::MagicLink,
            started: now,
            last_used: now,
        };
        match gate::admit(
            cell.state(),
            &probe,
            Action::Read(ReadAction::ReadContent),
            None,
            now,
            &GATE_POLICY,
        ) {
            Err(Deny::NotImplemented(op)) => Err(NotImplemented::new(op)),
            Err(Deny::WeakSessionForRole) => Ok(true),
            Ok(_) | Err(_) => Ok(false),
        }
    }

    fn login(
        &self,
        holds: bool,
        m: RefMethod,
        enabled: RefEnabled,
    ) -> Result<bool, NotImplemented> {
        match fstp_auth::admit_method(holds, prod_method(m), &prod_enabled(enabled)) {
            Ok(()) => Ok(true),
            Err(e) => login_ni(e),
        }
    }

    fn session(
        &self,
        holds: bool,
        s: &RefSession,
        binding_ended: bool,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        // A holding and a binding end evaluated outside production cannot
        // drive the gate, which reads them from the cell roster.
        let _ = (holds, s, binding_ended, now, p72);
        Err(NotImplemented::new(
            "fstp_celltest::mc::auth_model::Production::session: production answers through session_in, gate::admit over the cell roster",
        ))
    }

    fn session_in(
        &self,
        roster: &RefRoster,
        s: &RefSession,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        if s.ended.is_some_and(|(at, _)| at.micros() <= now.micros()) {
            // An ended session has an `auth_log.session_end` row, and the
            // shell finds no session for its cookie.
            return Ok(false);
        }
        let mut cell = match self.cell_for(roster, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e).map(|_| false),
        };
        if p72 != RefLifetimes::DEFAULT {
            // The tenant admin sets P-72 through the login policy
            // ([`P72_SEAM`], closed by lane W2c). A value that lengthens a
            // default is refused as an invalid value, and the defaults then
            // apply. Any other refusal is a production defect, surfaced.
            let policy = fstp_cell_core::tenant::TenantLoginPolicy {
                p71_us: None,
                p72_idle_us: Some(p72.idle_us),
                p72_absolute_us: Some(p72.absolute_us),
            };
            let cmd = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::SetLoginPolicy {
                policy: policy.encode(),
            });
            let lengthens = format!(
                "{:?}",
                fstp_domain::refusal::Refusal::new(
                    fstp_domain::refusal::RuleRef::Input,
                    fstp_domain::refusal::RefusalReason::InvalidValue,
                )
            );
            // At the latest recorded instant, so a binding end recorded after
            // T0 cannot make the command earlier than the ledger.
            let at = cell.state().now_floor().max(T0);
            match cell.exec(cmd, ADMIN, at) {
                Ok(_) => {}
                Err(ProdError::Refused(r)) if r == lengthens => {}
                Err(ProdError::Refused(_)) => {
                    return Err(NotImplemented::new(
                        "fstp_celltest::mc::auth_model::Production::session_in: SetLoginPolicy was refused for a cause other than a value that lengthens a default (lane W2c)",
                    ));
                }
                Err(e) => return prod_ni(e).map(|_| false),
            }
        }
        session_admitted(gate::admit(
            cell.state(),
            &prod_session(s),
            Action::Read(ReadAction::ReadContent),
            None,
            now,
            &GATE_POLICY,
        ))
    }

    fn batch_ends(
        &self,
        change: RosterChange,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let mut cell = match self.cell_for(before, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let (account, batch) = match change {
            RosterChange::Grant {
                account,
                role,
                until,
            } => {
                let id = binding_of(account, role);
                let step = match until {
                    Some(e) => match grant_until(id, account, P1, role, now, e) {
                        Ok(s) => s,
                        Err(why) => return prod_ni(ProdError::Refused(why)),
                    },
                    None => grant(id, account, P1, role, now),
                };
                (account, cell.exec_step(&step, now))
            }
            RosterChange::End { account, role } => (
                account,
                cell.exec_step(&end(binding_of(account, role), now), now),
            ),
            RosterChange::GrantAdmin { account } => {
                (account, cell.exec_tenant_admin_grant(ADMIN, account, now))
            }
        };
        self.ends_of(batch, sessions, account)
    }

    fn suspension_ends(
        &self,
        account: AccountId,
        role: Role,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let mut cell = match self.cell_for(before, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let batch = cell.suspend_for_conflict(account, binding_of(account, role), now);
        self.ends_of(batch, sessions, account)
    }

    fn revocation_ends(
        &self,
        account: AccountId,
        device: u8,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let mut cell = match self.cell_for(before, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let credential = credential_of(account, device);
        let register = CellCommand::Auth(AuthCommand::RegisterCredential {
            account,
            credential: credential.clone(),
        });
        if let Err(e) = cell.exec(register, account, T0) {
            return prod_ni(e);
        }
        let revoke = CellCommand::Auth(AuthCommand::RevokeCredential {
            account,
            credential,
        });
        let batch = cell.exec(revoke, account, now);
        self.ends_of(batch, sessions, account)
    }
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthDefect {
    /// `admit_method` ignores scheduled bindings: a binding with an end
    /// instant does not count as a holding at login.
    LoginIgnoresScheduledBindings,
    /// The batch of a grant omits `SessionEnded`.
    GrantBatchOmitsSessionEnded,
    /// The batch of a recorded binding end omits `SessionEnded` (Q16 A).
    EndBatchOmitsSessionEnded,
    /// The gate admits a weak session of a holder.
    WeakSessionAdmitted,
}

/// `inner` with one seeded defect.
#[derive(Clone, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: AuthDefect,
}

impl<B: AuthBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: AuthDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }
}

impl<B: AuthBackend> AuthBackend for Mutant<B> {
    fn holds(
        &self,
        roster: &RefRoster,
        a: AccountId,
        now: Timestamp,
    ) -> Result<bool, NotImplemented> {
        if self.defect == AuthDefect::LoginIgnoresScheduledBindings {
            let mut cut = roster.clone();
            cut.bindings.retain(|b| b.end.is_none());
            return self.inner.holds(&cut, a, now);
        }
        self.inner.holds(roster, a, now)
    }

    fn login(
        &self,
        holds: bool,
        m: RefMethod,
        enabled: RefEnabled,
    ) -> Result<bool, NotImplemented> {
        self.inner.login(holds, m, enabled)
    }

    fn session(
        &self,
        holds: bool,
        s: &RefSession,
        binding_ended: bool,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        if self.defect == AuthDefect::WeakSessionAdmitted && !s.method.phishing_resistant() {
            return Ok(s.ended.is_none());
        }
        self.inner.session(holds, s, binding_ended, now, p72)
    }

    fn session_in(
        &self,
        roster: &RefRoster,
        s: &RefSession,
        now: Timestamp,
        p72: RefLifetimes,
    ) -> Result<bool, NotImplemented> {
        if self.defect == AuthDefect::WeakSessionAdmitted && !s.method.phishing_resistant() {
            // The inner backend is asked once, so a stub still halts the run.
            self.inner.session_in(roster, s, now, p72)?;
            return Ok(s.ended.is_none());
        }
        self.inner.session_in(roster, s, now, p72)
    }

    fn batch_ends(
        &self,
        change: RosterChange,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let out = self.inner.batch_ends(change, before, sessions, now)?;
        let grant = matches!(
            change,
            RosterChange::Grant { .. } | RosterChange::GrantAdmin { .. }
        );
        let omit = match self.defect {
            AuthDefect::GrantBatchOmitsSessionEnded => grant,
            AuthDefect::EndBatchOmitsSessionEnded => !grant,
            AuthDefect::LoginIgnoresScheduledBindings | AuthDefect::WeakSessionAdmitted => false,
        };
        if omit {
            return Ok(out.map(|_| Vec::new()));
        }
        Ok(out)
    }

    fn suspension_ends(
        &self,
        account: AccountId,
        role: Role,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        self.inner
            .suspension_ends(account, role, before, sessions, now)
    }

    fn revocation_ends(
        &self,
        account: AccountId,
        device: u8,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        self.inner
            .revocation_ends(account, device, before, sessions, now)
    }
}

// ---------------------------------------------------------------------------
// The model.

/// The scheduled end instant of the universe: 20 minutes after `T0`, the
/// instant of [`ProdCell::bootstrapped`]. A session started at `T0` is
/// still inside the P-72 idle lifetime just before it.
pub const END_AT: Timestamp = Timestamp::from_micros(T0.micros() + 20 * r::MINUTE_US);

/// The reduced clock: one minute before the end, one microsecond before
/// it, the instant, and one microsecond after.
pub const CLOCK: [Timestamp; 4] = [
    Timestamp::from_micros(END_AT.micros() - r::MINUTE_US),
    Timestamp::from_micros(END_AT.micros() - 1),
    END_AT,
    Timestamp::from_micros(END_AT.micros() + 1),
];

/// The tick of [`END_AT`] in [`CLOCK`].
pub const END_TICK: u8 = 2;

/// The accounts, in model order: admin1, admin2, a, b.
pub const ACCOUNTS: [AccountId; 4] = [ADMIN, ADMIN_2, A, B];

/// The tenant setting of the universe: passkeys and magic links.
pub const ENABLED: RefEnabled = RefEnabled {
    magic_link: true,
    eudi_wallet: false,
    opaque: false,
};

/// The device of every passkey of the universe.
pub const DEVICE: u8 = 0;

/// The time at `tick`.
pub fn at(tick: u8) -> Timestamp {
    CLOCK
        .get(usize::from(tick))
        .copied()
        .unwrap_or(Timestamp::from_micros(i64::MAX))
}

/// The state of one binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bind {
    /// Not granted.
    None,
    /// Granted, with no end.
    Active,
    /// Granted, with its end scheduled at [`END_AT`].
    Until,
    /// Ended by `EndRole` at the tick.
    Ended(u8),
}

impl Bind {
    fn end(self) -> Option<Timestamp> {
        match self {
            Bind::None | Bind::Active => None,
            Bind::Until => Some(END_AT),
            Bind::Ended(t) => Some(at(t)),
        }
    }
}

/// A live session of the model. Ended sessions leave the state. Two
/// sessions with equal fields behave alike under every rule, so they share
/// an id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sess {
    /// The account's index in [`ACCOUNTS`].
    pub account: u8,
    /// The login method.
    pub method: RefMethod,
    /// The tick of the login.
    pub started: u8,
}

/// The state of M-AUTH.
///
/// The accounts never interact: no rule of the universe reads one
/// account's sessions for another account. So each initial state focuses
/// on one account, a, b or admin2, and enables that account's actions
/// only. The union of the focused runs has every behaviour of the full
/// product that a property can see, at the cost of a sum of state counts
/// instead of a product.
///
/// admin1 holds tenant admin from genesis to the end. Its logins are
/// checked in every run, but its passkey sessions are not stored, since
/// they never change a decision. Admin sessions carry tick 0 as their
/// start, since no admin grant ends in the universe.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthState {
    /// The focused account's index in [`ACCOUNTS`]: 1, 2 or 3.
    pub focus: u8,
    /// The tick of the reduced clock.
    pub tick: u8,
    /// a's committee member binding.
    pub cm_a: Bind,
    /// Whether a's committee binding is suspended for a conflict of interest.
    pub cm_suspended: bool,
    /// b's finance approver binding.
    pub fa_b: Bind,
    /// Whether admin2 is a tenant admin.
    pub admin2: bool,
    /// Whether a's passkey is revoked.
    pub revoked: bool,
    /// The live sessions of the focused account, sorted.
    pub sessions: Vec<Sess>,
    /// The logins the focused account made.
    pub logins: u8,
    /// Whether a grant batch ended a weak session (witness).
    pub grant_ended_weak: bool,
    /// The first batch whose ended sessions differed from the reference's.
    pub diverged: Option<String>,
    /// The first backend operation that answered `NotImplemented`, or a
    /// backend refusal of a roster change the reference accepts.
    pub halt: Option<&'static str>,
}

/// The index of admin1 in [`ACCOUNTS`].
pub const IX_ADMIN1: u8 = 0;
/// The index of admin2 in [`ACCOUNTS`].
pub const IX_ADMIN2: u8 = 1;
/// The index of account a in [`ACCOUNTS`].
pub const IX_A: u8 = 2;
/// The index of account b in [`ACCOUNTS`].
pub const IX_B: u8 = 3;

impl AuthState {
    /// Genesis with `focus`: admin1 is the tenant admin, and nothing else is held.
    pub fn genesis(focus: u8) -> AuthState {
        AuthState {
            focus,
            tick: 0,
            cm_a: Bind::None,
            cm_suspended: false,
            fa_b: Bind::None,
            admin2: false,
            revoked: false,
            sessions: Vec::new(),
            logins: 0,
            grant_ended_weak: false,
            diverged: None,
            halt: None,
        }
    }

    /// The time now.
    pub fn now(&self) -> Timestamp {
        at(self.tick)
    }

    /// The roster as the reference sees it.
    pub fn roster(&self) -> RefRoster {
        let mut roster = RefRoster {
            bindings: Vec::new(),
            admins: vec![RefAdmin {
                account: ADMIN,
                end: None,
            }],
        };
        if self.admin2 {
            roster.admins.push(RefAdmin {
                account: ADMIN_2,
                end: None,
            });
        }
        for (account, role, b, suspended) in [
            (A, Role::CommitteeMember, self.cm_a, self.cm_suspended),
            (B, Role::FinanceApprover, self.fa_b, false),
        ] {
            if b != Bind::None {
                roster.bindings.push(RefBinding {
                    account,
                    role,
                    end: b.end(),
                    suspended,
                    voided: false,
                });
            }
        }
        roster
    }

    /// The reference session of a model session.
    pub fn session(&self, s: &Sess) -> RefSession {
        RefSession {
            id: session_id(s),
            account: account(s.account),
            method: s.method,
            device: (s.method == RefMethod::Passkey).then_some(DEVICE),
            started: at(s.started),
            last_used: at(s.started),
            ended: None,
        }
    }

    /// Every live session as the reference sees it.
    pub fn ref_sessions(&self) -> Vec<RefSession> {
        self.sessions.iter().map(|s| self.session(s)).collect()
    }

    /// Whether the reference admits session `rs` now.
    pub fn reference_admits_ref(&self, rs: &RefSession) -> bool {
        Reference
            .session_in(&self.roster(), rs, self.now(), RefLifetimes::DEFAULT)
            .unwrap_or(false)
    }

    /// Whether the reference admits session `s` now.
    pub fn reference_admits(&self, s: &Sess) -> bool {
        self.reference_admits_ref(&self.session(s))
    }

    /// The sessions the gate is probed with: every live session, and for
    /// each account a passkey and a magic-link session that start now.
    pub fn probes(&self) -> Vec<RefSession> {
        let mut out = self.ref_sessions();
        for i in 0..4u8 {
            for method in [RefMethod::Passkey, RefMethod::MagicLink] {
                let mut s = self.session(&Sess {
                    account: i,
                    method,
                    started: self.tick,
                });
                s.id[5] = 0xFF;
                out.push(s);
            }
        }
        out
    }
}

/// The account at model index `i`.
pub fn account(i: u8) -> AccountId {
    ACCOUNTS.get(usize::from(i)).copied().unwrap_or(ADMIN)
}

/// The session id of a model session: account, tick and method.
pub fn session_id(s: &Sess) -> [u8; 16] {
    [
        0xA7,
        s.account,
        s.started,
        u8::from(s.method == RefMethod::MagicLink),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// An action of M-AUTH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthAction {
    /// The clock moves one tick.
    Tick,
    /// Grant committee member to a.
    GrantCm,
    /// Grant committee member to a, with its end scheduled at [`END_AT`].
    GrantCmUntil,
    /// End a's committee member binding now.
    EndCm,
    /// The vault reaction suspends a's committee binding for a conflict of
    /// interest (I-06). The binding still holds (design section 8.2).
    SuspendCm,
    /// Grant finance approver to b.
    GrantFa,
    /// End b's finance approver binding now.
    EndFa,
    /// Grant tenant admin to admin2.
    GrantAdmin2,
    /// A login of the account at the index with the method.
    Login(u8, RefMethod),
    /// Revoke a's passkey, which removes its device.
    Revoke,
    /// The system command `EndSessionsAtBindingEnd` for a's scheduled end.
    EndAtBindingEnd,
}

/// What a backend batch ended, against the reference's set.
type Ends = Result<Option<Vec<[u8; 16]>>, NotImplemented>;

/// M-AUTH over a backend.
#[derive(Clone, Debug)]
pub struct AuthModel<B> {
    backend: B,
}

impl<B: AuthBackend> AuthModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> AuthModel<B> {
        AuthModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Removes from `next` the sessions a backend batch ended, after
    /// comparing them with the reference's batch. A difference is recorded
    /// in `diverged` for the two-way property. Returns whether a weak
    /// session was ended.
    fn apply_ends(next: &mut AuthState, what: &str, got: Ends, want: Ends) -> Option<bool> {
        let ended = match got {
            Err(e) => {
                next.halt = Some(e.operation);
                return None;
            }
            Ok(None) => {
                next.halt = Some("the backend refused a roster change the reference accepts");
                return None;
            }
            Ok(Some(ids)) => sorted(ids),
        };
        if let Ok(Some(w)) = want
            && sorted(w.clone()) != ended
            && next.diverged.is_none()
        {
            next.diverged = Some(format!(
                "two-way: the batch of {what} ended {ended:?}, reference {w:?}"
            ));
        }
        let mut weak_ended = false;
        next.sessions.retain(|x| {
            let gone = ended.contains(&session_id(x));
            weak_ended |= gone && x.method == RefMethod::MagicLink;
            !gone
        });
        Some(weak_ended)
    }

    /// Applies a roster change and the sessions its batch ends.
    fn change(&self, s: &AuthState, change: RosterChange) -> Option<AuthState> {
        let mut next = s.clone();
        match change {
            RosterChange::Grant {
                role: Role::CommitteeMember,
                until,
                ..
            } => {
                next.cm_a = if until.is_some() {
                    Bind::Until
                } else {
                    Bind::Active
                }
            }
            RosterChange::Grant { .. } => next.fa_b = Bind::Active,
            RosterChange::End {
                role: Role::CommitteeMember,
                ..
            } => next.cm_a = Bind::Ended(s.tick),
            RosterChange::End { .. } => next.fa_b = Bind::Ended(s.tick),
            RosterChange::GrantAdmin { .. } => next.admin2 = true,
        }
        let sessions = s.ref_sessions();
        let roster = s.roster();
        let got = self.backend.batch_ends(change, &roster, &sessions, s.now());
        let want = Reference.batch_ends(change, &roster, &sessions, s.now());
        let is_grant = !matches!(change, RosterChange::End { .. });
        if let Some(weak) = Self::apply_ends(&mut next, &format!("{change:?}"), got, want) {
            next.grant_ended_weak |= weak && is_grant;
        }
        Some(next)
    }

    /// `change` when `guard` holds.
    fn guarded(&self, guard: bool, s: &AuthState, change: RosterChange) -> Option<AuthState> {
        if guard { self.change(s, change) } else { None }
    }

    /// The suspension of a's committee binding and the sessions its
    /// reaction ends.
    fn suspend(&self, s: &AuthState) -> Option<AuthState> {
        let open = s.cm_a == Bind::Active || (s.cm_a == Bind::Until && s.tick < END_TICK);
        if !open || s.cm_suspended {
            return None;
        }
        let mut next = s.clone();
        next.cm_suspended = true;
        let sessions = s.ref_sessions();
        let roster = s.roster();
        let role = Role::CommitteeMember;
        let got = self
            .backend
            .suspension_ends(A, role, &roster, &sessions, s.now());
        let want = Reference.suspension_ends(A, role, &roster, &sessions, s.now());
        Self::apply_ends(
            &mut next,
            "the suspension of a's committee binding",
            got,
            want,
        );
        Some(next)
    }

    /// The revocation of a's passkey and the sessions its batch ends.
    fn revoke(&self, s: &AuthState) -> Option<AuthState> {
        if s.revoked {
            return None;
        }
        let mut next = s.clone();
        next.revoked = true;
        let sessions = s.ref_sessions();
        let roster = s.roster();
        let got = self
            .backend
            .revocation_ends(A, DEVICE, &roster, &sessions, s.now());
        let want = Reference.revocation_ends(A, DEVICE, &roster, &sessions, s.now());
        Self::apply_ends(&mut next, "the revocation of a's passkey", got, want);
        Some(next)
    }

    /// A login. The bound of two stored logins is enforced in
    /// [`Model::actions`] as well, so no pruned login is offered.
    /// A passkey login of a after the revocation is not offered:
    /// `admit_method` has no credential input, and the credential check is
    /// `fstp_webauthn::verify_assertion` against the stored credentials,
    /// which the R-LG-04 machine drives over HTTP.
    fn login(&self, s: &AuthState, i: u8, m: RefMethod) -> Option<AuthState> {
        let stored = i == s.focus;
        if stored && (s.logins >= 2 || (m == RefMethod::Passkey && i == IX_A && s.revoked)) {
            return None;
        }
        let mut next = s.clone();
        let decision = self
            .backend
            .holds(&s.roster(), account(i), s.now())
            .and_then(|h| self.backend.login(h, m, ENABLED));
        match decision {
            Err(e) => {
                next.halt = Some(e.operation);
                Some(next)
            }
            Ok(false) => None,
            Ok(true) if !stored => Some(next),
            Ok(true) => {
                next.logins = s.logins.saturating_add(1);
                let admin = i == IX_ADMIN1 || i == IX_ADMIN2;
                next.sessions.push(Sess {
                    account: i,
                    method: m,
                    started: if admin { 0 } else { s.tick },
                });
                next.sessions.sort();
                Some(next)
            }
        }
    }
}

impl<B: AuthBackend> Model for AuthModel<B> {
    type State = AuthState;
    type Action = AuthAction;

    fn init(&self) -> Vec<AuthState> {
        vec![
            AuthState::genesis(IX_ADMIN2),
            AuthState::genesis(IX_A),
            AuthState::genesis(IX_B),
        ]
    }

    fn actions(&self, s: &AuthState, out: &mut Vec<AuthAction>) {
        if s.halt.is_some() {
            return;
        }
        out.push(AuthAction::Tick);
        match s.focus {
            IX_A => out.extend([
                AuthAction::GrantCm,
                AuthAction::GrantCmUntil,
                AuthAction::EndCm,
                AuthAction::SuspendCm,
                AuthAction::Revoke,
                AuthAction::EndAtBindingEnd,
            ]),
            IX_B => out.extend([AuthAction::GrantFa, AuthAction::EndFa]),
            _ => out.push(AuthAction::GrantAdmin2),
        }
        // A login that the model's bound prunes is not offered, so a login
        // with no step is one the login rule refuses. The I-77 HTTP machine
        // reads a missing step as a refusal by the cell.
        out.push(AuthAction::Login(IX_ADMIN1, RefMethod::Passkey));
        out.push(AuthAction::Login(IX_ADMIN1, RefMethod::MagicLink));
        if s.logins < 2 {
            if !(s.focus == IX_A && s.revoked) {
                out.push(AuthAction::Login(s.focus, RefMethod::Passkey));
            }
            out.push(AuthAction::Login(s.focus, RefMethod::MagicLink));
        }
    }

    fn step(&self, s: &AuthState, a: &AuthAction) -> Option<AuthState> {
        let cm = |until| RosterChange::Grant {
            account: A,
            role: Role::CommitteeMember,
            until,
        };
        match *a {
            AuthAction::Tick => {
                let tick = s
                    .tick
                    .checked_add(1)
                    .filter(|t| usize::from(*t) < CLOCK.len())?;
                let mut next = s.clone();
                next.tick = tick;
                Some(next)
            }
            AuthAction::GrantCm => self.guarded(s.cm_a == Bind::None, s, cm(None)),
            AuthAction::GrantCmUntil => self.guarded(
                s.cm_a == Bind::None && s.tick < END_TICK,
                s,
                cm(Some(END_AT)),
            ),
            AuthAction::EndCm => self.guarded(
                s.cm_a == Bind::Active || (s.cm_a == Bind::Until && s.tick < END_TICK),
                s,
                RosterChange::End {
                    account: A,
                    role: Role::CommitteeMember,
                },
            ),
            AuthAction::SuspendCm => self.suspend(s),
            AuthAction::GrantFa => self.guarded(
                s.fa_b == Bind::None,
                s,
                RosterChange::Grant {
                    account: B,
                    role: Role::FinanceApprover,
                    until: None,
                },
            ),
            AuthAction::EndFa => self.guarded(
                s.fa_b == Bind::Active,
                s,
                RosterChange::End {
                    account: B,
                    role: Role::FinanceApprover,
                },
            ),
            AuthAction::GrantAdmin2 => {
                self.guarded(!s.admin2, s, RosterChange::GrantAdmin { account: ADMIN_2 })
            }
            AuthAction::Revoke => self.revoke(s),
            AuthAction::EndAtBindingEnd => {
                if s.cm_a != Bind::Until || s.tick < END_TICK {
                    return None;
                }
                let mut next = s.clone();
                let before = next.sessions.len();
                next.sessions
                    .retain(|x| !(x.account == IX_A && x.started < END_TICK));
                (next.sessions.len() != before).then_some(next)
            }
            AuthAction::Login(i, m) => self.login(s, i, m),
        }
    }

    fn is_terminal(&self, s: &AuthState) -> bool {
        s.halt.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-AUTH.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-77 over states: no live weak session of a management holder.
    pub const I77: &str = "I-77";
    /// I-77 over logins: no weak login of a holder is admitted.
    pub const I77_LOGIN: &str = "I-77-login";
    /// I-77 at the gate: the backend admits no session the reference refuses.
    pub const I77_ADMIT: &str = "I-77-admit";
    /// Two-way: every backend decision and every batch equals the reference's.
    pub const TWO_WAY: &str = "two-way";
    /// Witness: an applicant logged in by magic link.
    pub const W_APPLICANT_MAGIC: &str = "witness-applicant-by-magic-link";
    /// Witness: a committee member logged in by passkey.
    pub const W_MEMBER_PASSKEY: &str = "witness-committee-member-by-passkey";
    /// Witness: a grant ended a weak session in its batch.
    pub const W_GRANT_ENDS_WEAK: &str = "witness-grant-ends-weak-session";
    /// Witness: at the scheduled end instant, a's earlier session is refused.
    pub const W_SCHEDULED_END: &str = "witness-scheduled-end-refuses-at-its-instant";
    /// Witness: a suspended committee member logged in again by passkey.
    pub const W_SUSPENDED_PASSKEY: &str = "witness-suspended-member-by-passkey";
}

/// Whether the reference says the live session `s` is a weak session of a holder.
fn weak_of_holder(st: &AuthState, s: &Sess) -> bool {
    s.method == RefMethod::MagicLink && st.roster().holds_management(account(s.account), st.now())
}

/// The I-77 check of the gate in one state: no probe session that the
/// reference refuses is admitted.
fn gate_check<B: AuthBackend>(m: &AuthModel<B>, s: &AuthState) -> Result<(), String> {
    let roster = s.roster();
    for rs in s.probes() {
        let admitted = m
            .backend()
            .session_in(&roster, &rs, s.now(), RefLifetimes::DEFAULT);
        if admitted == Ok(true) && !s.reference_admits_ref(&rs) {
            return Err(format!("I-77: the gate admitted session {rs:?}"));
        }
    }
    Ok(())
}

/// The two-way check of one state: every batch so far, and every
/// holdings, login and session decision of the backend, equals the
/// reference's.
fn two_way<B: AuthBackend>(m: &AuthModel<B>, s: &AuthState) -> Result<(), String> {
    if let Some(why) = &s.diverged {
        return Err(why.clone());
    }
    let roster = s.roster();
    let now = s.now();
    for (i, a) in ACCOUNTS.iter().enumerate() {
        let want_holds = roster.holds_management(*a, now);
        if let Ok(h) = m.backend().holds(&roster, *a, now)
            && h != want_holds
        {
            return Err(format!(
                "two-way: holds of account {i} is {h}, reference {want_holds}"
            ));
        }
        for method in [RefMethod::Passkey, RefMethod::MagicLink] {
            let want = r::admit_login(want_holds, method, true, ENABLED).is_ok();
            if let Ok(got) = m.backend().login(want_holds, method, ENABLED)
                && got != want
            {
                return Err(format!(
                    "two-way: login of {i} by {method:?} is {got}, reference {want}"
                ));
            }
        }
    }
    for rs in s.probes() {
        let want = s.reference_admits_ref(&rs);
        if let Ok(got) = m
            .backend()
            .session_in(&roster, &rs, now, RefLifetimes::DEFAULT)
            && got != want
        {
            return Err(format!(
                "two-way: session {rs:?} admitted {got}, reference {want}"
            ));
        }
    }
    Ok(())
}

/// Every property of M-AUTH. A backend call inside a property that answers
/// `NotImplemented` counts as no evidence, so only `backend-answers`
/// reports a stub.
pub fn properties<'a, B: AuthBackend>(m: &'a AuthModel<B>) -> Vec<Property<'a, AuthModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &AuthState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::always_with(ids::I77, |s: &AuthState| {
            match s.sessions.iter().find(|x| weak_of_holder(s, x)) {
                None => Ok(()),
                Some(x) => Err(format!("I-77: live weak session {x:?} of a holder")),
            }
        }),
        Property::transition_with(
            ids::I77_LOGIN,
            |s: &AuthState, a: &AuthAction, t: &AuthState| match a {
                AuthAction::Login(i, RefMethod::MagicLink) if t.halt.is_none() => {
                    if s.roster().holds_management(account(*i), s.now()) {
                        Err(format!(
                            "I-77: a magic-link login of holder {i} was admitted"
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            },
        ),
        Property::always_with(ids::I77_ADMIT, move |s: &AuthState| gate_check(m, s)),
        Property::always_with(ids::TWO_WAY, move |s: &AuthState| two_way(m, s)),
        Property::reachable(ids::W_APPLICANT_MAGIC, |s: &AuthState| {
            s.fa_b == Bind::None
                && s.sessions.iter().any(|x| {
                    x.account == IX_B && x.method == RefMethod::MagicLink && s.reference_admits(x)
                })
        }),
        Property::reachable(ids::W_MEMBER_PASSKEY, |s: &AuthState| {
            s.cm_a == Bind::Active
                && s.sessions.iter().any(|x| {
                    x.account == IX_A && x.method == RefMethod::Passkey && s.reference_admits(x)
                })
        }),
        Property::reachable(ids::W_GRANT_ENDS_WEAK, |s: &AuthState| s.grant_ended_weak),
        Property::reachable(ids::W_SCHEDULED_END, |s: &AuthState| {
            s.tick == END_TICK
                && s.cm_a == Bind::Until
                && s.sessions.iter().any(|x| {
                    x.account == IX_A && x.method == RefMethod::Passkey && !s.reference_admits(x)
                })
        }),
        Property::reachable(ids::W_SUSPENDED_PASSKEY, |s: &AuthState| {
            s.cm_suspended
                && s.cm_a == Bind::Active
                && s.sessions.iter().any(|x| {
                    x.account == IX_A && x.method == RefMethod::Passkey && s.reference_admits(x)
                })
        }),
    ]
}

// ---------------------------------------------------------------------------
// The HTTP seam of the I-77, I-79 and R-LG-04 machines.

/// The HTTP client the machines of design section 14.4 drive a cell with.
///
/// `CellHandle` has no HTTP client yet, and the cell has no routes. Every
/// call refuses with [`http::HTTP_SEAM`], so a machine is red for that
/// reason only. Lanes W1a and W3a remove the seam. The method set and
/// routes follow design sections 8.2 to 8.7.
pub mod http {
    use fstp_domain::id::AccountId;
    use fstp_domain::time::Timestamp;

    use super::RosterChange;
    use crate::NotImplemented;
    use crate::reference::auth::RefMethod;
    use crate::world::{CellHandle, DbMode, VaultLayout, World, WorldError, WorldSpec};

    /// Why every call refuses for now.
    pub const HTTP_SEAM: &str = "fstp_celltest::world::CellHandle has no HTTP client and the cell has no auth routes yet (lanes W1a and W3a)";

    /// The former seam of [`production_routes`], kept so callers that name
    /// it still compile. Lane W3a closed the seam: `fstp-cell` exposes its
    /// route table as `fstp_cell::routes::table` (design section 8.7).
    pub const ROUTE_TABLE_SEAM: &str = "fstp_celltest::mc::auth_model::http::production_routes: fstp-cell exposes no route table yet, only the Route type (design section 8.7, lane W3a)";

    /// Every route of the production cell with its risk class, from
    /// `fstp_cell::routes::table`. It no longer refuses.
    pub fn production_routes() -> Result<Vec<fstp_cell::routes::Route>, NotImplemented> {
        Ok(fstp_cell::routes::table().to_vec())
    }

    /// A one-cell SaaS world for the machines.
    pub fn one_cell_world() -> Result<World, WorldError> {
        World::start(WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        })
    }

    /// A session cookie value the cell set.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Cookie(pub Vec<u8>);

    /// A recovery case reference the cell returned.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct CaseRef(pub Vec<u8>);

    /// A reply of a cell route.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Reply {
        /// The status code.
        pub status: u16,
        /// The body.
        pub body: Vec<u8>,
    }

    impl Reply {
        /// Whether the status is 2xx.
        pub fn ok(&self) -> bool {
            (200..300).contains(&self.status)
        }
    }

    /// The auth client of one cell.
    #[derive(Debug)]
    pub struct AuthClient<'w> {
        cell: &'w CellHandle,
    }

    impl<'w> AuthClient<'w> {
        /// The client of `cell`.
        pub fn new(cell: &'w CellHandle) -> AuthClient<'w> {
            AuthClient { cell }
        }

        /// One request. Refuses with [`HTTP_SEAM`] until the seam goes.
        pub fn call(
            &self,
            method: &str,
            path: &str,
            cookie: Option<&Cookie>,
            body: &[u8],
        ) -> Result<Reply, NotImplemented> {
            let _ = (self.cell.index(), method, path, cookie, body);
            Err(NotImplemented::new(HTTP_SEAM))
        }

        /// Sets the cell's test clock.
        pub fn set_clock(&self, at: Timestamp) -> Result<(), NotImplemented> {
            self.call(
                "POST",
                "/test/clock",
                None,
                at.micros().to_string().as_bytes(),
            )
            .map(|_| ())
        }

        /// Enrols `account` through an invitation with a software passkey.
        pub fn enrol(&self, account: AccountId) -> Result<bool, NotImplemented> {
            let path = format!("/auth/invitations/{}/register", account.raw());
            Ok(self.call("POST", &path, None, b"{}")?.ok())
        }

        /// A login of `account` by `m`: the passkey routes, or the magic
        /// link routes ending in `POST /auth/magic/consume`.
        pub fn login(
            &self,
            account: AccountId,
            m: RefMethod,
        ) -> Result<Option<Cookie>, NotImplemented> {
            let body = format!("{{\"account\":\"{}\"}}", account.raw());
            let reply = match m {
                RefMethod::MagicLink => {
                    self.call("POST", "/auth/magic/request", None, body.as_bytes())?;
                    self.call("POST", "/auth/magic/consume", None, body.as_bytes())?
                }
                _ => {
                    self.call("POST", "/auth/passkey/login/options", None, body.as_bytes())?;
                    self.call("POST", "/auth/passkey/login", None, body.as_bytes())?
                }
            };
            Ok(reply.ok().then_some(Cookie(reply.body)))
        }

        /// A roster change by admin1 with a fresh step-up, through
        /// `POST /api/v1/commands`.
        pub fn roster(&self, admin: &Cookie, change: RosterChange) -> Result<bool, NotImplemented> {
            let body = format!("{change:?}");
            self.call("POST", "/auth/stepup/options", Some(admin), body.as_bytes())?;
            self.call("POST", "/auth/stepup", Some(admin), body.as_bytes())?;
            Ok(self
                .call("POST", "/api/v1/commands", Some(admin), body.as_bytes())?
                .ok())
        }

        /// Seeds a vault fact through the test seeding of design section
        /// 6.9 that gives `account` a conflict of interest, so the cell's
        /// reaction suspends its Judging bindings (I-06).
        pub fn suspend_for_conflict(&self, account: AccountId) -> Result<bool, NotImplemented> {
            let body = format!("{{\"conflict\":\"{}\"}}", account.raw());
            Ok(self
                .call("POST", "/test/vault/conflict", None, body.as_bytes())?
                .ok())
        }

        /// Whether the cell admits a request in the session.
        pub fn admitted(&self, session: &Cookie) -> Result<bool, NotImplemented> {
            Ok(self.call("GET", "/auth/sessions", Some(session), b"")?.ok())
        }

        /// `GET /auth/sessions`: the session ids listed.
        pub fn sessions(&self, session: &Cookie) -> Result<Option<Vec<u8>>, NotImplemented> {
            let r = self.call("GET", "/auth/sessions", Some(session), b"")?;
            Ok(r.ok().then_some(r.body))
        }

        /// `DELETE /auth/sessions/{id}`.
        pub fn end_session(&self, session: &Cookie, id: &[u8]) -> Result<bool, NotImplemented> {
            let path = format!("/auth/sessions/{}", hex(id));
            Ok(self.call("DELETE", &path, Some(session), b"")?.ok())
        }

        /// `GET /auth/devices`: the devices listed.
        pub fn devices(&self, session: &Cookie) -> Result<Option<Vec<u8>>, NotImplemented> {
            let r = self.call("GET", "/auth/devices", Some(session), b"")?;
            Ok(r.ok().then_some(r.body))
        }

        /// `DELETE /auth/devices/{id}`, with a step-up when `stepup` holds.
        pub fn remove_device(
            &self,
            session: &Cookie,
            device: u8,
            stepup: bool,
        ) -> Result<bool, NotImplemented> {
            if stepup {
                self.call("POST", "/auth/stepup", Some(session), b"{}")?;
            }
            let path = format!("/auth/devices/{device}");
            Ok(self.call("DELETE", &path, Some(session), b"")?.ok())
        }

        /// `POST /auth/recovery` for `account`.
        pub fn recovery(&self, account: AccountId) -> Result<Option<CaseRef>, NotImplemented> {
            let body = format!("{{\"account\":\"{}\"}}", account.raw());
            let r = self.call("POST", "/auth/recovery", None, body.as_bytes())?;
            Ok(r.ok().then_some(CaseRef(r.body)))
        }

        /// `POST /auth/recovery/{case}/email`.
        pub fn recovery_email(&self, case: &CaseRef) -> Result<bool, NotImplemented> {
            let path = format!("/auth/recovery/{}/email", hex(&case.0));
            Ok(self.call("POST", &path, None, b"{}")?.ok())
        }

        /// `POST /auth/recovery/{case}/approve` in `approver`'s session.
        pub fn recovery_approve(
            &self,
            case: &CaseRef,
            approver: &Cookie,
            stepup: bool,
        ) -> Result<bool, NotImplemented> {
            if stepup {
                self.call("POST", "/auth/stepup", Some(approver), b"{}")?;
            }
            let path = format!("/auth/recovery/{}/approve", hex(&case.0));
            Ok(self.call("POST", &path, Some(approver), b"{}")?.ok())
        }

        /// An operator ticket for `case`, signed by the test control plane.
        pub fn recovery_ticket(
            &self,
            case: &CaseRef,
            two_staff: bool,
        ) -> Result<bool, NotImplemented> {
            let body = format!("{{\"two_staff\":{two_staff}}}");
            let path = format!("/test/operator-ticket/{}", hex(&case.0));
            Ok(self.call("POST", &path, None, body.as_bytes())?.ok())
        }

        /// `POST /auth/recovery/{case}/complete` with a new software passkey.
        pub fn recovery_complete(&self, case: &CaseRef) -> Result<Option<Cookie>, NotImplemented> {
            let path = format!("/auth/recovery/{}/complete", hex(&case.0));
            let r = self.call("POST", &path, None, b"{}")?;
            Ok(r.ok().then_some(Cookie(r.body)))
        }

        /// The tenant audit view as `session` sees it.
        pub fn audit_view(&self, session: &Cookie) -> Result<Vec<u8>, NotImplemented> {
            Ok(self
                .call("GET", "/api/v1/audit/anchors", Some(session), b"")?
                .body)
        }
    }

    /// Lower-case hex of `b`.
    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

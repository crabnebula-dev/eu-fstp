//! M-STEPUP (design section 14.2, I-78). Lane W1b owns this file.
//!
//! The universe: one tenant admin with a passkey session, and one
//! applicant with a magic-link session. Four high-risk commands: two of
//! kind `ManagementRoleChange` (so a digest compared by kind only shows),
//! `ReleasePayment` and `AddPasskey`. Step-ups by passkey with user
//! verification, by passkey without it, and from the magic-link session,
//! all asserted at the first tick. Ticks at P-71 minus 1 µs, P-71 and
//! P-71 plus 1 µs. P-71 is 5 minutes or a tenant's 1 minute. Admission and
//! commit are separate steps, so freshness is checked at both. One replay:
//! at most two commits, so a consumed step-up can be offered again.
//!
//! The applicant b already holds a passkey, so `AddPasskey` in its
//! magic-link session adds a second passkey to its own account. Only the
//! magic-link rule refuses it, not the first-passkey rule (design section
//! 8.3). This is the takeover path of a stolen mailbox.
//!
//! The model runs over a [`StepUpBackend`]: [`Reference`],
//! [`Production`] (`fstp_cell_core::gate::admit` over a production cell
//! from genesis) or a [`Mutant`] with one seeded defect. Admission and
//! commit decisions are both compared with the reference.

use fstp_auth::AuthCommand;
use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, StepUpView};
use fstp_domain::id::{AccountId, BindingId, RequestId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, B, P1, T0, grant};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::mc::auth_model::{ProdCell, ProdError, credential_of, prod_session};
use crate::reference::auth::{self as r, MINUTE_US, RefHighRisk, RefMethod, RefSession, RefStepUp};

// ---------------------------------------------------------------------------
// The universe.

/// The instant every step-up is asserted at.
pub const ASSERTED_AT: Timestamp = Timestamp::from_micros(3_000_000_000);

/// The P-71 values: the default and a tenant's shorter value.
pub const P71_VALUES: [i64; 2] = [r::P71_DEFAULT_US, MINUTE_US];

/// The P-71 of variant `v`.
pub fn p71(v: u8) -> i64 {
    P71_VALUES
        .get(usize::from(v))
        .copied()
        .unwrap_or(r::P71_DEFAULT_US)
}

/// The time at `tick` under P-71 variant `v`: the assertion, then P-71
/// minus 1 µs, P-71 and P-71 plus 1 µs after it.
pub fn at(v: u8, tick: u8) -> Timestamp {
    let base = ASSERTED_AT.micros();
    let off = match tick {
        0 => 0,
        1 => p71(v).saturating_sub(1),
        2 => p71(v),
        _ => p71(v).saturating_add(1),
    };
    Timestamp::from_micros(base.saturating_add(off))
}

/// The index of the admin's passkey session.
pub const S_ADMIN: u8 = 0;
/// The index of the applicant's magic-link session.
pub const S_MAGIC: u8 = 1;

/// The session at index `i`.
pub fn session(i: u8) -> RefSession {
    let (account, method, id) = if i == S_MAGIC {
        (B, RefMethod::MagicLink, 0x52)
    } else {
        (ADMIN, RefMethod::Passkey, 0x51)
    };
    let mut sid = [0u8; 16];
    sid[0] = id;
    RefSession {
        id: sid,
        account,
        method,
        device: (method == RefMethod::Passkey).then_some(0),
        started: ASSERTED_AT,
        last_used: ASSERTED_AT,
        ended: None,
    }
}

/// The commands, by index: two role grants, a payment release and adding a passkey.
pub const COMMANDS: [&str; 4] = ["GrantRole", "GrantRole", "ReleasePayment", "AddPasskey"];

/// The command id of command `c`.
pub fn command_id(c: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0xC0;
    id[1] = c;
    id
}

/// The reference canonical form of command `c`: its name and its index.
/// The digest binds the command id too, so two equal names still differ.
pub fn canonical(c: u8) -> Vec<u8> {
    let mut out = COMMANDS
        .get(usize::from(c))
        .copied()
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    out.push(b'#');
    out.push(c);
    out
}

/// The action digest of command `c`.
pub fn digest(c: u8) -> [u8; 32] {
    r::action_digest(&canonical(c), command_id(c))
}

/// The high-risk class of command `c`.
pub fn class(c: u8) -> Option<RefHighRisk> {
    COMMANDS
        .get(usize::from(c))
        .and_then(|n| r::high_risk_of(n))
}

/// The command whose digest is `d`, if any.
pub fn command_of(d: &[u8; 32]) -> Option<u8> {
    (0..4u8).find(|c| digest(*c) == *d)
}

/// The production cell command of command `c` in the admin session.
///
/// Gap: the stubs have no `AddPasskey` command. `RegisterCredential`
/// stands in for it, as the only credential command of `AuthCommand`.
pub fn cell_command(c: u8) -> CellCommand {
    cell_command_in(S_ADMIN, c)
}

/// The production cell command of command `c` in session `session`.
/// `AddPasskey` names the session's own account, so the applicant's
/// magic-link session asks to add a passkey to its own account.
pub fn cell_command_in(session: u8, c: u8) -> CellCommand {
    let core = |cmd| CellCommand::Engine(fstp_engine::Command::Core(cmd));
    let own = if session == S_MAGIC { B } else { ADMIN };
    match c {
        0 => core(grant(BindingId::from_raw(2_001), A, P1, Role::CommitteeMember, T0).cmd),
        1 => core(grant(BindingId::from_raw(2_002), B, P1, Role::FinanceApprover, T0).cmd),
        2 => core(fstp_domain::Command::ReleasePayment {
            request: RequestId::from_raw(1),
        }),
        _ => CellCommand::Auth(AuthCommand::RegisterCredential {
            account: own,
            credential: vec![0x5E, c, session],
        }),
    }
}

/// The session index of session id `id`.
pub fn session_index(id: [u8; 16]) -> u8 {
    if id == session(S_MAGIC).id {
        S_MAGIC
    } else {
        S_ADMIN
    }
}

/// The seam of [`prod_action_digest`], closed by lane W2c:
/// `fstp_cell_core::action_digest` gives the digest, and
/// `gate::admit_command` checks it under the command id (design section
/// 8.4). The constant stays for the suites that name it.
pub const DIGEST_SEAM: &str = "fstp_celltest::mc::stepup_model::prod_action_digest: fstp-cell-core exposes no canonical command encoding and gate::admit takes no command id (design section 8.4, lane W2c)";

/// `SHA-256(canonical(command) || command_id)` as production computes it
/// (design section 8.4): `fstp_cell_core::action_digest`.
pub fn prod_action_digest(
    cmd: &CellCommand,
    command_id: [u8; 16],
) -> Result<[u8; 32], NotImplemented> {
    Ok(fstp_cell_core::action_digest(cmd, command_id))
}

/// The seam of [`prod_self_grant_digest`], closed by lane W2c:
/// `fstp_cell_core::self_grant_digest` gives the digest, and
/// `fstp_cell_core::attest_at` and `decide_with_id` take the command id
/// (design section 5.1). It remains the refusal for a command that is not
/// a `GrantRole`.
pub const SELF_GRANT_DIGEST_SEAM: &str = "fstp_celltest::mc::stepup_model::prod_self_grant_digest: fstp-cell-core exposes no canonical GrantRole encoding without second_admin, and CellCtx and attest take no command id (design section 5.1, lane W2c)";

/// `grant_digest = SHA-256(canonical(GrantRole without second_admin) ||
/// command_id)` as production computes it (design section 5.1, SoD-07).
/// Production computes it with `fstp_cell_core::self_grant_digest`. A
/// command that is not a `GrantRole` refuses with
/// [`SELF_GRANT_DIGEST_SEAM`].
pub fn prod_self_grant_digest(
    grant: &CellCommand,
    command_id: [u8; 16],
) -> Result<[u8; 32], NotImplemented> {
    match grant {
        CellCommand::Engine(g) => fstp_cell_core::self_grant_digest(g, command_id)
            .ok_or(NotImplemented::new(SELF_GRANT_DIGEST_SEAM)),
        _ => Err(NotImplemented::new(SELF_GRANT_DIGEST_SEAM)),
    }
}

/// The seam of [`Production::commit`]: no pure entry point runs an
/// `Admitted` command (`CellEngine::execute` lives in the shell), and
/// `AuthRecord` has no `StepUpConsumed`, so consumption cannot be read
/// from a batch (design section 5.1, lane W2c). The harness owns this seam.
pub const CONSUME_SEAM: &str = "fstp_celltest::mc::stepup_model::Production::commit: no pure execute(Admitted) and no StepUpConsumed record to read consumption from (design section 5.1, lane W2c)";

/// The seam of [`login_policy_p71`], closed by lane W2c: the canonical
/// form is `fstp_cell_core::tenant::TenantLoginPolicy` (design section
/// 5.1). The constant stays for the suites that name it.
pub const POLICY_SEAM: &str = "fstp_celltest::mc::stepup_model::login_policy_p71: the canonical login policy form of SetLoginPolicy is not defined (design section 5.1, lane W2c)";

/// The canonical login policy that sets P-71 to `p71_us`, for
/// `SetLoginPolicy`: `fstp_cell_core::tenant::TenantLoginPolicy`.
pub fn login_policy_p71(p71_us: i64) -> Result<Vec<u8>, NotImplemented> {
    Ok(fstp_cell_core::tenant::TenantLoginPolicy {
        p71_us: Some(p71_us),
        ..Default::default()
    }
    .encode())
}

// ---------------------------------------------------------------------------
// Backends.

/// The decisions M-STEPUP asks of a backend.
pub trait StepUpBackend {
    /// Whether command `c` is admitted in `session` with `stepup` at `now`.
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented>;

    /// Whether the admitted command `c` commits at `now`. `Some(consumed)`
    /// when it commits, saying whether its batch consumes the step-up.
    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented>;
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl StepUpBackend for Reference {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        Ok(r::admit_high_risk(
            session,
            digest(c),
            stepup,
            now,
            r::effective_p71(Some(p71_us)),
        )
        .is_ok())
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        let ok = self.admit(session, c, stepup, now, p71_us)?;
        Ok(ok.then_some(stepup.is_some()))
    }
}

/// The production backend: `gate::admit` over a production cell from
/// genesis with tenant admin `ADMIN`.
///
/// Gaps, reported by lane W1b. A step-up's digest must be production's
/// own, so an admission with a step-up refuses with [`DIGEST_SEAM`]. The
/// commit-time freshness check has no API of its own, so commit asks
/// `gate::admit` again at the commit instant. Consumption must come from
/// the batch, so a commit refuses with [`CONSUME_SEAM`] after the gate.
#[derive(Clone, Debug)]
pub struct Production {
    cell: ProdCell,
}

fn deny_ni(d: Deny) -> Result<bool, NotImplemented> {
    match d {
        Deny::NotImplemented(op) => Err(NotImplemented::new(op)),
        _ => Ok(false),
    }
}

/// The production view of step-up `u`. Its digest is production's digest
/// of the command the model's step-up was requested for, in its session.
fn prod_view(u: &RefStepUp) -> Result<StepUpView, NotImplemented> {
    let action_digest = match command_of(&u.action_digest) {
        Some(c) => {
            prod_action_digest(&cell_command_in(session_index(u.session), c), command_id(c))?
        }
        None => u.action_digest,
    };
    Ok(StepUpView {
        id: u.id,
        session: u.session,
        action_digest,
        asserted_at: u.asserted_at,
        strong: u.method.phishing_resistant() && u.uv,
        consumed: u.consumed,
    })
}

impl Production {
    /// The production backend over a bootstrapped production cell in
    /// which the applicant b holds a passkey, registered at `T0`. So
    /// `AddPasskey` in b's magic-link session adds a second passkey,
    /// and only the magic-link rule refuses it (design section 8.3).
    pub fn new() -> Result<Production, ProdError> {
        let mut cell = ProdCell::bootstrapped()?;
        let first = CellCommand::Auth(AuthCommand::RegisterCredential {
            account: B,
            credential: credential_of(B, 0),
        });
        cell.exec(first, B, T0)?;
        Ok(Production { cell })
    }

    fn gate(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<gate::Admitted>, NotImplemented> {
        let view = stepup.map(prod_view).transpose()?;
        let policy = LoginPolicy {
            stepup_freshness_us: p71_us,
        };
        // The gate checks the step-up digest under the command id
        // ([`DIGEST_SEAM`], closed by lane W2c).
        match gate::admit_command(
            self.cell.state(),
            &prod_session(session),
            Action::Command(cell_command_in(session_index(session.id), c)),
            command_id(c),
            view.as_ref(),
            now,
            &policy,
        ) {
            Ok(a) => Ok(Some(a)),
            Err(d) => deny_ni(d).map(|_| None),
        }
    }
}

impl StepUpBackend for Production {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        Ok(self.gate(session, c, stepup, now, p71_us)?.is_some())
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        match self.gate(session, c, stepup, now, p71_us)? {
            None => Ok(None),
            Some(_admitted) => Err(NotImplemented::new(CONSUME_SEAM)),
        }
    }
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepUpDefect {
    /// A step-up 1 µs past P-71 is still accepted.
    StaleAccepted,
    /// `>=` for staleness: a step-up exactly P-71 old is refused.
    FreshAtP71Refused,
    /// The batch does not consume the step-up, and the gate ignores consumption.
    ConsumptionDropped,
    /// The digest is compared by the command's kind only.
    DigestComparedByKind,
    /// The gate forgets that a magic-link session never performs a
    /// high-risk action (design section 8.3).
    MagicLinkRuleDropped,
}

/// `inner` with one seeded defect.
#[derive(Clone, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: StepUpDefect,
}

impl<B: StepUpBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: StepUpDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }

    fn rewrite(&self, c: u8, stepup: Option<&RefStepUp>, p71_us: i64) -> (Option<RefStepUp>, i64) {
        let mut u = stepup.copied();
        let mut p = p71_us;
        match self.defect {
            StepUpDefect::StaleAccepted => p = p71_us.saturating_add(1),
            StepUpDefect::FreshAtP71Refused => p = p71_us.saturating_sub(1),
            StepUpDefect::ConsumptionDropped => {
                if let Some(x) = u.as_mut() {
                    x.consumed = false;
                }
            }
            StepUpDefect::DigestComparedByKind => {
                if let Some(x) = u.as_mut()
                    && command_of(&x.action_digest).and_then(class) == class(c)
                {
                    x.action_digest = digest(c);
                }
            }
            StepUpDefect::MagicLinkRuleDropped => {}
        }
        (u, p)
    }

    /// The session the inner backend sees: a magic-link session passes as
    /// a passkey session under [`StepUpDefect::MagicLinkRuleDropped`].
    fn session_seen(&self, session: &RefSession) -> RefSession {
        let mut s = *session;
        if self.defect == StepUpDefect::MagicLinkRuleDropped {
            s.method = RefMethod::Passkey;
        }
        s
    }
}

impl<B: StepUpBackend> StepUpBackend for Mutant<B> {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        let (u, p) = self.rewrite(c, stepup, p71_us);
        self.inner
            .admit(&self.session_seen(session), c, u.as_ref(), now, p)
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        let (u, p) = self.rewrite(c, stepup, p71_us);
        let out = self
            .inner
            .commit(&self.session_seen(session), c, u.as_ref(), now, p)?;
        if self.defect == StepUpDefect::ConsumptionDropped {
            return Ok(out.map(|_| false));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The model.

/// A step-up of the model, asserted at [`ASSERTED_AT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Su {
    /// The session index.
    pub session: u8,
    /// The command it was requested for.
    pub cmd: u8,
    /// Whether the passkey gave user verification.
    pub uv: bool,
    /// Whether a committed batch consumed it.
    pub consumed: bool,
}

/// An admitted command waiting to commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pending {
    /// The session index.
    pub session: u8,
    /// The command.
    pub cmd: u8,
    /// The step-up named, by index.
    pub stepup: Option<u8>,
    /// The tick of admission.
    pub admitted: u8,
}

/// A committed command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commit {
    /// The session index.
    pub session: u8,
    /// The command.
    pub cmd: u8,
    /// The step-up named, by index.
    pub stepup: Option<u8>,
    /// The tick of admission.
    pub admitted: u8,
    /// The tick of commit.
    pub committed: u8,
}

/// The state of M-STEPUP.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StepUpState {
    /// The P-71 variant: 0 for 5 minutes, 1 for 1 minute.
    pub p71: u8,
    /// The tick.
    pub tick: u8,
    /// The step-ups, by index.
    pub stepups: Vec<Su>,
    /// The admitted command, if any.
    pub pending: Option<Pending>,
    /// The committed commands, in order.
    pub commits: Vec<Commit>,
    /// Whether the backend refused an admission that offered a consumed
    /// step-up again (witness).
    pub replay_refused: bool,
    /// The first commit decision of the backend that differed from the
    /// reference's.
    pub diverged: Option<String>,
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

/// The most step-ups of a run.
pub const MAX_STEPUPS: usize = 2;
/// The most commits of a run: one, then one replay.
pub const MAX_COMMITS: usize = 2;

/// The step-up requests of the universe: by passkey with UV for every
/// command, by passkey without UV for a role grant, and from the
/// magic-link session for a role grant and for adding a passkey to its
/// own account.
pub const STEPUP_REQUESTS: [(u8, u8, bool); 7] = [
    (S_ADMIN, 0, true),
    (S_ADMIN, 1, true),
    (S_ADMIN, 2, true),
    (S_ADMIN, 3, true),
    (S_ADMIN, 0, false),
    (S_MAGIC, 0, true),
    (S_MAGIC, 3, true),
];

/// The admissions of the universe: every command in the admin session,
/// and in the magic-link session a role grant and `AddPasskey` for its
/// own account. Only the magic-link rule refuses the last one (design
/// section 8.3).
pub const ADMITS: [(u8, u8); 6] = [
    (S_ADMIN, 0),
    (S_ADMIN, 1),
    (S_ADMIN, 2),
    (S_ADMIN, 3),
    (S_MAGIC, 0),
    (S_MAGIC, 3),
];

impl StepUpState {
    /// The time now.
    pub fn now(&self) -> Timestamp {
        at(self.p71, self.tick)
    }

    /// The P-71 in microseconds.
    pub fn p71_us(&self) -> i64 {
        p71(self.p71)
    }

    /// The reference step-up at index `i`.
    pub fn stepup(&self, i: u8) -> Option<RefStepUp> {
        let su = self.stepups.get(usize::from(i))?;
        let mut id = [0u8; 16];
        id[0] = 0x5C;
        id[1] = i;
        Some(RefStepUp {
            id,
            session: session(su.session).id,
            action_digest: digest(su.cmd),
            asserted_at: ASSERTED_AT,
            method: RefMethod::Passkey,
            uv: su.uv,
            consumed: su.consumed,
        })
    }

    /// The step-up choices of an admission: none, or each existing one.
    pub fn stepup_choices(&self) -> Vec<Option<u8>> {
        let mut out = vec![None];
        for i in 0..self.stepups.len() {
            if let Ok(i) = u8::try_from(i) {
                out.push(Some(i));
            }
        }
        out
    }
}

/// The action of M-STEPUP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepUpAction {
    /// The clock moves one tick.
    Tick,
    /// `POST /auth/stepup` in the session for the command, with or without UV.
    StepUp(u8, u8, bool),
    /// The gate admits the command in the session, naming the step-up.
    Admit(u8, u8, Option<u8>),
    /// The admitted command commits, or is refused at commit.
    Commit,
}

/// M-STEPUP over a backend.
#[derive(Clone, Debug)]
pub struct StepUpModel<B> {
    backend: B,
}

impl<B: StepUpBackend> StepUpModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> StepUpModel<B> {
        StepUpModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: StepUpBackend> Model for StepUpModel<B> {
    type State = StepUpState;
    type Action = StepUpAction;

    fn init(&self) -> Vec<StepUpState> {
        (0..2u8)
            .map(|p71| StepUpState {
                p71,
                tick: 0,
                stepups: Vec::new(),
                pending: None,
                commits: Vec::new(),
                replay_refused: false,
                diverged: None,
                halt: None,
            })
            .collect()
    }

    fn actions(&self, s: &StepUpState, out: &mut Vec<StepUpAction>) {
        if s.halt.is_some() {
            return;
        }
        out.push(StepUpAction::Tick);
        for (session, cmd, uv) in STEPUP_REQUESTS {
            out.push(StepUpAction::StepUp(session, cmd, uv));
        }
        for (session, cmd) in ADMITS {
            for u in s.stepup_choices() {
                out.push(StepUpAction::Admit(session, cmd, u));
            }
        }
        out.push(StepUpAction::Commit);
    }

    fn step(&self, s: &StepUpState, a: &StepUpAction) -> Option<StepUpState> {
        let mut next = s.clone();
        match *a {
            StepUpAction::Tick => {
                next.tick = s.tick.checked_add(1).filter(|t| *t <= 3)?;
                Some(next)
            }
            StepUpAction::StepUp(session, cmd, uv) => {
                if s.tick != 0 || s.stepups.len() >= MAX_STEPUPS {
                    return None;
                }
                next.stepups.push(Su {
                    session,
                    cmd,
                    uv,
                    consumed: false,
                });
                Some(next)
            }
            StepUpAction::Admit(sess, cmd, u) => {
                if s.pending.is_some() || s.commits.len() >= MAX_COMMITS {
                    return None;
                }
                let su = match u {
                    Some(i) => Some(s.stepup(i)?),
                    None => None,
                };
                match self
                    .backend
                    .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                {
                    Err(e) => {
                        next.halt = Some(e.operation);
                        Some(next)
                    }
                    Ok(false) => {
                        let replay = su.is_some_and(|x| x.consumed);
                        if replay && !s.replay_refused {
                            next.replay_refused = true;
                            Some(next)
                        } else {
                            None
                        }
                    }
                    Ok(true) => {
                        next.pending = Some(Pending {
                            session: sess,
                            cmd,
                            stepup: u,
                            admitted: s.tick,
                        });
                        Some(next)
                    }
                }
            }
            StepUpAction::Commit => {
                let p = s.pending?;
                next.pending = None;
                let su = match p.stepup {
                    Some(i) => Some(s.stepup(i)?),
                    None => None,
                };
                let got = self.backend.commit(
                    &session(p.session),
                    p.cmd,
                    su.as_ref(),
                    s.now(),
                    s.p71_us(),
                );
                let want =
                    Reference.commit(&session(p.session), p.cmd, su.as_ref(), s.now(), s.p71_us());
                if let (Ok(g), Ok(w)) = (&got, &want)
                    && g != w
                    && next.diverged.is_none()
                {
                    next.diverged = Some(format!(
                        "two-way: commit of {p:?} at tick {} is {g:?}, reference {w:?}",
                        s.tick
                    ));
                }
                match got {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => {}
                    Ok(Some(consumed)) => {
                        next.commits.push(Commit {
                            session: p.session,
                            cmd: p.cmd,
                            stepup: p.stepup,
                            admitted: p.admitted,
                            committed: s.tick,
                        });
                        if let (true, Some(i)) = (consumed, p.stepup)
                            && let Some(x) = next.stepups.get_mut(usize::from(i))
                        {
                            x.consumed = true;
                        }
                    }
                }
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &StepUpState) -> bool {
        s.halt.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-STEPUP.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-78: every committed high-risk command had a strong, fresh, unconsumed step-up for its digest.
    pub const I78: &str = "I-78";
    /// I-78: no step-up authorised two commits.
    pub const I78_SINGLE_USE: &str = "I-78-single-use";
    /// Two-way: every admission and commit decision equals the reference's.
    pub const TWO_WAY: &str = "two-way";
    /// Witness: a command commits exactly P-71 after its step-up.
    pub const W_AT_P71: &str = "witness-commit-at-exactly-p71";
    /// Witness: a consumed step-up is offered again, and the backend
    /// refuses the admission.
    pub const W_REPLAY: &str = "witness-replay-refused";
}

/// Why the commit `c` breaks I-78, given the state before it.
fn i78_breach(s: &StepUpState, c: &Commit) -> Option<String> {
    let Some(i) = c.stepup else {
        return Some(format!("I-78: {c:?} committed with no step-up"));
    };
    let Some(su) = s.stepups.get(usize::from(i)) else {
        return Some(format!("I-78: {c:?} named a missing step-up"));
    };
    let sess = session(c.session);
    let p = s.p71_us();
    let fresh = |tick| r::within(ASSERTED_AT, at(s.p71, tick), p);
    if !sess.method.phishing_resistant() {
        Some(format!("I-78: {c:?} committed in a magic-link session"))
    } else if su.session != c.session {
        Some(format!("I-78: {c:?} used another session's step-up"))
    } else if digest(su.cmd) != digest(c.cmd) {
        Some(format!("I-78: {c:?} used a step-up for command {}", su.cmd))
    } else if !su.uv {
        Some(format!(
            "I-78: {c:?} used a step-up without user verification"
        ))
    } else if !fresh(c.admitted) || !fresh(c.committed) {
        Some(format!("I-78: {c:?} used a step-up older than P-71"))
    } else if s.commits.iter().any(|x| x.stepup == c.stepup) {
        Some(format!("I-78: {c:?} used a consumed step-up"))
    } else {
        None
    }
}

/// The two-way check of one state: the commit decisions so far, then
/// every admission.
fn two_way<B: StepUpBackend>(m: &StepUpModel<B>, s: &StepUpState) -> Result<(), String> {
    if let Some(why) = &s.diverged {
        return Err(why.clone());
    }
    for (sess, cmd) in ADMITS {
        for u in s.stepup_choices() {
            let su = u.and_then(|i| s.stepup(i));
            let want = Reference
                .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                .unwrap_or(false);
            if let Ok(got) =
                m.backend()
                    .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                && got != want
            {
                return Err(format!(
                    "two-way: admit of {cmd} in session {sess} with {u:?} at tick {} is {got}, reference {want}",
                    s.tick
                ));
            }
        }
    }
    Ok(())
}

/// Every property of M-STEPUP.
pub fn properties<'a, B: StepUpBackend>(
    m: &'a StepUpModel<B>,
) -> Vec<Property<'a, StepUpModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &StepUpState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::transition_with(
            ids::I78,
            |s: &StepUpState, _a: &StepUpAction, t: &StepUpState| {
                if t.commits.len() <= s.commits.len() {
                    return Ok(());
                }
                match t.commits.last().and_then(|c| i78_breach(s, c)) {
                    None => Ok(()),
                    Some(why) => Err(why),
                }
            },
        ),
        Property::always_with(ids::I78_SINGLE_USE, |s: &StepUpState| {
            for (i, c) in s.commits.iter().enumerate() {
                let reused = s
                    .commits
                    .iter()
                    .skip(i.saturating_add(1))
                    .any(|x| x.stepup.is_some() && x.stepup == c.stepup);
                if reused {
                    return Err(format!(
                        "I-78-single-use: step-up {:?} authorised two commits",
                        c.stepup
                    ));
                }
            }
            Ok(())
        }),
        Property::always_with(ids::TWO_WAY, move |s: &StepUpState| two_way(m, s)),
        Property::reachable(ids::W_AT_P71, |s: &StepUpState| {
            s.commits.iter().any(|c| c.committed == 2)
        }),
        Property::reachable(ids::W_REPLAY, |s: &StepUpState| s.replay_refused),
    ]
}

/// The account of the admin session, for tests that name it.
pub const ADMIN_ACCOUNT: AccountId = ADMIN;

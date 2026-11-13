//! The scripted call cycle of [`crate::world::World::run_cycle`] (design
//! sections 14.3, 14.4 and 19, lanes F-CYCLE1 and F-CYCLE2).
//!
//! Each step drives the cell's own routes over HTTP with software
//! passkeys, through [`crate::mc::auth_model::http::AuthClient`]. Nothing
//! here writes a store or a ledger. The step vocabulary is lane W3b's
//! (`FULL_CYCLE` in `tests/slice_http.rs`):
//!
//! - `login`: the first tenant admin enrols through the split invitation
//!   and logs in with a passkey.
//! - `create-programme`: the creator path of M4 design section 3.4. The
//!   first admin invites the second tenant admin, two programme managers
//!   and the call drafter, and grants the second admin. Their
//!   verifications are seeded (design section 6.9). The first admin opens
//!   the draft with a step-up and grants the first manager, the
//!   [`BUILDER`], with a step-up. The builder saves the synthetic spec,
//!   acknowledges the roster warning and requests activation. The second
//!   admin, who built nothing, approves with a step-up (I-66, I-67, D2e).
//!   The first admin then grants the second programme manager and the
//!   call drafter, each with a step-up.
//! - `publish-call`: `DraftCall` by the call drafter,
//!   `ApproveCallPublication` by the programme manager, then
//!   `PublishCall` by the manager with a step-up (R-PC-03, I-12).
//! - `signup`: an applicant self-registers (design section 8.3 ceremony
//!   2) with an email proof read from the world's mail capture
//!   (`crate::world_mail`) and a passkey. Its verification is seeded.
//! - `verify-identity`: the applicant's over-18 attestation is seeded
//!   (design section 6.9; the vault ticket routes cannot sign yet).
//! - `submit-proposal`: `CreateDraft`, the plan and `Submit` once the call
//!   is open.
//! - `score`: after the deadline, the Judging staff of the M2 life models
//!   are granted, two committee members are assigned, the knock-out
//!   check and admission run, both score, and stage 1 closes.
//! - `rank`: "no questions" by both reviewers.
//! - `negotiate`: the cut-off vote and the IRC validations.
//! - `grant`: the determination, the acceptance, the approval and the
//!   contract port's EFFECTIVE fact, issued in process since the cell runs
//!   no contract signature route yet.
//! - `minor-applicant:...`: the I-18 variant "Minor applicant", with a
//!   seeded guardian consent that is verified or not.
//!
//! Lane F-CYCLE3: the cell clock moves to the call's opening and past its
//! deadline, and every session is renewed by passkey after a move
//! (P-72). The world keeps a cycle's memory per cell, so a second script
//! continues the first.
//!
//! A step the cell cannot run over HTTP yet refuses with a seam that
//! names the missing part. The first refusal ends the cycle. A step name
//! outside the vocabulary refuses with [`UNKNOWN_STEP_SEAM`].
//!
//! Claims built on this cycle say so: the verifications of the staff are
//! seeded into the world's seeded vault (design section 6.9), and the
//! world cell decides creator commands over the world's creator shell
//! (`crate::world_shell`), whose probes pass and whose profile carries
//! synthetic wording in place of the pending legal wording (Q6).
//!
//! The former reading of lane F-CYCLE1, that each call of `run_cycle`
//! starts its own client, is replaced by the memory of lane F-CYCLE3.

use std::collections::BTreeMap;

use fstp_cell_core::CellCommand;
use fstp_creator::{
    CheckId, CheckSubject, CreatorCommand, FieldEdit, Provenance, ValueDigest, WarningKey,
};
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, ContentDigest, ContractId, DecisionId, Handle,
    LlmConfigId, MilestoneId, PlanVersionId, PolicyVersionId, ProposalId, TextId, TextRef,
};
use fstp_domain::roles::Role;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, STAFF_DRAFTER, STAFF_PM};
use fstp_domain_testkit::r#gen::{money, review};
use fstp_domain_testkit::mc::life_model;
use fstp_programme::{Field, FieldId, FieldValue, ProgrammeSpec};

use crate::NotImplemented;
use crate::canary::CanaryKind;
use crate::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN, Reply};
use crate::reference::auth::RefMethod;
use crate::vault_seed::SeedSource;

use crate::world::CellHandle;

/// A step that needs `login` first.
pub const NOT_LOGGED_IN: &str =
    "fstp_celltest::cycle: the step needs the login step first (its script has none before it)";

/// A step that needs `create-programme` first.
pub const NO_PROGRAMME: &str = "fstp_celltest::cycle: the step needs the create-programme step first (its script has none before it)";

/// A step that needs `publish-call` first.
pub const NO_CALL: &str = "fstp_celltest::cycle: the step needs the publish-call step first (its script has none before it)";

/// The cell refused a step it should take. Not a seam: a defect of the
/// cell or the harness, which the failing test then shows. The step and
/// the cell's reply are written to the test's standard error.
pub const STEP_REFUSED: &str = "fstp_celltest::cycle: the cell refused a request of a cycle step that it serves (the reply is on standard error)";

/// The former seam of the creator activation. Lane F-CYCLE2 closed it:
/// `fstp-cell` decides creator commands over its own environment
/// (`fstp_cell_core::creator`), and the world cell over the world shell.
pub const CREATOR_ENVIRONMENT_SEAM: &str = "fstp_celltest::cycle create-programme: the creator's activation by a second tenant admin cannot run over HTTP, since fstp-cell decides creator commands with fstp_engine::NoEnvironment (no funder profile, probes, SoD preview or attested tenant admins), and strict D2e refuses a core ActivateProgramme";

/// The former seam of `publish-call`, closed with
/// [`CREATOR_ENVIRONMENT_SEAM`].
pub const NO_ACTIVE_PROGRAMME_SEAM: &str = "fstp_celltest::cycle publish-call and later steps: no programme activates over HTTP (CREATOR_ENVIRONMENT_SEAM), so no call is drafted, approved or published";

/// The former seam of `signup`, closed by lane F-CYCLE3: `POST /auth/signup`
/// fails closed (501) no more. Self-registration needs a cell command, an email
/// proof with a lifetime and the world's mail capture.
pub const SIGNUP_SEAM: &str = "fstp_celltest::cycle signup: POST /auth/signup fails closed (501), since fstp-cell-core has no self-registration command and the email proof has no delivery (design section 8.3 ceremony 2)";

/// `verify-identity` refuses: the vault ticket routes answer 501 before
/// the engine runs them, since the route layer holds no `Ticket` key.
pub const VERIFY_IDENTITY_SEAM: &str = "fstp_celltest::cycle verify-identity: POST /api/v1/vault-tickets and /api/v1/verifications answer 501, since the route layer holds no Ticket key to sign a write ticket (design section 6.5)";

/// The former seam of `submit-proposal` and the evaluation steps, closed
/// by lane F-CYCLE3.
pub const PROPOSAL_SEAM: &str = "fstp_celltest::cycle submit-proposal, score, rank, negotiate and grant: the cycle drives no applicant or evaluation step over HTTP yet (an applicant needs signup, SIGNUP_SEAM; the M2 evaluation path needs staff and reviewer roles on the published call)";

/// The former seam of the seeding steps. Lane F-CYCLE2 closed its first
/// part: a world cell runs the seeded vault ([`crate::seeded_vault`]).
pub const VAULT_SEED_SEAM: &str = "fstp_celltest::cycle seed steps: start_cell runs fstp_vault::service::serve, not the test-only fstp-vault-seeded, so no design section 6.9 seeding (vault_seed::SeedSource) reaches a world cell's vault";

/// A seeding step of a synthetic ground truth (`seed:ground-truth:...`)
/// refuses: the M2 generators name their own account ids, and a world
/// cell's accounts are random ids made at enrolment, so no ground truth
/// maps onto a world cell yet.
pub const GROUND_TRUTH_SEAM: &str = "fstp_celltest::cycle seed:ground-truth steps: the M2 ground truth names generator account ids, and a world cell's accounts are random ids made at enrolment, so no ground truth maps onto a world cell yet";

/// An M2 path or suite step (`m2:...`, `m2-suite:...`) refuses: each replays an
/// M2 generator on the cell, whose commands name generator account ids
/// and instants. The cycle drives no generator over HTTP yet: each step
/// needs an enrolled account per generator account and the generator's
/// proposals through the command route.
pub const M2_SETUP_SEAM: &str = "fstp_celltest::cycle m2 and m2-suite steps: the cycle drives no M2 generator over HTTP yet (each needs an enrolled cell account per generator account at the generator's own id, the generator's programme through the creator path, and its instants on the cell clock; the cycle's own path from signup to GRANTED runs over HTTP since lane F-CYCLE3)";

/// A step name outside the vocabulary of the module documentation.
pub const UNKNOWN_STEP_SEAM: &str = "fstp_celltest::cycle: the step is outside lane W3b's vocabulary (login, create-programme, publish-call, signup, verify-identity, submit-proposal, score, rank, negotiate, grant); the canary and fault steps of other tests are not defined yet";

/// An evaluation step that needs a proposal the cycle drafted, or a
/// Judging staff member it granted.
pub const NO_PROPOSAL: &str = "fstp_celltest::cycle: the step needs a proposal drafted by submit-proposal or minor-applicant:draft, and the Judging staff of the score step, before it";

/// A step that needs an applicant who signed up and has not drafted yet.
pub const NO_APPLICANT: &str =
    "fstp_celltest::cycle: the step needs the signup step first (its script has none before it)";

/// The model ids of applicants and guardians start above this number, so
/// they never meet an M2 generator account.
const APPLICANTS: u128 = 9_000;

/// A stage 1 score in full on each P-01 criterion of the SuperSAFE
/// fixture: three criteria on a scale of 0 to 5.
const FULL_MARKS: [u8; 3] = [5, 5, 5];

/// The draft's first policy version.
const VERSION: PolicyVersionId = PolicyVersionId::from_raw(1);
/// The programme manager who builds the draft. R-PC-03 counts the last
/// authors of P-01 and P-09 as drafters of every call of the programme,
/// so the builder never approves a call. `STAFF_PM` approves and
/// publishes.
pub const BUILDER: AccountId = AccountId::from_raw(5);
/// The binding of the builder.
const BUILDER_BINDING: BindingId = BindingId::from_raw(1);
/// The binding of the programme manager who publishes.
const PM_BINDING: BindingId = BindingId::from_raw(3);
/// The binding of the call drafter.
const DRAFTER_BINDING: BindingId = BindingId::from_raw(2);
/// The activation decision.
const ACTIVATION: DecisionId = DecisionId::from_raw(900);
/// The cycle's call.
pub const CALL: CallId = CallId::from_raw(1);
/// The call's publication approval.
const CALL_APPROVAL: DecisionId = DecisionId::from_raw(101);
/// The P-21 primary model of the SuperSAFE fixture, which a publication
/// pins.
const PRIMARY_MODEL: &str = "placeholder-model";
/// One day, in microseconds.
const DAY: i64 = 86_400_000_000;

/// One proposal the cycle drives: its applicant, its plan and the
/// assignments of its evaluation.
struct Run {
    /// The applicant's model account.
    lead: AccountId,
    /// The applicant's session.
    cookie: Cookie,
    /// The proposal.
    proposal: ProposalId,
    /// Its submitted plan.
    plan: PlanVersionId,
    /// The stage 1 reviewers and their assignments.
    reviewers: Vec<(AccountId, AssignmentId)>,
    /// The IRC members and their assignments.
    irc: Vec<(AccountId, AssignmentId)>,
}

/// What a cycle keeps between two scripts on one cell (lane F-CYCLE3):
/// the client's passkeys and sessions and the cycle's progress. The
/// world keeps it per cell, so `World::run_cycle` continues a cell's
/// cycle, and a second script reuses the first one's programme and call.
pub struct CycleMemory {
    client: crate::mc::auth_model::http::ClientMemory,
    admin: Option<Cookie>,
    approver: Option<Cookie>,
    manager: Option<Cookie>,
    drafter: Option<Cookie>,
    active: bool,
    call: bool,
    window: Option<(i64, i64)>,
    calls: u128,
    person: u64,
    judges: BTreeMap<AccountId, Cookie>,
    next: u128,
    applicants: u128,
    pending: Option<(AccountId, Cookie)>,
    current: Option<Run>,
}

impl std::fmt::Debug for CycleMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CycleMemory")
            .field("active", &self.active)
            .field("call", &self.call)
            .finish_non_exhaustive()
    }
}

/// One cycle on one cell.
pub struct Cycle<'w> {
    client: AuthClient<'w>,
    admin: Option<Cookie>,
    approver: Option<Cookie>,
    manager: Option<Cookie>,
    drafter: Option<Cookie>,
    active: bool,
    call: bool,
    /// The call's opening instant and deadline, once published.
    window: Option<(i64, i64)>,
    /// The calls published so far. The latest is the current call.
    calls: u128,
    /// The next synthetic person id of a seeded verification.
    person: u64,
    /// The sessions of the Judging staff, once granted ([`JUDGES`]).
    judges: BTreeMap<AccountId, Cookie>,
    /// The next synthetic id of a proposal, binding, assignment, decision
    /// or contract.
    next: u128,
    /// The applicants who signed up so far.
    applicants: u128,
    /// The applicant who signed up and has not drafted yet.
    pending: Option<(AccountId, Cookie)>,
    /// The proposal the evaluation steps act on.
    current: Option<Run>,
}

impl<'w> Cycle<'w> {
    /// A cycle on `cell`.
    pub fn new(cell: &'w CellHandle) -> Cycle<'w> {
        Cycle {
            client: AuthClient::new(cell),
            admin: None,
            approver: None,
            manager: None,
            drafter: None,
            active: false,
            call: false,
            window: None,
            calls: 0,
            person: 1,
            judges: BTreeMap::new(),
            next: 1_000,
            applicants: 0,
            pending: None,
            current: None,
        }
    }

    /// The cycle on `cell` that continues from `memory`.
    pub fn resume(cell: &'w CellHandle, memory: CycleMemory) -> Cycle<'w> {
        Cycle {
            client: AuthClient::resume(cell, memory.client),
            admin: memory.admin,
            approver: memory.approver,
            manager: memory.manager,
            drafter: memory.drafter,
            active: memory.active,
            call: memory.call,
            window: memory.window,
            calls: memory.calls,
            person: memory.person,
            judges: memory.judges,
            next: memory.next,
            applicants: memory.applicants,
            pending: memory.pending,
            current: memory.current,
        }
    }

    /// What the cycle keeps for the next script on its cell.
    pub fn into_memory(self) -> CycleMemory {
        CycleMemory {
            client: self.client.into_memory(),
            admin: self.admin,
            approver: self.approver,
            manager: self.manager,
            drafter: self.drafter,
            active: self.active,
            call: self.call,
            window: self.window,
            calls: self.calls,
            person: self.person,
            judges: self.judges,
            next: self.next,
            applicants: self.applicants,
            pending: self.pending,
            current: self.current,
        }
    }

    /// Runs `steps` in order and stops at the first refusal.
    ///
    /// # Errors
    ///
    /// The seam or refusal of the first step that did not run.
    pub fn run(&mut self, steps: &[String]) -> Result<(), NotImplemented> {
        for step in steps {
            self.step(step)?;
        }
        Ok(())
    }

    /// Runs one step.
    ///
    /// # Errors
    ///
    /// The step's seam, [`STEP_REFUSED`] or [`UNKNOWN_STEP_SEAM`].
    pub fn step(&mut self, step: &str) -> Result<(), NotImplemented> {
        match step {
            "login" => self.login(),
            "create-programme" => self.create_programme(),
            "publish-call" => self.publish_call(),
            "signup" => self.signup(),
            "verify-identity" => self.verify_identity(),
            "submit-proposal" => self.submit_proposal(),
            "score" => self.score(),
            "rank" => self.rank(),
            "negotiate" => self.negotiate(),
            "grant" => self.grant(),
            "minor-applicant:draft" => self.minor_draft(),
            "minor-applicant:submit" => self.submit(),
            "minor-applicant:evaluate" => {
                self.score()?;
                self.rank()?;
                self.cut_off()
            }
            "minor-applicant:irc-validate" => self.irc_validate(),
            "minor-applicant:seed-verified-guardian-consent" => self.guardian_consent(true),
            "minor-applicant:seed-unverified-guardian-consent" => self.guardian_consent(false),
            "minor-applicant:negotiate-and-grant" => {
                self.revalidate()?;
                self.grant()
            }
            s if s.starts_with("seed:ground-truth") => Err(NotImplemented::new(GROUND_TRUTH_SEAM)),
            s if s.starts_with("m2:") || s.starts_with("m2-suite:") => {
                Err(NotImplemented::new(M2_SETUP_SEAM))
            }
            _ => Err(NotImplemented::new(UNKNOWN_STEP_SEAM)),
        }
    }

    fn refused(step: &str, what: &str, reply: Option<&Reply>) -> NotImplemented {
        match reply {
            Some(r) => eprintln!(
                "fstp_celltest::cycle {step}: {what} refused: {} {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            ),
            None => eprintln!("fstp_celltest::cycle {step}: {what} refused"),
        }
        NotImplemented::new(STEP_REFUSED)
    }

    /// `command` in `session`, with a step-up when `stepup` holds. A
    /// refusal ends the step with [`STEP_REFUSED`].
    fn command(
        &self,
        step: &str,
        what: &str,
        session: &Cookie,
        command: CellCommand,
        stepup: bool,
    ) -> Result<(), NotImplemented> {
        match self.client.command_reply(session, &command, stepup)? {
            Some(r) if r.ok() => Ok(()),
            other => Err(Self::refused(step, what, other.as_ref())),
        }
    }

    /// The cell's state, replayed from its ledger.
    fn state(&self) -> Result<fstp_cell_core::CellState, NotImplemented> {
        let failed = || NotImplemented::new(STEP_REFUSED);
        let ledger = self.client.cell().ledger().map_err(|_| failed())?;
        fstp_cell_core::replay(&ledger).map_err(|_| failed())
    }

    /// The cell's clock instant.
    fn now(&self) -> i64 {
        self.client.cell().clock().now()
    }

    /// The cell account of the enrolled model account `who`.
    fn account(&self, step: &str, who: AccountId) -> Result<AccountId, NotImplemented> {
        self.client
            .cell_account(who)
            .ok_or_else(|| Self::refused(step, "the account lookup", None))
    }

    /// Enrols `who` and logs it in with its passkey.
    fn enrol_and_login(&self, step: &str, who: AccountId) -> Result<Cookie, NotImplemented> {
        if !self.client.enrol(who)? {
            return Err(Self::refused(step, "an enrolment", None));
        }
        self.client
            .login(who, RefMethod::Passkey)?
            .ok_or_else(|| Self::refused(step, "a passkey login", None))
    }

    /// Seeds a verification of `who` with an identity of its own (design
    /// section 6.9). It becomes effective once the cell reacts to its
    /// epoch, before the cell's next command that asks the vault.
    fn verify(&mut self, step: &str, who: AccountId) -> Result<(), NotImplemented> {
        let account = self.account(step, who)?;
        // A synthetic attribute tuple of its own per person.
        let attributes = format!("synthetic-person-{}", self.person);
        self.person = self.person.saturating_add(1);
        self.client
            .cell()
            .seed_verification(account, attributes.as_bytes())
            .map(|_| ())
            .map_err(|e| {
                eprintln!("fstp_celltest::cycle {step}: the seeded verification: {e}");
                NotImplemented::new(STEP_REFUSED)
            })
    }

    /// `login`: the first admin enrols with both invitation halves and
    /// logs in with a passkey (I-77, design section 8.3).
    fn login(&mut self) -> Result<(), NotImplemented> {
        if !self.client.enrol(FIRST_ADMIN)? {
            return Err(Self::refused("login", "the first admin's enrolment", None));
        }
        let session = self
            .client
            .login(FIRST_ADMIN, RefMethod::Passkey)?
            .ok_or_else(|| Self::refused("login", "the first admin's login", None))?;
        self.admin = Some(session);
        Ok(())
    }

    /// `create-programme` (module documentation): the creator path to an
    /// active programme P1, then the call drafter's grant.
    fn create_programme(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "create-programme";
        if self.active {
            return Ok(());
        }
        let admin = self
            .admin
            .clone()
            .ok_or(NotImplemented::new(NOT_LOGGED_IN))?;
        // The second tenant admin, who approves, and the staff.
        let approver = self.enrol_and_login(STEP, ADMIN_2)?;
        if !self.client.roster(
            &admin,
            crate::mc::auth_model::RosterChange::GrantAdmin { account: ADMIN_2 },
        )? {
            return Err(Self::refused(STEP, "GrantTenantAdmin", None));
        }
        let builder = self.enrol_and_login(STEP, BUILDER)?;
        let manager = self.enrol_and_login(STEP, STAFF_PM)?;
        let drafter = self.enrol_and_login(STEP, STAFF_DRAFTER)?;
        // Design section 6.9: the verifications SoD-09 and I-67 read.
        for who in [FIRST_ADMIN, ADMIN_2, BUILDER, STAFF_PM, STAFF_DRAFTER] {
            self.verify(STEP, who)?;
        }
        // The draft, opened by the first admin (R-PG-02, D1).
        let he = fstp_programme::FunderProfile::horizon_europe();
        let profile = fstp_programme::compile(
            &he.blank(),
            &he,
            fstp_programme::CompileIds::new(P1, VERSION, None),
        )
        .map_err(|_| Self::refused(STEP, "the blank policy", None))?
        .policy
        .frozen
        .p53;
        self.command(
            STEP,
            "OpenDraft",
            &admin,
            creator(CreatorCommand::OpenDraft {
                programme: P1,
                version: VERSION,
                profile,
            }),
            true,
        )?;
        let b = self.account(STEP, BUILDER)?;
        self.command(
            STEP,
            "the builder's GrantRole",
            &admin,
            grant(BUILDER_BINDING, b, Role::ProgrammeManager, self.now()),
            true,
        )?;
        // The builder builds the draft.
        let head = self.head(STEP)?;
        self.command(
            STEP,
            "SaveFields",
            &builder,
            creator(CreatorCommand::SaveFields {
                programme: P1,
                base: head,
                fields: save_of(&synthetic_spec()?),
            }),
            false,
        )?;
        let head = self.head(STEP)?;
        self.command(
            STEP,
            "the roster warning's acknowledgement",
            &builder,
            creator(CreatorCommand::AcknowledgeWarning {
                programme: P1,
                revision: head,
                warning: WarningKey {
                    check: CheckId::RosterShort,
                    subject: CheckSubject::Draft,
                },
            }),
            false,
        )?;
        let head = self.head(STEP)?;
        self.command(
            STEP,
            "RequestActivation",
            &builder,
            creator(CreatorCommand::RequestActivation {
                programme: P1,
                revision: head,
            }),
            false,
        )?;
        // I-66, I-67, D2e: the second admin approves with a step-up.
        let head = self.head(STEP)?;
        self.command(
            STEP,
            "ApproveActivation",
            &approver,
            creator(CreatorCommand::ApproveActivation {
                programme: P1,
                revision: head,
                decision: ACTIVATION,
            }),
            true,
        )?;
        self.active = true;
        let pm = self.account(STEP, STAFF_PM)?;
        self.command(
            STEP,
            "the programme manager's GrantRole",
            &admin,
            grant(PM_BINDING, pm, Role::ProgrammeManager, self.now()),
            true,
        )?;
        let d = self.account(STEP, STAFF_DRAFTER)?;
        self.command(
            STEP,
            "the call drafter's GrantRole",
            &admin,
            grant(DRAFTER_BINDING, d, Role::CallDrafter, self.now()),
            true,
        )?;
        self.approver = Some(approver);
        self.manager = Some(manager);
        self.drafter = Some(drafter);
        Ok(())
    }

    /// The head revision of the draft of P1.
    fn head(&self, step: &str) -> Result<fstp_creator::DraftRevision, NotImplemented> {
        self.state()?
            .engine()
            .creator
            .head(P1)
            .ok_or_else(|| Self::refused(step, "the draft's head", None))
    }

    /// `publish-call`: the call drafter drafts the call, the programme
    /// manager approves its publication and publishes it with a step-up
    /// (R-PC-03, I-12). The call opens a day after the cell's instant and
    /// closes thirty days after it.
    fn publish_call(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "publish-call";
        // A published call that still takes drafts serves the script. Once
        // its deadline passed, a later script gets a new call (lane
        // F-CYCLE3).
        if self.call
            && self
                .window
                .is_some_and(|(_, deadline)| self.now() < deadline)
        {
            return Ok(());
        }
        if !self.active {
            return Err(NotImplemented::new(NO_PROGRAMME));
        }
        let (Some(manager), Some(drafter)) = (self.manager.clone(), self.drafter.clone()) else {
            return Err(NotImplemented::new(NO_PROGRAMME));
        };
        let call = CallId::from_raw(self.calls.saturating_add(1));
        let approval = if self.calls == 0 {
            CALL_APPROVAL
        } else {
            DecisionId::from_raw(self.fresh())
        };
        let now = self.now();
        self.window = Some((now.saturating_add(DAY), now.saturating_add(30 * DAY)));
        let budget = fstp_money::Amount::from_minor(40_000_000, fstp_money::Currency::Eur)
            .ok()
            .and_then(|a| fstp_money::NonNegAmount::new(a).ok())
            .ok_or_else(|| Self::refused(STEP, "the call budget", None))?;
        let zone = ZoneName::new("Europe/Brussels")
            .ok_or_else(|| Self::refused(STEP, "the zone", None))?;
        self.command(
            STEP,
            "DraftCall",
            &drafter,
            core(fstp_domain::Command::DraftCall {
                call,
                programme: P1,
                opens: Timestamp::from_micros(now.saturating_add(DAY)),
                deadline: Timestamp::from_micros(now.saturating_add(30 * DAY)),
                deadline_zone: zone,
                budget,
                text: synthetic_text(0x0c),
            }),
            false,
        )?;
        self.command(
            STEP,
            "ApproveCallPublication",
            &manager,
            core(fstp_domain::Command::ApproveCallPublication {
                call,
                decision: approval,
            }),
            false,
        )?;
        self.command(
            STEP,
            "PublishCall",
            &manager,
            core(fstp_domain::Command::PublishCall {
                call,
                config: LlmConfigId::from_raw(1),
                config_model: fstp_domain::policy::ModelRef(PRIMARY_MODEL.to_owned()),
            }),
            true,
        )?;
        self.call = true;
        self.calls = self.calls.saturating_add(1);
        Ok(())
    }

    // -----------------------------------------------------------------
    // The applicant and the evaluation (lane F-CYCLE3).

    /// The current call: the latest one published ([`CALL`] first).
    fn call_id(&self) -> CallId {
        CallId::from_raw(self.calls.max(1))
    }

    /// A fresh synthetic id.
    fn fresh(&mut self) -> u128 {
        self.next = self.next.saturating_add(1);
        self.next
    }

    /// Moves the cell clock forward to `at`, never back. A move ends every
    /// session by P-72, so each person the cycle holds a session of logs
    /// in again with its passkey.
    fn clock_to(&mut self, step: &str, at: i64) -> Result<(), NotImplemented> {
        let clock = self.client.cell().clock();
        if clock.now() >= at {
            return Ok(());
        }
        clock.set(at);
        let again = |c: &Self, who: AccountId| -> Result<Cookie, NotImplemented> {
            c.client
                .login(who, RefMethod::Passkey)?
                .ok_or_else(|| Self::refused(step, "a passkey login after the clock moved", None))
        };
        for (slot, who) in [
            (0, FIRST_ADMIN),
            (1, ADMIN_2),
            (2, STAFF_PM),
            (3, STAFF_DRAFTER),
        ] {
            let held = match slot {
                0 => self.admin.is_some(),
                1 => self.approver.is_some(),
                2 => self.manager.is_some(),
                _ => self.drafter.is_some(),
            };
            if held {
                let c = again(self, who)?;
                match slot {
                    0 => self.admin = Some(c),
                    1 => self.approver = Some(c),
                    2 => self.manager = Some(c),
                    _ => self.drafter = Some(c),
                }
            }
        }
        let judges: Vec<AccountId> = self.judges.keys().copied().collect();
        for who in judges {
            let c = again(self, who)?;
            self.judges.insert(who, c);
        }
        if let Some((who, _)) = self.pending.clone() {
            let c = again(self, who)?;
            self.pending = Some((who, c));
        }
        if let Some(lead) = self.current.as_ref().map(|r| r.lead) {
            let c = again(self, lead)?;
            if let Some(run) = self.current.as_mut() {
                run.cookie = c;
            }
        }
        Ok(())
    }

    /// The current proposal, or [`NO_PROPOSAL`].
    fn run_of(&self) -> Result<&Run, NotImplemented> {
        self.current
            .as_ref()
            .ok_or(NotImplemented::new(NO_PROPOSAL))
    }

    /// The session of the Judging staff member `who`.
    fn judge(&self, who: AccountId) -> Result<Cookie, NotImplemented> {
        self.judges
            .get(&who)
            .cloned()
            .ok_or(NotImplemented::new(NO_PROPOSAL))
    }

    /// Runs `command` by `who`'s session `cookie` with no step-up.
    fn by(
        &self,
        step: &str,
        what: &str,
        cookie: &Cookie,
        command: fstp_domain::Command,
    ) -> Result<(), NotImplemented> {
        self.command(step, what, cookie, core(command), false)
    }

    /// A new applicant self-registers (design section 8.3 ceremony 2) with
    /// a canary address, and its verification is seeded (design section
    /// 6.9). Its session is the current applicant's.
    fn new_applicant(&mut self, step: &str) -> Result<(AccountId, Cookie), NotImplemented> {
        self.applicants = self.applicants.saturating_add(1);
        let who = AccountId::from_raw(APPLICANTS.saturating_add(self.applicants));
        let email = crate::canary::Canary::generate(self.client.cell().index(), CanaryKind::Email)
            .map_err(|_| Self::refused(step, "the canary address", None))?
            .email_address();
        let cookie = self
            .client
            .signup(who, &email)?
            .ok_or_else(|| Self::refused(step, "the self-registration", None))?;
        self.verify(step, who)?;
        Ok((who, cookie))
    }

    /// `signup`: an applicant self-registers with an email proof from the
    /// world's mail capture and a passkey (design section 8.3 ceremony 2).
    fn signup(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "signup";
        if !self.call {
            return Err(NotImplemented::new(NO_CALL));
        }
        let (who, cookie) = self.new_applicant(STEP)?;
        self.pending = Some((who, cookie));
        Ok(())
    }

    /// `verify-identity`: the applicant's over-18 attestation reaches the
    /// vault. Claim: it is seeded (design section 6.9), since the vault
    /// ticket routes cannot sign a write ticket yet
    /// ([`VERIFY_IDENTITY_SEAM`]). The verification itself was seeded at
    /// signup.
    fn verify_identity(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "verify-identity";
        let (who, _) = self
            .pending
            .clone()
            .ok_or(NotImplemented::new(NO_APPLICANT))?;
        let account = self.account(STEP, who)?;
        self.client
            .cell()
            .seed_vault_fact(
                SeedSource::SyntheticVerification,
                fstp_vault_core::fact::Fact::AdultAttestation {
                    account: fstp_vault_proto::WireAccount(account.raw()),
                    adult_from: crate::world::WORLD_CLOCK_START,
                },
            )
            .map(|_| ())
            .map_err(|e| {
                eprintln!("fstp_celltest::cycle {STEP}: the seeded attestation: {e}");
                NotImplemented::new(STEP_REFUSED)
            })
    }

    /// The draft of the pending applicant, opened with its plan once the
    /// call is open: `CreateDraft` (the cell sets the minor flag, I-18)
    /// and `RecordPlanVersion` of one milestone of 20 000.00 EUR.
    fn draft(&mut self, step: &str) -> Result<(), NotImplemented> {
        let (opens, _) = self.window.ok_or(NotImplemented::new(NO_CALL))?;
        self.clock_to(step, opens.saturating_add(DAY / 24))?;
        let (lead, cookie) = self
            .pending
            .take()
            .ok_or(NotImplemented::new(NO_APPLICANT))?;
        let proposal = ProposalId::from_raw(self.fresh());
        let binding = BindingId::from_raw(self.fresh());
        self.by(
            step,
            "CreateDraft",
            &cookie,
            fstp_domain::Command::CreateDraft {
                proposal,
                call: self.call_id(),
                binding,
                minor: true,
            },
        )?;
        let plan = PlanVersionId::from_raw(self.fresh());
        let milestone = MilestoneId::from_raw(self.fresh());
        let now = self.now();
        let amount = fstp_money::Amount::from_minor(2_000_000, fstp_money::Currency::Eur)
            .ok()
            .and_then(|a| fstp_money::PosAmount::new(a).ok())
            .ok_or_else(|| Self::refused(step, "the milestone amount", None))?;
        let mut digest = [0u8; 32];
        digest[..16].copy_from_slice(&plan.raw().to_be_bytes());
        self.by(
            step,
            "RecordPlanVersion",
            &cookie,
            fstp_domain::Command::RecordPlanVersion {
                plan,
                proposal,
                origin: fstp_domain::proposal::PlanOrigin::Submitted,
                supersedes: None,
                tasks: vec![fstp_domain::proposal::Task {
                    milestones: vec![fstp_domain::proposal::Milestone {
                        id: milestone,
                        amount,
                        start: Timestamp::from_micros(now),
                        due: Timestamp::from_micros(now.saturating_add(365 * DAY)),
                        activity: None,
                        deliverables: Vec::new(),
                    }],
                }],
                content: ContentDigest::from_bytes(digest),
            },
        )?;
        self.current = Some(Run {
            lead,
            cookie,
            proposal,
            plan,
            reviewers: Vec::new(),
            irc: Vec::new(),
        });
        Ok(())
    }

    /// The applicant submits the current proposal (R-SB-05, R-NG-06).
    fn submit(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "submit-proposal";
        let run = self.run_of()?;
        let s = review::submit(run.lead, run.proposal, run.plan, false);
        self.by(STEP, "Submit", &run.cookie, s.cmd)
    }

    /// `submit-proposal`: `CreateDraft`, the plan and `Submit` by the
    /// applicant (design section 14.4). An applicant signs up first when
    /// the script has no `signup` step.
    fn submit_proposal(&mut self) -> Result<(), NotImplemented> {
        // A script without `signup` (`t_iso_i19`, `i19_boundary`) still
        // has its applicant sign up first.
        if self.pending.is_none() {
            let applicant = self.new_applicant("submit-proposal")?;
            self.pending = Some(applicant);
        }
        self.draft("submit-proposal")?;
        self.submit()
    }

    /// The Judging staff of the evaluation (`life_judges` of the M2 life
    /// models): each enrols, its verification is seeded, and the first
    /// tenant admin grants its role on P1 with a step-up. Runs once per
    /// cell.
    fn ensure_judges(&mut self, step: &str) -> Result<(), NotImplemented> {
        if !self.judges.is_empty() {
            return Ok(());
        }
        let admin = self
            .admin
            .clone()
            .ok_or(NotImplemented::new(NOT_LOGGED_IN))?;
        for (who, role, org) in life_model::life_judges() {
            let cookie = self.enrol_and_login(step, who)?;
            self.verify(step, who)?;
            let account = self.account(step, who)?;
            let binding = BindingId::from_raw(self.fresh());
            let mut command = grant(binding, account, role, self.now());
            if let CellCommand::Engine(fstp_engine::Command::Core(
                fstp_domain::Command::GrantRole { organisation, .. },
            )) = &mut command
            {
                *organisation = org;
            }
            self.command(step, "a Judging GrantRole", &admin, command, true)?;
            self.judges.insert(who, cookie);
        }
        Ok(())
    }

    /// `score`: after the call deadline, the coordinator assigns two
    /// committee members of two organisations (P-03, P-39), each declares
    /// no conflict, the coordinator declares none for the proposal, checks
    /// the knock-out criteria (P-09) and admits it to STAGE1. Both
    /// reviewers score it in full (P-01), and the coordinator closes stage
    /// 1 (R-EV-01 to R-EV-04).
    fn score(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "score";
        let (_, deadline) = self.window.ok_or(NotImplemented::new(NO_CALL))?;
        self.clock_to(STEP, deadline.saturating_add(1_000_000))?;
        self.ensure_judges(STEP)?;
        let coordinator = self.judge(review::COORDINATOR)?;
        let (proposal, plan) = {
            let run = self.run_of()?;
            (run.proposal, run.plan)
        };
        let mut reviewers = Vec::new();
        for r in [review::R1, review::R2] {
            let reviewer = self.account(STEP, r)?;
            let assignment = AssignmentId::from_raw(self.fresh());
            let handle = Handle::from_bytes(self.fresh().to_be_bytes());
            // Assign is a strict addition to the high-risk table (G28, Q38).
            self.command(
                STEP,
                "Assign",
                &coordinator,
                core(
                    review::assign(
                        review::COORDINATOR,
                        assignment,
                        proposal,
                        reviewer,
                        AssignmentKind::Reviewer,
                        Some(handle),
                    )
                    .cmd,
                ),
                true,
            )?;
            let own = self.judge(r)?;
            self.by(
                STEP,
                "the reviewer's DeclareConflict",
                &own,
                review::declare(r, DeclarationSubject::Assignment(assignment), false, false).cmd,
            )?;
            reviewers.push((r, assignment));
        }
        self.by(
            STEP,
            "the coordinator's DeclareConflict",
            &coordinator,
            review::declare(
                review::COORDINATOR,
                DeclarationSubject::Proposal(proposal),
                false,
                false,
            )
            .cmd,
        )?;
        let mut knock = life_model::knock_out(proposal, true).cmd;
        if let fstp_domain::Command::RecordKnockOut { decision, .. } = &mut knock {
            *decision = DecisionId::from_raw(self.fresh());
        }
        self.by(STEP, "RecordKnockOut", &coordinator, knock)?;
        let admission = DecisionId::from_raw(self.fresh());
        self.by(
            STEP,
            "AdmitToStage1",
            &coordinator,
            fstp_domain::Command::AdmitToStage1 {
                decision: admission,
                proposal,
            },
        )?;
        for (r, assignment) in &reviewers {
            let own = self.judge(*r)?;
            let key = ScoreKey {
                assignment: *assignment,
                stage: Stage::One,
                plan,
            };
            self.by(
                STEP,
                "RecordScore",
                &own,
                life_model::score(*r, key, &FULL_MARKS).cmd,
            )?;
        }
        self.by(
            STEP,
            "CloseStage1",
            &coordinator,
            fstp_domain::Command::CloseStage1 { proposal },
        )?;
        if let Some(run) = self.current.as_mut() {
            run.reviewers = reviewers;
        }
        Ok(())
    }

    /// `rank`: each reviewer records "no questions" in stage 2, which
    /// ranks the proposal on its stage 1 score (R-EV-05, R-EV-06).
    fn rank(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "rank";
        let run = self.run_of()?;
        for (r, assignment) in &run.reviewers {
            let own = self.judge(*r)?;
            self.by(
                STEP,
                "RecordNoQuestions",
                &own,
                fstp_domain::Command::RecordNoQuestions {
                    proposal: run.proposal,
                    assignment: *assignment,
                },
            )?;
        }
        Ok(())
    }

    /// The cut-off of the call's ranked proposals (R-EV-08, R-EV-09): a
    /// committee member opens the round, the three committee members vote
    /// for it, and the opener records it. The proposal goes to IRC_REVIEW.
    fn cut_off(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "negotiate";
        let proposal = self.run_of()?.proposal;
        let round = DecisionId::from_raw(self.fresh());
        let steps = life_model::cut_off(
            review::R1,
            round,
            self.call_id(),
            vec![proposal],
            1,
            false,
            life_model::ballots(&[review::R1, review::R2, review::R3], Vote::For),
        );
        for s in steps {
            let Actor::Account(who) = s.actor else {
                return Err(Self::refused(STEP, "a cut-off step", None));
            };
            let own = self.judge(who)?;
            self.by(STEP, "a cut-off step", &own, s.cmd)?;
        }
        Ok(())
    }

    /// The coordinator assigns the two IRC members (P-15), each declares
    /// no conflict and validates (R-IR-01). An adult's proposal goes to
    /// NEGOTIATION. A minor-flagged one stays in IRC_REVIEW until its
    /// guardian consent is effective (I-18, NOTE 14).
    fn irc_validate(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "negotiate";
        let coordinator = self.judge(review::COORDINATOR)?;
        let proposal = self.run_of()?.proposal;
        let mut irc = Vec::new();
        for m in [review::IRC, life_model::IRC2] {
            let member = self.account(STEP, m)?;
            let assignment = AssignmentId::from_raw(self.fresh());
            let handle = Handle::from_bytes(self.fresh().to_be_bytes());
            self.command(
                STEP,
                "the IRC Assign",
                &coordinator,
                core(
                    review::assign(
                        review::COORDINATOR,
                        assignment,
                        proposal,
                        member,
                        AssignmentKind::Irc,
                        Some(handle),
                    )
                    .cmd,
                ),
                true,
            )?;
            let own = self.judge(m)?;
            self.by(
                STEP,
                "the IRC member's DeclareConflict",
                &own,
                review::declare(m, DeclarationSubject::Assignment(assignment), false, false).cmd,
            )?;
            irc.push((m, assignment));
        }
        for (m, assignment) in &irc {
            let own = self.judge(*m)?;
            self.by(
                STEP,
                "RecordIrcReview",
                &own,
                life_model::irc_review(*m, *assignment, true).cmd,
            )?;
        }
        if let Some(run) = self.current.as_mut() {
            run.irc = irc;
        }
        Ok(())
    }

    /// `negotiate`: the cut-off, then the IRC review (state machine NOTE
    /// 14).
    fn negotiate(&mut self) -> Result<(), NotImplemented> {
        self.cut_off()?;
        self.irc_validate()
    }

    /// The last IRC member repeats the validation, which records the entry
    /// into NEGOTIATION once the guardian consent is effective. Without an
    /// effective consent the cell refuses it (I-18, R-IR-01).
    fn revalidate(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "negotiate";
        let (m, assignment) = self
            .run_of()?
            .irc
            .last()
            .copied()
            .ok_or(NotImplemented::new(NO_PROPOSAL))?;
        let own = self.judge(m)?;
        self.by(
            STEP,
            "the repeated RecordIrcReview",
            &own,
            life_model::irc_review(m, assignment, true).cmd,
        )
    }

    /// `grant`: the first reviewer determines the amount on the submitted
    /// plan, the applicant accepts it, the programme manager approves it,
    /// and the contract port records the contract EFFECTIVE, which takes
    /// the proposal to GRANTED (R-NG-01 to R-NG-03, I-30).
    ///
    /// Claim: the contract fact is issued in process
    /// (`CellHandle::contract_effective`), since the cell runs no contract
    /// signature route yet. Every other step goes through the routes.
    fn grant(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "grant";
        let manager = self
            .manager
            .clone()
            .ok_or(NotImplemented::new(NO_PROGRAMME))?;
        let (lead, cookie, proposal, plan) = {
            let run = self.run_of()?;
            (run.lead, run.cookie.clone(), run.proposal, run.plan)
        };
        let reviewer = self.judge(review::R1)?;
        let determination = DecisionId::from_raw(self.fresh());
        let determine = money::determine(review::R1, proposal, determination, plan, &[])
            .map_err(|_| Self::refused(STEP, "the determination", None))?;
        self.by(STEP, "DetermineAmount", &reviewer, determine.cmd)?;
        let accept = DecisionId::from_raw(self.fresh());
        self.by(
            STEP,
            "AcceptGrant",
            &cookie,
            money::accept_grant_as(lead, proposal, accept, determination).cmd,
        )?;
        let approve = DecisionId::from_raw(self.fresh());
        self.by(
            STEP,
            "ApproveGrant",
            &manager,
            money::approve_grant_as(STAFF_PM, proposal, approve, determination).cmd,
        )?;
        let contract = ContractId::from_raw(self.fresh());
        self.client
            .cell()
            .contract_effective(proposal, contract)
            .map_err(|e| {
                eprintln!("fstp_celltest::cycle {STEP}: the contract port's fact: {e}");
                NotImplemented::new(STEP_REFUSED)
            })
    }

    /// `minor-applicant:draft` (I-18, corpus variant "Minor applicant"): the
    /// set-up steps if this cell has not run them, then a new applicant
    /// with a seeded verification and no over-18 attestation drafts a
    /// proposal.
    fn minor_draft(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "minor-applicant:draft";
        self.login()?;
        self.create_programme()?;
        self.publish_call()?;
        let applicant = self.new_applicant(STEP)?;
        self.pending = Some(applicant);
        self.draft(STEP)
    }

    /// A guardian self-registers, the applicant adds them to the proposal,
    /// and their consent is seeded (design section 6.9). With `verified`
    /// the guardian's verification is seeded too, so the consent counts
    /// (`fstp_vault_core::eval::guardian_consent`). Without it the consent
    /// does not count.
    fn guardian_consent(&mut self, verified: bool) -> Result<(), NotImplemented> {
        const STEP: &str = "minor-applicant:seed-guardian-consent";
        self.applicants = self.applicants.saturating_add(1);
        let guardian = AccountId::from_raw(APPLICANTS.saturating_add(self.applicants));
        let email = crate::canary::Canary::generate(self.client.cell().index(), CanaryKind::Email)
            .map_err(|_| Self::refused(STEP, "the canary address", None))?
            .email_address();
        self.client
            .signup(guardian, &email)?
            .ok_or_else(|| Self::refused(STEP, "the guardian's self-registration", None))?;
        if verified {
            self.verify(STEP, guardian)?;
        }
        let account = self.account(STEP, guardian)?;
        let (cookie, proposal) = {
            let run = self.run_of()?;
            (run.cookie.clone(), run.proposal)
        };
        let binding = BindingId::from_raw(self.fresh());
        self.by(
            STEP,
            "AddGuardian",
            &cookie,
            fstp_domain::Command::AddGuardian {
                proposal,
                account,
                binding,
            },
        )?;
        self.client
            .cell()
            .seed_vault_fact(
                SeedSource::SyntheticConsent,
                fstp_vault_core::fact::Fact::GuardianConsent {
                    proposal: fstp_vault_proto::WireProposal(proposal.raw()),
                    guardian: fstp_vault_proto::WireAccount(account.raw()),
                },
            )
            .map(|_| ())
            .map_err(|e| {
                eprintln!("fstp_celltest::cycle {STEP}: the seeded consent: {e}");
                NotImplemented::new(STEP_REFUSED)
            })
    }
}

/// The cell command of a creator command.
fn creator(c: CreatorCommand) -> CellCommand {
    CellCommand::Engine(fstp_engine::Command::Creator(c))
}

/// The cell command of a core command.
fn core(c: fstp_domain::Command) -> CellCommand {
    CellCommand::Engine(fstp_engine::Command::Core(c))
}

/// A synthetic text reference: id `n`, digest of `n` bytes.
fn synthetic_text(n: u8) -> TextRef {
    TextRef::new(
        TextId::from_raw(50_000 + u128::from(n)),
        ContentDigest::from_bytes([n; 32]),
    )
}

/// The `GrantRole` of `role` on P1 to `account` from `start`.
fn grant(binding: BindingId, account: AccountId, role: Role, start: i64) -> CellCommand {
    core(fstp_domain::Command::GrantRole {
        binding,
        account,
        programme: P1,
        role,
        start: Timestamp::from_micros(start),
        second_admin: None,
        confidentiality: Some(synthetic_text(0x0b)),
        organisation: None,
        end: None,
    })
}

/// The SuperSAFE fixture spec with its P-09 wording stored as text
/// references (ADR-007), as `fstp-engine`'s creator path tests build it.
fn synthetic_spec() -> Result<ProgrammeSpec, NotImplemented> {
    let failed = || NotImplemented::new(STEP_REFUSED);
    let item = |id: u8| {
        let hex: String = std::iter::repeat_n(format!("{id:02x}"), 32).collect();
        format!("{{\"id\":\"{id}\",\"text\":{{\"digest\":\"{hex}\",\"text\":\"10{id}\"}}}}")
    };
    let p09 = format!("[{},{},{}]", item(1), item(2), item(3));
    let mut spec = fstp_programme::supersafe_fixture()
        .map_err(|_| failed())?
        .spec;
    spec.set(
        fstp_programme::decode_field_value(FieldId::P09, p09.as_bytes()).map_err(|_| failed())?,
    );
    Ok(spec)
}

/// A manual save of every field `spec` sets, P-53 aside, each under a
/// synthetic digest.
fn save_of(spec: &ProgrammeSpec) -> Vec<FieldEdit> {
    FieldId::ALL
        .iter()
        .enumerate()
        .filter(|(_, f)| **f != FieldId::P53)
        .filter_map(|(i, f)| match spec.get(*f) {
            Field::Set(value) => {
                let value: FieldValue = value;
                let mut b = [1u8; 32];
                b[..8].copy_from_slice(&u64::try_from(i).unwrap_or(u64::MAX).to_be_bytes());
                Some(FieldEdit {
                    field: *f,
                    value,
                    digest: ValueDigest::new(ContentDigest::from_bytes(b)),
                    provenance: Provenance::Manual,
                })
            }
            Field::Unset => None,
        })
        .collect()
}

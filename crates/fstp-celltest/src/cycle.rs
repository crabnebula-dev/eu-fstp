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
//! - `signup`, `verify-identity`, `submit-proposal`, `score`, `rank`,
//!   `negotiate` and `grant`: the rest of the cycle.
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
//! Reading of lane F-CYCLE1: each call of `run_cycle` starts its own
//! client, so a second script on the same cell cannot log the first admin
//! in again. No test runs two scripts that both reach `login` yet.

use fstp_cell_core::CellCommand;
use fstp_creator::{
    CheckId, CheckSubject, CreatorCommand, FieldEdit, Provenance, ValueDigest, WarningKey,
};
use fstp_domain::id::{
    AccountId, BindingId, CallId, ContentDigest, DecisionId, LlmConfigId, PolicyVersionId, TextId,
    TextRef,
};
use fstp_domain::roles::Role;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, STAFF_DRAFTER, STAFF_PM};
use fstp_programme::{Field, FieldId, FieldValue, ProgrammeSpec};

use crate::NotImplemented;
use crate::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN, Reply};
use crate::reference::auth::RefMethod;

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

/// `signup` refuses: `POST /auth/signup/options` and `POST /auth/signup`
/// fail closed (501). Self-registration needs a cell command, an email
/// proof with a lifetime and the world's mail capture.
pub const SIGNUP_SEAM: &str = "fstp_celltest::cycle signup: POST /auth/signup fails closed (501), since fstp-cell-core has no self-registration command and the email proof has no delivery (design section 8.3 ceremony 2)";

/// `verify-identity` refuses: the vault ticket routes answer 501 before
/// the engine runs them, since the route layer holds no `Ticket` key.
pub const VERIFY_IDENTITY_SEAM: &str = "fstp_celltest::cycle verify-identity: POST /api/v1/vault-tickets and /api/v1/verifications answer 501, since the route layer holds no Ticket key to sign a write ticket (design section 6.5)";

/// `submit-proposal` and the evaluation steps refuse: each needs an
/// applicant account (`signup`) and the M2 proposal path over the
/// command route.
pub const PROPOSAL_SEAM: &str = "fstp_celltest::cycle submit-proposal, score, rank, negotiate and grant: the cycle drives no applicant or evaluation step over HTTP yet (an applicant needs signup, SIGNUP_SEAM; the M2 evaluation path needs staff and reviewer roles on the published call)";

/// The former seam of the seeding steps. Lane F-CYCLE2 closed its first
/// part: a world cell runs the seeded vault ([`crate::seeded_vault`]).
pub const VAULT_SEED_SEAM: &str = "fstp_celltest::cycle seed steps: start_cell runs fstp_vault::service::serve, not the test-only fstp-vault-seeded, so no design section 6.9 seeding (vault_seed::SeedSource) reaches a world cell's vault";

/// A seeding step of a synthetic ground truth (`seed:ground-truth:...`)
/// refuses: the M2 generators name their own account ids, and a world
/// cell's accounts are random ids made at enrolment, so no ground truth
/// maps onto a world cell yet.
pub const GROUND_TRUTH_SEAM: &str = "fstp_celltest::cycle seed:ground-truth steps: the M2 ground truth names generator account ids, and a world cell's accounts are random ids made at enrolment, so no ground truth maps onto a world cell yet";

/// An M2 path or suite step (`m2:...`, `m2-suite:...`) or a step of the
/// I-18 minor applicant (`minor-applicant:...`) refuses: each replays an
/// M2 generator on the cell, whose commands name generator account ids
/// and instants. The cycle drives no generator over HTTP yet: each step
/// needs an enrolled account per generator account and the generator's
/// proposals through the command route.
pub const M2_SETUP_SEAM: &str = "fstp_celltest::cycle m2, m2-suite and minor-applicant steps: the cycle drives no M2 generator over HTTP yet (each needs an enrolled cell account per generator account, an applicant through signup, and the generator's proposals and evaluation through the command route)";

/// A step name outside the vocabulary of the module documentation.
pub const UNKNOWN_STEP_SEAM: &str = "fstp_celltest::cycle: the step is outside lane W3b's vocabulary (login, create-programme, publish-call, signup, verify-identity, submit-proposal, score, rank, negotiate, grant); the canary and fault steps of other tests are not defined yet";

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

/// One cycle on one cell.
pub struct Cycle<'w> {
    client: AuthClient<'w>,
    admin: Option<Cookie>,
    approver: Option<Cookie>,
    manager: Option<Cookie>,
    drafter: Option<Cookie>,
    active: bool,
    call: bool,
    /// The next synthetic person id of a seeded verification.
    person: u64,
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
            person: 1,
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
            "submit-proposal" | "score" | "rank" | "negotiate" | "grant" => {
                Err(NotImplemented::new(PROPOSAL_SEAM))
            }
            "signup" => Err(NotImplemented::new(SIGNUP_SEAM)),
            "verify-identity" => Err(NotImplemented::new(VERIFY_IDENTITY_SEAM)),
            s if s.starts_with("seed:ground-truth") => Err(NotImplemented::new(GROUND_TRUTH_SEAM)),
            s if s.starts_with("m2:")
                || s.starts_with("m2-suite:")
                || s.starts_with("minor-applicant:") =>
            {
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
        if !self.active {
            return Err(NotImplemented::new(NO_PROGRAMME));
        }
        let (Some(manager), Some(drafter)) = (self.manager.clone(), self.drafter.clone()) else {
            return Err(NotImplemented::new(NO_PROGRAMME));
        };
        let now = self.now();
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
                call: CALL,
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
                call: CALL,
                decision: CALL_APPROVAL,
            }),
            false,
        )?;
        self.command(
            STEP,
            "PublishCall",
            &manager,
            core(fstp_domain::Command::PublishCall {
                call: CALL,
                config: LlmConfigId::from_raw(1),
                config_model: fstp_domain::policy::ModelRef(PRIMARY_MODEL.to_owned()),
            }),
            true,
        )?;
        self.call = true;
        Ok(())
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

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
//! - `create-programme`: `CreateProgramme` with a step-up, then a second
//!   tenant admin through an invitation and `GrantTenantAdmin`, each with
//!   a step-up, then the creator's activation by that second admin.
//! - `publish-call`, `signup`, `verify-identity`, `submit-proposal`,
//!   `score`, `rank`, `negotiate` and `grant`: the rest of the cycle.
//!
//! A step the cell cannot run over HTTP yet refuses with a seam that
//! names the missing part. The first refusal ends the cycle. A step name
//! outside the vocabulary refuses with [`UNKNOWN_STEP_SEAM`].
//!
//! Reading of lane F-CYCLE1: each call of `run_cycle` starts its own
//! client, so a second script on the same cell cannot log the first admin
//! in again. No test runs two scripts that both reach `login` yet.

use fstp_cell_core::CellCommand;
use fstp_domain::id::AccountId;
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, SodSetup};

use crate::NotImplemented;
use crate::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use crate::reference::auth::RefMethod;
use crate::world::CellHandle;

/// A step that needs `login` first.
pub const NOT_LOGGED_IN: &str =
    "fstp_celltest::cycle: the step needs the login step first (its script has none before it)";

/// The cell refused a step it should take. Not a seam: a defect of the
/// cell or the harness, which the failing test then shows.
pub const STEP_REFUSED: &str = "fstp_celltest::cycle: the cell refused a request of a cycle step that it serves (login, CreateProgramme, the second admin's invitation or grant)";

/// The creator's activation refuses over HTTP. The cell decides creator
/// commands with `fstp_engine::NoEnvironment`: no funder profile, no
/// probes, no SoD preview and no attested tenant admins, so every check
/// that needs a shell fact fails closed (`fstp_engine::compose`). Strict
/// D2e refuses a core `ActivateProgramme`. So no programme activates, and
/// nothing past a draft runs (M4 design D1, D3 and 15.0).
pub const CREATOR_ENVIRONMENT_SEAM: &str = "fstp_celltest::cycle create-programme: the creator's activation by a second tenant admin cannot run over HTTP, since fstp-cell decides creator commands with fstp_engine::NoEnvironment (no funder profile, probes, SoD preview or attested tenant admins), and strict D2e refuses a core ActivateProgramme";

/// `publish-call` and every later step need an active programme
/// ([`CREATOR_ENVIRONMENT_SEAM`]).
pub const NO_ACTIVE_PROGRAMME_SEAM: &str = "fstp_celltest::cycle publish-call and later steps: no programme activates over HTTP (CREATOR_ENVIRONMENT_SEAM), so no call is drafted, approved or published";

/// `signup` refuses: `POST /auth/signup/options` and `POST /auth/signup`
/// fail closed (501). Self-registration needs a cell command, an email
/// proof with a lifetime and the world's mail capture.
pub const SIGNUP_SEAM: &str = "fstp_celltest::cycle signup: POST /auth/signup fails closed (501), since fstp-cell-core has no self-registration command and the email proof has no delivery or lifetime (design section 8.3 ceremony 2, ADR-008)";

/// `verify-identity` refuses: the vault ticket routes answer 501 before
/// the engine runs them, and no test-only seeding (design section 6.9)
/// reaches a world cell's vault.
pub const VERIFY_IDENTITY_SEAM: &str = "fstp_celltest::cycle verify-identity: POST /api/v1/vault-tickets and /api/v1/verifications answer 501 (no ticket signing in the route layer), and no section 6.9 seeding reaches a world cell's vault (fstp-vault-seeded is not started by start_cell)";

/// A step name outside the vocabulary of the module documentation. The
/// scripts of `seam_world`, `i18_guardian_consent`, `i38_egress`,
/// `i39_licence` and others name steps of their own (`m2-suite:...`,
/// `minor-applicant:...`, `seed:...`, canary steps), which no lane has
/// defined yet.
pub const UNKNOWN_STEP_SEAM: &str = "fstp_celltest::cycle: the step is outside lane W3b's vocabulary (login, create-programme, publish-call, signup, verify-identity, submit-proposal, score, rank, negotiate, grant); the M2 suite, seeding, canary and fault steps of other tests are not defined yet (lane F-CYCLE2)";

/// One cycle on one cell.
pub struct Cycle<'w> {
    client: AuthClient<'w>,
    admin: Option<Cookie>,
}

impl<'w> Cycle<'w> {
    /// A cycle on `cell`.
    pub fn new(cell: &'w CellHandle) -> Cycle<'w> {
        Cycle {
            client: AuthClient::new(cell),
            admin: None,
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
            "publish-call" | "submit-proposal" | "score" | "rank" | "negotiate" | "grant" => {
                Err(NotImplemented::new(NO_ACTIVE_PROGRAMME_SEAM))
            }
            "signup" => Err(NotImplemented::new(SIGNUP_SEAM)),
            "verify-identity" => Err(NotImplemented::new(VERIFY_IDENTITY_SEAM)),
            _ => Err(NotImplemented::new(UNKNOWN_STEP_SEAM)),
        }
    }

    fn refused() -> NotImplemented {
        NotImplemented::new(STEP_REFUSED)
    }

    /// `login`: the first admin enrols with both invitation halves and
    /// logs in with a passkey (I-77, design section 8.3).
    fn login(&mut self) -> Result<(), NotImplemented> {
        if !self.client.enrol(FIRST_ADMIN)? {
            return Err(Self::refused());
        }
        let session = self
            .client
            .login(FIRST_ADMIN, RefMethod::Passkey)?
            .ok_or_else(Self::refused)?;
        self.admin = Some(session);
        Ok(())
    }

    /// `create-programme`: `CreateProgramme` of P1 with a step-up (R-PC-01,
    /// I-78), then the second tenant admin who approves its activation:
    /// an invitation and `GrantTenantAdmin`, each with a step-up. The
    /// activation itself refuses with [`CREATOR_ENVIRONMENT_SEAM`].
    fn create_programme(&mut self) -> Result<(), NotImplemented> {
        let admin = self
            .admin
            .clone()
            .ok_or(NotImplemented::new(NOT_LOGGED_IN))?;
        let policy = SodSetup::one(1, &[])
            .version(P1)
            .map_err(|_| Self::refused())?;
        let create = CellCommand::Engine(fstp_engine::Command::Core(
            fstp_domain::Command::CreateProgramme {
                policy: Box::new(policy),
            },
        ));
        if !self.client.command_with_stepup(&admin, &create)? {
            return Err(Self::refused());
        }
        self.second_admin(&admin, ADMIN_2)?;
        Err(NotImplemented::new(CREATOR_ENVIRONMENT_SEAM))
    }

    /// Invites, enrols and grants tenant admin to `who`, each step with a
    /// step-up where the cell asks one.
    fn second_admin(&mut self, admin: &Cookie, who: AccountId) -> Result<(), NotImplemented> {
        if !self.client.enrol(who)? {
            return Err(Self::refused());
        }
        let ok = self.client.roster(
            admin,
            crate::mc::auth_model::RosterChange::GrantAdmin { account: who },
        )?;
        if !ok {
            return Err(Self::refused());
        }
        Ok(())
    }
}

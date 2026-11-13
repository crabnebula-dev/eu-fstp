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
use fstp_cell_core::driver::{self, DriverCore, Event, ExecError, Need};
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, ReadAction};
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellRefusal, CellState, FoldError};
use fstp_domain::command::{Actor, SystemCause};
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::oracle::Answers;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, ADMIN, ADMIN_2, B, P1, SodSetup, Step, T0, add_staff, end, grant, grant_until,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
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

/// The seam that stood for building the `fstp_ledger::Entry` values that
/// `fstp_cell_core::apply` folds. Closed by the lead: `fstp-celltest`
/// depends on `fstp-ledger` since lane W2c, and every [`ProdCell`] batch
/// is appended to an `fstp_ledger::MemStore` and folded from the entries
/// the store returns. No production path returns it. The constant stays
/// for the suites that name it.
pub const FOLD_SEAM: &str = "ProdCell::fold: closed by the lead; every batch folds from the fstp_ledger entries its MemStore returns, and no production path returns this seam";

/// Closed by lane F-AUTHP: [`ProdCell::suspend_for_conflict`] gives the
/// ground truth a conflict-of-interest fact, and production decides the
/// `VaultChanged` reaction under its `System(Vault)` actor
/// ([`ProdCell::react`]). No production path returns this seam. The
/// constant stays for the suites that name it.
pub const SUSPEND_SEAM: &str = "fstp_celltest::mc::auth_model::ProdCell::suspend_for_conflict: CellCtx has no system actor for the VaultChanged reaction that suspends a binding (design sections 5.1 and 6.9, lanes W2c and W2d)";

/// Closed by lane F-AUTHP: [`ProdCell::open_session`] writes the live
/// session rows, and every command of a [`ProdCell`] reads them as its
/// route does (`fstp_cell_core::RouteInputs`). A route-only command that
/// still lacks its session rows names this seam ([`refusal_of`]). The
/// constant stays for the suites that name it.
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

/// Not a seam: a harness passkey could not be built. Its key comes from
/// `fstp_crypto::sig` and its bytes from the [`crate::soft_authn`]
/// builders, so this is a crypto or builder failure, which stops the run
/// as a backend that did not answer.
pub const PASSKEY_BUILD_FAILED: &str = "fstp_celltest::mc::auth_model::HarnessPasskey: the Ed25519 key or the registration bytes could not be built";

/// The refusal text of a batch that `decide` recorded for
/// `RegisterCredential` although no verified credential reached it. The
/// verified key is a route input (`fstp_cell_core::RouteInput`), so such a
/// batch is a production defect, and the harness refuses it.
pub const DECIDED_WITHOUT_KEY: &str =
    "fstp_cell_core::decide recorded RegisterCredential without the verified credential";

/// The refusal text of an append whose step-up is older than P-71 at the
/// commit instant. The store refuses it (design section 8.4,
/// `SideEffects::stepup_fresh_until`), and so does the harness shell.
pub const STEPUP_STALE_AT_COMMIT: &str =
    "the append is later than its step-up's P-71 limit (SideEffects::stepup_fresh_until)";

/// The refusal text of [`ProdCell::register_passkey`] for an account that
/// holds a live passkey already. Every first passkey ceremony refuses it,
/// and a second passkey is the high-risk action `AddPasskey` (design
/// section 8.3, [`ProdCell::add_passkey`]).
pub const SECOND_PASSKEY_REFUSED: &str = "a first passkey ceremony refuses an account that holds a passkey; a second passkey is AddPasskey, with a step-up (design section 8.3)";

/// The first bytes of every command id that [`ProdCell::draw`] gives.
/// They lie outside the reserved and system prefixes (`fstp:vc:`,
/// `fstp:st:`).
pub const DRAW_PREFIX: [u8; 4] = [0xCE, 0x11, 0xD7, 0xA0];

/// The relying party host of every harness passkey: a synthetic cell host
/// of three labels, as `fstp_webauthn::RelyingParty::new` requires (B11).
pub const RP_HOST: &str = "cell-1.tenant.example";

/// A synthetic passkey of the harness: an Ed25519 key from
/// `fstp_crypto::sig` whose seed is derived from the credential id, so
/// one id always names one key. Its registration is written with the
/// [`crate::soft_authn`] builders, in the byte formats of WebAuthn Level 2,
/// and verified by `fstp_webauthn` through `fstp_auth::ceremony`.
///
/// `SoftAuthenticator::register` still refuses (lane W1a), so the harness
/// writes the registration from the authenticator's public builders.
pub struct HarnessPasskey {
    key: fstp_crypto::sig::Ed25519SigningKey,
    id: Vec<u8>,
}

impl std::fmt::Debug for HarnessPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HarnessPasskey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl HarnessPasskey {
    /// The passkey of credential id `credential`.
    ///
    /// # Errors
    ///
    /// [`PASSKEY_BUILD_FAILED`] when `fstp_crypto` refuses the seed.
    pub fn of(credential: &[u8]) -> Result<HarnessPasskey, NotImplemented> {
        let mut h = fstp_crypto::Sha256::new();
        h.update(b"fstp-celltest-passkey-v1");
        h.update(credential);
        let seed = h.finish();
        let key = fstp_crypto::sig::Ed25519SigningKey::from_seed(&seed)
            .map_err(|_| NotImplemented::new(PASSKEY_BUILD_FAILED))?;
        Ok(HarnessPasskey {
            key,
            id: credential.to_vec(),
        })
    }

    /// The COSE public key.
    pub fn public_key(&self) -> fstp_webauthn::CoseKey {
        fstp_webauthn::CoseKey::Ed25519 {
            x: self.key.public_key(),
        }
    }

    /// A registration response over `challenge` for [`RP_HOST`]: client
    /// data of `webauthn.create`, and a `none` attestation object whose
    /// authenticator data attests this credential with sign count 0, user
    /// presence and, when `uv`, user verification.
    ///
    /// # Errors
    ///
    /// [`PASSKEY_BUILD_FAILED`] when a builder refuses.
    pub fn registration(
        &self,
        challenge: [u8; 32],
        uv: bool,
    ) -> Result<fstp_webauthn::RegistrationResponse, NotImplemented> {
        use crate::soft_authn::{self as sa, Alg, AttestedCredential, Ceremony};
        let client_data_json = sa::SoftAuthenticator::for_rp(RP_HOST)
            .client_data(Ceremony::Create, challenge, &[])
            .map_err(|_| NotImplemented::new(PASSKEY_BUILD_FAILED))?;
        let attested = AttestedCredential {
            aaguid: [0; 16],
            id: self.id.clone(),
            cose_key: sa::cose_key(Alg::Ed25519, &self.key.public_key(), None),
        };
        let flag_bits = if uv {
            sa::flags::UP | sa::flags::UV
        } else {
            sa::flags::UP
        };
        let auth_data = sa::authenticator_data(RP_HOST, flag_bits, 0, Some(&attested));
        Ok(fstp_webauthn::RegistrationResponse {
            client_data_json,
            attestation_object: sa::none_attestation_object(&auth_data),
        })
    }

    /// An assertion over `challenge` for [`RP_HOST`]: client data of
    /// `webauthn.get`, authenticator data with user presence, user
    /// verification when `uv`, and sign count 0. The signature is this
    /// key's Ed25519 signature over the authenticator data and the
    /// SHA-256 of the client data (WebAuthn Level 2 section 6.3.3).
    ///
    /// # Errors
    ///
    /// [`PASSKEY_BUILD_FAILED`] when a builder or the signature refuses.
    pub fn assertion(
        &self,
        challenge: [u8; 32],
        uv: bool,
    ) -> Result<fstp_webauthn::AssertionResponse, NotImplemented> {
        use crate::soft_authn::{self as sa, Ceremony};
        let client_data_json = sa::SoftAuthenticator::for_rp(RP_HOST)
            .client_data(Ceremony::Get, challenge, &[])
            .map_err(|_| NotImplemented::new(PASSKEY_BUILD_FAILED))?;
        let flag_bits = if uv {
            sa::flags::UP | sa::flags::UV
        } else {
            sa::flags::UP
        };
        let authenticator_data = sa::authenticator_data(RP_HOST, flag_bits, 0, None);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client_data_json));
        let signature = self
            .key
            .sign(&message)
            .map_err(|_| NotImplemented::new(PASSKEY_BUILD_FAILED))?;
        Ok(fstp_webauthn::AssertionResponse {
            credential_id: self.id.clone(),
            client_data_json,
            authenticator_data,
            signature: signature.to_vec(),
        })
    }
}

/// The cell id of every harness step-up challenge: a synthetic id.
pub const HARNESS_CELL: [u8; 16] = [0xCE; 16];

/// The step-up request of the harness for `action_digest` in `session`
/// at `at`. A route draws the id and the nonce at random. The harness
/// derives them, so a run is reproducible.
fn stepup_request(
    session: [u8; 16],
    action_digest: [u8; 32],
    at: Timestamp,
) -> Result<fstp_auth::stepup::StepUpRequest, ProdError> {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-celltest-stepup-nonce-v1");
    h.update(&session);
    h.update(&action_digest);
    h.update(&at.micros().to_be_bytes());
    let nonce = h.finish();
    let mut id = [0u8; 16];
    id.copy_from_slice(nonce.get(..16).unwrap_or(&[0; 16]));
    let rp = fstp_webauthn::RelyingParty::new(RP_HOST)
        .map_err(|_| ProdError::NotImplemented(PASSKEY_BUILD_FAILED))?;
    Ok(fstp_auth::stepup::StepUpRequest {
        id,
        cell: HARNESS_CELL,
        action_digest,
        nonce,
        rp,
    })
}

/// The route check of `POST /auth/stepup` (design section 8.4), run by
/// the harness: the passkey `credential` asserts over the challenge of
/// `action_digest` in `session` at `at`, with user verification when
/// `uv`, and `fstp_auth::stepup::verify_step_up` decides it against the
/// credential that `state` holds.
///
/// So a magic-link session, a credential of another account, an unknown
/// or revoked credential and an assertion without user verification are
/// all refused, as the route refuses them. The inner `Err` is the
/// route's refusal. A magic-link session is refused first, as
/// `verify_step_up` does. Then an unknown or revoked credential gives
/// `StepUpDeny::OtherAccount`, since the session's account holds none.
///
/// # Errors
///
/// [`PASSKEY_BUILD_FAILED`] when the harness cannot build the assertion.
pub fn verify_harness_stepup(
    state: &CellState,
    session: &SessionView,
    credential: &[u8],
    action_digest: [u8; 32],
    uv: bool,
    at: Timestamp,
) -> Result<Result<(), fstp_auth::stepup::StepUpDeny>, ProdError> {
    verify_stepup_with(
        state.auth().stored_credential(credential, 0),
        session,
        credential,
        action_digest,
        uv,
        at,
    )
}

/// [`verify_harness_stepup`] against `stored`, the owner and the stored
/// form of `credential` as a registration record gives them
/// (`fstp_auth::AuthRecord::stored_credential`), or `None` when no live
/// credential has that id. The operational sign count is 0.
///
/// # Errors
///
/// [`PASSKEY_BUILD_FAILED`] when the harness cannot build the assertion.
pub fn verify_stepup_with(
    stored: Option<(AccountId, fstp_auth::StoredCredential)>,
    session: &SessionView,
    credential: &[u8],
    action_digest: [u8; 32],
    uv: bool,
    at: Timestamp,
) -> Result<Result<(), fstp_auth::stepup::StepUpDeny>, ProdError> {
    use fstp_auth::stepup::StepUpDeny;
    if !session.method.phishing_resistant() {
        return Ok(Err(StepUpDeny::MagicLinkSession));
    }
    let Some((owner, stored)) = stored.filter(|(_, s)| s.id == credential) else {
        return Ok(Err(StepUpDeny::OtherAccount));
    };
    let req = stepup_request(session.id, action_digest, at)?;
    let challenge = fstp_auth::stepup::challenge(req.cell, session.id, action_digest, req.nonce);
    let assertion = HarnessPasskey::of(credential)?.assertion(challenge, uv)?;
    Ok(
        fstp_auth::stepup::verify_step_up(session, &req, &assertion, &stored, owner, at)
            .map(|_| ()),
    )
}

/// The challenge of the harness registration of `credential` for
/// `account`. A route draws a single-use random challenge. The harness
/// derives one, so a run is reproducible.
fn registration_challenge(account: AccountId, credential: &[u8]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-celltest-registration-v1");
    h.update(&account.raw().to_be_bytes());
    h.update(credential);
    h.finish()
}

/// The new passkey `credential` of `account`, as
/// `fstp_auth::ceremony::verify_fresh_passkey` returns it: the harness
/// registration ([`HarnessPasskey::registration`], with user
/// verification) verified by `fstp_webauthn::verify_registration` for
/// [`RP_HOST`], with user verification required, and an id that `known`
/// does not hold.
///
/// # Errors
///
/// [`ProdError::Refused`] when verification refuses, and
/// [`ProdError::NotImplemented`] with [`PASSKEY_BUILD_FAILED`] when the
/// harness cannot build the registration.
pub fn verified_passkey(
    account: AccountId,
    credential: &[u8],
    known: &dyn fstp_auth::ceremony::CredentialIndex,
) -> Result<fstp_webauthn::NewCredential, ProdError> {
    let challenge = registration_challenge(account, credential);
    let response = HarnessPasskey::of(credential)?.registration(challenge, true)?;
    let rp = fstp_webauthn::RelyingParty::new(RP_HOST)
        .map_err(|_| ProdError::NotImplemented(PASSKEY_BUILD_FAILED))?;
    let reg = fstp_auth::ceremony::Registration {
        response: &response,
        rp: &rp,
        challenge,
    };
    fstp_auth::ceremony::verify_fresh_passkey(&reg, true, known)
        .map_err(|e| ProdError::Refused(format!("passkey verification: {e:?}")))
}

/// The synthetic vault as the oracle of a composed setup entry. The cell
/// processes the vault change first, so the truth's epoch is the state's.
struct TruthOracle<'a>(&'a GroundTruth);

impl fstp_engine::IdentityOracle for TruthOracle<'_> {
    fn ask(
        &self,
        q: &fstp_domain::oracle::Query,
    ) -> Result<fstp_domain::oracle::Answer, fstp_domain::oracle::OracleDown> {
        Ok(self.0.answer(q))
    }

    fn epoch(&self) -> Result<fstp_domain::id::VaultEpoch, fstp_domain::oracle::OracleDown> {
        Ok(self.0.epoch())
    }
}

/// Whether the decided batch `batch` holds only records the store reads
/// back unchanged, as `decide` checks for its own batches (I-23).
fn storable(batch: &[CellRecord]) -> bool {
    batch.iter().all(|r| {
        fstp_cell_core::decode_cell_record(&fstp_cell_core::encode_cell_record(r))
            .is_ok_and(|back| back == *r)
    })
}

/// The refusal of `cmd` by production, with a refusal for a missing route
/// input of session rows named as [`SESSIONS_SEAM`]: `decide` sees no
/// session rows (design section 4.2), so the harness cannot give them.
fn refusal_of(cmd: &CellCommand, e: CellRefusal) -> ProdError {
    match (cmd, e) {
        (CellCommand::Auth(a), CellRefusal::Domain(d))
            if d == fstp_cell_core::ROUTE_INPUT_MISSING
                && fstp_cell_core::route_inputs(a)
                    .contains(&fstp_cell_core::RouteInput::SessionRows) =>
        {
            ProdError::NotImplemented(SESSIONS_SEAM)
        }
        (_, e) => refusal(e),
    }
}

/// A production cell from genesis: `fstp_cell_core::replay` of an empty
/// ledger, then `queries`, `decide`, an append and `apply` for each
/// command. No state is built by hand (design section 14.1).
///
/// Every batch is appended to an `fstp_ledger::MemStore`, and the state
/// is folded with `fstp_cell_core::apply` from the entries the store
/// returns. So the state is always the replay of the store (I-23).
///
/// [`ProdCell::exec`] decides a command directly, as a test harness that
/// writes the ledger may: it passes no gate. [`ProdCell::execute`] runs an
/// admitted command through `fstp_cell_core::driver::DriverCore`, which
/// adds the step-up consumption (design sections 5.1 and 5.2). The vault
/// of both is the synthetic `GroundTruth`.
#[derive(Clone, Debug)]
pub struct ProdCell {
    log: Vec<Appended>,
    store: MemStore<CellRecord>,
    state: CellState,
    truth: GroundTruth,
    drawn: u128,
    /// The live rows of `auth.session`, as a login writes them. They are
    /// operational rows, so no ledger record holds them (design section
    /// 4.2). Each command reads them as its route does.
    sessions: Vec<SessionView>,
    /// The credential each passkey session of [`ProdCell::sessions`]
    /// logged in with.
    logins: Vec<fstp_auth::session::SessionLogin>,
}

impl ProdCell {
    /// The empty cell over `truth`.
    pub fn genesis(truth: GroundTruth) -> Result<ProdCell, ProdError> {
        let state = fstp_cell_core::replay(&[]).map_err(fold)?;
        Ok(ProdCell {
            log: Vec::new(),
            store: MemStore::new(),
            state,
            truth,
            drawn: 0,
            sessions: Vec::new(),
            logins: Vec::new(),
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

    /// The next command id: [`DRAW_PREFIX`] and a counter, so ids never
    /// repeat. The store refuses a repeated command id (ADR-007). The
    /// prefix keeps the drawn ids apart from the small ids a caller of
    /// [`ProdCell::exec_with_id`] passes, such as a shrunk generated id.
    pub fn draw(&mut self) -> [u8; 16] {
        self.drawn = self.drawn.saturating_add(1);
        let mut id = self.drawn.to_be_bytes();
        if let Some(head) = id.get_mut(..DRAW_PREFIX.len()) {
            head.copy_from_slice(&DRAW_PREFIX);
        }
        id
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
    /// `fstp_cell_core::decide_with_id` decides under it, as the driver
    /// does. A command id the ledger holds already is a retry: its stored
    /// result stands, and the batch returned is empty (ADR-007).
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
        let command = match id {
            Some(c) => c,
            None => self.draw(),
        };
        if self.state.committed(command).is_some() {
            // A retry: the stored result stands, and nothing is decided
            // again (ADR-007), as `DriverCore` finishes a crash retry.
            return Ok(Vec::new());
        }
        self.react(at)?;
        let x = CellCtx {
            actor,
            at: at.micros(),
        };
        let qs = fstp_cell_core::queries_with_id(&self.state, &cmd, &x, command)
            .map_err(|e| refusal_of(&cmd, e))?;
        let mut answers = Answers::new();
        for q in qs {
            let a = self.truth.answer(&q);
            answers.insert(q, a);
        }
        let inputs = self.route_inputs();
        let batch =
            fstp_cell_core::decide_with_inputs(&self.state, &cmd, &x, command, &inputs, &answers)
                .map_err(|e| refusal_of(&cmd, e))?;
        if batch.is_empty() {
            return Ok(batch);
        }
        self.fold(at, command, &batch)?;
        Ok(batch)
    }

    /// Processes the vault's change first when the vault epoch is ahead of
    /// the state's (NOTE 3), as `DriverCore` does before a command. The
    /// reaction is `VaultChanged` to the epoch of the `ChangedSince`
    /// answer. `fstp_cell_core::decide_reaction` decides it over the
    /// answers to `reaction_queries`, and it is appended under its reserved
    /// command id (NOTE 4). The ground truth has no provisional facts, so
    /// no acknowledgement follows.
    fn react(&mut self, at: Timestamp) -> Result<(), ProdError> {
        let ours = self.state.engine().epoch();
        if self.truth.epoch() <= ours {
            return Ok(());
        }
        let changed_q = fstp_domain::oracle::Query::ChangedSince { epoch: ours };
        let answer = self.truth.answer(&changed_q);
        let Some(changed) = answer.accounts.clone() else {
            return Err(ProdError::Refused(
                "the vault answered ChangedSince without the changed accounts".to_owned(),
            ));
        };
        let target = answer.epoch;
        let cmd = fstp_cell_core::vault_changed(target, changed);
        let mut answers = Answers::new();
        for q in fstp_cell_core::reaction_queries(&self.state, &cmd, at).map_err(refusal)? {
            let a = self.truth.answer(&q);
            answers.insert(q, a);
        }
        let inputs = self.route_inputs();
        let batch =
            fstp_cell_core::decide_reaction_with_inputs(&self.state, &cmd, at, &inputs, &answers)
                .map_err(refusal)?;
        if batch.is_empty() {
            return Ok(());
        }
        self.fold(
            at,
            fstp_cell_core::reaction_command_id(target.raw()),
            &batch,
        )
    }

    /// Appends `batch` at `at` under `command` with the state's head as the
    /// expected head, then folds the entries the store returns with
    /// `fstp_cell_core::apply`. The append and the fold run on copies, so
    /// a refusal of either leaves the store and the state as they were.
    fn fold(
        &mut self,
        at: Timestamp,
        command: [u8; 16],
        batch: &[CellRecord],
    ) -> Result<(), ProdError> {
        let expected = self.state.head();
        let mut store = self.store.clone();
        let head = store
            .append(expected, at.micros(), command, batch.to_vec())
            .map_err(|e| ProdError::Refused(format!("append: {e}")))?;
        let mut entries = Vec::with_capacity(batch.len());
        store
            .read(
                Seq::from_raw(expected.raw().saturating_add(1)),
                batch.len(),
                &mut entries,
            )
            .map_err(|e| ProdError::Refused(format!("read: {e}")))?;
        let mut state = self.state.clone();
        for e in &entries {
            fstp_cell_core::apply(&mut state, e).map_err(fold)?;
        }
        if state.head() != head {
            return Err(ProdError::Refused(format!(
                "the fold reached head {} and the store {}",
                state.head().raw(),
                head.raw()
            )));
        }
        self.store = store;
        self.state = state;
        self.log.push(Appended {
            at: at.micros(),
            command,
            batch: batch.to_vec(),
        });
        Ok(())
    }

    /// Every entry of the ledger, in order, as the store returns them.
    pub fn entries(&self) -> Vec<Entry<CellRecord>> {
        let mut out = Vec::new();
        // A read of the in-memory store never fails.
        let _ = self.store.read(Seq::ZERO, usize::MAX, &mut out);
        out
    }

    /// Registers the first passkey `credential` of `account` at `at`, as
    /// a first passkey ceremony does (design section 8.3), and returns the
    /// batch.
    ///
    /// Every first passkey ceremony refuses an account that holds a live
    /// passkey: the invitation gives `EnrolDeny::InviteeNotNew`, and
    /// self-registration needs a new account. So this refuses with
    /// [`SECOND_PASSKEY_REFUSED`] then. A second passkey is the high-risk
    /// action `AddPasskey`, with a step-up ([`ProdCell::add_passkey`]).
    ///
    /// `RegisterCredential` needs a verified key, which only a route holds
    /// (`fstp_cell_core::RouteInput::VerifiedCredential`, lane W3a). So the
    /// harness runs the route's part itself: `decide_with_id` makes every
    /// ledger check of the command and must then refuse for the missing
    /// route input alone. The passkey is then verified by
    /// [`verified_passkey`], with user verification required, and its
    /// `CredentialRegistered` record comes from
    /// `fstp_auth::AuthRecord::registration`. A refusal for any other
    /// cause is returned as it is.
    pub fn register_passkey(
        &mut self,
        account: AccountId,
        credential: Vec<u8>,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        if self.state.auth().has_any_credential(account) {
            return Err(ProdError::Refused(SECOND_PASSKEY_REFUSED.to_owned()));
        }
        let command = self.draw();
        let cmd = CellCommand::Auth(AuthCommand::RegisterCredential {
            account,
            credential: credential.clone(),
        });
        self.react(at)?;
        self.route_checks(&cmd, account, at, command)?;
        let state = &self.state;
        let cred = verified_passkey(account, &credential, &|id: &[u8]| {
            state.auth().is_registered(id)
        })?;
        let batch = vec![CellRecord::Auth(fstp_auth::AuthRecord::registration(
            account, &cred,
        ))];
        if !storable(&batch) {
            return Err(ProdError::Refused(
                "the registration record does not read back from the store".to_owned(),
            ));
        }
        self.fold(at, command, &batch)?;
        Ok(batch)
    }

    /// The ledger checks of a route-only command `cmd` by `actor` at `at`:
    /// `decide_with_id` must refuse it for its missing route input alone
    /// ([`fstp_cell_core::ROUTE_INPUT_MISSING`]). Any other refusal is
    /// returned, and a batch is refused with [`DECIDED_WITHOUT_KEY`].
    fn route_checks(
        &self,
        cmd: &CellCommand,
        actor: AccountId,
        at: Timestamp,
        command: [u8; 16],
    ) -> Result<(), ProdError> {
        let x = CellCtx {
            actor,
            at: at.micros(),
        };
        match fstp_cell_core::decide_with_id(&self.state, cmd, &x, command, &Answers::new()) {
            Err(CellRefusal::Domain(d)) if d == fstp_cell_core::ROUTE_INPUT_MISSING => Ok(()),
            Err(e) => Err(refusal(e)),
            Ok(_) => Err(ProdError::Refused(DECIDED_WITHOUT_KEY.to_owned())),
        }
    }

    /// Runs the route `POST /auth/stepup` (design section 8.4) for the
    /// passkey `credential` in `session`, for `action_digest`, asserted at
    /// `at` with user verification when `uv`. It returns the id of the
    /// step-up the ledger granted, or the route's refusal.
    ///
    /// The route verifies the passkey assertion, then issues
    /// `GrantStepUp`. Its admission is lane W3a's
    /// (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`), so the harness runs
    /// both parts. [`verify_harness_stepup`] makes the route check through
    /// `fstp_auth::stepup::verify_step_up`. Only an accepted assertion is
    /// granted: production's `decide` then records `StepUpGranted` for the
    /// session's account, with the id it derives, at the entry instant
    /// `at`. A refused one writes nothing, as the route writes nothing.
    /// So every step-up in the ledger came from a passkey session, a
    /// credential of the session's own account, and user verification.
    pub fn grant_stepup(
        &mut self,
        session: &SessionView,
        credential: &[u8],
        action_digest: [u8; 32],
        uv: bool,
        at: Timestamp,
    ) -> Result<Result<[u8; 16], fstp_auth::stepup::StepUpDeny>, ProdError> {
        if let Err(deny) =
            verify_harness_stepup(&self.state, session, credential, action_digest, uv, at)?
        {
            return Ok(Err(deny));
        }
        let cmd = CellCommand::Auth(AuthCommand::GrantStepUp {
            session: session.id,
            action_digest,
        });
        let account = session.account;
        let session = session.id;
        let batch = self.exec(cmd, account, at)?;
        let ids: Vec<[u8; 16]> = batch
            .iter()
            .filter_map(|r| match r {
                CellRecord::Auth(fstp_auth::AuthRecord::StepUpGranted {
                    id,
                    action_digest: d,
                    session: s,
                }) if *d == action_digest && *s == session => Some(*id),
                _ => None,
            })
            .collect();
        match ids.as_slice() {
            [id] if batch.len() == 1 => Ok(Ok(*id)),
            _ => Err(ProdError::Refused(format!(
                "GrantStepUp recorded {batch:?}, not one StepUpGranted for its digest and session"
            ))),
        }
    }

    /// Runs the admitted command through `DriverCore` over this cell's
    /// store and `GroundTruth` vault, and returns the command's batch.
    /// The batch of a high-risk command carries `StepUpConsumed`, which
    /// the driver adds (design section 5.1). A run that found the command
    /// id stored already appended nothing, and the batch is empty.
    ///
    /// The vault answers every request from the ground truth at its
    /// epoch, reactions included, and accepts every acknowledgement. The
    /// shell holds no audit chain, so every link it reports is zero.
    ///
    /// The emulated store has its own commit clock, `commit_at`, apart
    /// from the entry instant, which is the admission instant. As the
    /// store does (design sections 5.3 and 8.4), it refuses an append
    /// whose `SideEffects::stepup_fresh_until` lies before `commit_at`,
    /// with [`STEPUP_STALE_AT_COMMIT`]. So a command admitted with a fresh
    /// step-up and committed after its P-71 limit is refused by the
    /// limit that `DriverCore` computed, not by a second gate check.
    ///
    /// # Errors
    ///
    /// The outer error is the driver's `NotImplemented`, a shell refusal
    /// or a protocol fault. The inner one is how the driver ended the run.
    pub fn execute(
        &mut self,
        admitted: gate::Admitted,
        commit_at: Timestamp,
    ) -> Result<Result<Vec<CellRecord>, ExecError>, ProdError> {
        let command = admitted.command_id();
        let mut run = DriverCore::start(admitted);
        let mut ev: Option<Event> = None;
        let mut committed: Vec<CellRecord> = Vec::new();
        for _ in 0..256 {
            match run.step(&mut self.state, ev.take()) {
                driver::Step::Done(Ok(_)) => return Ok(Ok(committed)),
                driver::Step::Done(Err(ExecError::NotImplemented(op))) => {
                    return Err(ProdError::NotImplemented(op));
                }
                driver::Step::Done(Err(e)) => return Ok(Err(e)),
                driver::Step::Need(n) => {
                    ev = Some(self.meet(n, command, commit_at, &mut committed)?);
                }
            }
        }
        Err(ProdError::Refused(
            "the driver did not finish in 256 steps".to_owned(),
        ))
    }

    /// The event that meets the driver's need `n`. An append under
    /// `command` puts its batch in `committed`. `commit_at` is the
    /// store's commit clock.
    fn meet(
        &mut self,
        n: Need,
        command: Option<[u8; 16]>,
        commit_at: Timestamp,
        committed: &mut Vec<CellRecord>,
    ) -> Result<Event, ProdError> {
        Ok(match n {
            Need::ReadFrom(from) => {
                let mut out = Vec::new();
                let start = Seq::from_raw(from.raw().saturating_add(1));
                let read = self.store.read(start, usize::MAX, &mut out);
                read.map_err(|e| ProdError::Refused(format!("read: {e}")))?;
                Event::Read(out)
            }
            Need::Epoch => Event::Epoch(Ok(self.truth.epoch())),
            Need::Ask { queries, .. } => {
                let mut answers = Answers::new();
                for q in queries {
                    let a = self.truth.answer(&q);
                    answers.insert(q, a);
                }
                Event::Answers(Ok(answers))
            }
            Need::Append {
                expected,
                at,
                command: id,
                batch,
                side,
            } => {
                if side.stepup_consumed.is_some()
                    && side
                        .stepup_fresh_until
                        .is_none_or(|until| commit_at.micros() > until)
                {
                    return Err(ProdError::Refused(STEPUP_STALE_AT_COMMIT.to_owned()));
                }
                let r = self.store.append(expected, at, id, batch.clone());
                if r.is_ok() {
                    if Some(id) == command {
                        committed.clone_from(&batch);
                    }
                    self.log.push(Appended {
                        at,
                        command: id,
                        batch,
                    });
                }
                Event::Appended(r.map(|head| (head, [0; 32])))
            }
            Need::Ack { .. } => Event::Acked(Ok(())),
        })
    }

    /// Runs the `AddPasskey` route for the admitted command, which
    /// `gate::admit_command` admitted in `session` at `now`, and returns
    /// its batch: the verified registration and `StepUpConsumed`.
    ///
    /// `DriverCore` cannot run it, since `decide` refuses
    /// `RegisterCredential` without the verified key, a route input of
    /// lane W3a. So the harness runs the route's part, from production
    /// parts only. `decide_with_id` makes the ledger checks and must
    /// refuse for the route input alone. `fstp_auth::ceremony::
    /// enrol_add_passkey` applies the `AddPasskey` rule and verifies the
    /// new passkey through `fstp_webauthn`, with user verification
    /// required for a management holder. The batch consumes the admitted
    /// step-up, as `DriverCore` does for a high-risk command, and its
    /// freshness is checked again at `now`.
    pub fn add_passkey(
        &mut self,
        admitted: &gate::Admitted,
        session: &SessionView,
        now: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let (account, credential) = match admitted.action() {
            Action::Command(CellCommand::Auth(AuthCommand::RegisterCredential {
                account,
                credential,
            })) => (*account, credential.clone()),
            other => {
                return Err(ProdError::Refused(format!(
                    "AddPasskey runs RegisterCredential, not {other:?}"
                )));
            }
        };
        let gate::Principal::Account(actor) = admitted.principal() else {
            return Err(ProdError::Refused(
                "the admitted AddPasskey has no account principal".to_owned(),
            ));
        };
        if actor != session.account {
            return Err(ProdError::Refused(
                "the admitted AddPasskey was admitted for another session's account".to_owned(),
            ));
        }
        let Some(command) = admitted.command_id() else {
            return Err(ProdError::Refused(
                "the admitted AddPasskey carries no command id".to_owned(),
            ));
        };
        let Some(stepup) = admitted.stepup() else {
            return Err(ProdError::Refused(
                "the admitted AddPasskey carries no step-up".to_owned(),
            ));
        };
        if self.state.committed(command).is_some() {
            return Ok(Vec::new());
        }
        if stepup
            .fresh_until()
            .is_none_or(|until| now.micros() > until)
        {
            return Err(ProdError::Refused(STEPUP_STALE_AT_COMMIT.to_owned()));
        }
        let cmd = CellCommand::Auth(AuthCommand::RegisterCredential {
            account,
            credential: credential.clone(),
        });
        self.react(now)?;
        // The actor is the admitted principal, so `decide` checks that the
        // command names the actor's own account (`wrong_actor`).
        self.route_checks(&cmd, actor, now, command)?;
        let holds = gate::management_holders(&self.state, now).contains(&account)
            || self.state.tenant().is_admin(account);
        let challenge = registration_challenge(account, &credential);
        let response = HarnessPasskey::of(&credential)?.registration(challenge, true)?;
        let rp = fstp_webauthn::RelyingParty::new(RP_HOST)
            .map_err(|_| ProdError::NotImplemented(PASSKEY_BUILD_FAILED))?;
        let reg = fstp_auth::ceremony::Registration {
            response: &response,
            rp: &rp,
            challenge,
        };
        let state = &self.state;
        let record = fstp_auth::ceremony::enrol_add_passkey(
            state.auth().has_any_credential(account),
            session,
            Ok(()),
            holds,
            &reg,
            &|id: &[u8]| state.auth().is_registered(id),
        )
        .map_err(|e| ProdError::Refused(format!("AddPasskey: {e:?}")))?;
        let batch = vec![
            CellRecord::Auth(record),
            CellRecord::Auth(fstp_auth::AuthRecord::StepUpConsumed { id: stepup.id }),
        ];
        if !storable(&batch) {
            return Err(ProdError::Refused(
                "the AddPasskey batch does not read back from the store".to_owned(),
            ));
        }
        self.fold(now, command, &batch)?;
        Ok(batch)
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
        if matches!(
            s.cmd,
            fstp_domain::Command::CreateProgramme { .. }
                | fstp_domain::Command::ActivateProgramme { .. }
        ) {
            return self.exec_composed(s, actor, at);
        }
        let cmd = CellCommand::Engine(fstp_engine::Command::Core(s.cmd.clone()));
        self.exec(cmd, actor, at)
    }

    /// Runs a setup `CreateProgramme` or `ActivateProgramme` through the
    /// creator path, since strict D2e refuses both as core commands (M4
    /// design section 15.0, as `52cdc5c` did for the M4 setups). The
    /// entry is the one `fstp_domain_testkit::activation::run_core`
    /// composes: a creator `OpenDraft` for a `CreateProgramme`, a creator
    /// `ApproveActivation` for an `ActivateProgramme`. The vault change is
    /// processed first. The cell attests what its tenant fold holds, and the
    /// step's own tenant admin flag stands for the shell attestation of a
    /// setup approver, as `activation_step` reads it.
    fn exec_composed(
        &mut self,
        s: &Step,
        actor: AccountId,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        use fstp_domain_testkit::activation::{activation_records, open_records};
        let command = self.draw();
        self.react(at)?;
        let cmd = &s.cmd;
        let engine_cmd = fstp_engine::Command::Core(cmd.clone());
        let a = fstp_cell_core::attest_at(&self.state, actor, &engine_cmd, command, at);
        let ctx = fstp_domain::command::Ctx {
            now: at,
            actor: Actor::Account(actor),
            command: fstp_domain::id::CommandId::from_bytes(command),
            via: fstp_domain::command::Via::Web,
            tenant_admin: a.tenant_admin || s.flags.tenant_admin,
            second_tenant_admin: None,
            binds_tenant_admin: a.binds_tenant_admin,
        };
        let oracle = TruthOracle(&self.truth);
        let engine = self.state.engine();
        let records = match cmd {
            fstp_domain::Command::CreateProgramme { policy } => {
                open_records(engine, &oracle, policy, &ctx)
            }
            _ => activation_records(engine, &oracle, cmd, &ctx),
        }
        .map_err(|e| ProdError::Refused(format!("{:?} refused: {e:?}", cmd.kind())))?;
        let batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
        if !storable(&batch) {
            return Err(ProdError::Refused(
                "the composed batch does not read back from the store".to_owned(),
            ));
        }
        self.fold(at, command, &batch)?;
        Ok(batch)
    }

    /// Runs an M2 step of `fstp-domain-testkit` at `at`, by an account
    /// ([`ProdCell::exec_step`]), by the timeline
    /// ([`ProdCell::exec_system`]) or by an M5 port
    /// ([`ProdCell::exec_port_fact`]). A vault reaction is no step: the
    /// cell runs it before a command when the vault epoch is ahead.
    pub fn exec_any_step(&mut self, s: &Step, at: Timestamp) -> Result<Vec<CellRecord>, ProdError> {
        match s.actor {
            Actor::Account(_) => self.exec_step(s, at),
            Actor::System(SystemCause::Timeline) => self.exec_system(
                CellCommand::Engine(fstp_engine::Command::Core(s.cmd.clone())),
                fstp_cell_core::SystemTask::Timeline,
                at,
            ),
            Actor::System(SystemCause::Vault) => Err(ProdError::Refused(
                "a vault reaction runs before a command, never as a step".to_owned(),
            )),
            Actor::System(port) => self.exec_port_fact(port, s.cmd.clone(), at),
        }
    }

    /// Runs `cmd` of the system task `task` at `at` and returns the batch:
    /// `fstp_cell_core::queries_system`, `decide_system`, an append and
    /// `apply`, as the cell's own task does. The timeline decides only
    /// the M2 commands that `fstp_domain::due` lists at `at`.
    pub fn exec_system(
        &mut self,
        cmd: CellCommand,
        task: fstp_cell_core::SystemTask,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let command = self.draw();
        self.react(at)?;
        let x = fstp_cell_core::SystemCtx {
            task,
            at: at.micros(),
        };
        let qs = fstp_cell_core::queries_system(&self.state, &cmd, &x, command).map_err(refusal)?;
        let mut answers = Answers::new();
        for q in qs {
            let a = self.truth.answer(&q);
            answers.insert(q, a);
        }
        let batch = fstp_cell_core::decide_system(&self.state, &cmd, &x, command, &answers)
            .map_err(refusal)?;
        if batch.is_empty() {
            return Ok(batch);
        }
        self.fold(at, command, &batch)?;
        Ok(batch)
    }

    /// Runs the fact `cmd` of the M5 port `port` at `at` and returns the
    /// batch.
    ///
    /// Gap: the cell has no task for the M5 ports. `SystemTask` holds the
    /// erasure runner and the timeline only. So the harness decides the
    /// fact with the cell's own M2 decider, `fstp_engine::DomainDecider`,
    /// over the cell's M2 state, with the port as the `System` actor and
    /// no attestation. The records are production's, and the harness
    /// appends and folds them, as a test harness that writes the ledger
    /// directly may.
    pub fn exec_port_fact(
        &mut self,
        port: SystemCause,
        cmd: fstp_domain::Command,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        use fstp_engine::Decider;
        if matches!(port, SystemCause::Timeline | SystemCause::Vault) {
            return Err(ProdError::Refused(format!(
                "{port:?} is a cell task, not an M5 port"
            )));
        }
        let command = self.draw();
        self.react(at)?;
        let ctx = fstp_domain::command::Ctx {
            now: at,
            actor: Actor::System(port),
            command: fstp_domain::id::CommandId::from_bytes(command),
            via: fstp_domain::command::Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        let cmd = fstp_engine::Command::Core(cmd);
        let domain = |r: fstp_domain::Refusal| ProdError::Refused(format!("{r:?}"));
        let qs = fstp_engine::DomainDecider
            .queries(self.state.engine(), &cmd, &ctx)
            .map_err(domain)?;
        let mut answers = Answers::new();
        for q in qs {
            let a = self.truth.answer(&q);
            answers.insert(q, a);
        }
        let records = fstp_engine::DomainDecider
            .decide(self.state.engine(), &cmd, &ctx, &answers)
            .map_err(domain)?;
        let batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Engine).collect();
        if batch.is_empty() {
            return Ok(batch);
        }
        if !storable(&batch) {
            return Err(ProdError::Refused(
                "the port fact's batch does not read back from the store".to_owned(),
            ));
        }
        self.fold(at, command, &batch)?;
        Ok(batch)
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
    ///
    /// The vault learns a fact that gives `account` a conflict of
    /// interest: its identity is merged into the identity of a Drafting
    /// holder of the binding's programme (Identity discovery, I-06). The
    /// ground truth then lists `account` as changed at a new epoch, and
    /// the cell processes that change first, as `DriverCore` does before
    /// any command (NOTE 3). So the suspension is production's own
    /// `VaultChanged` reaction ([`ProdCell::react`]), decided by
    /// `fstp_cell_core::decide_reaction_with_inputs` with the live session
    /// rows, under the `System(Vault)` actor. Nothing is built by hand.
    ///
    /// It refuses when the binding is not open, when its programme has no
    /// other Drafting holder with an identity, or when the reaction does
    /// not suspend the binding under I-06.
    pub fn suspend_for_conflict(
        &mut self,
        account: AccountId,
        binding: BindingId,
        at: Timestamp,
    ) -> Result<Vec<CellRecord>, ProdError> {
        let roster = self.state.engine().core.roster();
        let Some(b) = roster.binding(binding).filter(|b| b.account == account) else {
            return Err(ProdError::Refused(format!(
                "{binding:?} is not an open binding of {account:?}"
            )));
        };
        let programme = b.programme;
        let holder = roster
            .bindings()
            .filter(|(_, d)| {
                d.programme == programme
                    && d.group() == fstp_domain::roles::Group::Drafting
                    && d.account != account
                    && !d.voided()
            })
            .find_map(|(_, d)| self.truth.identity_of(d.account));
        let Some(identity) = holder else {
            return Err(ProdError::Refused(format!(
                "no Drafting holder of {programme:?} has an identity to share"
            )));
        };
        let logged = self.log.len();
        self.truth.set_identity(account, identity);
        self.react(at)?;
        let batch: Vec<CellRecord> = self
            .log
            .get(logged..)
            .unwrap_or_default()
            .iter()
            .flat_map(|a| a.batch.iter().cloned())
            .collect();
        let suspended = batch.iter().any(|r| {
            matches!(
                r,
                CellRecord::Engine(fstp_engine::Record::Core(fstp_domain::Record::BindingSuspended(
                    fstp_domain::record::BindingSuspended { binding: got, rule, .. }
                ))) if *got == binding && *rule == fstp_domain::refusal::RuleRef::I06
            )
        });
        if !suspended {
            return Err(ProdError::Refused(format!(
                "the vault reaction did not suspend {binding:?} under I-06: {batch:?}"
            )));
        }
        Ok(batch)
    }

    /// Opens session `s` in the cell, as a login does, so that later
    /// batches can end it. The login route writes a live `auth.session`
    /// row and no ledger record (design section 4.2). Every later command
    /// of this cell reads the live rows as its route does, so its batch
    /// names the sessions it ends (design section 5.1).
    ///
    /// The harness does not decide the login itself: M-AUTH asks
    /// `fstp_auth::admit_method` for that. It refuses a session the ledger
    /// ended, and a second row under an open id. The same row again is the
    /// one row it is.
    pub fn open_session(&mut self, s: &SessionView) -> Result<(), ProdError> {
        self.open_session_with(s, None)
    }

    /// [`ProdCell::open_session`] for a passkey session logged in with
    /// `credential`, which the logins side table records.
    pub fn open_session_with(
        &mut self,
        s: &SessionView,
        credential: Option<Vec<u8>>,
    ) -> Result<(), ProdError> {
        if self.state.auth().session_ended(s.id) {
            return Err(ProdError::Refused(format!(
                "session {:?} was ended before",
                s.id
            )));
        }
        if let Some(row) = self.sessions.iter().find(|r| r.id == s.id) {
            // `auth.session` holds one row per id. The same login again
            // writes nothing new; another row under that id is refused.
            return if row == s {
                Ok(())
            } else {
                Err(ProdError::Refused(format!(
                    "session {:?} is open with another row",
                    s.id
                )))
            };
        }
        self.sessions.push(s.clone());
        if let Some(credential) = credential {
            self.logins.push(fstp_auth::session::SessionLogin {
                session: s.id,
                credential,
            });
        }
        Ok(())
    }

    /// The route inputs of a command: the live session rows and their
    /// logins. `decide` ignores a row the ledger ended.
    fn route_inputs(&self) -> fstp_cell_core::RouteInputs {
        fstp_cell_core::RouteInputs::none().with_sessions(fstp_cell_core::SessionRows::new(
            self.sessions.clone(),
            self.logins.clone(),
        ))
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
/// The sessions of the model are opened in that cell as live rows before
/// a roster change, so each batch names the sessions it ends (design
/// sections 4.2 and 5.1). A suspension is the vault reaction
/// ([`ProdCell::suspend_for_conflict`]). A credential revocation
/// registers a verified passkey first ([`ProdCell::register_passkey`]).
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

    /// [`Production::cell_for`] with every session of `sessions` that is
    /// live at `now` opened in the cell, as its logins wrote them. A
    /// passkey session records the credential of its device.
    fn cell_with_sessions(
        &self,
        roster: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<ProdCell, ProdError> {
        let mut cell = self.cell_for(roster, now)?;
        for s in sessions {
            if s.ended.is_some_and(|(at, _)| at.micros() <= now.micros()) {
                continue;
            }
            let credential = s.device.map(|d| credential_of(s.account, d));
            cell.open_session_with(&prod_session(s), credential)?;
        }
        Ok(cell)
    }

    /// The ended ids of `batch`.
    fn ends_of(
        &self,
        batch: Result<Vec<CellRecord>, ProdError>,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        match batch {
            Err(e) => prod_ni(e),
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
        let mut cell = match self.cell_with_sessions(before, sessions, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let batch = match change {
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
                cell.exec_step(&step, now)
            }
            RosterChange::End { account, role } => {
                cell.exec_step(&end(binding_of(account, role), now), now)
            }
            RosterChange::GrantAdmin { account } => {
                cell.exec_tenant_admin_grant(ADMIN, account, now)
            }
        };
        self.ends_of(batch)
    }

    fn suspension_ends(
        &self,
        account: AccountId,
        role: Role,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let mut cell = match self.cell_with_sessions(before, sessions, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let batch = cell.suspend_for_conflict(account, binding_of(account, role), now);
        self.ends_of(batch)
    }

    fn revocation_ends(
        &self,
        account: AccountId,
        device: u8,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        let mut cell = match self.cell_with_sessions(before, sessions, now) {
            Ok(c) => c,
            Err(e) => return prod_ni(e),
        };
        let credential = credential_of(account, device);
        // A verified passkey, registered at the latest recorded instant so
        // the ledger stays time-monotone.
        let at = cell.state().now_floor().max(T0);
        if let Err(e) = cell.register_passkey(account, credential.clone(), at) {
            return prod_ni(e);
        }
        let revoke = CellCommand::Auth(AuthCommand::RevokeCredential {
            account,
            credential,
        });
        let batch = cell.exec(revoke, account, now);
        self.ends_of(batch)
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
// The HTTP client of the I-77, I-79 and R-LG-04 machines.

/// The HTTP client the machines of design section 14.4 drive a cell with
/// (lane F-HTTP).
///
/// Each call goes through `CellHandle::request`, so through the world's
/// edge to the cell's tunnel listener, as a browser on the cell origin
/// sends it. Every registration and assertion is real WebAuthn from a
/// software passkey per account and device. What the cell cannot do over
/// HTTP yet refuses with a seam that names the missing part:
///
/// - [`http::MAGIC_LINK_SEAM`]: an invited account has no email address,
///   and the world captures no outbox mail.
/// - [`http::ROLE_GRANT_SEAM`]: a programme role needs an active
///   programme, and no programme activates over HTTP.
/// - [`http::SUSPEND_SEAM_HTTP`]: no vault fact seeding reaches a world
///   cell's reaction (design section 6.9, lane F-AUTHP).
/// - [`http::RECOVERY_SEAM`]: the recovery request, email proof and
///   completion routes fail closed (ADR-008 "Unset lifetimes").
/// - [`http::OPERATOR_TICKET_SEAM`]: no control-plane signer of operator
///   tickets runs in the world.
pub mod http {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use fstp_cell_core::CellCommand;
    use fstp_cell_core::tenant::TenantCommand;
    use fstp_domain::id::AccountId;
    use fstp_domain::time::Timestamp;

    use super::RosterChange;
    use crate::NotImplemented;
    use crate::reference::auth::RefMethod;
    use crate::soft_authn::{self as sa, Alg, AttestedCredential, Ceremony, SoftAuthenticator};
    use crate::world::{
        CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldError, WorldSpec,
    };

    /// The former seam of every call. Lane F-HTTP closed it: the calls
    /// below drive the cell's routes.
    pub const HTTP_SEAM: &str = "fstp_celltest::world::CellHandle has no HTTP client and the cell has no auth routes yet (lanes W1a and W3a)";

    /// The former seam of [`production_routes`], kept so callers that name
    /// it still compile. Lane W3a closed the seam: `fstp-cell` exposes its
    /// route table as `fstp_cell::routes::table` (design section 8.7).
    pub const ROUTE_TABLE_SEAM: &str = "fstp_celltest::mc::auth_model::http::production_routes: fstp-cell exposes no route table yet, only the Route type (design section 8.7, lane W3a)";

    /// The former seam of [`AuthClient::set_clock`]. Lane F-CYCLE2 closed
    /// it: a world cell runs on its `crate::world::WorldClock`.
    pub const CLOCK_SEAM: &str = "fstp_celltest::mc::auth_model::http::AuthClient::set_clock: a world cell runs on the host clock, and no test clock reaches its backend (fstp-cell routes/pg.rs, world.rs start_cell)";

    /// A magic-link login refuses: an invited account has no email
    /// address the cell knows, and the world captures no outbox mail.
    pub const MAGIC_LINK_SEAM: &str = "fstp_celltest::mc::auth_model::http::AuthClient::login by magic link: an invited account has no email address in the cell (self-registration is not built), and the pg backend puts no magic link in an outbox the world could capture (fstp-cell routes/pg.rs send_magic_link)";

    /// A programme role grant or end refuses: every programme role names
    /// an active programme, and this client sets up none of its own. The
    /// cycle's creator path activates one over HTTP (lane F-CYCLE2).
    pub const ROLE_GRANT_SEAM: &str = "fstp_celltest::mc::auth_model::http::AuthClient::roster: a programme role needs an active programme; the cycle activates one through the creator path (fstp_celltest::cycle create-programme), but the machine client sets up no programme of its own yet";

    /// A conflict-of-interest suspension refuses: the world's seeded vault
    /// takes facts now, but this client seeds no conflict fact yet.
    pub const SUSPEND_SEAM_HTTP: &str = "fstp_celltest::mc::auth_model::http::AuthClient::suspend_for_conflict: the world runs the seeded vault (CellHandle::seed), but the client seeds no conflict fact yet, and the cell side of the suspension is SUSPEND_SEAM (lane F-AUTHP)";

    /// The recovery ceremonies refuse: the request, email proof and
    /// completion routes fail closed with 501.
    pub const RECOVERY_SEAM: &str = "fstp_celltest::mc::auth_model::http::AuthClient recovery: POST /auth/recovery, .../email and .../complete fail closed (501): the gate admits no ProveRecoveryEmail or CompleteRecovery (fstp_cell_core::gate::ROUTE_ADMISSION_SEAM), though fstp_cell_core::lifetimes now holds the interim token lifetimes of ADR-008 \"Unset lifetimes\"";

    /// An operator ticket refuses: no control-plane signer runs in the
    /// world, and the cell refuses `ApplyOperatorTicket` (no ticket form).
    pub const OPERATOR_TICKET_SEAM: &str = "fstp_celltest::mc::auth_model::http::AuthClient::recovery_ticket: no control-plane ticket signer runs in the world, and fstp-cell-core refuses ApplyOperatorTicket (no operator ticket form)";

    /// The client refuses: the cell answered in a way the harness cannot
    /// read, or a passkey could not be built. Not a seam: a defect.
    pub const HARNESS_FAILED: &str =
        "fstp_celltest::mc::auth_model::http::AuthClient: the harness could not drive the cell";

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

    /// A session cookie the cell set: the `Cookie` field value
    /// `__Host-fstp=<value>`.
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

    fn failed() -> NotImplemented {
        NotImplemented::new(HARNESS_FAILED)
    }

    /// A software passkey of one device: the authenticator's builders for
    /// the cell host and an Ed25519 key.
    struct Device {
        auth: SoftAuthenticator,
        key: fstp_crypto::sig::Ed25519SigningKey,
        id: Vec<u8>,
    }

    impl Device {
        fn new(host: &str) -> Result<Device, NotImplemented> {
            Ok(Device {
                auth: SoftAuthenticator::for_rp(host),
                key: fstp_crypto::sig::Ed25519SigningKey::generate().map_err(|_| failed())?,
                id: fstp_crypto::random_array::<16>()
                    .map_err(|_| failed())?
                    .to_vec(),
            })
        }

        /// The registration body `{attestation_object, challenge_id,
        /// client_data_json}` over `challenge`, with UP and UV.
        fn registration_body(
            &mut self,
            challenge_id: &str,
            challenge: [u8; 32],
        ) -> Result<Vec<u8>, NotImplemented> {
            let client_data = self
                .auth
                .client_data(Ceremony::Create, challenge, &[])
                .map_err(|_| failed())?;
            let attested = AttestedCredential {
                aaguid: [0; 16],
                id: self.id.clone(),
                cose_key: sa::cose_key(Alg::Ed25519, &self.key.public_key(), None),
            };
            let auth_data = sa::authenticator_data(
                self.auth.rp_id(),
                sa::flags::UP | sa::flags::UV,
                0,
                Some(&attested),
            );
            let attestation = sa::none_attestation_object(&auth_data);
            Ok(format!(
                "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{challenge_id}\",\"client_data_json\":\"{}\"}}",
                hex(&attestation),
                hex(&client_data)
            )
            .into_bytes())
        }

        /// The assertion body over `challenge` with UP, UV and the next
        /// counter.
        fn assertion_body(
            &mut self,
            challenge_id: &str,
            challenge: [u8; 32],
        ) -> Result<Vec<u8>, NotImplemented> {
            let client_data = self
                .auth
                .client_data(Ceremony::Get, challenge, &[])
                .map_err(|_| failed())?;
            let auth_data = self.auth.assertion_data(&[]).map_err(|_| failed())?;
            let mut message = auth_data.clone();
            message.extend_from_slice(&fstp_crypto::sha256(&client_data));
            let signature = self.key.sign(&message).map_err(|_| failed())?;
            Ok(format!(
                "{{\"authenticator_data\":\"{}\",\"challenge_id\":\"{challenge_id}\",\
                 \"client_data_json\":\"{}\",\"credential_id\":\"{}\",\"signature\":\"{}\"}}",
                hex(&auth_data),
                hex(&client_data),
                hex(&self.id),
                hex(&signature),
            )
            .into_bytes())
        }
    }

    /// One account the client enrolled: its id in the cell and its
    /// devices, device 0 first.
    struct Person {
        cell: AccountId,
        devices: Vec<Device>,
    }

    /// What the client knows of the cell.
    #[derive(Default)]
    struct Known {
        /// The machines' accounts, by their model id.
        people: BTreeMap<AccountId, Person>,
        /// The harness's own session of the first tenant admin, which
        /// issues the invitations.
        admin: Option<Cookie>,
        /// Each cookie the cell set: the model account and the session id.
        sessions: BTreeMap<Vec<u8>, (AccountId, [u8; 16])>,
    }

    /// What an [`AuthClient`] knows of its cell, kept between clients
    /// ([`AuthClient::resume`]).
    pub struct ClientMemory(Known);

    impl std::fmt::Debug for ClientMemory {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ClientMemory").finish_non_exhaustive()
        }
    }

    /// The auth client of one cell.
    pub struct AuthClient<'w> {
        cell: &'w CellHandle,
        known: Mutex<Known>,
    }

    impl std::fmt::Debug for AuthClient<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AuthClient")
                .field("cell", &self.cell.index())
                .finish_non_exhaustive()
        }
    }

    /// The model account of the cell's first tenant admin. The first admin
    /// enrols through the split invitation of provisioning (design section
    /// 8.3, Q35). Every other account enrols through a tenant admin's
    /// invitation, which the harness issues in its own admin session.
    pub const FIRST_ADMIN: AccountId = fstp_domain_testkit::r#gen::roster::ADMIN;

    impl<'w> AuthClient<'w> {
        /// The client of `cell`.
        pub fn new(cell: &'w CellHandle) -> AuthClient<'w> {
            AuthClient {
                cell,
                known: Mutex::new(Known::default()),
            }
        }

        /// The client of `cell` that resumes from `memory`: the passkeys,
        /// account ids and sessions an earlier client of the same cell
        /// kept (lane F-CYCLE3, so `World::run_cycle` continues a cell's
        /// cycle).
        pub fn resume(cell: &'w CellHandle, memory: ClientMemory) -> AuthClient<'w> {
            AuthClient {
                cell,
                known: Mutex::new(memory.0),
            }
        }

        /// What this client knows of its cell, for [`AuthClient::resume`].
        pub fn into_memory(self) -> ClientMemory {
            ClientMemory(
                self.known
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        }

        fn known(&self) -> std::sync::MutexGuard<'_, Known> {
            self.known
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// One request: `Host` is the cell host, a `POST` or `DELETE`
        /// carries the cell origin, and a `POST` a JSON body.
        pub fn call(
            &self,
            method: &str,
            path: &str,
            cookie: Option<&Cookie>,
            body: &[u8],
        ) -> Result<Reply, NotImplemented> {
            let r = self.send(method, path, cookie, body)?;
            Ok(Reply {
                status: r.status,
                body: r.body,
            })
        }

        /// [`AuthClient::call`] with the reply's header fields.
        fn send(
            &self,
            method: &str,
            path: &str,
            cookie: Option<&Cookie>,
            body: &[u8],
        ) -> Result<HttpReply, NotImplemented> {
            let host = self.cell.host();
            let mut r = HttpRequest::new(method, path).header("host", host);
            if matches!(method, "POST" | "DELETE") {
                r = r.header("origin", format!("https://{host}"));
            }
            if method == "POST" {
                r = r
                    .header("content-type", "application/json")
                    .body(body.to_vec());
            }
            if let Some(c) = cookie {
                r = r.header("cookie", c.0.clone());
            }
            self.cell.request(&r).map_err(|_| failed())
        }

        /// The `challenge_id` and challenge of an options reply.
        fn options(reply: &Reply) -> Option<(String, [u8; 32])> {
            if !reply.ok() {
                return None;
            }
            let id = json_str(&reply.body, "challenge_id")?;
            let challenge = unbase64url(&json_str(&reply.body, "challenge")?)?;
            Some((id, challenge.try_into().ok()?))
        }

        /// Sets the cell's test clock (`crate::world::WorldClock`). The
        /// former [`CLOCK_SEAM`] is closed: a world cell runs on it.
        pub fn set_clock(&self, at: Timestamp) -> Result<(), NotImplemented> {
            self.cell.clock().set(at.micros());
            Ok(())
        }

        /// Registers a new device of `person` through the invitation proof
        /// `token` (hex of one token or of both halves).
        fn register(&self, token: &str, device: &mut Device) -> Result<bool, NotImplemented> {
            let base = format!("/auth/invitations/{token}/register");
            let options = self.call("POST", &format!("{base}/options"), None, b"{}")?;
            let Some((id, challenge)) = Self::options(&options) else {
                return Ok(false);
            };
            let body = device.registration_body(&id, challenge)?;
            Ok(self.call("POST", &base, None, &body)?.ok())
        }

        /// Enrols the first tenant admin through the split invitation and
        /// opens the harness's admin session.
        fn enrol_first_admin(&self) -> Result<bool, NotImplemented> {
            if self.known().people.contains_key(&FIRST_ADMIN) {
                return Ok(true);
            }
            let inv = self.cell.first_admin_invitation().map_err(|_| failed())?;
            let token = format!("{}{}", hex(&inv.first), hex(&inv.second));
            let mut device = Device::new(self.cell.host())?;
            if !self.register(&token, &mut device)? {
                return Ok(false);
            }
            let ledger = self.cell.ledger().map_err(|_| failed())?;
            let cell = ledger
                .iter()
                .find_map(|e| match &e.record {
                    fstp_cell_core::CellRecord::Auth(
                        fstp_auth::AuthRecord::FirstAdminEnrolled { account },
                    ) => Some(*account),
                    _ => None,
                })
                .ok_or_else(failed)?;
            self.known().people.insert(
                FIRST_ADMIN,
                Person {
                    cell,
                    devices: vec![device],
                },
            );
            let admin = self.passkey_login(FIRST_ADMIN)?.ok_or_else(failed)?;
            self.known().admin = Some(admin);
            Ok(true)
        }

        /// A step-up for `command` under `command_id` in `session`, by the
        /// session account's device 0. The step-up id, or `None` when the
        /// cell refused it.
        fn step_up(
            &self,
            session: &Cookie,
            command: &CellCommand,
            command_id: [u8; 16],
        ) -> Result<Option<[u8; 16]>, NotImplemented> {
            let Some((account, _)) = self.known().sessions.get(&session.0).copied() else {
                return Ok(None);
            };
            let options = self.call(
                "POST",
                "/auth/stepup/options",
                Some(session),
                &command_body(command, command_id, None),
            )?;
            let Some((id, challenge)) = Self::options(&options) else {
                return Ok(None);
            };
            let body = {
                let mut k = self.known();
                let device = k
                    .people
                    .get_mut(&account)
                    .and_then(|p| p.devices.first_mut())
                    .ok_or_else(failed)?;
                device.assertion_body(&id, challenge)?
            };
            let reply = self.call("POST", "/auth/stepup", Some(session), &body)?;
            if !reply.ok() {
                eprintln!(
                    "fstp_celltest AuthClient: the step-up was refused: {} {}",
                    reply.status,
                    String::from_utf8_lossy(&reply.body)
                );
                return Ok(None);
            }
            Ok(unhex_array(&id))
        }

        /// `command` with a step-up through `POST /api/v1/commands` in
        /// `session`, as the cell's pages send it. Whether the cell
        /// committed it.
        pub fn command_with_stepup(
            &self,
            session: &Cookie,
            command: &CellCommand,
        ) -> Result<bool, NotImplemented> {
            let command_id = fstp_crypto::random_array::<16>().map_err(|_| failed())?;
            let Some(stepup) = self.step_up(session, command, command_id)? else {
                return Ok(false);
            };
            Ok(self
                .call(
                    "POST",
                    "/api/v1/commands",
                    Some(session),
                    &command_body(command, command_id, Some(stepup)),
                )?
                .ok())
        }

        /// Enrols `account` with a software passkey: the first admin
        /// through the split invitation, any other account through an
        /// invitation the harness issues as the first admin, with a
        /// step-up (`TenantCommand::IssueInvitation`). The cell account id
        /// is random. An account enrolled already gives `false`, except
        /// the first admin, whom the harness may have enrolled first.
        pub fn enrol(&self, account: AccountId) -> Result<bool, NotImplemented> {
            if account == FIRST_ADMIN {
                return self.enrol_first_admin();
            }
            if self.known().people.contains_key(&account) {
                return Ok(false);
            }
            if !self.enrol_first_admin()? {
                return Ok(false);
            }
            // A fresh session of the first admin: the cell clock may have
            // moved past the idle lifetime (P-72) of the last one.
            let admin = self.passkey_login(FIRST_ADMIN)?.ok_or_else(failed)?;
            self.known().admin = Some(admin.clone());
            let raw = u128::from_be_bytes(fstp_crypto::random_array::<16>().map_err(|_| failed())?);
            let cell = AccountId::from_raw(raw | 1);
            let token = fstp_crypto::random_array::<32>().map_err(|_| failed())?;
            let command = CellCommand::Tenant(TenantCommand::IssueInvitation {
                invitation: fstp_crypto::random_array::<16>().map_err(|_| failed())?,
                account: cell,
                token_digest: fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(token)),
            });
            if !self.command_with_stepup(&admin, &command)? {
                return Ok(false);
            }
            let mut device = Device::new(self.cell.host())?;
            if !self.register(&hex(&token), &mut device)? {
                return Ok(false);
            }
            self.known().people.insert(
                account,
                Person {
                    cell,
                    devices: vec![device],
                },
            );
            Ok(true)
        }

        /// Self-registers `account` with the synthetic address `email` and a
        /// software passkey (design section 8.3 ceremony 2, lane F-CYCLE3):
        /// `POST /auth/signup/options {email}`, the proof from the world's
        /// mail capture (`crate::world_mail`), `POST /auth/signup/options
        /// {token}` and `POST /auth/signup`. The new account's session, or
        /// `None` when the cell refused a step. The cell account id is read
        /// from the `CredentialRegistered` record of the new passkey.
        pub fn signup(
            &self,
            account: AccountId,
            email: &str,
        ) -> Result<Option<Cookie>, NotImplemented> {
            if self.known().people.contains_key(&account) {
                return Ok(None);
            }
            let asked = self.call(
                "POST",
                "/auth/signup/options",
                None,
                format!("{{\"email\":\"{email}\"}}").as_bytes(),
            )?;
            if asked.status != 202 {
                return Ok(None);
            }
            let Some(token) = self
                .cell
                .mail()
                .latest(fstp_cell::mail::ProofKind::Signup, email)
            else {
                return Ok(None);
            };
            let token = hex(&token);
            let options = self.call(
                "POST",
                "/auth/signup/options",
                None,
                format!("{{\"token\":\"{token}\"}}").as_bytes(),
            )?;
            let Some((id, challenge)) = Self::options(&options) else {
                return Ok(None);
            };
            let mut device = Device::new(self.cell.host())?;
            let mut body = device.registration_body(&id, challenge)?;
            // The registration body is one canonical object; the token joins
            // it as its last member, in key order.
            body.pop();
            body.extend_from_slice(format!(",\"token\":\"{token}\"}}").as_bytes());
            let reply = self.send("POST", "/auth/signup", None, &body)?;
            if !reply.ok() {
                eprintln!(
                    "fstp_celltest AuthClient: the signup was refused: {} {}",
                    reply.status,
                    String::from_utf8_lossy(&reply.body)
                );
                return Ok(None);
            }
            let pair: Vec<u8> = reply
                .header("set-cookie")
                .and_then(|set| set.split(|b| *b == b';').next())
                .ok_or_else(failed)?
                .to_vec();
            let session: [u8; 16] = json_str(&reply.body, "session")
                .and_then(|s| unhex_array(&s))
                .ok_or_else(failed)?;
            let ledger = self.cell.ledger().map_err(|_| failed())?;
            let cell = ledger
                .iter()
                .find_map(|e| match &e.record {
                    fstp_cell_core::CellRecord::Auth(
                        fstp_auth::AuthRecord::CredentialRegistered {
                            account,
                            credential,
                            ..
                        },
                    ) if *credential == device.id => Some(*account),
                    _ => None,
                })
                .ok_or_else(failed)?;
            let mut k = self.known();
            k.people.insert(
                account,
                Person {
                    cell,
                    devices: vec![device],
                },
            );
            k.sessions.insert(pair.clone(), (account, session));
            Ok(Some(Cookie(pair)))
        }

        /// The cell's account id of the model account `account`, once
        /// [`AuthClient::enrol`] enrolled it.
        pub fn cell_account(&self, account: AccountId) -> Option<AccountId> {
            self.known().people.get(&account).map(|p| p.cell)
        }

        /// The cell (the world's handle) this client drives.
        pub fn cell(&self) -> &'w CellHandle {
            self.cell
        }

        /// `command` through `POST /api/v1/commands` in `session`, with a
        /// step-up when `stepup` holds: the cell's reply. A step-up the
        /// cell refused gives `None`.
        pub fn command_reply(
            &self,
            session: &Cookie,
            command: &CellCommand,
            stepup: bool,
        ) -> Result<Option<Reply>, NotImplemented> {
            let command_id = fstp_crypto::random_array::<16>().map_err(|_| failed())?;
            let granted = if stepup {
                match self.step_up(session, command, command_id)? {
                    Some(id) => Some(id),
                    None => return Ok(None),
                }
            } else {
                None
            };
            Ok(Some(self.call(
                "POST",
                "/api/v1/commands",
                Some(session),
                &command_body(command, command_id, granted),
            )?))
        }

        /// The harness's own session of the first tenant admin, once
        /// [`AuthClient::enrol`] enrolled the first admin.
        pub fn admin_session(&self) -> Option<Cookie> {
            self.known().admin.clone()
        }

        /// A passkey login of `account` with its device 0.
        fn passkey_login(&self, account: AccountId) -> Result<Option<Cookie>, NotImplemented> {
            if !self.known().people.contains_key(&account) {
                return Ok(None);
            }
            let options = self.call("POST", "/auth/passkey/login/options", None, b"{}")?;
            let Some((id, challenge)) = Self::options(&options) else {
                return Ok(None);
            };
            let body = {
                let mut k = self.known();
                let device = k
                    .people
                    .get_mut(&account)
                    .and_then(|p| p.devices.first_mut())
                    .ok_or_else(failed)?;
                device.assertion_body(&id, challenge)?
            };
            let reply = self.send("POST", "/auth/passkey/login", None, &body)?;
            if !reply.ok() {
                return Ok(None);
            }
            let pair: Vec<u8> = reply
                .header("set-cookie")
                .and_then(|set| set.split(|b| *b == b';').next())
                .ok_or_else(failed)?
                .to_vec();
            let session: [u8; 16] = json_str(&reply.body, "session")
                .and_then(|s| unhex_array(&s))
                .ok_or_else(failed)?;
            self.known()
                .sessions
                .insert(pair.clone(), (account, session));
            Ok(Some(Cookie(pair)))
        }

        /// A login of `account` by `m`: the passkey routes with device 0.
        /// A magic link refuses with [`MAGIC_LINK_SEAM`].
        pub fn login(
            &self,
            account: AccountId,
            m: RefMethod,
        ) -> Result<Option<Cookie>, NotImplemented> {
            match m {
                RefMethod::MagicLink => Err(NotImplemented::new(MAGIC_LINK_SEAM)),
                _ => self.passkey_login(account),
            }
        }

        /// A roster change in the session `admin`, with a fresh step-up,
        /// through `POST /api/v1/commands`. A tenant admin grant is
        /// `GrantTenantAdmin`. A programme role grant or end refuses with
        /// [`ROLE_GRANT_SEAM`].
        pub fn roster(&self, admin: &Cookie, change: RosterChange) -> Result<bool, NotImplemented> {
            match change {
                RosterChange::GrantAdmin { account } => {
                    let Some(cell) = self.known().people.get(&account).map(|p| p.cell) else {
                        return Ok(false);
                    };
                    let command =
                        CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: cell });
                    self.command_with_stepup(admin, &command)
                }
                RosterChange::Grant { .. } | RosterChange::End { .. } => {
                    Err(NotImplemented::new(ROLE_GRANT_SEAM))
                }
            }
        }

        /// Gives `account` a conflict of interest through vault seeding.
        /// Refuses with [`SUSPEND_SEAM_HTTP`].
        pub fn suspend_for_conflict(&self, account: AccountId) -> Result<bool, NotImplemented> {
            let _ = account;
            Err(NotImplemented::new(SUSPEND_SEAM_HTTP))
        }

        /// Whether the cell admits a request in the session:
        /// `GET /auth/sessions` answers 2xx.
        pub fn admitted(&self, session: &Cookie) -> Result<bool, NotImplemented> {
            Ok(self.call("GET", "/auth/sessions", Some(session), b"")?.ok())
        }

        /// `GET /auth/sessions`: the body that lists the sessions.
        pub fn sessions(&self, session: &Cookie) -> Result<Option<Vec<u8>>, NotImplemented> {
            let r = self.call("GET", "/auth/sessions", Some(session), b"")?;
            Ok(r.ok().then_some(r.body))
        }

        /// `DELETE /auth/sessions/{id}`. `id` is a cookie the cell set,
        /// which stands for its session id, or a session id.
        pub fn end_session(&self, session: &Cookie, id: &[u8]) -> Result<bool, NotImplemented> {
            let target = match self.known().sessions.get(id) {
                Some((_, s)) => s.to_vec(),
                None => id.to_vec(),
            };
            let path = format!("/auth/sessions/{}", hex(&target));
            Ok(self.call("DELETE", &path, Some(session), b"")?.ok())
        }

        /// `GET /auth/devices`: the body that lists the devices.
        pub fn devices(&self, session: &Cookie) -> Result<Option<Vec<u8>>, NotImplemented> {
            let r = self.call("GET", "/auth/devices", Some(session), b"")?;
            Ok(r.ok().then_some(r.body))
        }

        /// `DELETE /auth/devices/{id}?command_id=..&stepup=..` of the
        /// session account's device `device`, with a step-up when `stepup`
        /// holds. Without one, the request names a step-up id the cell
        /// never granted.
        pub fn remove_device(
            &self,
            session: &Cookie,
            device: u8,
            stepup: bool,
        ) -> Result<bool, NotImplemented> {
            let found = {
                let k = self.known();
                k.sessions.get(&session.0).and_then(|(account, _)| {
                    let p = k.people.get(account)?;
                    let d = p.devices.get(usize::from(device))?;
                    Some((p.cell, d.id.clone()))
                })
            };
            let Some((account, credential)) = found else {
                return Ok(false);
            };
            let command = CellCommand::Auth(fstp_auth::AuthCommand::RevokeCredential {
                account,
                credential: credential.clone(),
            });
            let command_id = fstp_crypto::random_array::<16>().map_err(|_| failed())?;
            let granted = if stepup {
                self.step_up(session, &command, command_id)?
            } else {
                None
            };
            let id = match granted {
                Some(id) => id,
                None => fstp_crypto::random_array::<16>().map_err(|_| failed())?,
            };
            let path = format!(
                "/auth/devices/{}?command_id={}&stepup={}",
                hex(&credential),
                hex(&command_id),
                hex(&id)
            );
            Ok(self.call("DELETE", &path, Some(session), b"")?.ok())
        }

        /// `POST /auth/recovery` for `account`. Refuses with
        /// [`RECOVERY_SEAM`].
        pub fn recovery(&self, account: AccountId) -> Result<Option<CaseRef>, NotImplemented> {
            let _ = account;
            Err(NotImplemented::new(RECOVERY_SEAM))
        }

        /// `POST /auth/recovery/{case}/email`. Refuses with
        /// [`RECOVERY_SEAM`].
        pub fn recovery_email(&self, case: &CaseRef) -> Result<bool, NotImplemented> {
            let _ = case;
            Err(NotImplemented::new(RECOVERY_SEAM))
        }

        /// `POST /auth/recovery/{case}/approve` in `approver`'s session.
        /// Refuses with [`RECOVERY_SEAM`], since no case can be opened.
        pub fn recovery_approve(
            &self,
            case: &CaseRef,
            approver: &Cookie,
            stepup: bool,
        ) -> Result<bool, NotImplemented> {
            let _ = (case, approver, stepup);
            Err(NotImplemented::new(RECOVERY_SEAM))
        }

        /// An operator ticket for `case`. Refuses with
        /// [`OPERATOR_TICKET_SEAM`].
        pub fn recovery_ticket(
            &self,
            case: &CaseRef,
            two_staff: bool,
        ) -> Result<bool, NotImplemented> {
            let _ = (case, two_staff);
            Err(NotImplemented::new(OPERATOR_TICKET_SEAM))
        }

        /// `POST /auth/recovery/{case}/complete` with a new software
        /// passkey. Refuses with [`RECOVERY_SEAM`].
        pub fn recovery_complete(&self, case: &CaseRef) -> Result<Option<Cookie>, NotImplemented> {
            let _ = case;
            Err(NotImplemented::new(RECOVERY_SEAM))
        }

        /// The tenant audit view as `session` sees it:
        /// `GET /api/v1/audit/anchors`.
        pub fn audit_view(&self, session: &Cookie) -> Result<Vec<u8>, NotImplemented> {
            Ok(self
                .call("GET", "/api/v1/audit/anchors", Some(session), b"")?
                .body)
        }
    }

    /// The canonical command body `{command, command_id, stepup?}`.
    fn command_body(
        command: &CellCommand,
        command_id: [u8; 16],
        stepup: Option<[u8; 16]>,
    ) -> Vec<u8> {
        let mut c =
            String::from_utf8_lossy(&fstp_cell_core::encode_cell_command(command)).into_owned();
        // I-18, NOTE 14: a request never names the minor flag of a draft;
        // the cell sets it. The canonical form orders `minor` before
        // `proposal`, so the member and its comma go together.
        if let CellCommand::Engine(fstp_engine::Command::Core(
            fstp_domain::Command::CreateDraft { minor, .. },
        )) = command
        {
            c = c.replace(&format!("\"minor\":{minor},"), "");
        }
        let mut body = format!("{{\"command\":{c},\"command_id\":\"{}\"", hex(&command_id));
        if let Some(s) = stepup {
            body.push_str(&format!(",\"stepup\":\"{}\"", hex(&s)));
        }
        body.push('}');
        body.into_bytes()
    }

    /// The string member `key` of a JSON reply. The cell writes canonical
    /// JSON whose strings here hold only hexadecimal or base64url, so the
    /// first `"key":"` names it.
    fn json_str(body: &[u8], key: &str) -> Option<String> {
        let t = std::str::from_utf8(body).ok()?;
        let (_, rest) = t.split_once(&format!("\"{key}\":\""))?;
        let (v, _) = rest.split_once('"')?;
        Some(v.to_owned())
    }

    /// Lower-case hex of `b`.
    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => {
                    let digits = [*a, *b];
                    u8::from_str_radix(std::str::from_utf8(&digits).ok()?, 16).ok()
                }
                _ => None,
            })
            .collect()
    }

    fn unhex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
        unhex(s)?.try_into().ok()
    }

    /// The base64url alphabet (RFC 4648 section 5).
    const BASE64URL: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Unpadded base64url, as an options reply writes its challenge.
    fn unbase64url(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for c in s.bytes() {
            let v = u32::try_from(BASE64URL.iter().position(|x| *x == c)?).ok()?;
            acc = (acc << 6) | v;
            bits = bits.checked_add(6)?;
            if bits >= 8 {
                bits = bits.checked_sub(8)?;
                out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
                acc &= (1u32 << bits).checked_sub(1)?;
            }
        }
        Some(out)
    }
}

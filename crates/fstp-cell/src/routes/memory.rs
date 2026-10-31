//! An in-memory cell for tests and local development (design sections
//! 5.2 and 14.3).
//!
//! [`MemoryBackend`] implements [`Backend`] over a `fstp_ledger::MemStore`
//! and in-memory operational rows. It runs each admitted command through
//! the real `DriverCore`, with a vault that reports the genesis epoch and
//! answers no query, so a command with vault questions fails closed
//! (NOTE 2). It holds no keys, no witness and no database.
//!
//! [`LocalCell`] puts the production [`Front`] over a `MemoryBackend` and
//! seeds two synthetic accounts: a tenant admin with an Ed25519 passkey,
//! and a Receiving-only applicant with a login email. Their sessions come
//! from the real login routes: a passkey assertion for the admin and a
//! magic link for the applicant.
//!
//! Seeding appends records to the in-memory store without `decide`. It
//! reaches no other store, so it cannot write any real cell's ledger. The
//! `fstp-cell` binary must never build a `LocalCell`. As a second guard,
//! [`LocalCell::start`] refuses every host outside the `.test` domain
//! (RFC 2606), so it never answers for a real tenant host.

use std::collections::BTreeMap;
use std::future::{Future, ready};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use fstp_auth::{AuthRecord, CoseKey, EnabledMethods, Method};
use fstp_cell_core::driver::{Done, DriverCore, Event, ExecError, Need, Step, VaultFault};
use fstp_cell_core::gate::Admitted;
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellRecord, CellState};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::id::{AccountId, VaultEpoch};
use fstp_domain::time::Timestamp;
use fstp_http::{Method as HttpMethod, Request, RequestTarget, Response};
use fstp_json::{Object, Value};
use fstp_ledger::{MemStore, RecordStore, Seq};
use fstp_obs::LogEvent;

use crate::http::body::{hex, hex_array};
use crate::http::front::{Front, FrontConfig, FrontError, MemoryLog};
use crate::routes::{
    AnchorRow, Backend, BackendFault, ChallengeRow, ErasureRow, SessionRow, TokenKind, TokenRow,
};

/// 2026-10-29T00:00:00Z in UTC microseconds: the default clock of a
/// [`MemoryBackend`].
pub const DEFAULT_NOW_US: i64 = 1_793_232_000_000_000;

/// The most driver steps one command may take in memory.
const MAX_STEPS: usize = 256;

/// The command id prefix of seeded entries. It is neither the reserved
/// prefix `fstp:vc:` nor the system task prefix `fstp:st:`.
const SEED_PREFIX: [u8; 8] = *b"fstp:sd:";

#[derive(Default)]
struct Mem {
    store: MemStore<CellRecord>,
    state: Option<Arc<CellState>>,
    seeded: u64,
    sessions: BTreeMap<[u8; 32], SessionRow>,
    challenges: BTreeMap<[u8; 16], ChallengeRow>,
    sign_counts: BTreeMap<Vec<u8>, u32>,
    emails: BTreeMap<String, AccountId>,
    tokens: BTreeMap<[u8; 32], TokenRow>,
    outbox: Vec<(AccountId, [u8; 32])>,
}

impl Mem {
    fn state(&mut self) -> Arc<CellState> {
        Arc::clone(
            self.state
                .get_or_insert_with(|| Arc::new(CellState::genesis())),
        )
    }
}

/// Why seeding the memory backend failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// The store refused the batch.
    Append,
    /// The fold refused a seeded record.
    Fold,
    /// The backend lock is poisoned.
    Lock,
}

/// An in-memory [`Backend`] (module documentation).
pub struct MemoryBackend {
    mem: Mutex<Mem>,
    now: AtomicI64,
}

impl std::fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryBackend").finish_non_exhaustive()
    }
}

impl Default for MemoryBackend {
    fn default() -> MemoryBackend {
        MemoryBackend::new()
    }
}

impl MemoryBackend {
    /// An empty cell at [`DEFAULT_NOW_US`].
    pub fn new() -> MemoryBackend {
        MemoryBackend {
            mem: Mutex::new(Mem::default()),
            now: AtomicI64::new(DEFAULT_NOW_US),
        }
    }

    /// Sets the clock.
    pub fn set_now(&self, now: Timestamp) {
        self.now.store(now.micros(), Ordering::SeqCst);
    }

    fn with<T>(&self, f: impl FnOnce(&mut Mem) -> T) -> Result<T, BackendFault> {
        let mut g = self.mem.lock().map_err(|_| BackendFault::Unavailable)?;
        Ok(f(&mut g))
    }

    /// Appends `records` at `at` as one seeded batch and folds them,
    /// without `decide` (module documentation).
    ///
    /// # Errors
    ///
    /// A [`SeedError`] when the store or the fold refuses the batch.
    pub fn seed(&self, at: Timestamp, records: Vec<CellRecord>) -> Result<(), SeedError> {
        let mut g = self.mem.lock().map_err(|_| SeedError::Lock)?;
        let mut command = [0u8; 16];
        let (prefix, counter) = command.split_at_mut(8);
        prefix.copy_from_slice(&SEED_PREFIX);
        counter.copy_from_slice(&g.seeded.to_be_bytes());
        g.seeded = g.seeded.saturating_add(1);
        let head = g.store.head();
        g.store
            .append(head, at.micros(), command, records)
            .map_err(|_| SeedError::Append)?;
        let mut entries = Vec::new();
        g.store
            .read(next(head), usize::MAX, &mut entries)
            .map_err(|_| SeedError::Append)?;
        let mut state = (*g.state()).clone();
        for e in &entries {
            fstp_cell_core::apply(&mut state, e).map_err(|_| SeedError::Fold)?;
        }
        g.state = Some(Arc::new(state));
        Ok(())
    }

    /// Registers `email` as the login email of `account`.
    pub fn add_login_email(&self, email: &str, account: AccountId) {
        let _ = self.with(|m| m.emails.insert(email.to_ascii_lowercase(), account));
    }

    /// The challenge row `id`, without taking it. A test authenticator
    /// reads the bytes it signs from here.
    pub fn peek_challenge(&self, id: [u8; 16]) -> Option<ChallengeRow> {
        self.with(|m| m.challenges.get(&id).cloned()).ok().flatten()
    }

    /// Every magic link the outbox holds, in order.
    pub fn outbox(&self) -> Vec<(AccountId, [u8; 32])> {
        self.with(|m| m.outbox.clone()).unwrap_or_default()
    }

    /// Runs one admitted command through `DriverCore` over the store.
    fn run(&self, admitted: Admitted) -> Result<Result<Done, ExecError>, BackendFault> {
        self.with(|m| {
            let mut state = (*m.state()).clone();
            let mut driver = DriverCore::start(admitted);
            let mut event: Option<Event> = None;
            for _ in 0..MAX_STEPS {
                match driver.step(&mut state, event.take()) {
                    Step::Done(result) => {
                        m.state = Some(Arc::new(state));
                        return result;
                    }
                    Step::Need(need) => event = Some(answer(&mut m.store, need)),
                }
            }
            Err(ExecError::Protocol)
        })
    }
}

/// The sequence after `s`.
fn next(s: Seq) -> Seq {
    Seq::from_raw(s.raw().saturating_add(1))
}

/// The memory shell's answer to one driver need.
fn answer(store: &mut MemStore<CellRecord>, need: Need) -> Event {
    match need {
        Need::ReadFrom(seq) => {
            let mut out = Vec::new();
            let _ = store.read(next(seq), usize::MAX, &mut out);
            Event::Read(out)
        }
        Need::Epoch => Event::Epoch(Ok(VaultEpoch::GENESIS)),
        // The memory cell has no vault: every question fails closed.
        Need::Ask { .. } => Event::Answers(Err(VaultFault::Unavailable)),
        Need::Append {
            expected,
            at,
            command,
            batch,
            side,
        } => {
            let _ = side;
            let result = store.append(expected, at, command, batch).map(|head| {
                let link = fstp_crypto::sha256(&head.raw().to_be_bytes());
                (head, link)
            });
            Event::Appended(result)
        }
        Need::Ack { .. } => Event::Acked(Ok(())),
    }
}

impl Backend for MemoryBackend {
    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.now.load(Ordering::SeqCst))
    }

    fn state(&self) -> impl Future<Output = Result<Arc<CellState>, BackendFault>> + Send {
        ready(self.with(Mem::state))
    }

    fn execute(
        &self,
        admitted: Admitted,
    ) -> impl Future<Output = Result<Result<Done, ExecError>, BackendFault>> + Send {
        ready(self.run(admitted))
    }

    fn session(
        &self,
        token: [u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, BackendFault>> + Send {
        ready(self.with(|m| m.sessions.get(&token).cloned()))
    }

    fn sessions_of(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<SessionRow>, BackendFault>> + Send {
        ready(self.with(|m| {
            m.sessions
                .values()
                .filter(|s| s.account == account)
                .cloned()
                .collect()
        }))
    }

    fn open_session(
        &self,
        token: [u8; 32],
        row: SessionRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| {
            m.sessions.insert(token, row);
        }))
    }

    fn touch_session(
        &self,
        id: [u8; 16],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| {
            for s in m.sessions.values_mut().filter(|s| s.id == id) {
                s.last_used = at;
            }
        }))
    }

    fn put_challenge(
        &self,
        row: ChallengeRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| {
            m.challenges.insert(row.id, row);
        }))
    }

    fn challenge(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<ChallengeRow>, BackendFault>> + Send {
        ready(self.with(|m| m.challenges.get(&id).cloned()))
    }

    fn take_challenge(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<ChallengeRow>, BackendFault>> + Send {
        ready(self.with(|m| m.challenges.remove(&id)))
    }

    fn sign_count(
        &self,
        credential: Vec<u8>,
    ) -> impl Future<Output = Result<u32, BackendFault>> + Send {
        ready(self.with(|m| m.sign_counts.get(&credential).copied().unwrap_or(0)))
    }

    fn set_sign_count(
        &self,
        credential: Vec<u8>,
        count: u32,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| {
            m.sign_counts.insert(credential, count);
        }))
    }

    fn login_account(
        &self,
        email: String,
    ) -> impl Future<Output = Result<Option<AccountId>, BackendFault>> + Send {
        ready(self.with(|m| m.emails.get(&email.to_ascii_lowercase()).copied()))
    }

    fn put_token(&self, row: TokenRow) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| {
            m.tokens.insert(row.digest, row);
        }))
    }

    fn take_token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> impl Future<Output = Result<Option<TokenRow>, BackendFault>> + Send {
        ready(self.with(|m| match m.tokens.get(&digest) {
            Some(r) if r.kind == kind => m.tokens.remove(&digest),
            _ => None,
        }))
    }

    fn send_magic_link(
        &self,
        account: AccountId,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        ready(self.with(|m| m.outbox.push((account, token))))
    }

    fn stepup_asserted_at(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<Timestamp>, BackendFault>> + Send {
        // The entry instant of the `StepUpGranted` record, as the fold
        // holds it. Seeded and committed grants both reach the fold, so
        // every step-up the ledger knows has its instant here.
        ready(self.with(|m| m.state().auth().stepup_grant(id).map(|g| g.granted_at)))
    }

    fn anchors(&self) -> impl Future<Output = Result<Vec<AnchorRow>, BackendFault>> + Send {
        // The memory cell has no chain and no witness, so it has no anchor.
        ready(Ok(Vec::new()))
    }

    fn erasures(&self) -> impl Future<Output = Result<Vec<ErasureRow>, BackendFault>> + Send {
        ready(Ok(Vec::new()))
    }
}

/// The seeded tenant admin of a [`LocalCell`]. Synthetic.
pub const LOCAL_ADMIN: AccountId = AccountId::from_raw(0xad01);
/// The seeded Receiving-only applicant of a [`LocalCell`]. Synthetic.
pub const LOCAL_APPLICANT: AccountId = AccountId::from_raw(0xa901);

/// Why a [`LocalCell`] call failed. No variant carries content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalError {
    /// The host is outside the `.test` domain.
    Host,
    /// The front refused the configuration.
    Front(FrontError),
    /// Seeding failed.
    Seed(SeedError),
    /// A key or a random value was not available.
    Crypto,
    /// A login route did not answer as the login needs. It names the
    /// step.
    Login(&'static str),
}

impl std::fmt::Display for LocalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalError::Host => f.write_str("a local cell serves .test hosts only"),
            LocalError::Front(e) => write!(f, "the front refused: {e}"),
            LocalError::Seed(e) => write!(f, "seeding failed: {e:?}"),
            LocalError::Crypto => f.write_str("no key or random value"),
            LocalError::Login(step) => write!(f, "the login failed at {step}"),
        }
    }
}

impl std::error::Error for LocalError {}

/// A cell in process: the production front over a [`MemoryBackend`],
/// with a seeded tenant admin and applicant (module documentation).
pub struct LocalCell {
    front: Front<MemoryBackend, MemoryLog>,
    backend: Arc<MemoryBackend>,
    log: Arc<MemoryLog>,
    cell: [u8; 16],
    host: String,
    admin_key: Ed25519SigningKey,
    admin_credential: Vec<u8>,
    sign_count: Mutex<u32>,
    applicant_email: String,
}

impl std::fmt::Debug for LocalCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCell")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl LocalCell {
    /// Starts the cell `cell` served at `host`, which must end in `.test`.
    /// Passkeys and magic links are enabled (P-70).
    ///
    /// # Errors
    ///
    /// A [`LocalError`] for another host, a refused front or seed, or no
    /// key.
    pub fn start(cell: [u8; 16], host: &str) -> Result<LocalCell, LocalError> {
        if !host.ends_with(".test") {
            return Err(LocalError::Host);
        }
        let backend = Arc::new(MemoryBackend::new());
        let log = Arc::new(MemoryLog::default());
        let cfg = FrontConfig {
            cell,
            host: host.to_owned(),
            enabled: EnabledMethods {
                methods: vec![Method::Passkey, Method::MagicLink],
            },
        };
        let front =
            Front::new(cfg, Arc::clone(&backend), Arc::clone(&log)).map_err(LocalError::Front)?;
        let admin_key = Ed25519SigningKey::generate().map_err(|_| LocalError::Crypto)?;
        let admin_credential = fstp_crypto::random_array::<16>()
            .map_err(|_| LocalError::Crypto)?
            .to_vec();
        let at = Timestamp::from_micros(DEFAULT_NOW_US.saturating_sub(1_000_000));
        backend
            .seed(
                at,
                vec![
                    CellRecord::Tenant(TenantRecord::TenantAdminGranted {
                        account: LOCAL_ADMIN,
                    }),
                    CellRecord::Auth(AuthRecord::CredentialRegistered {
                        account: LOCAL_ADMIN,
                        credential: admin_credential.clone(),
                        key: CoseKey::Ed25519 {
                            x: admin_key.public_key(),
                        },
                        user_verified: true,
                    }),
                ],
            )
            .map_err(LocalError::Seed)?;
        let applicant_email = format!("applicant.CNRY-a1-email-{}@fstp.test", hex(&cell));
        backend.add_login_email(&applicant_email, LOCAL_APPLICANT);
        Ok(LocalCell {
            front,
            backend,
            log,
            cell,
            host: host.to_owned(),
            admin_key,
            admin_credential,
            sign_count: Mutex::new(0),
            applicant_email,
        })
    }

    /// The cell id.
    pub fn id(&self) -> [u8; 16] {
        self.cell
    }

    /// The backend.
    pub fn backend(&self) -> &MemoryBackend {
        &self.backend
    }

    /// Serves one request on the tunnel listener.
    pub fn serve(&self, req: Request) -> Response {
        fstp_rt::future::block_on(self.front.serve(req))
    }

    /// Serves one request on the loopback health listener.
    pub fn serve_health(&self, req: Request) -> Response {
        fstp_rt::future::block_on(self.front.serve_health(req))
    }

    /// Every log event the front wrote so far, in order.
    pub fn logs(&self) -> Vec<LogEvent> {
        self.log.events()
    }

    /// The login email of the seeded applicant. Synthetic.
    pub fn applicant_email(&self) -> &str {
        &self.applicant_email
    }

    /// A POST of `body` to `path` as the cell's own pages send it.
    fn post(&self, path: &str, body: &Value) -> Result<Response, LocalError> {
        Ok(self.serve(self.post_request(path, body)?))
    }

    /// The request of [`LocalCell::post`].
    fn post_request(&self, path: &str, body: &Value) -> Result<Request, LocalError> {
        let target = RequestTarget::origin(path).map_err(|_| LocalError::Login("target"))?;
        let text = fstp_json::to_canonical(body).map_err(|_| LocalError::Login("body"))?;
        let mut req = Request::new(HttpMethod::POST, target)
            .try_with_header("host", self.host.clone())
            .and_then(|r| r.try_with_header("origin", format!("https://{}", self.host)))
            .and_then(|r| r.try_with_header("content-type", "application/json"))
            .map_err(|_| LocalError::Login("header"))?;
        req.body = text.into_bytes();
        Ok(req)
    }

    /// The `Cookie` field value of a response's session cookie.
    fn cookie_of(resp: &Response, step: &'static str) -> Result<Vec<u8>, LocalError> {
        if !resp.status.is_success() {
            return Err(LocalError::Login(step));
        }
        let set = resp
            .headers
            .get("set-cookie")
            .ok_or(LocalError::Login(step))?;
        let pair = set
            .as_bytes()
            .split(|b| *b == b';')
            .next()
            .ok_or(LocalError::Login(step))?;
        Ok(pair.to_vec())
    }

    /// The `Cookie` field value of a fresh passkey session of the seeded
    /// tenant admin, through `POST /auth/passkey/login/options` and
    /// `POST /auth/passkey/login` with a software authenticator.
    ///
    /// # Errors
    ///
    /// [`LocalError::Login`] naming the step that failed.
    pub fn admin_session(&self) -> Result<Vec<u8>, LocalError> {
        let login = self.serve(self.admin_login_request()?);
        LocalCell::cookie_of(&login, "login")
    }

    /// A signed `POST /auth/passkey/login` of the seeded tenant admin,
    /// over a fresh challenge from `POST /auth/passkey/login/options`. It
    /// is not sent, so a test can send it twice.
    ///
    /// # Errors
    ///
    /// [`LocalError::Login`] naming the step that failed.
    pub fn admin_login_request(&self) -> Result<Request, LocalError> {
        let options = self.post("/auth/passkey/login/options", &Value::Object(Object::new()))?;
        let reply = fstp_json::parse(&options.body).map_err(|_| LocalError::Login("options"))?;
        let id = reply
            .get("challenge_id")
            .and_then(Value::as_str)
            .and_then(hex_array::<16>)
            .ok_or(LocalError::Login("options"))?;
        let challenge = self
            .backend
            .peek_challenge(id)
            .ok_or(LocalError::Login("challenge"))?
            .nonce;
        let body = self.admin_assertion(id, &challenge)?;
        self.post_request("/auth/passkey/login", &body)
    }

    /// A signed `POST /auth/stepup` of the seeded tenant admin in the
    /// session whose `Cookie` field value is `cookie`, over the step-up
    /// challenge `id` that `POST /auth/stepup/options` issued (design
    /// section 8.4). It is not sent. Each call signs with the next sign
    /// count.
    ///
    /// # Errors
    ///
    /// [`LocalError::Login`] naming the step that failed.
    pub fn admin_stepup_request(&self, cookie: &[u8], id: [u8; 16]) -> Result<Request, LocalError> {
        let row = self
            .backend
            .peek_challenge(id)
            .ok_or(LocalError::Login("challenge"))?;
        let (Some(session), Some(digest)) = (row.session, row.action_digest) else {
            return Err(LocalError::Login("challenge"));
        };
        let challenge = fstp_auth::stepup::challenge(self.cell, session, digest, row.nonce);
        let body = self.admin_assertion(id, &challenge)?;
        self.post_request("/auth/stepup", &body)?
            .try_with_header("cookie", cookie.to_vec())
            .map_err(|_| LocalError::Login("header"))
    }

    /// The assertion body of the seeded tenant admin's passkey over
    /// `challenge`, naming the challenge row `id`, with UP, UV and the
    /// next sign count.
    fn admin_assertion(&self, id: [u8; 16], challenge: &[u8]) -> Result<Value, LocalError> {
        let count = {
            let mut c = self.sign_count.lock().map_err(|_| LocalError::Crypto)?;
            *c = c.saturating_add(1);
            *c
        };
        let client_data = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
            base64url(challenge),
            self.host
        );
        let mut auth_data = fstp_crypto::sha256(self.host.as_bytes()).to_vec();
        auth_data.push(fstp_webauthn::flags::UP | fstp_webauthn::flags::UV);
        auth_data.extend_from_slice(&count.to_be_bytes());
        let mut message = auth_data.clone();
        message.extend_from_slice(&fstp_crypto::sha256(client_data.as_bytes()));
        let signature = self
            .admin_key
            .sign(&message)
            .map_err(|_| LocalError::Crypto)?;
        let mut o = Object::with_capacity(5);
        o.insert("authenticator_data", Value::String(hex(&auth_data)));
        o.insert("challenge_id", Value::String(hex(&id)));
        o.insert(
            "client_data_json",
            Value::String(hex(client_data.as_bytes())),
        );
        o.insert("credential_id", Value::String(hex(&self.admin_credential)));
        o.insert("signature", Value::String(hex(&signature)));
        Ok(Value::Object(o))
    }

    /// The `Cookie` field value of a fresh magic-link session of the
    /// seeded applicant, through `POST /auth/magic/request`, the outbox
    /// and `POST /auth/magic/consume`.
    ///
    /// # Errors
    ///
    /// [`LocalError::Login`] naming the step that failed.
    pub fn applicant_session(&self) -> Result<Vec<u8>, LocalError> {
        let mut o = Object::with_capacity(1);
        o.insert("email", Value::String(self.applicant_email.clone()));
        let asked = self.post("/auth/magic/request", &Value::Object(o))?;
        if !asked.status.is_success() {
            return Err(LocalError::Login("request"));
        }
        let token = self
            .backend
            .outbox()
            .iter()
            .rev()
            .find(|(a, _)| *a == LOCAL_APPLICANT)
            .map(|(_, t)| *t)
            .ok_or(LocalError::Login("outbox"))?;
        let mut o = Object::with_capacity(1);
        o.insert("token", Value::String(hex(&token)));
        let consumed = self.post("/auth/magic/consume", &Value::Object(o))?;
        LocalCell::cookie_of(&consumed, "consume")
    }
}

/// Unpadded base64url, as a browser writes the client data challenge.
fn base64url(bytes: &[u8]) -> String {
    crate::routes::auth::base64url(bytes)
}

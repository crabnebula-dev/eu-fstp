//! The route backend of a serving cell, over its engine and its
//! application database (design sections 4.2, 5.2 and 5.4). Lane int5.
//!
//! [`PgBackend`] implements [`Backend`]:
//!
//! - commands run through the cell's [`CellEngine`], so every write goes
//!   through `DriverCore` and `PgRecordStore` (design section 5.3), and
//!   reads take the engine's state after the last commit;
//! - the operational rows of design section 4.2 live in `auth.session`,
//!   `auth.challenge`, `auth.sign_count` and `auth.token`, through the
//!   `c_<cell>_app` pool. A session token and a magic-link token are
//!   stored only as their SHA-256 digests. A sign count is keyed by the
//!   HMAC of the credential id under the cell's CredLookup key;
//! - the anchors come from `audit.anchor`, which the app role reads.
//!
//! Readings of lane int5, reported to the lead:
//!
//! - `auth.session` has no column for the credential a passkey session
//!   logged in with (`SessionRow::credential`). The backend keeps that
//!   side table in process memory, so after a restart a device removal
//!   ends no session that logged in before the restart.
//! - The CredLookup key is handed in by the caller. Its keystore group
//!   is not written yet (design section 3.5).
//! - The keyed login email lookup runs in the keystore owner
//!   (`crate::tasks::erasure`), which holds the `Lookup` group and the
//!   index (lane m3/login-m2http). A backend without it fails closed with
//!   [`BackendFault::Unavailable`]. Magic links and recovery email proofs
//!   go to the login email through the proof mail port (`crate::mail`)
//!   until M6 delivers through the outbox, whose data keys the keystore
//!   does not give yet. Interim, pending Daniel.
//! - The address of a pending self-registration or invitation, and the
//!   verified operator ticket of a recovery case, are held in process
//!   memory between two ceremony steps (`Pending`). Interim, pending
//!   Daniel.
//! - The erasure log needs the programme of each text (G30, Q42), which
//!   no record holds yet. It fails closed the same way.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_auth::Method;
use fstp_cell_core::CellState;
use fstp_cell_core::driver::{Done, ExecError};
use fstp_cell_core::gate::Admitted;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_pgstore::Pool;
use fstp_pgwire::Uuid;
use fstp_rt::Runtime;

use crate::engine::{CellEngine, EngineError};
use crate::routes::{
    AnchorRow, Backend, BackendFault, ChallengePurpose, ChallengeRow, ErasureRow, SessionRow,
    TokenKind, TokenRow,
};

/// The `auth.session.method` code of a login method.
const fn method_code(m: Method) -> i16 {
    match m {
        Method::Passkey => 1,
        Method::EudiWallet => 2,
        Method::Opaque => 3,
        Method::MagicLink => 4,
    }
}

fn method_of(code: i16) -> Option<Method> {
    Method::ALL
        .iter()
        .copied()
        .find(|m| method_code(*m) == code)
}

/// The `auth.challenge.purpose` code of a challenge purpose.
const fn purpose_code(p: ChallengePurpose) -> i16 {
    match p {
        ChallengePurpose::Login => 1,
        ChallengePurpose::StepUp => 2,
        ChallengePurpose::Registration => 3,
        ChallengePurpose::Signup => 4,
        ChallengePurpose::Recovery => 5,
    }
}

fn purpose_of(code: i16) -> Option<ChallengePurpose> {
    [
        ChallengePurpose::Login,
        ChallengePurpose::StepUp,
        ChallengePurpose::Registration,
        ChallengePurpose::Signup,
        ChallengePurpose::Recovery,
    ]
    .into_iter()
    .find(|p| purpose_code(*p) == code)
}

/// The `auth.token.kind` code of a token kind.
const fn token_code(k: TokenKind) -> i16 {
    match k {
        TokenKind::MagicLink => 1,
        TokenKind::SignupProof => 2,
        TokenKind::RecoveryEmail => 3,
        TokenKind::RecoveryEnrolment => 4,
    }
}

/// How long a token of `kind` stays valid.
const fn token_lifetime(k: TokenKind) -> i64 {
    match k {
        TokenKind::MagicLink => crate::routes::MAGIC_LINK_US,
        TokenKind::SignupProof => fstp_cell_core::lifetimes::SIGNUP_PROOF_US,
        // Interim, pending Daniel: the email proof of a recovery case
        // lives as long as its case (ADR-008 "Unset lifetimes").
        TokenKind::RecoveryEmail => fstp_cell_core::lifetimes::RECOVERY_CASE_US,
        TokenKind::RecoveryEnrolment => fstp_cell_core::lifetimes::RECOVERY_ENROLMENT_TOKEN_US,
    }
}

fn uuid16(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn account_uuid(a: AccountId) -> Uuid {
    Uuid::from_bytes(a.raw().to_be_bytes())
}

fn account_of(u: &Uuid) -> AccountId {
    AccountId::from_raw(u128::from_be_bytes(*u.as_bytes()))
}

fn fault<E>(_: E) -> BackendFault {
    BackendFault::Unavailable
}

fn arr<const N: usize>(v: &[u8]) -> Result<[u8; N], BackendFault> {
    <[u8; N]>::try_from(v).map_err(fault)
}

/// The route backend of a serving cell (module documentation).
pub struct PgBackend<R: Runtime> {
    engine: CellEngine,
    app: Pool<R>,
    cred_lookup: [u8; 32],
    logins: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
    clock: crate::engine::CommitClock,
    shell: Arc<dyn crate::shell::CreatorShell>,
    proof_mail: Arc<dyn crate::mail::ProofMail>,
    /// The keystore owner, which holds the keyed login email index.
    keys: Option<crate::tasks::erasure::ErasureHandle>,
    /// The cell's deployment mode.
    mode: Option<fstp_auth::recovery::Deployment>,
    /// The pinned control-plane key of operator tickets.
    operator_key: Option<Vec<u8>>,
    /// What the routes keep between two steps of a ceremony (module
    /// documentation).
    pending: Mutex<Pending>,
}

/// What the routes keep between two steps of a ceremony, in process
/// memory. Interim, pending Daniel (lane m3/login-m2http): a restart
/// loses it, so the ceremony starts again.
#[derive(Default)]
struct Pending {
    /// The address each self-registration proves, by its new account.
    signups: BTreeMap<u128, String>,
    /// The address of each invitation, by its token digest.
    invitations: BTreeMap<[u8; 32], String>,
    /// The verified operator ticket of each recovery case.
    tickets: BTreeMap<[u8; 16], Vec<u8>>,
}

impl<R: Runtime> std::fmt::Debug for PgBackend<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgBackend").finish_non_exhaustive()
    }
}

impl<R: Runtime> PgBackend<R> {
    /// The backend of the cell that `engine` runs, over the `c_<cell>_app`
    /// pool `app`, with the CredLookup key `cred_lookup` and the system
    /// clock.
    ///
    /// # Errors
    ///
    /// [`BackendFault::Unavailable`] for a pool of another role.
    pub fn new(
        engine: CellEngine,
        app: Pool<R>,
        cred_lookup: [u8; 32],
    ) -> Result<PgBackend<R>, BackendFault> {
        if app.role() != fstp_pgstore::Role::App {
            return Err(BackendFault::Unavailable);
        }
        Ok(PgBackend {
            engine,
            app,
            cred_lookup,
            logins: Mutex::new(BTreeMap::new()),
            clock: crate::engine::system_commit_clock(),
            shell: Arc::new(crate::shell::ProductionShell),
            proof_mail: Arc::new(crate::mail::NoProofMail),
            keys: None,
            mode: None,
            operator_key: None,
            pending: Mutex::new(Pending::default()),
        })
    }

    /// The same backend over the creator shell `shell` (`crate::shell`).
    #[must_use]
    pub fn with_shell(mut self, shell: Arc<dyn crate::shell::CreatorShell>) -> PgBackend<R> {
        self.shell = shell;
        self
    }

    /// The same backend over the proof mail port `mail` (`crate::mail`).
    #[must_use]
    pub fn with_proof_mail(mut self, mail: Arc<dyn crate::mail::ProofMail>) -> PgBackend<R> {
        self.proof_mail = mail;
        self
    }

    /// The same backend on the cell clock `clock` (`crate::process::StartOptions`).
    #[must_use]
    pub fn with_clock(mut self, clock: crate::engine::CommitClock) -> PgBackend<R> {
        self.clock = clock;
        self
    }

    /// The same backend over the keystore owner `keys`, which holds the
    /// keyed login email index (`crate::tasks::erasure`).
    #[must_use]
    pub fn with_login_index(mut self, keys: crate::tasks::erasure::ErasureHandle) -> PgBackend<R> {
        self.keys = Some(keys);
        self
    }

    /// The same backend in the deployment mode `mode`.
    #[must_use]
    pub fn with_mode(mut self, mode: fstp_auth::recovery::Deployment) -> PgBackend<R> {
        self.mode = Some(mode);
        self
    }

    /// The same backend with the pinned control-plane operator ticket key
    /// `key`, encoded (design section 8.5).
    #[must_use]
    pub fn with_operator_key(mut self, key: Option<Vec<u8>>) -> PgBackend<R> {
        self.operator_key = key;
        self
    }

    /// Keeps `email` as the address of the invitation whose token digest
    /// is `digest` (provisioning of the first admin, design section 9.2
    /// step 10).
    pub fn note_first_admin_email(&self, digest: [u8; 32], email: String) {
        self.pending().invitations.insert(digest, email);
    }

    fn pending(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn login_index(&self) -> Result<&crate::tasks::erasure::ErasureHandle, BackendFault> {
        self.keys.as_ref().ok_or(BackendFault::Unavailable)
    }

    /// Binds `email` to `account` in the keyed index. `false` when it is
    /// another account's login email.
    async fn bind(&self, account: AccountId, email: String) -> Result<bool, BackendFault> {
        match self.login_index()?.set_login_email(account, email).await {
            Ok(crate::tasks::erasure::LoginEmailSet::Set) => Ok(true),
            Ok(crate::tasks::erasure::LoginEmailSet::Taken) => Ok(false),
            Err(_) => Err(BackendFault::Unavailable),
        }
    }

    /// Sends `token` of `kind` to the login email of `account`.
    async fn mail_account(
        &self,
        account: AccountId,
        kind: crate::mail::ProofKind,
        token: [u8; 32],
    ) -> Result<(), BackendFault> {
        let email = self
            .login_index()?
            .login_email(account)
            .await
            .map_err(fault)?
            .ok_or(BackendFault::Unavailable)?;
        self.proof_mail.send(kind, &email, token).map_err(fault)
    }

    fn logins(&self) -> MutexGuard<'_, BTreeMap<[u8; 16], Vec<u8>>> {
        self.logins.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn credential_key(&self, credential: &[u8]) -> Vec<u8> {
        fstp_crypto::hmac_sha256(&self.cred_lookup, credential).to_vec()
    }

    fn session_row(&self, row: &fstp_pgwire::Row) -> Result<SessionRow, BackendFault> {
        let id: Uuid = row.get(0).map_err(fault)?;
        let account: Uuid = row.get(1).map_err(fault)?;
        let method =
            method_of(row.get::<i16>(2).map_err(fault)?).ok_or(BackendFault::Unavailable)?;
        let started: i64 = row.get(3).map_err(fault)?;
        let last: i64 = row.get(4).map_err(fault)?;
        let id = *id.as_bytes();
        Ok(SessionRow {
            id,
            account: account_of(&account),
            method,
            started: Timestamp::from_micros(started),
            last_used: Timestamp::from_micros(last),
            credential: self.logins().get(&id).cloned(),
        })
    }
}

impl<R: Runtime> Backend for PgBackend<R> {
    fn now(&self) -> Timestamp {
        Timestamp::from_micros((self.clock)())
    }

    fn creator_facts(
        &self,
        state: &CellState,
        cmd: &fstp_creator::CreatorCommand,
    ) -> fstp_cell_core::creator::CreatorFacts {
        self.shell.facts(state, cmd)
    }

    fn state(&self) -> impl Future<Output = Result<Arc<CellState>, BackendFault>> + Send {
        std::future::ready(Ok(self.engine.state()))
    }

    async fn execute(&self, admitted: Admitted) -> Result<Result<Done, ExecError>, BackendFault> {
        match self.engine.execute(admitted).await {
            Ok(done) => Ok(Ok(done)),
            Err(EngineError::Exec(e)) => Ok(Err(e)),
            Err(EngineError::ShuttingDown | EngineError::Stopped) => Err(BackendFault::Unavailable),
        }
    }

    async fn session(&self, token: [u8; 32]) -> Result<Option<SessionRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT session_id, account_id, method, created_at, last_seen_at FROM auth.session WHERE token_hash = $1",
                &[&token.to_vec()],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(None),
            [row] => self.session_row(row).map(Some),
            _ => Err(BackendFault::Unavailable),
        }
    }

    async fn sessions_of(&self, account: AccountId) -> Result<Vec<SessionRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT session_id, account_id, method, created_at, last_seen_at FROM auth.session WHERE account_id = $1 ORDER BY session_id",
                &[&account_uuid(account)],
            )
            .await
            .map_err(fault)?;
        c.release();
        rows.iter().map(|r| self.session_row(r)).collect()
    }

    async fn open_session(&self, token: [u8; 32], row: SessionRow) -> Result<(), BackendFault> {
        let lifetimes = fstp_auth::SessionLifetimes::DEFAULT;
        let started = row.started.micros();
        let last = row.last_used.micros();
        let idle = last.saturating_add(lifetimes.idle_us);
        let absolute = started.saturating_add(lifetimes.absolute_us);
        let mut c = self.app.get().await.map_err(fault)?;
        c.execute(
            "INSERT INTO auth.session (token_hash, session_id, account_id, method, created_at, last_seen_at, idle_expiry, absolute_expiry) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &token.to_vec(),
                &uuid16(row.id),
                &account_uuid(row.account),
                &method_code(row.method),
                &started,
                &last,
                &idle,
                &absolute,
            ],
        )
        .await
        .map_err(fault)?;
        c.release();
        if let Some(cred) = row.credential {
            self.logins().insert(row.id, cred);
        }
        Ok(())
    }

    async fn touch_session(&self, id: [u8; 16], at: Timestamp) -> Result<(), BackendFault> {
        let idle = at
            .micros()
            .saturating_add(fstp_auth::SessionLifetimes::DEFAULT.idle_us);
        let mut c = self.app.get().await.map_err(fault)?;
        c.execute(
            "UPDATE auth.session SET last_seen_at = greatest(last_seen_at, $2), idle_expiry = greatest(idle_expiry, $3) WHERE session_id = $1",
            &[&uuid16(id), &at.micros(), &idle],
        )
        .await
        .map_err(fault)?;
        c.release();
        Ok(())
    }

    async fn put_challenge(&self, row: ChallengeRow) -> Result<(), BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        c.execute(
            "INSERT INTO auth.challenge (id, session_id, purpose, action_digest, challenge, issued_at) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &uuid16(row.id),
                &row.session.map(uuid16),
                &purpose_code(row.purpose),
                &row.action_digest.map(|d| d.to_vec()),
                &row.nonce.to_vec(),
                &row.issued_at.micros(),
            ],
        )
        .await
        .map_err(fault)?;
        c.release();
        Ok(())
    }

    async fn challenge(&self, id: [u8; 16]) -> Result<Option<ChallengeRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT id, session_id, purpose, action_digest, challenge, issued_at FROM auth.challenge WHERE id = $1",
                &[&uuid16(id)],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(None),
            [row] => challenge_row(row).map(Some),
            _ => Err(BackendFault::Unavailable),
        }
    }

    async fn take_challenge(&self, id: [u8; 16]) -> Result<Option<ChallengeRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        // A step-up challenge is never taken: only the writer's
        // `auth_log.stepup_consumed` row ends it (design section 4.2).
        let rows = c
            .query(
                "DELETE FROM auth.challenge WHERE id = $1 AND purpose <> 2 \
                 RETURNING id, session_id, purpose, action_digest, challenge, issued_at",
                &[&uuid16(id)],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(None),
            [row] => challenge_row(row).map(Some),
            _ => Err(BackendFault::Unavailable),
        }
    }

    async fn sign_count(&self, credential: Vec<u8>) -> Result<u32, BackendFault> {
        let key = self.credential_key(&credential);
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT sign_count FROM auth.sign_count WHERE credential_key = $1",
                &[&key],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(0),
            [row] => u32::try_from(row.get::<i64>(0).map_err(fault)?).map_err(fault),
            _ => Err(BackendFault::Unavailable),
        }
    }

    async fn set_sign_count(&self, credential: Vec<u8>, count: u32) -> Result<(), BackendFault> {
        let key = self.credential_key(&credential);
        let now = (self.clock)();
        let mut c = self.app.get().await.map_err(fault)?;
        // The count only rises, so a late writer never lowers it.
        c.execute(
            "INSERT INTO auth.sign_count (credential_key, sign_count, last_used_at) VALUES ($1, $2, $3) \
             ON CONFLICT (credential_key) DO UPDATE SET sign_count = greatest(auth.sign_count.sign_count, EXCLUDED.sign_count), last_used_at = EXCLUDED.last_used_at",
            &[&key, &i64::from(count), &now],
        )
        .await
        .map_err(fault)?;
        c.release();
        Ok(())
    }

    async fn login_account(&self, email: String) -> Result<Option<AccountId>, BackendFault> {
        // The keyed lookup under the keystore's `Lookup` key (module
        // documentation).
        self.login_index()?
            .login_account(email)
            .await
            .map_err(fault)
    }

    async fn token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> Result<Option<TokenRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT account_id, expires_at FROM auth.token WHERE token_hash = $1 AND kind = $2 AND consumed_at IS NULL",
                &[&digest.to_vec(), &token_code(kind)],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(None),
            [row] => {
                let account: Option<Uuid> = row.get(0).map_err(fault)?;
                let expires: i64 = row.get(1).map_err(fault)?;
                let account = account.ok_or(BackendFault::Unavailable)?;
                Ok(Some(TokenRow {
                    digest,
                    kind,
                    account: account_of(&account),
                    issued_at: Timestamp::from_micros(expires.saturating_sub(token_lifetime(kind))),
                }))
            }
            _ => Err(BackendFault::Unavailable),
        }
    }

    fn note_signup_email(
        &self,
        account: AccountId,
        email: String,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.pending().signups.insert(account.raw(), email);
        std::future::ready(Ok(()))
    }

    async fn bind_signup_email(&self, account: AccountId) -> Result<bool, BackendFault> {
        let email = self.pending().signups.remove(&account.raw());
        match email {
            Some(e) => self.bind(account, e).await,
            None => Err(BackendFault::Unavailable),
        }
    }

    fn note_invitation_email(
        &self,
        digest: [u8; 32],
        email: String,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.pending().invitations.insert(digest, email);
        std::future::ready(Ok(()))
    }

    async fn bind_invitation_email(
        &self,
        digest: [u8; 32],
        account: AccountId,
    ) -> Result<(), BackendFault> {
        let email = self.pending().invitations.remove(&digest);
        match email {
            // An invitation that named no address enrols an account with
            // no login email, as before lane m3/login-m2http.
            None => Ok(()),
            Some(e) => match self.bind(account, e).await? {
                true => Ok(()),
                false => Err(BackendFault::Unavailable),
            },
        }
    }

    async fn send_recovery_proof(
        &self,
        account: AccountId,
        case: [u8; 16],
        token: [u8; 32],
    ) -> Result<(), BackendFault> {
        self.mail_account(account, crate::mail::ProofKind::Recovery { case }, token)
            .await
    }

    async fn send_recovery_enrolment(
        &self,
        account: AccountId,
        case: [u8; 16],
        token: [u8; 32],
    ) -> Result<(), BackendFault> {
        self.mail_account(
            account,
            crate::mail::ProofKind::RecoveryEnrolment { case },
            token,
        )
        .await
    }

    fn deployment(&self) -> Option<fstp_auth::recovery::Deployment> {
        self.mode
    }

    fn operator_key(&self) -> Option<Vec<u8>> {
        self.operator_key.clone()
    }

    fn put_operator_ticket(
        &self,
        case: [u8; 16],
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, BackendFault>> + Send {
        let mut p = self.pending();
        let fresh = !p.tickets.contains_key(&case);
        if fresh {
            p.tickets.insert(case, bytes);
        }
        std::future::ready(Ok(fresh))
    }

    fn operator_ticket(
        &self,
        case: [u8; 16],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, BackendFault>> + Send {
        std::future::ready(Ok(self.pending().tickets.get(&case).cloned()))
    }

    async fn put_token(&self, row: TokenRow) -> Result<(), BackendFault> {
        let expires = row
            .issued_at
            .micros()
            .saturating_add(token_lifetime(row.kind));
        let mut c = self.app.get().await.map_err(fault)?;
        c.execute(
            "INSERT INTO auth.token (token_hash, kind, account_id, expires_at, consumed_at) VALUES ($1, $2, $3, $4, NULL)",
            &[
                &row.digest.to_vec(),
                &token_code(row.kind),
                &account_uuid(row.account),
                &expires,
            ],
        )
        .await
        .map_err(fault)?;
        c.release();
        Ok(())
    }

    async fn take_token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> Result<Option<TokenRow>, BackendFault> {
        let now = (self.clock)();
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "UPDATE auth.token SET consumed_at = $3 WHERE token_hash = $1 AND kind = $2 AND consumed_at IS NULL \
                 RETURNING account_id, expires_at",
                &[&digest.to_vec(), &token_code(kind), &now],
            )
            .await
            .map_err(fault)?;
        c.release();
        match rows.as_slice() {
            [] => Ok(None),
            [row] => {
                let account: Option<Uuid> = row.get(0).map_err(fault)?;
                let expires: i64 = row.get(1).map_err(fault)?;
                let Some(account) = account else {
                    return Err(BackendFault::Unavailable);
                };
                Ok(Some(TokenRow {
                    digest,
                    kind,
                    account: account_of(&account),
                    issued_at: Timestamp::from_micros(expires.saturating_sub(token_lifetime(kind))),
                }))
            }
            _ => Err(BackendFault::Unavailable),
        }
    }

    async fn send_magic_link(
        &self,
        account: AccountId,
        token: [u8; 32],
    ) -> Result<(), BackendFault> {
        // Interim, pending Daniel: the link goes through the proof mail
        // port to the account's login email until M6 delivers it through
        // the outbox (module documentation).
        self.mail_account(account, crate::mail::ProofKind::MagicLink, token)
            .await
    }

    fn send_signup_proof(
        &self,
        email: String,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        std::future::ready(
            self.proof_mail
                .send(crate::mail::ProofKind::Signup, &email, token)
                .map_err(fault),
        )
    }

    fn stepup_asserted_at(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<Timestamp>, BackendFault>> + Send {
        // The entry instant of the `StepUpGranted` record, as the fold
        // holds it.
        std::future::ready(Ok(self
            .engine
            .state()
            .auth()
            .stepup_grant(id)
            .map(|g| g.granted_at)))
    }

    async fn anchors(&self) -> Result<Vec<AnchorRow>, BackendFault> {
        let mut c = self.app.get().await.map_err(fault)?;
        let rows = c
            .query(
                "SELECT n, link, at, witness_seq FROM audit.anchor ORDER BY n",
                &[],
            )
            .await
            .map_err(fault)?;
        c.release();
        rows.iter()
            .map(|r| {
                let n: i64 = r.get(0).map_err(fault)?;
                let link: Vec<u8> = r.get(1).map_err(fault)?;
                let at: i64 = r.get(2).map_err(fault)?;
                let seq: i64 = r.get(3).map_err(fault)?;
                Ok(AnchorRow {
                    n: u64::try_from(n).map_err(fault)?,
                    link: arr(&link)?,
                    at,
                    witness_seq: u64::try_from(seq).map_err(fault)?,
                })
            })
            .collect()
    }

    fn erasures(&self) -> impl Future<Output = Result<Vec<ErasureRow>, BackendFault>> + Send {
        // The programme scope of each text is not recorded (module
        // documentation).
        std::future::ready(Err(BackendFault::Unavailable))
    }
}

fn challenge_row(row: &fstp_pgwire::Row) -> Result<ChallengeRow, BackendFault> {
    let id: Uuid = row.get(0).map_err(fault)?;
    let session: Option<Uuid> = row.get(1).map_err(fault)?;
    let purpose = purpose_of(row.get::<i16>(2).map_err(fault)?).ok_or(BackendFault::Unavailable)?;
    let digest: Option<Vec<u8>> = row.get(3).map_err(fault)?;
    let nonce: Vec<u8> = row.get(4).map_err(fault)?;
    let issued: i64 = row.get(5).map_err(fault)?;
    Ok(ChallengeRow {
        id: *id.as_bytes(),
        purpose,
        session: session.map(|s| *s.as_bytes()),
        action_digest: digest.map(|d| arr(&d)).transpose()?,
        nonce: arr(&nonce)?,
        issued_at: Timestamp::from_micros(issued),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Design section 4.2: the method, purpose and token codes are one to
    /// one, so a row reads back as the value it stored.
    #[test]
    fn adr008_operational_codes_round_trip() {
        for m in Method::ALL {
            assert_eq!(method_of(method_code(m)), Some(m));
        }
        for p in [
            ChallengePurpose::Login,
            ChallengePurpose::StepUp,
            ChallengePurpose::Registration,
        ] {
            assert_eq!(purpose_of(purpose_code(p)), Some(p));
        }
        assert_eq!(method_of(0), None);
        assert_eq!(purpose_of(9), None);
        assert_eq!(token_code(TokenKind::MagicLink), 1);
    }
}

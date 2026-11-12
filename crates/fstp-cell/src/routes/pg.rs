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
//! - The keyed login email lookup and the outbox need the Lookup key and
//!   the outbox data keys, which the keystore does not give yet. Both
//!   calls fail closed with [`BackendFault::Unavailable`].
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
    }
}

fn purpose_of(code: i16) -> Option<ChallengePurpose> {
    [
        ChallengePurpose::Login,
        ChallengePurpose::StepUp,
        ChallengePurpose::Registration,
    ]
    .into_iter()
    .find(|p| purpose_code(*p) == code)
}

/// The `auth.token.kind` code of a token kind.
const fn token_code(k: TokenKind) -> i16 {
    match k {
        TokenKind::MagicLink => 1,
    }
}

/// How long a token of `kind` stays valid.
const fn token_lifetime(k: TokenKind) -> i64 {
    match k {
        TokenKind::MagicLink => crate::routes::MAGIC_LINK_US,
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
        })
    }

    /// The same backend on the cell clock `clock` (`crate::process::start_with_clock`).
    #[must_use]
    pub fn with_clock(mut self, clock: crate::engine::CommitClock) -> PgBackend<R> {
        self.clock = clock;
        self
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

    fn login_account(
        &self,
        email: String,
    ) -> impl Future<Output = Result<Option<AccountId>, BackendFault>> + Send {
        // The keyed lookup needs the Lookup key (module documentation).
        let _ = email;
        std::future::ready(Err(BackendFault::Unavailable))
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

    fn send_magic_link(
        &self,
        account: AccountId,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        // The outbox row is sealed under an outbox data key, which the
        // keystore does not give yet (module documentation).
        let _ = (account, token);
        std::future::ready(Err(BackendFault::Unavailable))
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

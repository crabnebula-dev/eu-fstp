//! What the routes need from the cell runtime (design sections 4.2, 5.2
//! and 5.4).
//!
//! The route layer holds no state of its own. It reads the folded ledger
//! and runs admitted commands through the engine, and it reads and writes
//! the operational rows of design section 4.2: sessions, challenges,
//! tokens and sign counts. [`Backend`] names each of these. The cell's
//! engine (lane W3a agent two) implements it over `PgRecordStore` and the
//! application database. `crate::routes::memory::MemoryBackend`
//! implements it in memory for tests, behind the test-only `memory`
//! feature.
//!
//! Every call is async, so a backend over the database never blocks a
//! request task. A [`BackendFault`] makes the route answer 503: the
//! request fails closed and nothing is decided on partial data.

use std::future::Future;
use std::sync::Arc;

use fstp_auth::Method;
use fstp_cell_core::CellState;
use fstp_cell_core::driver::{Done, ExecError};
use fstp_cell_core::gate::Admitted;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

/// Why the backend did not answer. It carries no detail, so a refusal
/// never shows storage content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendFault {
    /// The database, the engine or the outbox is unavailable.
    Unavailable,
}

/// One row of `auth.session` (design section 4.2), with the credential a
/// passkey session logged in with (`fstp_auth::session::SessionLogin`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    /// The session id.
    pub id: [u8; 16],
    /// The account.
    pub account: AccountId,
    /// The login method.
    pub method: Method,
    /// When the session started.
    pub started: Timestamp,
    /// When the session was last used.
    pub last_used: Timestamp,
    /// The credential a passkey session logged in with.
    pub credential: Option<Vec<u8>>,
}

/// The purpose a challenge is bound to (ADR-008 "Challenges").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// A passkey login.
    Login,
    /// A step-up for one action digest in one session.
    StepUp,
    /// The registration of a first passkey in an invitation ceremony
    /// (design section 8.3), bound to the digest of the invitation proof
    /// its options call named.
    Registration,
    /// The registration of the first passkey of a self-registration
    /// (design section 8.3 ceremony 2), bound to the digest of the email
    /// proof token its options call named.
    Signup,
    /// The registration of the new passkey of a recovery completion
    /// (design section 8.5), bound to the digest of the case and its
    /// enrolment token.
    Recovery,
}

/// One row of `auth.challenge` (design section 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeRow {
    /// The challenge id.
    pub id: [u8; 16],
    /// The purpose.
    pub purpose: ChallengePurpose,
    /// The session of a step-up challenge.
    pub session: Option<[u8; 16]>,
    /// The action digest of a step-up challenge, or the invitation proof
    /// digest a registration challenge is bound to
    /// (`fstp_auth::ceremony::token_digest` or `split_token_digest`).
    pub action_digest: Option<[u8; 32]>,
    /// The nonce the challenge was made from, or the challenge itself for
    /// a login.
    pub nonce: [u8; 32],
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// The kind of a single-use token in `auth.token` (design section 4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// A magic link.
    MagicLink,
    /// The email proof of a self-registration. Its row names the new
    /// account the route drew (design section 8.3 ceremony 2).
    SignupProof,
    /// The email proof of a recovery case (design section 8.5). Its
    /// digest is `SHA-256(case || token)`, so it proves one case only.
    RecoveryEmail,
    /// The one-time enrolment token of a recovery case, given to the
    /// holder who proved the email (design section 8.5). Its digest is
    /// `SHA-256(case || token)`.
    RecoveryEnrolment,
}

/// One row of `auth.token`. Only the token's SHA-256 digest is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenRow {
    /// The SHA-256 digest of the token.
    pub digest: [u8; 32],
    /// The kind.
    pub kind: TokenKind,
    /// The account.
    pub account: AccountId,
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// One row of `audit.anchor` (design section 4.2), as an Auditor or a
/// tenant admin reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRow {
    /// The chain position.
    pub n: u64,
    /// The chain link.
    pub link: [u8; 32],
    /// UTC microseconds.
    pub at: i64,
    /// The witness sequence of the receipt.
    pub witness_seq: u64,
}

/// One erasure-log entry (ADR-007, design section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasureRow {
    /// The text id.
    pub text: [u8; 16],
    /// When the erasure was requested, UTC microseconds.
    pub requested_at: i64,
    /// When it completed, if it did.
    pub completed_at: Option<i64>,
    /// The cause, as a closed code.
    pub cause: u16,
    /// The programme the text belongs to, or `None` for a tenant-wide text
    /// such as a login email (G30, Q42).
    pub programme: Option<u128>,
}

/// What the routes need from the cell runtime.
pub trait Backend: Send + Sync + 'static {
    /// The cell clock, UTC microseconds.
    fn now(&self) -> Timestamp;

    /// The creator shell facts of `cmd` on `state` (`crate::shell`). The
    /// default holds none, so every check that needs one fails closed.
    fn creator_facts(
        &self,
        state: &CellState,
        cmd: &fstp_creator::CreatorCommand,
    ) -> fstp_cell_core::creator::CreatorFacts {
        let _ = (state, cmd);
        fstp_cell_core::creator::CreatorFacts::default()
    }

    /// The state folded to the engine's head.
    fn state(&self) -> impl Future<Output = Result<Arc<CellState>, BackendFault>> + Send;

    /// Runs one admitted command through the engine (design section 5.2).
    /// It is the only way a command reaches `DriverCore`.
    fn execute(
        &self,
        admitted: Admitted,
    ) -> impl Future<Output = Result<Result<Done, ExecError>, BackendFault>> + Send;

    /// The live session whose token has the SHA-256 digest `token`.
    fn session(
        &self,
        token: [u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, BackendFault>> + Send;

    /// Every session row of `account`.
    fn sessions_of(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<SessionRow>, BackendFault>> + Send;

    /// Opens a session under the token digest `token`.
    fn open_session(
        &self,
        token: [u8; 32],
        row: SessionRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// Records a use of session `id` at `at`, for the idle lifetime.
    fn touch_session(
        &self,
        id: [u8; 16],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// Stores a challenge.
    fn put_challenge(
        &self,
        row: ChallengeRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// Reads challenge `id` without consuming it.
    ///
    /// A step-up challenge is never taken by a route. It ends only by the
    /// `auth_log.stepup_consumed` row that the writer inserts with
    /// `StepUpConsumed` (design section 4.2, ADR-008). A login route reads
    /// the row first and takes it only once its purpose is a login, so no
    /// request burns a challenge of another purpose.
    ///
    /// The provided body fails closed: a backend that does not override it
    /// answers every passkey login and step-up with 503. The memory backend
    /// overrides it, and the engine's backend (lane w3ae) must too.
    fn challenge(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<ChallengeRow>, BackendFault>> + Send {
        let _ = id;
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// Takes login or registration challenge `id`, at most once: a second
    /// take finds nothing. Only the passkey login route and the ceremony
    /// routes take a challenge, each only of its own purpose.
    fn take_challenge(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<ChallengeRow>, BackendFault>> + Send;

    /// The stored sign count of `credential`, zero when none is stored.
    fn sign_count(
        &self,
        credential: Vec<u8>,
    ) -> impl Future<Output = Result<u32, BackendFault>> + Send;

    /// Stores the sign count of `credential`.
    fn set_sign_count(
        &self,
        credential: Vec<u8>,
        count: u32,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// The account whose login email is `email`, through the keyed lookup
    /// of design section 4.2. The backend normalises the address.
    fn login_account(
        &self,
        email: String,
    ) -> impl Future<Output = Result<Option<AccountId>, BackendFault>> + Send;

    /// Stores a single-use token.
    fn put_token(&self, row: TokenRow) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// Takes the token of `kind` with digest `digest`, at most once.
    fn take_token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> impl Future<Output = Result<Option<TokenRow>, BackendFault>> + Send;

    /// Puts a magic link for `account` with `token` into the outbox. M6
    /// delivers it.
    fn send_magic_link(
        &self,
        account: AccountId,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send;

    /// Sends the email proof `token` of a self-registration to `email`
    /// through the cell's proof mail port (`crate::mail`). The provided
    /// body fails closed.
    fn send_signup_proof(
        &self,
        email: String,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (email, token);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// The live token of `kind` with digest `digest`, without taking it.
    /// The provided body fails closed.
    fn token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> impl Future<Output = Result<Option<TokenRow>, BackendFault>> + Send {
        let _ = (digest, kind);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// Keeps `email` as the address the self-registration of `account`
    /// proves, until [`Backend::bind_signup_email`]. The provided body
    /// keeps nothing.
    fn note_signup_email(
        &self,
        account: AccountId,
        email: String,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (account, email);
        std::future::ready(Ok(()))
    }

    /// Makes the address kept for `account` its login email, through the
    /// keyed index (design section 4.2). `false` when the address is the
    /// login email of another account. The provided body keeps no index
    /// and answers `true`.
    fn bind_signup_email(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<bool, BackendFault>> + Send {
        let _ = account;
        std::future::ready(Ok(true))
    }

    /// Keeps `email` as the address of the invitation whose token digest
    /// is `digest`, until [`Backend::bind_invitation_email`]. The provided
    /// body fails closed.
    fn note_invitation_email(
        &self,
        digest: [u8; 32],
        email: String,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (digest, email);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// Makes the address kept for the invitation `digest` the login email
    /// of `account`, which enrolled through it. The provided body keeps
    /// nothing.
    fn bind_invitation_email(
        &self,
        digest: [u8; 32],
        account: AccountId,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (digest, account);
        std::future::ready(Ok(()))
    }

    /// Sends the email proof `token` of recovery case `case` to the login
    /// email of `account` through the cell's proof mail port. The provided
    /// body fails closed.
    fn send_recovery_proof(
        &self,
        account: AccountId,
        case: [u8; 16],
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (account, case, token);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// Sends the one-time enrolment token `token` of recovery case `case`
    /// to the login email of `account` through the cell's proof mail port.
    /// The provided body fails closed.
    fn send_recovery_enrolment(
        &self,
        account: AccountId,
        case: [u8; 16],
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        let _ = (account, case, token);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// The cell's deployment mode, which picks the recovery path. `None`
    /// fails the recovery request closed.
    fn deployment(&self) -> Option<fstp_auth::recovery::Deployment> {
        None
    }

    /// The pinned control-plane key of operator tickets (design section
    /// 8.5), encoded. `None` refuses every ticket.
    fn operator_key(&self) -> Option<Vec<u8>> {
        None
    }

    /// Keeps the verified operator ticket `bytes` of case `case`. `false`
    /// when the case holds one already. The provided body fails closed.
    fn put_operator_ticket(
        &self,
        case: [u8; 16],
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, BackendFault>> + Send {
        let _ = (case, bytes);
        std::future::ready(Err(BackendFault::Unavailable))
    }

    /// The operator ticket kept for case `case`, if any.
    fn operator_ticket(
        &self,
        case: [u8; 16],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, BackendFault>> + Send {
        let _ = case;
        std::future::ready(Ok(None))
    }

    /// When step-up `id` was asserted: the instant of its `StepUpGranted`
    /// entry.
    fn stepup_asserted_at(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<Timestamp>, BackendFault>> + Send;

    /// Every anchor of the cell's chain, in chain order.
    fn anchors(&self) -> impl Future<Output = Result<Vec<AnchorRow>, BackendFault>> + Send;

    /// Every erasure-log entry, in request order.
    fn erasures(&self) -> impl Future<Output = Result<Vec<ErasureRow>, BackendFault>> + Send;
}

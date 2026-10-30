//! The `/auth` routes (I-77, I-78, R-LG-04, ADR-008, design sections 8.1
//! to 8.5 and 8.7).
//!
//! Body forms, a reading of this lane: every body is canonical JSON
//! ([`crate::http::body`]), and byte strings are lowercase hexadecimal, as
//! in the `fstp-auth` codecs. A page converts the browser's base64url
//! `toJSON()` members to hexadecimal, so the cell needs no base64url
//! parser. Option replies carry the WebAuthn JSON members that
//! `parseRequestOptionsFromJSON` reads, with base64url challenges.
//!
//! Steps that need an API the sources do not offer yet fail closed with
//! 501 after every check that applies before them:
//! - `GrantStepUp` after a verified step-up assertion: the route asks
//!   `fstp_cell_core::gate::admit_stepup_grant` and runs the grant under
//!   the challenge id. That admission refuses until the gate can verify
//!   the step-up proof (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`).
//! - `EndSession` and `RevokeCredential`: `decide` takes no session rows
//!   (`fstp_cell_core::RouteInput::SessionRows`).
//! - Adding a passkey: the step-up digest of `AddPasskey` names a
//!   credential id that the options call cannot know yet.
//! - The invitation enrolment: the options call and the register checks
//!   are built (design section 8.3), and the commit needs
//!   [`INVITATION_SEAM`].
//! - Self-registration, the recovery request and its email proof, and the
//!   recovery completion: their routes are not written yet. Int3 added
//!   `admit_recovery_request` and `admit_recovery_completion`, which
//!   these routes are to call.

use fstp_auth::ceremony::{
    InvitationProof, MagicLink, Registration, admit_magic_link, may_issue_magic_link,
    split_token_digest, token_digest, verify_new_passkey,
};
use fstp_auth::codec::Token;
use fstp_auth::session::{LoginRefusal, may_end_session, verify_passkey_login};
use fstp_auth::stepup::{Granted, StepUpRequest, challenge as stepup_challenge, verify_step_up};
use fstp_auth::{Method, SessionLifetimes, SessionView};
use fstp_cell_core::gate::{
    Action, HighRiskAction, ReadAction, RouteDeny, admit_stepup_grant, management_holders,
};
use fstp_cell_core::{CellCommand, CellState};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_http::{Request, StatusCode};
use fstp_json::{Array, Number, Object, Value};
use fstp_webauthn::{AssertionResponse, RegistrationResponse};

use crate::http::body::{self, BodyRefusal};
use crate::http::{decode_command_body, set_session_cookie};
use crate::routes::handle::{
    Caller, Ctx, Reply, Rule, admit, bad_body, decimal, denied, hex_value, needs_route_input,
    random, run, unavailable,
};
use crate::routes::{
    AUTH_BODY_LIMIT, Backend, CEREMONY_BODY_LIMIT, ChallengePurpose, ChallengeRow, SessionRow,
    TokenKind, TokenRow,
};

/// How long a login or step-up challenge stays valid: 5 minutes.
/// Interim, pending Daniel: the design sets no challenge lifetime, so this
/// lane takes the P-71 default.
pub const CHALLENGE_US: i64 = fstp_cell_core::tenant::P71_DEFAULT_US;

/// How long a magic link stays valid: 15 minutes. Interim, pending Daniel
/// (ADR-008 open point "Unset lifetimes").
pub const MAGIC_LINK_US: i64 = 15 * 60 * 1_000_000;

/// The WebAuthn `timeout` of an options reply, in milliseconds.
const TIMEOUT_MS: &str = "300000";

/// The longest client data JSON a body may carry.
const MAX_CLIENT_DATA: usize = 4096;
/// The longest authenticator data an assertion may carry.
const MAX_AUTH_DATA: usize = 1024;
/// The longest signature: RSA with a 4096-bit modulus.
const MAX_SIGNATURE: usize = 512;
/// The longest credential id (WebAuthn Level 2 section 5.8.3).
const MAX_CREDENTIAL: usize = fstp_auth::codec::MAX_CREDENTIAL_LEN;
/// The longest login email (RFC 5321 path limit).
const MAX_EMAIL: usize = 254;

/// Unpadded base64url of `bytes` (RFC 4648 section 5). An encoder only:
/// the cell parses no base64url.
pub(crate) fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        let chars = chunk.len().saturating_add(1);
        for k in 0..chars {
            let shift = 18usize.saturating_sub(k.saturating_mul(6));
            let idx = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            if let Some(c) = ALPHABET.get(idx) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

/// Whether `issued + lifetime_us >= now >= issued`. An overflow is false.
fn fresh(issued: Timestamp, now: Timestamp, lifetime_us: i64) -> bool {
    match now.micros().checked_sub(issued.micros()) {
        Some(age) => age >= 0 && age <= lifetime_us,
        None => false,
    }
}

/// Whether `a` holds a management role at `now` (design section 8.2):
/// a Drafting, Judging or Operations binding, or tenant admin.
pub(crate) fn holds(s: &CellState, a: AccountId, now: Timestamp) -> bool {
    s.tenant().is_admin(a) || management_holders(s, now).contains(&a)
}

/// The P-72 lifetimes of the tenant.
fn lifetimes(s: &CellState) -> SessionLifetimes {
    let p = s.tenant().policy();
    SessionLifetimes {
        idle_us: p.p72_idle_us(),
        absolute_us: p.p72_absolute_us(),
    }
}

/// A login refusal: 401, the same body for every cause.
fn login_refused(rule: Rule) -> Reply {
    Reply::refuse(StatusCode::UNAUTHORIZED, Some(rule), "login")
}

/// A step-up refusal: 403 under I-78.
fn stepup_refused() -> Reply {
    Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::I78), "stepup")
}

/// Decodes an empty schema: `{}`.
fn decode_empty_object(bytes: &[u8]) -> Result<(), BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &[], &[])
}

/// A passkey assertion body and the challenge it answers.
struct AssertionBody {
    challenge_id: [u8; 16],
    assertion: AssertionResponse,
}

/// The members of an assertion body.
const ASSERTION_MEMBERS: [&str; 5] = [
    "authenticator_data",
    "challenge_id",
    "client_data_json",
    "credential_id",
    "signature",
];

fn decode_assertion(bytes: &[u8]) -> Result<AssertionBody, BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &ASSERTION_MEMBERS, &[])?;
    Ok(AssertionBody {
        challenge_id: body::hex_member::<16>(&o, "challenge_id")?,
        assertion: AssertionResponse {
            credential_id: body::bytes_member(&o, "credential_id", MAX_CREDENTIAL)?,
            client_data_json: body::bytes_member(&o, "client_data_json", MAX_CLIENT_DATA)?,
            authenticator_data: body::bytes_member(&o, "authenticator_data", MAX_AUTH_DATA)?,
            signature: body::bytes_member(&o, "signature", MAX_SIGNATURE)?,
        },
    })
}

/// The WebAuthn request options of a challenge.
fn request_options<B>(ctx: &Ctx<B>, challenge: &[u8; 32], uv: &str, allow: &[Vec<u8>]) -> Value {
    let mut pk = Object::with_capacity(5);
    if !allow.is_empty() {
        let creds: Array = allow
            .iter()
            .map(|id| {
                let mut c = Object::with_capacity(2);
                c.insert("id", Value::String(base64url(id)));
                c.insert("type", Value::String("public-key".to_owned()));
                Value::Object(c)
            })
            .collect();
        pk.insert("allowCredentials", Value::Array(creds));
    }
    pk.insert("challenge", Value::String(base64url(challenge)));
    pk.insert("rpId", Value::String(ctx.cfg.rp.parts().0.to_owned()));
    if let Ok(n) = Number::from_lexeme(TIMEOUT_MS) {
        pk.insert("timeout", Value::Number(n));
    }
    pk.insert("userVerification", Value::String(uv.to_owned()));
    Value::Object(pk)
}

/// Opens a session for `account` and answers with its cookie.
async fn open_session<B: Backend>(
    ctx: &Ctx<B>,
    account: AccountId,
    method: Method,
    credential: Option<Vec<u8>>,
) -> Reply {
    let token = match random::<32>() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let id = match random::<16>() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = ctx.backend.now();
    let row = SessionRow {
        id,
        account,
        method,
        started: now,
        last_used: now,
        credential,
    };
    if let Err(f) = ctx
        .backend
        .open_session(fstp_crypto::sha256(&token), row)
        .await
    {
        return unavailable(f);
    }
    let mut o = Object::with_capacity(1);
    o.insert("session", hex_value(&id));
    Reply::json(StatusCode::OK, &Value::Object(o))
        .with_cookie(set_session_cookie(ctx.cfg.cell, &token))
}

/// `POST /auth/passkey/login/options` (Public): a single-use login
/// challenge. The body is `{}`.
pub(crate) async fn login_options<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    if let Err(r) = decode_empty_object(&req.body) {
        return bad_body(r);
    }
    let (id, nonce) = match (random::<16>(), random::<32>()) {
        (Ok(i), Ok(n)) => (i, n),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let row = ChallengeRow {
        id,
        purpose: ChallengePurpose::Login,
        session: None,
        action_digest: None,
        nonce,
        issued_at: ctx.backend.now(),
    };
    if let Err(f) = ctx.backend.put_challenge(row).await {
        return unavailable(f);
    }
    // UV is preferred here and required by the verifier for every
    // management holder (ADR-008 "User verification").
    let mut o = Object::with_capacity(2);
    o.insert("challenge_id", hex_value(&id));
    o.insert("public_key", request_options(ctx, &nonce, "preferred", &[]));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// `POST /auth/passkey/login` (Public, I-77): verifies the assertion over
/// the login challenge and opens a passkey session.
pub(crate) async fn login<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let b = match decode_assertion(&req.body) {
        Ok(b) => b,
        Err(r) => return bad_body(r),
    };
    let now = ctx.backend.now();
    // Read first and take only a login challenge, so a step-up challenge
    // id sent here is never burnt (design section 4.2).
    match ctx.backend.challenge(b.challenge_id).await {
        Err(f) => return unavailable(f),
        Ok(Some(row)) if row.purpose == ChallengePurpose::Login => {}
        Ok(_) => return login_refused(Rule::Adr008),
    }
    let row = match ctx.backend.take_challenge(b.challenge_id).await {
        Err(f) => return unavailable(f),
        Ok(None) => return login_refused(Rule::Adr008),
        Ok(Some(row)) => row,
    };
    if row.purpose != ChallengePurpose::Login || !fresh(row.issued_at, now, CHALLENGE_US) {
        return login_refused(Rule::Adr008);
    }
    let s = match ctx.backend.state().await {
        Ok(s) => s,
        Err(f) => return unavailable(f),
    };
    let credential = b.assertion.credential_id.clone();
    let count = match ctx.backend.sign_count(credential.clone()).await {
        Ok(c) => c,
        Err(f) => return unavailable(f),
    };
    let Some((account, stored)) = s.auth().stored_credential(&credential, count) else {
        return login_refused(Rule::Adr008);
    };
    let holdings = holds(&s, account, now);
    let ok = match verify_passkey_login(
        holdings,
        &ctx.cfg.enabled,
        &b.assertion,
        &stored,
        &ctx.cfg.rp,
        row.nonce,
    ) {
        Ok(ok) => ok,
        Err(LoginRefusal::Method(_) | LoginRefusal::NoUserVerification) => {
            return login_refused(Rule::I77);
        }
        // A regressed sign count should record `CredentialSuspect`. No
        // auth command records it yet, so the login is refused only.
        Err(LoginRefusal::Assertion(_) | LoginRefusal::CredentialSuspect) => {
            return login_refused(Rule::Adr008);
        }
    };
    if let Err(f) = ctx
        .backend
        .set_sign_count(credential.clone(), ok.sign_count)
        .await
    {
        return unavailable(f);
    }
    open_session(ctx, account, Method::Passkey, Some(credential)).await
}

/// The one reply of `POST /auth/magic/request`, whether or not the
/// account exists (ADR-008 "Magic links").
fn magic_accepted() -> Reply {
    let mut o = Object::with_capacity(1);
    o.insert("status", Value::String("accepted".to_owned()));
    Reply::json(StatusCode::ACCEPTED, &Value::Object(o))
}

/// `POST /auth/magic/request` (Public): `{"email":...}`. A Receiving-only
/// account of a tenant that enables magic links gets a link through the
/// outbox. Every request gets the same reply, so the reply tells nothing
/// about which emails hold accounts. A fault after the account lookup is
/// not shown either.
///
/// Open point, pending Daniel: the bytes are uniform, but the work is
/// not. For a known account the route also writes the token row and the
/// outbox row, so a database backend answers later. That gap could show
/// which emails hold accounts. Magic links work only in tests until M6
/// delivers email (ADR-008), so the gap matters from M6 on. The proposed
/// fix is one backend call that writes one outbox job for every request
/// and resolves the account off the request path.
pub(crate) async fn magic_request<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let email = match decode_email(&req.body) {
        Ok(e) => e,
        Err(r) => return bad_body(r),
    };
    let account = match ctx.backend.login_account(email).await {
        Ok(a) => a,
        Err(f) => return unavailable(f),
    };
    if let Some(account) = account {
        // Errors on this path are not shown (uniform reply).
        let _ = issue_magic_link(ctx, account).await;
    }
    magic_accepted()
}

fn decode_email(bytes: &[u8]) -> Result<String, BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &["email"], &[])?;
    let email = body::string(&o, "email")?;
    if email.is_empty() || email.len() > MAX_EMAIL || !email.contains('@') {
        return Err(BodyRefusal::Member("email"));
    }
    Ok(email.to_owned())
}

/// Issues and sends a magic link to `account` if the rule allows it.
async fn issue_magic_link<B: Backend>(ctx: &Ctx<B>, account: AccountId) -> Result<(), ()> {
    let s = ctx.backend.state().await.map_err(|_| ())?;
    let now = ctx.backend.now();
    may_issue_magic_link(holds(&s, account, now), &ctx.cfg.enabled).map_err(|_| ())?;
    let token = random::<32>().map_err(|_| ())?;
    let row = TokenRow {
        digest: fstp_crypto::sha256(&token),
        kind: TokenKind::MagicLink,
        account,
        issued_at: now,
    };
    ctx.backend.put_token(row).await.map_err(|_| ())?;
    ctx.backend
        .send_magic_link(account, token)
        .await
        .map_err(|_| ())
}

/// The confirm page of `GET /auth/magic` when the front serves no compiled
/// pages: a fixed document with no user text and no script. The token
/// stays in the URL, which is never logged, and `Referrer-Policy:
/// no-referrer` keeps it from other sites.
const MAGIC_PAGE: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title></title></head><body><main id=\"fstp-magic\"></main></body></html>";

/// `GET /auth/magic` (Public): the confirm page. With compiled pages it
/// is their shell, on which `web/src/auth/pages/magic.ts` mounts (design
/// section 11.2). Only `POST /auth/magic/consume` starts a session.
pub(crate) fn magic_confirm<B>(ctx: &Ctx<B>) -> Reply {
    let page = ctx.cfg.pages.as_ref().map_or(MAGIC_PAGE, |p| p.shell());
    Reply::fixed(StatusCode::OK, crate::http::pages::HTML, page)
}

/// A page route of `crate::routes::page_table` (Public, design section
/// 11.2): the shell of the compiled pages. A front without pages
/// registers no page route, so the 404 here is never reached through it.
pub(crate) fn page_shell<B>(ctx: &Ctx<B>) -> Reply {
    match ctx.cfg.pages.as_ref() {
        Some(p) => Reply::fixed(StatusCode::OK, crate::http::pages::HTML, p.shell()),
        None => Reply::refuse(StatusCode::NOT_FOUND, None, "route"),
    }
}

/// An asset route of `crate::routes::page_table` (Public, design section
/// 11.2): the loaded asset `<prefix><file>`, by name only. A name that
/// no loaded asset has gets 404.
pub(crate) fn page_asset<B>(ctx: &Ctx<B>, req: &Request, prefix: &str) -> Reply {
    let asset = ctx.cfg.pages.as_ref().and_then(|p| {
        req.param("file")
            .and_then(|f| p.asset(&format!("{prefix}{f}")))
    });
    match asset {
        Some(a) => Reply::fixed(StatusCode::OK, a.content_type, &a.body),
        None => Reply::refuse(StatusCode::NOT_FOUND, None, "route"),
    }
}

/// `POST /auth/magic/consume` (Public): `{"token":...}`. The token is
/// taken at most once, the holdings are read again, and a magic-link
/// session opens (I-77, ADR-008).
pub(crate) async fn magic_consume<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let token = match decode_token(&req.body) {
        Ok(t) => t,
        Err(r) => return bad_body(r),
    };
    let digest = fstp_crypto::sha256(&token);
    let row = match ctx.backend.take_token(digest, TokenKind::MagicLink).await {
        Err(f) => return unavailable(f),
        Ok(None) => return login_refused(Rule::Adr008),
        Ok(Some(r)) => r,
    };
    let s = match ctx.backend.state().await {
        Ok(s) => s,
        Err(f) => return unavailable(f),
    };
    let now = ctx.backend.now();
    let link = MagicLink {
        account: row.account,
        token_digest: row.digest,
        issued_at: row.issued_at,
        consumed: false,
    };
    let holdings = holds(&s, row.account, now);
    if admit_magic_link(
        holdings,
        &ctx.cfg.enabled,
        &link,
        &Token(token),
        now,
        MAGIC_LINK_US,
    )
    .is_err()
    {
        let rule = if holdings { Rule::I77 } else { Rule::Adr008 };
        return login_refused(rule);
    }
    open_session(ctx, row.account, Method::MagicLink, None).await
}

fn decode_token(bytes: &[u8]) -> Result<[u8; 32], BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &["token"], &[])?;
    body::hex_member::<32>(&o, "token")
}

/// A ceremony or recovery step whose record the sources cannot write yet
/// (module documentation). The body must still be one canonical JSON
/// object, then the step fails closed with 501. No body schema is fixed
/// for these steps yet.
pub(crate) fn not_built_ceremony(req: &Request) -> Reply {
    match body::object(&req.body, usize::MAX) {
        Ok(_) => Reply::not_built(),
        Err(r) => bad_body(r),
    }
}

// ---------------------------------------------------------------------------
// The invitation ceremony (design section 8.3 item 1, G10, Q35).

/// The longest attestation object a registration may carry: the CBOR
/// limit of `fstp-webauthn` (ADR-008 "Constants").
const MAX_ATTESTATION: usize = 64 * 1024;

/// The WebAuthn algorithms a new passkey may use (ADR-008, design section
/// 8.1): EdDSA, ES256 and RS256, in the cell's order of preference.
const ALGORITHMS: [&str; 3] = ["-8", "-7", "-257"];

/// The invitation enrolment cannot commit yet: `fstp-cell-core` has no
/// command form and no gate admission for it, and `CellState` finds no
/// invitation by its token digest. Provisioning has no command that
/// records the first admin's `InvitationIssued` either (design section
/// 9.2 step 10). The register route therefore fails closed with 501 after
/// its own checks, and records nothing.
pub const INVITATION_SEAM: &str = "fstp_cell_core admits no invitation enrolment (design section 8.3): no AuthCommand records InvitationConsumed and FirstAdminEnrolled with the verified passkey, no gate admission takes the invitation proof, CellState has no lookup of an invitation by its token digest, and no command records the provisioning InvitationIssued of design section 9.2 step 10";

/// The invitation proof in the `{token}` path parameter: 64 lowercase
/// hexadecimal digits for one token, or 128 for the two halves of a split
/// first-admin token, first half first (design section 8.3, Q35, a
/// reading of lane W3b).
fn invitation_proof(req: &Request) -> Result<InvitationProof, Reply> {
    let refuse = || bad_body(BodyRefusal::Member("token"));
    let p = req.param("token").ok_or_else(refuse)?;
    match p.len() {
        64 => body::hex_array::<32>(p)
            .map(|t| InvitationProof::Token(Token(t)))
            .ok_or_else(refuse),
        128 => {
            let (a, b) = p.split_at_checked(64).ok_or_else(refuse)?;
            match (body::hex_array::<32>(a), body::hex_array::<32>(b)) {
                (Some(a), Some(b)) => Ok(InvitationProof::Halves(Token(a), Token(b))),
                _ => Err(refuse()),
            }
        }
        _ => Err(refuse()),
    }
}

/// The digest an invitation stores for `proof`.
fn proof_digest(proof: &InvitationProof) -> [u8; 32] {
    match proof {
        InvitationProof::Token(t) => token_digest(t),
        InvitationProof::Halves(a, b) => split_token_digest(a, b),
    }
}

/// The WebAuthn creation options of a registration challenge, with the
/// members `parseCreationOptionsFromJSON` reads. The credential is
/// discoverable, since the passkey login names no credential.
///
/// User verification is required for every invitation (ADR-008 "User
/// verification"). A split token is the first admin's, and a single
/// token may be a self-hosted first admin's or a holder's. The options
/// call cannot tell which, since it never looks the invitation up. So it
/// asks for UV always, and an authenticator never skips UV only to be
/// refused at enrolment once its challenge is spent. Interim, pending
/// [`INVITATION_SEAM`]: the enrolment applies the rule of the invitation.
fn creation_options<B>(ctx: &Ctx<B>, challenge: &[u8; 32], user: &[u8; 16]) -> Value {
    let host = ctx.cfg.rp.parts().0.to_owned();
    let mut selection = Object::with_capacity(2);
    selection.insert("residentKey", Value::String("required".to_owned()));
    selection.insert("userVerification", Value::String("required".to_owned()));
    let params: Array = ALGORITHMS
        .iter()
        .filter_map(|alg| Number::from_lexeme(alg).ok())
        .map(|n| {
            let mut p = Object::with_capacity(2);
            p.insert("alg", Value::Number(n));
            p.insert("type", Value::String("public-key".to_owned()));
            Value::Object(p)
        })
        .collect();
    let mut rp = Object::with_capacity(2);
    rp.insert("id", Value::String(host.clone()));
    rp.insert("name", Value::String(host.clone()));
    // The cell knows no name of the invitee, so the passkey is named
    // after the cell host. The handle is random and the cell never reads
    // it: a login names the credential by its id.
    let mut u = Object::with_capacity(3);
    u.insert("displayName", Value::String(host.clone()));
    u.insert("id", Value::String(base64url(user)));
    u.insert("name", Value::String(host));
    let mut pk = Object::with_capacity(8);
    pk.insert("attestation", Value::String("none".to_owned()));
    pk.insert("authenticatorSelection", Value::Object(selection));
    pk.insert("challenge", Value::String(base64url(challenge)));
    pk.insert("pubKeyCredParams", Value::Array(params));
    pk.insert("rp", Value::Object(rp));
    if let Ok(n) = Number::from_lexeme(TIMEOUT_MS) {
        pk.insert("timeout", Value::Number(n));
    }
    pk.insert("user", Value::Object(u));
    Value::Object(pk)
}

/// `POST /auth/invitations/{token}/register/options` (Ceremony, design
/// section 8.3): `{}`. It answers `{challenge_id, public_key}` with the
/// creation options of a single-use registration challenge, bound to the
/// digest of the invitation proof in the path. The relying party is the
/// exact cell host (I-20).
///
/// The reply is the same whether or not an invitation holds that digest,
/// so the options call tells nothing about which tokens are live. The
/// register call checks the invitation.
pub(crate) async fn invitation_options<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let proof = match invitation_proof(req) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = decode_empty_object(&req.body) {
        return bad_body(r);
    }
    let (id, nonce, user) = match (random::<16>(), random::<32>(), random::<16>()) {
        (Ok(i), Ok(n), Ok(u)) => (i, n, u),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r,
    };
    let row = ChallengeRow {
        id,
        purpose: ChallengePurpose::Registration,
        session: None,
        action_digest: Some(proof_digest(&proof)),
        nonce,
        issued_at: ctx.backend.now(),
    };
    if let Err(f) = ctx.backend.put_challenge(row).await {
        return unavailable(f);
    }
    let mut o = Object::with_capacity(2);
    o.insert("challenge_id", hex_value(&id));
    o.insert("public_key", creation_options(ctx, &nonce, &user));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// A registration body: the browser's response and the challenge it
/// answers.
struct RegistrationBody {
    challenge_id: [u8; 16],
    response: RegistrationResponse,
}

/// Decodes `{attestation_object, challenge_id, client_data_json}` with an
/// optional `credential_id`, each in lowercase hexadecimal. The slice of
/// lane W3b sends the three members, and the `web/src/auth` pages add the
/// fourth from `rawId`. The attested data names the credential id, so
/// the fourth member is checked for its form only. Interim, pending the
/// lead: design section 8.3 fixes no body.
fn decode_registration(bytes: &[u8]) -> Result<RegistrationBody, BodyRefusal> {
    let o = body::object(bytes, CEREMONY_BODY_LIMIT)?;
    body::members(
        &o,
        &["attestation_object", "challenge_id", "client_data_json"],
        &["credential_id"],
    )?;
    if o.get("credential_id").is_some() {
        body::bytes_member(&o, "credential_id", MAX_CREDENTIAL)?;
    }
    Ok(RegistrationBody {
        challenge_id: body::hex_member::<16>(&o, "challenge_id")?,
        response: RegistrationResponse {
            client_data_json: body::bytes_member(&o, "client_data_json", MAX_CLIENT_DATA)?,
            attestation_object: body::bytes_member(&o, "attestation_object", MAX_ATTESTATION)?,
        },
    })
}

/// `POST /auth/invitations/{token}/register` (Ceremony, design section
/// 8.3, G10, Q35): enrols a first passkey through the invitation that the
/// token or the two halves in the path prove.
///
/// In order: the path and the body decode (400). The challenge is a
/// registration challenge issued for this proof, and the route takes it
/// once (401, the same reply for every cause). The registration must
/// answer that challenge on the cell origin, for the cell's relying party
/// (`fstp_webauthn::verify_registration`, 401 otherwise). A split proof
/// is the first admin's, so its registration needs UV here (401
/// otherwise). A single token is checked without the UV rule, which
/// depends on its invitation.
///
/// What follows needs [`INVITATION_SEAM`]: the invitation of the proof
/// must be found and admitted (`fstp_auth::ceremony::admit_invitation`),
/// the passkey verified again with the UV rule of the invitation and a
/// fresh credential id (`fstp_auth::ceremony::enrol_by_invitation`), and
/// the batch must record `InvitationConsumed`, `CredentialRegistered` and,
/// for the first admin, `FirstAdminEnrolled`. The route fails closed with
/// 501 there, with the challenge spent, and records nothing.
pub(crate) async fn invitation_register<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Reply {
    let proof = match invitation_proof(req) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let b = match decode_registration(&req.body) {
        Ok(b) => b,
        Err(r) => return bad_body(r),
    };
    let digest = proof_digest(&proof);
    let bound = |row: &ChallengeRow| {
        row.purpose == ChallengePurpose::Registration
            && row
                .action_digest
                .is_some_and(|d| fstp_crypto::constant_time_eq(&d, &digest))
    };
    // Read first and take only a registration challenge of this proof, so
    // a request never burns a login, step-up or other ceremony challenge.
    match ctx.backend.challenge(b.challenge_id).await {
        Err(f) => return unavailable(f),
        Ok(Some(row)) if bound(&row) => {}
        Ok(_) => return login_refused(Rule::Adr008),
    }
    let row = match ctx.backend.take_challenge(b.challenge_id).await {
        Err(f) => return unavailable(f),
        Ok(Some(row)) if bound(&row) => row,
        Ok(_) => return login_refused(Rule::Adr008),
    };
    if !fresh(row.issued_at, ctx.backend.now(), CHALLENGE_US) {
        return login_refused(Rule::Adr008);
    }
    let registration = Registration {
        response: &b.response,
        rp: &ctx.cfg.rp,
        challenge: row.nonce,
    };
    // Only the first admin's invitation is drawn as two halves (Q35), so
    // a split proof enrols a management passkey, which needs UV (ADR-008
    // "User verification"). A single token is checked again with the rule
    // of its invitation once INVITATION_SEAM closes
    // (`enrol_by_invitation`: holdings or first admin).
    let uv_required = matches!(proof, InvitationProof::Halves(..));
    if verify_new_passkey(&registration, uv_required).is_err() {
        return login_refused(Rule::Adr008);
    }
    // INVITATION_SEAM: no admission and no command records the enrolment.
    Reply::not_built()
}

/// The session's own live credentials.
fn own_credentials(s: &CellState, a: AccountId) -> Vec<Vec<u8>> {
    s.auth().live_credentials(a)
}

/// `POST /auth/stepup/options` (Session, design section 8.4):
/// `{command, command_id}`. It answers with a challenge bound to this
/// session and to `SHA-256(canonical(command) || command_id)`.
pub(crate) async fn stepup_options<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let r = match decode_command_body(&req.body) {
        Ok(r) => r,
        Err(e) => return bad_body(e),
    };
    if r.stepup.is_some() {
        return bad_body(BodyRefusal::Member("stepup"));
    }
    let Some(command) = r.command.map(|c| *c) else {
        return bad_body(BodyRefusal::Member("command"));
    };
    if !caller.view.method.phishing_resistant() {
        return stepup_refused();
    }
    let (s, _) = match admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadContent),
        None,
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    match HighRiskAction::of(&Action::Command(command.clone())) {
        Ok(Some(_)) => {}
        Ok(None) => return bad_body(BodyRefusal::Member("command")),
        Err(d) => return denied(d),
    }
    let Some(digest) = fstp_cell_core::try_action_digest(&command, r.command_id) else {
        return bad_body(BodyRefusal::Command);
    };
    let (id, nonce) = match (random::<16>(), random::<32>()) {
        (Ok(i), Ok(n)) => (i, n),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let row = ChallengeRow {
        id,
        purpose: ChallengePurpose::StepUp,
        session: Some(caller.row.id),
        action_digest: Some(digest),
        nonce,
        issued_at: ctx.backend.now(),
    };
    if let Err(f) = ctx.backend.put_challenge(row).await {
        return unavailable(f);
    }
    let challenge = stepup_challenge(ctx.cfg.cell, caller.row.id, digest, nonce);
    let allow = own_credentials(&s, caller.view.account);
    let mut o = Object::with_capacity(2);
    o.insert("challenge_id", hex_value(&id));
    o.insert(
        "public_key",
        request_options(ctx, &challenge, "required", &allow),
    );
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// `POST /auth/stepup` (Session, I-78): verifies a passkey assertion with
/// UV over the session's step-up challenge, then issues `GrantStepUp`,
/// which records `StepUpGranted` (design section 8.4).
///
/// The command id of `GrantStepUp` is the challenge id. So one challenge
/// grants at most one step-up: a replayed assertion runs under the same
/// command id, and the store answers it as a duplicate of the first
/// grant, never as a second grant (ADR-007). The route reads the
/// challenge and never deletes it.
///
/// The grant goes through the gate's route admission
/// `fstp_cell_core::gate::admit_stepup_grant` ([`grant_stepup`]). That
/// admission refuses until the gate can verify the step-up proof
/// (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`). A verified step-up
/// therefore fails closed with 501 after every check, and nothing is
/// recorded.
pub(crate) async fn stepup<B: Backend>(ctx: &Ctx<B>, req: &Request, caller: &Caller) -> Reply {
    let b = match decode_assertion(&req.body) {
        Ok(b) => b,
        Err(r) => return bad_body(r),
    };
    if !caller.view.method.phishing_resistant() {
        return stepup_refused();
    }
    let now = ctx.backend.now();
    // The route only reads the challenge. Its purpose and session are
    // checked before anything else, and nothing here consumes it: the
    // `auth_log.stepup_consumed` row ends it (design section 4.2).
    let row = match ctx.backend.challenge(b.challenge_id).await {
        Err(f) => return unavailable(f),
        Ok(None) => return stepup_refused(),
        Ok(Some(row)) => row,
    };
    let (Some(session), Some(digest)) = (row.session, row.action_digest) else {
        return stepup_refused();
    };
    if row.purpose != ChallengePurpose::StepUp
        || session != caller.row.id
        || !fresh(row.issued_at, now, CHALLENGE_US)
    {
        return stepup_refused();
    }
    let (s, _) = match admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadContent),
        None,
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    let credential = b.assertion.credential_id.clone();
    let count = match ctx.backend.sign_count(credential.clone()).await {
        Ok(c) => c,
        Err(f) => return unavailable(f),
    };
    let Some((owner, stored)) = s.auth().stored_credential(&credential, count) else {
        return stepup_refused();
    };
    let request = StepUpRequest {
        id: row.id,
        cell: ctx.cfg.cell,
        action_digest: digest,
        nonce: row.nonce,
        rp: ctx.cfg.rp.clone(),
    };
    match verify_step_up(&caller.view, &request, &b.assertion, &stored, owner, now) {
        Ok(granted) => {
            if let Err(f) = ctx
                .backend
                .set_sign_count(credential.clone(), granted.assertion.sign_count)
                .await
            {
                return unavailable(f);
            }
            grant_stepup(ctx, &s, caller, &granted, &credential, row.id, now).await
        }
        // A regressed sign count should record `CredentialSuspect`, as at
        // login. No auth command records it yet.
        Err(_) => stepup_refused(),
    }
}

/// Commits `GrantStepUp` for the verified step-up assertion `granted`, of
/// the credential `credential`, through the gate's route admission
/// `fstp_cell_core::gate::admit_stepup_grant` (design section 8.4, I-78).
///
/// The command runs under the challenge id `challenge` as its command id,
/// so one challenge grants at most one step-up: a replayed assertion runs
/// under the same command id, and the store answers it as a duplicate of
/// the first grant, never as a second grant (ADR-007). The step-up id is
/// that challenge id too (`fstp_cell_core::stepup_id`), so the action
/// request names it.
///
/// Every gate refusal answers through `denied`. While the gate cannot
/// verify the step-up proof it refuses with
/// `Deny::NotImplemented(ROUTE_ADMISSION_SEAM)`, so the route answers 501
/// and records nothing. A refusal of the step-up itself is 403 under
/// I-78. An admission that names another command id, session or digest
/// than this route verified is refused with 500, before the engine.
async fn grant_stepup<B: Backend>(
    ctx: &Ctx<B>,
    s: &CellState,
    caller: &Caller,
    granted: &Granted,
    credential: &[u8],
    challenge: [u8; 16],
    now: Timestamp,
) -> Reply {
    let digest = granted.stepup.action_digest;
    if granted.stepup.id != challenge {
        return stepup_refused();
    }
    let admitted = match admit_stepup_grant(s, &caller.view, &granted.stepup, credential, now) {
        Ok(a) => a,
        Err(RouteDeny::Gate(d)) => return denied(d),
        Err(_) => return stepup_refused(),
    };
    let names_this_grant = matches!(
        admitted.action(),
        Action::Command(CellCommand::Auth(fstp_auth::AuthCommand::GrantStepUp {
            session,
            action_digest,
        })) if *session == caller.row.id && *action_digest == digest
    );
    if admitted.command_id() != Some(challenge) || !names_this_grant {
        return Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal");
    }
    run(ctx, admitted).await
}

/// `POST /auth/passkeys/options` and `POST /auth/passkeys` (high risk
/// `AddPasskey`, design section 8.3): `{command_id, stepup}`. A magic-link
/// session never adds a passkey. The `AddPasskey` digest names the new
/// credential id, which the options call cannot know, so after the
/// session, method and step-up member checks the route fails closed with
/// 501.
pub(crate) async fn add_passkey<B: Backend>(ctx: &Ctx<B>, req: &Request, caller: &Caller) -> Reply {
    let r = match decode_command_body(&req.body) {
        Ok(r) => r,
        Err(e) => return bad_body(e),
    };
    if r.command.is_some() {
        return bad_body(BodyRefusal::Member("command"));
    }
    if r.stepup.is_none() {
        return bad_body(BodyRefusal::Member("stepup"));
    }
    if !caller.view.method.phishing_resistant() {
        return stepup_refused();
    }
    if let Err(reply) = admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadContent),
        None,
        None,
    )
    .await
    {
        return reply;
    }
    Reply::not_built()
}

/// Whether session `row` of the caller's account is live at `now`, as the
/// gate would admit it: not ended by a record, no binding end after its
/// start, and inside P-72 under I-77 (design sections 5.4 and 8.2).
fn live(s: &CellState, row: &SessionRow, holdings: bool, now: Timestamp) -> bool {
    let view = view_of(row);
    !s.auth().session_ended(row.id)
        && !s.binding_ended_between(row.account, row.started, now)
        && fstp_auth::admit_session(holdings, &view, now, &lifetimes(s)).is_ok()
}

fn view_of(row: &SessionRow) -> SessionView {
    SessionView {
        id: row.id,
        account: row.account,
        method: row.method,
        started: row.started,
        last_used: row.last_used,
    }
}

const fn method_name(m: Method) -> &'static str {
    match m {
        Method::Passkey => "passkey",
        Method::EudiWallet => "eudi_wallet",
        Method::Opaque => "opaque",
        Method::MagicLink => "magic_link",
    }
}

/// The live sessions of the caller's account.
async fn live_sessions<B: Backend>(
    ctx: &Ctx<B>,
    s: &CellState,
    caller: &Caller,
) -> Result<Vec<SessionRow>, Reply> {
    let now = ctx.backend.now();
    let account = caller.view.account;
    let holdings = holds(s, account, now);
    let mut rows = ctx
        .backend
        .sessions_of(account)
        .await
        .map_err(unavailable)?;
    rows.retain(|r| r.account == account && live(s, r, holdings, now));
    rows.sort_by_key(|r| r.id);
    Ok(rows)
}

/// `GET /auth/sessions` (Session, R-LG-04): the account's own live
/// sessions, and no other account's.
pub(crate) async fn sessions<B: Backend>(ctx: &Ctx<B>, caller: &Caller) -> Reply {
    let (s, _) = match admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadContent),
        None,
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    let rows = match live_sessions(ctx, &s, caller).await {
        Ok(r) => r,
        Err(reply) => return reply,
    };
    let list: Array = rows
        .iter()
        .map(|r| {
            let mut o = Object::with_capacity(5);
            o.insert("current", Value::Bool(r.id == caller.row.id));
            o.insert("id", hex_value(&r.id));
            o.insert("last_used", decimal(r.last_used.micros()));
            o.insert("method", Value::String(method_name(r.method).to_owned()));
            o.insert("started", decimal(r.started.micros()));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::with_capacity(1);
    o.insert("sessions", Value::Array(list));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// The id of path parameter `name` as lowercase hexadecimal of `N` bytes.
fn param<const N: usize>(req: &Request, name: &'static str) -> Result<[u8; N], Reply> {
    req.param(name)
        .and_then(body::hex_array::<N>)
        .ok_or_else(|| bad_body(BodyRefusal::Member(name)))
}

/// `DELETE /auth/sessions/{id}` (Session, R-LG-04): only the session's own
/// account ends it. The gate admits `EndSession`, then the route fails
/// closed with 501, since `decide` takes no session rows yet.
pub(crate) async fn end_session<B: Backend>(ctx: &Ctx<B>, req: &Request, caller: &Caller) -> Reply {
    let id = match param::<16>(req, "id") {
        Ok(id) => id,
        Err(r) => return r,
    };
    let command = CellCommand::Auth(fstp_auth::AuthCommand::EndSession { session: id });
    let blocked = needs_route_input(&command);
    let command_id = match random::<16>() {
        Ok(i) => i,
        Err(r) => return r,
    };
    let (s, admitted) = match admit(
        ctx,
        caller,
        Action::Command(command),
        Some(command_id),
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    let rows = match live_sessions(ctx, &s, caller).await {
        Ok(r) => r,
        Err(reply) => return reply,
    };
    let views: Vec<SessionView> = rows.iter().map(view_of).collect();
    if !may_end_session(&views, caller.view.account, id) {
        return Reply::refuse(StatusCode::NOT_FOUND, None, "session");
    }
    if blocked {
        return Reply::not_built();
    }
    run(ctx, admitted).await
}

/// `GET /auth/devices` (Session, R-LG-04): the account's own live
/// passkeys.
pub(crate) async fn devices<B: Backend>(ctx: &Ctx<B>, caller: &Caller) -> Reply {
    let (s, _) = match admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadContent),
        None,
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    let list: Array = own_credentials(&s, caller.view.account)
        .iter()
        .map(|id| {
            let mut o = Object::with_capacity(3);
            o.insert(
                "current",
                Value::Bool(caller.row.credential.as_deref() == Some(id.as_slice())),
            );
            o.insert("id", hex_value(id));
            o.insert(
                "user_verified",
                Value::Bool(s.auth().credential(id).is_some_and(|c| c.user_verified)),
            );
            Value::Object(o)
        })
        .collect();
    let mut o = Object::with_capacity(1);
    o.insert("devices", Value::Array(list));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// The ids a DELETE route takes from its query, since it has no body:
/// exactly `command_id=<32 hex>&stepup=<32 hex>`, in that order.
fn delete_query(req: &Request) -> Result<([u8; 16], [u8; 16]), Reply> {
    let refuse = || bad_body(BodyRefusal::Member("command_id"));
    let q = req.query().ok_or_else(refuse)?;
    let (a, b) = q.split_once('&').ok_or_else(refuse)?;
    let id = a
        .strip_prefix("command_id=")
        .and_then(body::hex_array::<16>)
        .ok_or_else(refuse)?;
    let stepup = b
        .strip_prefix("stepup=")
        .and_then(body::hex_array::<16>)
        .ok_or_else(|| bad_body(BodyRefusal::Member("stepup")))?;
    Ok((id, stepup))
}

/// `DELETE /auth/devices/{id}?command_id=..&stepup=..` (high risk
/// `ChangeLoginMethods`, R-LG-04). The gate checks the step-up for
/// `RevokeCredential` of the caller's own credential. Then the route
/// fails closed with 501, since `decide` takes no session rows yet.
pub(crate) async fn remove_device<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let Some(credential) = req
        .param("id")
        .and_then(|p| body::hex_vec(p, MAX_CREDENTIAL))
    else {
        return bad_body(BodyRefusal::Member("id"));
    };
    let (command_id, stepup) = match delete_query(req) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let command = CellCommand::Auth(fstp_auth::AuthCommand::RevokeCredential {
        account: caller.view.account,
        credential,
    });
    let blocked = needs_route_input(&command);
    let admitted = match admit(
        ctx,
        caller,
        Action::Command(command),
        Some(command_id),
        Some(stepup),
    )
    .await
    {
        Ok((_, a)) => a,
        Err(reply) => return reply,
    };
    if blocked {
        return Reply::not_built();
    }
    run(ctx, admitted).await
}

/// `POST /auth/recovery/{case}/approve` (high risk `ApproveRecovery`,
/// I-79): `{command_id, stepup}`. The gate checks the step-up, and the
/// engine decides the approval with the vault's identity answers.
pub(crate) async fn approve_recovery<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let case = match param::<16>(req, "case") {
        Ok(c) => c,
        Err(r) => return r,
    };
    let r = match decode_command_body(&req.body) {
        Ok(r) => r,
        Err(e) => return bad_body(e),
    };
    if r.command.is_some() {
        return bad_body(BodyRefusal::Member("command"));
    }
    let command = CellCommand::Auth(fstp_auth::AuthCommand::ApproveRecovery { case });
    match admit(
        ctx,
        caller,
        Action::Command(command),
        Some(r.command_id),
        r.stepup,
    )
    .await
    {
        Ok((_, admitted)) => run(ctx, admitted).await,
        Err(reply) => reply,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base64url encoder writes RFC 4648 section 10 vectors unpadded.
    #[test]
    fn base64url_vectors() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ] {
            assert_eq!(base64url(input), want);
        }
    }
}

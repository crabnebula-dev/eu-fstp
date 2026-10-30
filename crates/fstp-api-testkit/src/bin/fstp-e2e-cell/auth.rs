//! The M3 pages and ceremony routes the M4 journeys pass through, emulated
//! over the fake sessions and step-up port (M3 design sections 8.1 to 8.4
//! and 8.7, `web/src/auth`).
//!
//! The routes and bodies are the ones the auth pages of `web/src/auth`
//! send. Every state-changing route needs the cell `Origin` and
//! `X-FSTP-Request: 1`, as the cell's own routes do (ADR-014 "CSRF").
//!
//! - `GET /auth/{login,signup,invite,magic,recovery,account}`: the shell.
//! - `POST /auth/invitations/{token}/register/options` and
//!   `POST /auth/invitations/{token}/register`: a first passkey from a
//!   one-time invitation (design section 8.3 item 1). The token is single
//!   use and names its account.
//! - `POST /auth/signup/options {email}` mails a proof link,
//!   `POST /auth/signup/options {token}` answers the creation options and
//!   `POST /auth/signup` creates a Receiving account with its passkey
//!   (item 2).
//! - `POST /auth/passkey/login/options` and `POST /auth/passkey/login`: a
//!   passkey login with user verification.
//! - `GET /auth/sessions`, `DELETE /auth/sessions/{id}` and
//!   `GET /auth/devices`: the account page (R-LG-04).
//! - `POST /auth/stepup`: the assertion over a step-up challenge that the
//!   API core issued for one action digest (I-78). A verified assertion
//!   records the proof through `StepUp::finish`, and the retried call
//!   takes it.
//!
//! Each ceremony checks the ceremony type, the challenge, the origin, the
//! RP id hash, UP and UV, the credential id and the sign count. A
//! registration stores the attested COSE public key, and every assertion
//! verifies its signature over the authenticator data and the SHA-256 of
//! the client data, through `fstp-crypto` (aws-lc-rs). So a passkey login
//! and a step-up prove possession of the registered key. Magic
//! links, recovery and adding a second passkey are not emulated: their
//! routes answer 404, so the page shows that the action is unavailable.

use std::collections::BTreeMap;

use fstp_api_core::port::{LoginMethod, SessionId, Sessions, SessionsAdmin, StepUp};
use fstp_api_core::{Credential, RequestHead};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::IdentityTag;
use fstp_http::{Method, Request, Response, StatusCode};
use fstp_json::{Array, Object, Value};

use crate::wire::{self, b64url, dec, hex, obj, refuse, str_member, unhex};
use crate::{Inner, SiteInfo, lock};

/// The session cookie name (ADR-008 "Sessions").
const COOKIE: &str = "__Host-fstp";

/// How long a ceremony challenge lives, in milliseconds, as the options
/// state it to the browser.
const TIMEOUT_MS: i64 = 120_000;

/// The first account id of a self-registered applicant.
const FIRST_SIGNUP: u128 = 0x0e2e_0000_0000_0001;

/// The first synthetic identity the cell draws for an account the vault
/// does not know. It lies above every tag a seed or fixture sets, so a
/// drawn identity never names a seeded person.
const FIRST_SYNTHETIC_IDENTITY: u64 = 0x0e2e_1d00_0000_0001;

/// The M3 page paths that serve the shell.
const PAGES: [&str; 6] = [
    "/auth/login",
    "/auth/signup",
    "/auth/invite",
    "/auth/magic",
    "/auth/recovery",
    "/auth/account",
];

/// One message the cell sent, as `GET /test/mailbox` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mail {
    /// The address.
    pub(crate) to: String,
    /// `admin_invitation`, `invitation` or `signup`.
    pub(crate) kind: &'static str,
    /// The link, with any token in the fragment.
    pub(crate) link: String,
}

/// What a one-time enrolment token is for.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Invite {
    account: AccountId,
}

/// A registered passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Passkey {
    account: AccountId,
    key: fstp_webauthn::CoseKey,
    sign_count: u32,
}

/// What a ceremony challenge is for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Purpose {
    /// A first passkey from invitation token `token`.
    Invite { token: String },
    /// A first passkey of a self-registration with proof token `token`.
    Signup { token: String },
    /// A passkey login.
    Login,
}

/// One open ceremony challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Challenge {
    bytes: [u8; 32],
    purpose: Purpose,
}

/// The M3 records of one cell state.
#[derive(Debug)]
pub(crate) struct AuthState {
    rp_hash: [u8; 32],
    origin: String,
    host: String,
    emails: BTreeMap<String, AccountId>,
    next_signup: u128,
    next_identity: u64,
    invites: BTreeMap<String, Invite>,
    signups: BTreeMap<String, String>,
    passkeys: BTreeMap<Vec<u8>, Passkey>,
    challenges: BTreeMap<[u8; 16], Challenge>,
    session_passkey: BTreeMap<u128, Vec<u8>>,
    mailbox: Vec<Mail>,
}

impl AuthState {
    /// No account, invitation or passkey yet.
    pub(crate) fn new(site: &SiteInfo) -> AuthState {
        AuthState {
            rp_hash: fstp_crypto::sha256(site.host.as_bytes()),
            origin: site.origin.clone(),
            host: site.host.clone(),
            emails: BTreeMap::new(),
            next_signup: FIRST_SIGNUP,
            next_identity: FIRST_SYNTHETIC_IDENTITY,
            invites: BTreeMap::new(),
            signups: BTreeMap::new(),
            passkeys: BTreeMap::new(),
            challenges: BTreeMap::new(),
            session_passkey: BTreeMap::new(),
            mailbox: Vec::new(),
        }
    }

    /// Records that `email` is the login email of `account`.
    pub(crate) fn person(&mut self, email: &str, account: AccountId) {
        self.emails.insert(email.to_owned(), account);
    }

    /// The account with login email `email`.
    pub(crate) fn account(&self, email: &str) -> Option<AccountId> {
        self.emails.get(email).copied()
    }

    /// The login email of `account`.
    pub(crate) fn email_of(&self, account: AccountId) -> Option<&str> {
        self.emails
            .iter()
            .find(|(_, a)| **a == account)
            .map(|(e, _)| e.as_str())
    }

    /// A one-time enrolment link for `account`: `<origin>/auth/invite#<token>`.
    pub(crate) fn invite(&mut self, account: AccountId) -> Result<String, String> {
        let token = hex(&wire::random::<16>()?);
        self.invites.insert(token.clone(), Invite { account });
        Ok(format!("{}/auth/invite#{token}", self.origin))
    }

    /// A fresh synthetic identity, never drawn before in this cell state
    /// (I-67). `None` once the range is spent.
    pub(crate) fn fresh_identity(&mut self) -> Option<IdentityTag> {
        let tag = self.next_identity;
        self.next_identity = tag.checked_add(1)?;
        Some(IdentityTag::new(tag))
    }

    /// Puts a message in the mailbox.
    pub(crate) fn mail(&mut self, to: &str, kind: &'static str, link: String) {
        self.mailbox.push(Mail {
            to: to.to_owned(),
            kind,
            link,
        });
    }

    /// Every unused one-time enrolment link with its account, for the demo
    /// page.
    pub(crate) fn open_invites(&self) -> Vec<(AccountId, String)> {
        self.invites
            .iter()
            .map(|(t, i)| (i.account, format!("{}/auth/invite#{t}", self.origin)))
            .collect()
    }

    /// Every message the cell sent, oldest first, for the demo page.
    pub(crate) fn all_messages(&self) -> Vec<Mail> {
        self.mailbox.clone()
    }

    /// Every message to `to`, oldest first.
    pub(crate) fn messages(&self, to: &str) -> Vec<Mail> {
        self.mailbox
            .iter()
            .filter(|m| m.to == to)
            .cloned()
            .collect()
    }

    /// A challenge for `purpose`, with its id.
    fn challenge(&mut self, purpose: Purpose) -> Result<([u8; 16], [u8; 32]), String> {
        let id = wire::random::<16>()?;
        let bytes = wire::random::<32>()?;
        self.challenges.insert(id, Challenge { bytes, purpose });
        Ok((id, bytes))
    }

    /// The creation options of a first passkey for `account`.
    fn creation(&self, account: AccountId, email: &str, challenge: &[u8; 32]) -> Value {
        let alg = |n: i64| obj(vec![("type", "public-key".into()), ("alg", wire::int(n))]);
        obj(vec![
            ("challenge", b64url(challenge).into()),
            (
                "rp",
                obj(vec![
                    ("id", self.host.as_str().into()),
                    ("name", "FSTP e2e cell".into()),
                ]),
            ),
            (
                "user",
                obj(vec![
                    ("id", b64url(&account.raw().to_be_bytes()).into()),
                    ("name", email.into()),
                    ("displayName", email.into()),
                ]),
            ),
            (
                "pubKeyCredParams",
                Value::Array(Array::from(vec![alg(-7), alg(-8), alg(-257)])),
            ),
            (
                "authenticatorSelection",
                obj(vec![
                    ("residentKey", "required".into()),
                    ("requireResidentKey", true.into()),
                    ("userVerification", "required".into()),
                ]),
            ),
            ("attestation", "none".into()),
            ("timeout", wire::int(TIMEOUT_MS)),
        ])
    }

    /// The request options of a passkey login.
    fn request(&self, challenge: &[u8; 32]) -> Value {
        obj(vec![
            ("challenge", b64url(challenge).into()),
            ("rpId", self.host.as_str().into()),
            ("userVerification", "required".into()),
            ("timeout", wire::int(TIMEOUT_MS)),
        ])
    }

    /// Checks client data bytes against a ceremony.
    fn client_data(&self, bytes: &[u8], kind: &str, challenge: &[u8]) -> Result<(), &'static str> {
        let cd = fstp_webauthn::parse_client_data(bytes).map_err(|_| "client_data")?;
        if cd.kind != kind {
            return Err("ceremony_type");
        }
        if !fstp_crypto::constant_time_eq(&cd.challenge, challenge) {
            return Err("challenge");
        }
        if cd.origin != self.origin {
            return Err("origin");
        }
        Ok(())
    }

    /// Checks the RP id hash, UP and UV of authenticator data.
    fn auth_data(&self, ad: &fstp_webauthn::AuthenticatorData) -> Result<(), &'static str> {
        use fstp_webauthn::flags;
        if !fstp_crypto::constant_time_eq(&ad.rp_id_hash, &self.rp_hash) {
            return Err("rp_id_hash");
        }
        if ad.flags & flags::UP == 0 {
            return Err("user_presence");
        }
        if ad.flags & flags::UV == 0 {
            return Err("user_verification");
        }
        Ok(())
    }

    /// Verifies a registration body for `challenge` and stores the
    /// passkey for `account`.
    fn register(
        &mut self,
        body: &Object,
        challenge: &[u8; 32],
        account: AccountId,
    ) -> Result<Vec<u8>, &'static str> {
        let cd = hex_member(body, "client_data_json")?;
        let att = hex_member(body, "attestation_object")?;
        let id = hex_member(body, "credential_id")?;
        if id.is_empty() || self.passkeys.contains_key(&id) {
            return Err("credential_id");
        }
        self.client_data(&cd, "webauthn.create", challenge)?;
        let ao = fstp_webauthn::parse_attestation_object(&att).map_err(|_| "attestation_object")?;
        self.auth_data(&ao.auth_data)?;
        let key = attested_key(&att, &id)?;
        self.passkeys.insert(
            id.clone(),
            Passkey {
                account,
                key,
                sign_count: ao.auth_data.sign_count,
            },
        );
        Ok(id)
    }

    /// Verifies an assertion body for `challenge`. It returns the account
    /// and the credential id, and moves the stored sign count on.
    fn assert(
        &mut self,
        body: &Object,
        challenge: &[u8],
    ) -> Result<(AccountId, Vec<u8>), &'static str> {
        let id = hex_member(body, "credential_id")?;
        let cd = hex_member(body, "client_data_json")?;
        let ad_bytes = hex_member(body, "authenticator_data")?;
        let signature = hex_member(body, "signature")?;
        let stored = self.passkeys.get(&id).cloned().ok_or("credential_id")?;
        self.client_data(&cd, "webauthn.get", challenge)?;
        let ad =
            fstp_webauthn::parse_authenticator_data(&ad_bytes).map_err(|_| "authenticator_data")?;
        self.auth_data(&ad)?;
        if ad.flags & fstp_webauthn::flags::AT != 0 {
            return Err("authenticator_data");
        }
        let mut message = ad_bytes;
        message.extend_from_slice(&fstp_crypto::sha256(&cd));
        verify_signature(&stored.key, &message, &signature)?;
        // The count is checked after the signature, as `fstp-webauthn`
        // does, so only a signed regression is reported as one.
        if (stored.sign_count != 0 || ad.sign_count != 0) && ad.sign_count <= stored.sign_count {
            return Err("sign_count");
        }
        self.passkeys.insert(
            id.clone(),
            Passkey {
                account: stored.account,
                key: stored.key,
                sign_count: ad.sign_count,
            },
        );
        Ok((stored.account, id))
    }
}

/// The COSE public key that the attestation object `att` attests for the
/// credential `id`.
///
/// The attested credential data follows the 37 bytes of RP id hash, flags
/// and sign count: the AAGUID (16 bytes), the credential id length (2
/// bytes, big-endian), the credential id, then the key. Authenticator data
/// with extensions is refused, so the key is the rest of the bytes.
fn attested_key(att: &[u8], id: &[u8]) -> Result<fstp_webauthn::CoseKey, &'static str> {
    use fstp_webauthn::cbor::{Item, decode};
    use fstp_webauthn::flags;
    let bad = "attestation_object";
    let Item::Map(members) = decode(att).map_err(|_| bad)? else {
        return Err(bad);
    };
    let ad = members
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Item::Text(k), Item::Bytes(b)) if k == "authData" => Some(b.as_slice()),
            _ => None,
        })
        .ok_or(bad)?;
    let flag_bits = *ad.get(32).ok_or(bad)?;
    if flag_bits & flags::AT == 0 || flag_bits & flags::ED != 0 {
        return Err("attested_credential");
    }
    let len = ad
        .get(53..55)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(|b| usize::from(u16::from_be_bytes(b)))
        .ok_or(bad)?;
    let end = 55usize.checked_add(len).ok_or(bad)?;
    if ad.get(55..end) != Some(id) {
        return Err("credential_id");
    }
    fstp_webauthn::parse_cose_key(ad.get(end..).ok_or(bad)?).map_err(|_| "cose_key")
}

/// Verifies `signature` over `message` under `key`.
fn verify_signature(
    key: &fstp_webauthn::CoseKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    use fstp_crypto::sig;
    use fstp_webauthn::CoseKey;
    let r = match key {
        CoseKey::Es256 { x, y } => {
            let mut point = [0x04u8; sig::P256_POINT_LEN];
            for (dst, src) in point.iter_mut().skip(1).zip(x.iter().chain(y.iter())) {
                *dst = *src;
            }
            sig::ecdsa_p256_sha256_verify_point(&point, message, signature)
        }
        CoseKey::Ed25519 { x } => sig::ed25519_verify(x, message, signature),
        CoseKey::Rs256 { n, e } => sig::rsa_pkcs1_sha256_verify(n, e, message, signature),
    };
    r.map_err(|_| "signature")
}

/// The bytes of hex member `name`.
fn hex_member(o: &Object, name: &str) -> Result<Vec<u8>, &'static str> {
    str_member(o, name).and_then(unhex).ok_or("body")
}

/// The 16-byte id of hex member `name`.
fn id_member(o: &Object, name: &str) -> Option<[u8; 16]> {
    let b = unhex(str_member(o, name)?)?;
    <[u8; 16]>::try_from(b.as_slice()).ok()
}

/// The session cookie value of a request, if exactly one is present.
fn cookie(req: &Request) -> Option<Vec<u8>> {
    let mut found = None;
    for field in req.headers.get_all("cookie") {
        for pair in field.as_bytes().split(|b| *b == b';') {
            let pair = pair.trim_ascii();
            if let Some(v) = pair.strip_prefix(format!("{COOKIE}=").as_bytes()) {
                if found.is_some() {
                    return None;
                }
                found = Some(v.to_vec());
            }
        }
    }
    found
}

/// Whether a state-changing request passes the CSRF rule of the cell.
fn csrf(info: &SiteInfo, req: &Request) -> bool {
    let origin_ok = req
        .headers
        .get("origin")
        .is_some_and(|v| v.as_bytes() == info.origin.as_bytes());
    let mark_ok = req
        .headers
        .get("x-fstp-request")
        .is_some_and(|v| v.as_bytes() == b"1");
    origin_ok && mark_ok
}

/// A reply that opens a session for `account` and sets its cookie.
fn open_session(inner: &Inner, account: AccountId, passkey: Vec<u8>) -> Response {
    let login = inner.ports.sessions.login(account, LoginMethod::Passkey);
    lock(&inner.auth)
        .session_passkey
        .insert(login.session.raw(), passkey);
    let mut r = wire::ok_empty();
    let value = format!(
        "{COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        String::from_utf8_lossy(&login.cookie)
    );
    let _ = r.headers.try_insert("set-cookie", value.as_str());
    r
}

/// The session of a request: its id and account.
async fn session(inner: &Inner, req: &Request) -> Option<(SessionId, AccountId)> {
    let c = cookie(req)?;
    let now = inner.ports.clock.read();
    let p = inner
        .ports
        .sessions
        .principal(&RequestHead::new(), &Credential::SessionCookie(c), now)
        .await
        .ok()?;
    Some((p.session, p.account))
}

/// Answers one request below `/auth`.
pub(crate) async fn handle(info: &SiteInfo, inner: &Inner, req: Request) -> Response {
    let path = req.target.path().to_owned();
    if req.method == Method::GET && PAGES.contains(&path.as_str()) {
        return info.auth_assets.page();
    }
    if req.method != Method::GET && !csrf(info, &req) {
        return refuse(StatusCode::FORBIDDEN, "csrf");
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (req.method.clone(), segments.as_slice()) {
        (Method::POST, ["auth", "invitations", token, "register", "options"]) => {
            invite_options(inner, token)
        }
        (Method::POST, ["auth", "invitations", token, "register"]) => {
            invite_register(inner, token, &req)
        }
        (Method::POST, ["auth", "signup", "options"]) => signup_options(info, inner, &req),
        (Method::POST, ["auth", "signup"]) => signup_register(inner, &req),
        (Method::POST, ["auth", "passkey", "login", "options"]) => login_options(inner),
        (Method::POST, ["auth", "passkey", "login"]) => login(inner, &req),
        (Method::GET, ["auth", "sessions"]) => sessions(inner, &req).await,
        (Method::DELETE, ["auth", "sessions", id]) => end_session(inner, &req, id).await,
        (Method::GET, ["auth", "devices"]) => devices(inner, &req).await,
        (Method::POST, ["auth", "stepup"]) => step_up(inner, &req).await,
        _ => wire::not_found(),
    }
}

fn invite_options(inner: &Inner, token: &str) -> Response {
    let mut a = lock(&inner.auth);
    let Some(invite) = a.invites.get(token).cloned() else {
        return refuse(StatusCode::FORBIDDEN, "invitation");
    };
    let email = a
        .email_of(invite.account)
        .unwrap_or("synthetic@e2e.invalid")
        .to_owned();
    let Ok((id, bytes)) = a.challenge(Purpose::Invite {
        token: token.to_owned(),
    }) else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
    };
    let options = a.creation(invite.account, &email, &bytes);
    wire::json(
        StatusCode::OK,
        &obj(vec![
            ("challenge_id", hex(&id).into()),
            ("public_key", options),
        ]),
    )
}

fn invite_register(inner: &Inner, token: &str, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let registered = {
        let mut a = lock(&inner.auth);
        let Some(id) = id_member(&body, "challenge_id") else {
            return wire::bad("challenge_id");
        };
        let Some(ch) = a.challenges.remove(&id) else {
            return refuse(StatusCode::FORBIDDEN, "challenge");
        };
        if ch.purpose
            != (Purpose::Invite {
                token: token.to_owned(),
            })
        {
            return refuse(StatusCode::FORBIDDEN, "challenge");
        }
        let Some(invite) = a.invites.get(token).cloned() else {
            return refuse(StatusCode::FORBIDDEN, "invitation");
        };
        match a.register(&body, &ch.bytes, invite.account) {
            Ok(passkey) => {
                a.invites.remove(token);
                (invite.account, passkey)
            }
            Err(why) => return refuse(StatusCode::FORBIDDEN, why),
        }
    };
    open_session(inner, registered.0, registered.1)
}

fn signup_options(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let mut a = lock(&inner.auth);
    if let Some(email) = str_member(&body, "email") {
        // The same reply for every address (M3 design section 8.3).
        if a.account(email).is_none() {
            let Ok(raw) = wire::random::<16>() else {
                return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
            };
            let token = hex(&raw);
            a.signups.insert(token.clone(), email.to_owned());
            a.mail(
                email,
                "signup",
                format!("{}/auth/signup#{token}", info.origin),
            );
        }
        return wire::json(StatusCode::ACCEPTED, &Value::Object(Object::new()));
    }
    let Some(token) = str_member(&body, "token") else {
        return wire::bad("body");
    };
    let Some(email) = a.signups.get(token).cloned() else {
        return refuse(StatusCode::FORBIDDEN, "token");
    };
    let Ok((id, bytes)) = a.challenge(Purpose::Signup {
        token: token.to_owned(),
    }) else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
    };
    let account = AccountId::from_raw(a.next_signup);
    let options = a.creation(account, &email, &bytes);
    wire::json(
        StatusCode::OK,
        &obj(vec![
            ("challenge_id", hex(&id).into()),
            ("public_key", options),
        ]),
    )
}

fn signup_register(inner: &Inner, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let made = {
        let mut a = lock(&inner.auth);
        let (Some(id), Some(token)) =
            (id_member(&body, "challenge_id"), str_member(&body, "token"))
        else {
            return wire::bad("body");
        };
        let Some(ch) = a.challenges.remove(&id) else {
            return refuse(StatusCode::FORBIDDEN, "challenge");
        };
        if ch.purpose
            != (Purpose::Signup {
                token: token.to_owned(),
            })
        {
            return refuse(StatusCode::FORBIDDEN, "challenge");
        }
        let Some(email) = a.signups.get(token).cloned() else {
            return refuse(StatusCode::FORBIDDEN, "token");
        };
        let account = AccountId::from_raw(a.next_signup);
        match a.register(&body, &ch.bytes, account) {
            Ok(passkey) => {
                let Some(tag) = a.fresh_identity() else {
                    return refuse(StatusCode::SERVICE_UNAVAILABLE, "identity");
                };
                a.signups.remove(token);
                a.next_signup = a.next_signup.saturating_add(1);
                a.person(&email, account);
                (account, passkey, tag)
            }
            Err(why) => return refuse(StatusCode::FORBIDDEN, why),
        }
    };
    // The vault knows the new person under a fresh synthetic identity,
    // unverified and without an adult attestation, as a fresh
    // self-registration is.
    let tag = made.2;
    inner.ports.vault.change(|t| t.set_identity(made.0, tag));
    open_session(inner, made.0, made.1)
}

fn login_options(inner: &Inner) -> Response {
    let mut a = lock(&inner.auth);
    let Ok((id, bytes)) = a.challenge(Purpose::Login) else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
    };
    let options = a.request(&bytes);
    wire::json(
        StatusCode::OK,
        &obj(vec![
            ("challenge_id", hex(&id).into()),
            ("public_key", options),
        ]),
    )
}

fn login(inner: &Inner, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let done = {
        let mut a = lock(&inner.auth);
        let Some(id) = id_member(&body, "challenge_id") else {
            return wire::bad("challenge_id");
        };
        let Some(ch) = a.challenges.remove(&id) else {
            return refuse(StatusCode::UNAUTHORIZED, "challenge");
        };
        if ch.purpose != Purpose::Login {
            return refuse(StatusCode::UNAUTHORIZED, "challenge");
        }
        match a.assert(&body, &ch.bytes) {
            Ok(x) => x,
            Err(why) => return refuse(StatusCode::UNAUTHORIZED, why),
        }
    };
    open_session(inner, done.0, done.1)
}

/// A session id as the account page spells it: 16 bytes of hex.
fn session_hex(s: SessionId) -> String {
    hex(&s.raw().to_be_bytes())
}

async fn sessions(inner: &Inner, req: &Request) -> Response {
    let Some((current, account)) = session(inner, req).await else {
        return refuse(StatusCode::UNAUTHORIZED, "session");
    };
    let Ok(list) = inner.ports.sessions.list(account).await else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "sessions");
    };
    let items: Vec<Value> = list
        .iter()
        .map(|s| {
            let method = match s.method {
                LoginMethod::Passkey => "passkey",
                LoginMethod::MagicLink => "magic_link",
                _ => "other",
            };
            obj(vec![
                ("id", session_hex(s.session).into()),
                ("current", (s.session == current).into()),
                ("method", method.into()),
                ("started", dec(s.started.micros())),
                ("last_used", dec(s.started.micros())),
            ])
        })
        .collect();
    wire::json(
        StatusCode::OK,
        &obj(vec![("sessions", Value::Array(Array::from(items)))]),
    )
}

async fn end_session(inner: &Inner, req: &Request, id: &str) -> Response {
    let Some((_, account)) = session(inner, req).await else {
        return refuse(StatusCode::UNAUTHORIZED, "session");
    };
    let Some(raw) = unhex(id).and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok()) else {
        return wire::bad("session");
    };
    let s = SessionId::from_raw(u128::from_be_bytes(raw));
    match inner.ports.sessions.end(account, s).await {
        Ok(()) => wire::ok_empty(),
        Err(_) => refuse(StatusCode::NOT_FOUND, "session"),
    }
}

async fn devices(inner: &Inner, req: &Request) -> Response {
    let Some((current, account)) = session(inner, req).await else {
        return refuse(StatusCode::UNAUTHORIZED, "session");
    };
    let a = lock(&inner.auth);
    let used = a.session_passkey.get(&current.raw()).cloned();
    let items: Vec<Value> = a
        .passkeys
        .iter()
        .filter(|(_, p)| p.account == account)
        .map(|(id, _)| {
            obj(vec![
                ("id", hex(id).into()),
                ("current", (used.as_deref() == Some(id.as_slice())).into()),
            ])
        })
        .collect();
    wire::json(
        StatusCode::OK,
        &obj(vec![
            ("account", dec(account.raw())),
            ("devices", Value::Array(Array::from(items))),
        ]),
    )
}

async fn step_up(inner: &Inner, req: &Request) -> Response {
    let Some((session, account)) = session(inner, req).await else {
        return refuse(StatusCode::UNAUTHORIZED, "session");
    };
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(id) = id_member(&body, "challenge_id") else {
        return wire::bad("challenge_id");
    };
    let Some((owner, challenge)) = inner.ports.step_up.challenge_for(&id) else {
        return refuse(StatusCode::FORBIDDEN, "challenge");
    };
    if owner != session {
        return refuse(StatusCode::FORBIDDEN, "challenge");
    }
    let asserted = lock(&inner.auth).assert(&body, &challenge);
    match asserted {
        Ok((who, _)) if who == account => {}
        Ok(_) => return refuse(StatusCode::FORBIDDEN, "credential_id"),
        Err(why) => return refuse(StatusCode::FORBIDDEN, why),
    }
    match inner.ports.step_up.finish(session, &challenge).await {
        Ok(r) => wire::json(
            StatusCode::OK,
            &obj(vec![("stepup", hex(&r.0.to_be_bytes()).into())]),
        ),
        Err(_) => refuse(StatusCode::FORBIDDEN, "challenge"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_http::{Method, Request, RequestTarget};

    fn request(headers: &[(&str, &str)]) -> Request {
        let mut r = Request::new(Method::POST, RequestTarget::origin("/auth/stepup").unwrap());
        for (k, v) in headers {
            r.headers.try_append(k, *v).unwrap();
        }
        r
    }

    fn site() -> SiteInfo {
        SiteInfo {
            name: "a",
            host: "a.fstp.localhost".to_owned(),
            origin: "http://a.fstp.localhost:8640".to_owned(),
            control: "http://127.0.0.1:8641".to_owned(),
            assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
                .unwrap(),
            auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
        }
    }

    /// ADR-008: the session cookie is read by its exact name, once. Two
    /// cookies of that name are refused, so a tossed cookie never shadows
    /// the session.
    #[test]
    fn adr008_session_cookie_is_read_once_by_name() {
        let one = request(&[("cookie", "a=1; __Host-fstp=abc; b=2")]);
        assert_eq!(cookie(&one), Some(b"abc".to_vec()));
        let two = request(&[("cookie", "__Host-fstp=a; __Host-fstp=b")]);
        assert_eq!(cookie(&two), None);
        assert_eq!(cookie(&request(&[])), None);
    }

    /// ADR-014: an M3 ceremony route that changes state needs the cell
    /// origin and `X-FSTP-Request: 1`.
    #[test]
    fn adr014_ceremony_routes_need_origin_and_request_mark() {
        let s = site();
        let ok = request(&[
            ("origin", "http://a.fstp.localhost:8640"),
            ("x-fstp-request", "1"),
        ]);
        assert!(csrf(&s, &ok));
        let foreign = request(&[
            ("origin", "http://b.fstp.localhost:8642"),
            ("x-fstp-request", "1"),
        ]);
        assert!(!csrf(&s, &foreign));
        let unmarked = request(&[("origin", "http://a.fstp.localhost:8640")]);
        assert!(!csrf(&s, &unmarked));
    }

    /// I-78: a challenge is named by 16 bytes of lowercase hex, and a
    /// one-time invitation link carries its token in the fragment only.
    #[test]
    fn i78_challenge_ids_and_invitation_links() {
        let mut o = Object::new();
        let _ = o.insert(
            "challenge_id",
            Value::from("00112233445566778899aabbccddeeff"),
        );
        assert!(id_member(&o, "challenge_id").is_some());
        let _ = o.insert("challenge_id", Value::from("0011"));
        assert!(id_member(&o, "challenge_id").is_none());
        let mut a = AuthState::new(&site());
        let link = a.invite(AccountId::from_raw(7)).unwrap();
        let (base, token) = link.split_once('#').unwrap();
        assert_eq!(base, "http://a.fstp.localhost:8640/auth/invite");
        assert_eq!(token.len(), 32);
        assert!(!link.contains('?'));
    }

    /// A CBOR head of major type `major` and argument `n`, shortest form.
    fn head(major: u8, n: usize) -> Vec<u8> {
        let m = major << 5;
        match u8::try_from(n) {
            Ok(b) if b < 24 => vec![m | b],
            Ok(b) => vec![m | 24, b],
            Err(_) => {
                let w = u16::try_from(n).unwrap().to_be_bytes();
                vec![m | 25, w[0], w[1]]
            }
        }
    }

    fn text(s: &str) -> Vec<u8> {
        let mut v = head(3, s.len());
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn bytes(b: &[u8]) -> Vec<u8> {
        let mut v = head(2, b.len());
        v.extend_from_slice(b);
        v
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}"}}"#,
            b64url(challenge)
        )
        .into_bytes()
    }

    fn body(members: &[(&str, &[u8])]) -> Object {
        let mut o = Object::new();
        for (k, v) in members {
            let _ = o.insert(*k, Value::from(hex(v)));
        }
        o
    }

    /// ADR-008, I-78: an assertion proves possession of the attested key.
    /// A well-formed assertion for a known credential id is refused when
    /// its signature does not verify under that key, and the sign count
    /// stays as it was.
    #[test]
    fn adr008_assertion_signature_is_verified() {
        let s = site();
        let mut a = AuthState::new(&s);
        let key = fstp_crypto::sig::Ed25519SigningKey::generate().unwrap();
        let id = [7u8; 16];
        let rp = fstp_crypto::sha256(s.host.as_bytes());
        // COSE EdDSA key: kty 1 (OKP), alg -8, crv 6 (Ed25519), x.
        let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
        cose.extend(bytes(&key.public_key()));
        let mut auth = rp.to_vec();
        auth.push(0x45);
        auth.extend_from_slice(&[0; 4]);
        auth.extend_from_slice(&[0; 16]);
        auth.extend_from_slice(&[0, 16]);
        auth.extend_from_slice(&id);
        auth.extend(cose);
        let mut att = vec![0xa3];
        att.extend(text("fmt"));
        att.extend(text("none"));
        att.extend(text("attStmt"));
        att.push(0xa0);
        att.extend(text("authData"));
        att.extend(bytes(&auth));
        let challenge = [1u8; 32];
        let cd = client_data("webauthn.create", &challenge, &s.origin);
        let reg = body(&[
            ("client_data_json", &cd),
            ("attestation_object", &att),
            ("credential_id", &id),
        ]);
        let account = AccountId::from_raw(9);
        assert_eq!(a.register(&reg, &challenge, account), Ok(id.to_vec()));

        let assertion = |count: u8, sign: &dyn Fn(&[u8]) -> Vec<u8>| {
            let mut ad = rp.to_vec();
            ad.push(0x05);
            ad.extend_from_slice(&[0, 0, 0, count]);
            let cd = client_data("webauthn.get", &challenge, &s.origin);
            let mut message = ad.clone();
            message.extend_from_slice(&fstp_crypto::sha256(&cd));
            let sig = sign(&message);
            body(&[
                ("credential_id", &id),
                ("client_data_json", &cd),
                ("authenticator_data", &ad),
                ("signature", &sig),
            ])
        };
        let forged = assertion(1, &|_| vec![0u8; 64]);
        assert_eq!(a.assert(&forged, &challenge), Err("signature"));
        let other = fstp_crypto::sig::Ed25519SigningKey::generate().unwrap();
        let wrong_key = assertion(1, &|m| other.sign(m).unwrap().to_vec());
        assert_eq!(a.assert(&wrong_key, &challenge), Err("signature"));
        let signed = assertion(1, &|m| key.sign(m).unwrap().to_vec());
        assert_eq!(a.assert(&signed, &challenge), Ok((account, id.to_vec())));
        let replayed = assertion(1, &|m| key.sign(m).unwrap().to_vec());
        assert_eq!(a.assert(&replayed, &challenge), Err("sign_count"));
    }
}

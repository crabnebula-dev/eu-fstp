//! M-OAUTH and the OAuth test surface of lane W1e (M4 design sections 3.8
//! and 8.5, ADR-013, TH-61). Lane W1e owns this file, and its test author
//! wrote it from the design text and ADR-013 before the production code.
//!
//! The file holds four parts:
//!
//! - [`AuthServer`], the endpoint-level surface the `th61_*` tests drive.
//!   It takes wire bytes in and gives RFC wire replies out, so a test reads
//!   the same JSON, headers and redirects a client would.
//! - [`RefServer`], an independent reference authorisation server written
//!   from ADR-013 and the RFCs it names. The `_reference` twin of each test
//!   runs on it and must pass now.
//! - [`ProductionServer`], the adapter to `fstp-oauth`. Each method hands
//!   the wire bytes to `fstp_oauth::AuthorizationServer` and converts its
//!   reply, so the production twin of each test runs the shipped code.
//! - [`OauthModel`], the M-OAUTH model: one client and one account, with
//!   authorise, token, refresh, reuse, revoke, agent revocation and clock
//!   moves. Its abstract machine is the second reference.
//!
//! Interim readings, pending Daniel, each one a strict reading of ADR-013
//! and OAuth 2.1:
//!
//! - Lifetimes follow the repository convention of the fake step-up and of
//!   pending actions: a code, token or family is valid while younger than
//!   its lifetime and dead at exactly its lifetime.
//! - A second redemption of a code is refused and revokes the family the
//!   first redemption issued (the OAuth 2.1 "SHOULD revoke").
//! - Revoking a refresh token through RFC 7009 revokes its family (the RFC
//!   7009 "SHOULD"). Ending an agent through R-MC-03 revokes every family
//!   and every unredeemed code of that client for that account.
//! - A rotation leaves earlier access tokens of the family valid until they
//!   expire. Reuse of a rotated refresh token revokes all of them.
//! - Every access token expires at the earlier of 10 minutes after issue
//!   and the end of its family (P-72), so no token outlives its family.
//! - An exchange whose PKCE verifier fails may consume the code or leave it
//!   redeemable. The model admits both, because neither ADR-013 nor OAuth
//!   2.1 says which. The reference consumes it.
//! - The consent takes a step-up proof and checks it itself, as defence in
//!   depth behind the API core (I-78): a phishing-resistant session, a
//!   phishing-resistant proof by the same account, bound to the consent
//!   digest, younger than P-71.
//!
//! Model state: the abstract state, the trace that reached it with the
//! outcomes the backend gave, and the first divergence. Equality and
//! hashing read the abstract state and the divergence only. Two traces
//! that reach one abstract state are one model state, and the backend is
//! checked along the first trace found, as in M-PREP.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use fstp_json::{Object, Value};
use fstp_mc::{Model, Property};

use crate::NotImplemented;

// ---------------------------------------------------------------------------
// Profile constants (ADR-013, Q25, P-71, P-72)
// ---------------------------------------------------------------------------

/// Codes live 60 seconds (ADR-013).
pub const CODE_LIFETIME_MICROS: i64 = 60_000_000;
/// Access tokens live 10 minutes (ADR-013, Q25).
pub const ACCESS_LIFETIME_MICROS: i64 = 600_000_000;
/// P-72 absolute session lifetime: 12 hours, proposed
/// (`policy-parameters.md`). No refresh family outlives it (Q25).
pub const P72_ABSOLUTE_MICROS: i64 = 43_200_000_000;
/// P-71 step-up freshness: 5 minutes, proposed.
pub const P71_MICROS: i64 = crate::fake::step_up::P71_MICROS;

/// The synthetic cell's issuer.
pub const ISSUER: &str = "https://cell-a.example";
/// The synthetic cell's MCP URL, the only valid `resource` (RFC 8707).
pub const MCP_URL: &str = "https://cell-a.example/mcp";
/// Another cell's MCP URL.
pub const OTHER_RESOURCE: &str = "https://cell-b.example/mcp";
/// The well-known path of the protected resource metadata (RFC 9728).
pub const PRM_PATH: &str = "/.well-known/oauth-protected-resource";

/// The scopes issued in M4 (design section 3.8), spelt as on the wire.
pub const SCOPES: [&str; 12] = [
    "calls:read",
    "proposals:read",
    "proposals:draft",
    "proposals:binding",
    "stage2:draft",
    "review:read",
    "review:draft",
    "ranking:read",
    "findings:read",
    "creator:draft",
    "calls:draft",
    "audit:read",
];

/// The redirect URI of the model's client.
pub const MODEL_REDIRECT: &str = "https://agent.example/callback";
/// The scope the model's client asks for.
pub const MODEL_SCOPE: &str = "calls:read calls:draft";
/// The account of the model, with a canary pattern in its id.
pub const MODEL_ACCOUNT: AccountRef = AccountRef(0x7f3a_0000_c0de_0001);
/// The rate-limit key of the model's registration.
pub const SOURCE_A: SourceKey = SourceKey(1);
/// A second rate-limit key.
pub const SOURCE_B: SourceKey = SourceKey(2);

/// The configuration a server under test starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// The issuer (RFC 8414).
    pub issuer: String,
    /// This cell's MCP URL, the audience of every token.
    pub resource: String,
    /// P-72, the absolute lifetime of a refresh family.
    pub p72_absolute_micros: i64,
    /// P-71, the step-up freshness.
    pub p71_micros: i64,
    /// Registrations admitted per source within one window.
    pub registration_max: u32,
    /// The registration rate-limit window.
    pub registration_window_micros: i64,
}

impl ServerConfig {
    /// The synthetic cell's configuration: 5 registrations per hour.
    pub fn synthetic() -> ServerConfig {
        ServerConfig {
            issuer: ISSUER.to_owned(),
            resource: MCP_URL.to_owned(),
            p72_absolute_micros: P72_ABSOLUTE_MICROS,
            p71_micros: P71_MICROS,
            registration_max: 5,
            registration_window_micros: 3_600_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire helpers (test code: written for the tests, never shipped)
// ---------------------------------------------------------------------------

/// Microseconds on the server's clock.
pub type Micros = i64;

/// The characters RFC 3986 calls unreserved, which PKCE verifiers use.
pub const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

const HEX: &[u8; 16] = b"0123456789ABCDEF";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn hex_digit(n: u8) -> char {
    char::from(HEX.get(usize::from(n & 0x0f)).copied().unwrap_or(b'0'))
}

/// Percent-encodes `s` for a query or form value: unreserved characters
/// stay, every other byte becomes `%XX`.
pub fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if UNRESERVED.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex_digit(b.checked_shr(4).unwrap_or(0)));
            out.push(hex_digit(b));
        }
    }
    out
}

/// An `application/x-www-form-urlencoded` body, or a query, from pairs.
pub fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&pct(k));
        out.push('=');
        out.push_str(&pct(v));
    }
    out.into_bytes()
}

fn unhex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|n| n.checked_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').and_then(|n| n.checked_add(10)),
        _ => None,
    }
}

fn pct_decode(part: &[u8]) -> Result<String, String> {
    let mut out = Vec::with_capacity(part.len());
    let mut i = 0usize;
    while let Some(&b) = part.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = part.get(i.saturating_add(1)).copied().and_then(unhex);
                let lo = part.get(i.saturating_add(2)).copied().and_then(unhex);
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push(h.checked_shl(4).unwrap_or(0) | l),
                    _ => return Err("bad percent-encoding".to_owned()),
                }
                i = i.saturating_add(2);
            }
            _ => out.push(b),
        }
        i = i.saturating_add(1);
    }
    String::from_utf8(out).map_err(|_| "not UTF-8".to_owned())
}

/// Decodes a form body or query into pairs. An empty input has no pairs.
/// An empty segment, a segment without `=`, bad percent-encoding and
/// invalid UTF-8 are refused.
pub fn decode_pairs(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for seg in bytes.split(|&b| b == b'&') {
        let eq = seg
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| "a parameter without '='".to_owned())?;
        let (k, v) = seg.split_at(eq);
        let v = v.get(1..).unwrap_or(&[]);
        if k.is_empty() {
            return Err("an empty parameter name".to_owned());
        }
        out.push((pct_decode(k)?, pct_decode(v)?));
    }
    Ok(out)
}

/// The pairs of `bytes` as a map. A duplicated name is refused.
pub fn decode_unique(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for (k, v) in decode_pairs(bytes)? {
        if map.insert(k.clone(), v).is_some() {
            return Err(format!("duplicate parameter {k}"));
        }
    }
    Ok(map)
}

/// The query parameters of a redirect `location`, after `?` and before any
/// `#`. A duplicated name is refused.
pub fn location_params(location: &str) -> Result<BTreeMap<String, String>, String> {
    let before_fragment = location.split('#').next().unwrap_or("");
    let query = match before_fragment.split_once('?') {
        Some((_, q)) => q,
        None => "",
    };
    decode_unique(query.as_bytes())
}

/// Unpadded base64url of `bytes`.
pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = b0.checked_shl(16).unwrap_or(0) | b1.checked_shl(8).unwrap_or(0) | b2;
        let chars = chunk.len().saturating_add(1);
        for i in 0..chars {
            let shift = 18u32.saturating_sub(6u32.saturating_mul(u32::try_from(i).unwrap_or(0)));
            let idx = n.checked_shr(shift).unwrap_or(0) & 0x3f;
            let c = B64URL
                .get(usize::try_from(idx).unwrap_or(0))
                .copied()
                .unwrap_or(b'A');
            out.push(char::from(c));
        }
    }
    out
}

/// Decodes unpadded base64url text, or `None`.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v = B64URL.iter().position(|&x| x == c)?;
        acc = acc.checked_shl(6)? | u32::try_from(v).ok()?;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.checked_shr(bits)? & 0xff).ok()?);
            acc &= (1u32.checked_shl(bits)?).saturating_sub(1);
        }
    }
    if bits >= 6 {
        return None;
    }
    Some(out)
}

/// The PKCE `S256` challenge of `verifier` (RFC 7636).
pub fn s256(verifier: &str) -> String {
    b64url(&fstp_crypto::sha256(verifier.as_bytes()))
}

/// Whether `v` is a valid PKCE verifier: 43 to 128 unreserved characters.
pub fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len()) && v.bytes().all(|b| UNRESERVED.contains(&b))
}

/// Whether `t` looks like a token of ADR-013: 256 bits as 43 characters of
/// unpadded base64url, with no structure such as a JWT's dots.
pub fn opaque_256(t: &str) -> bool {
    t.len() == 43 && b64url_decode(t).is_some_and(|b| b.len() == 32)
}

// ---------------------------------------------------------------------------
// The test surface
// ---------------------------------------------------------------------------

/// The rate-limit key of a registration request, such as a connection's
/// source. Opaque to the tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey(pub u64);

/// An account of the cell, by id only. The authorisation server never
/// learns an identity attribute (I-86).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountRef(pub u64);

/// An HTTP reply of an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The headers, as sent.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Reply {
    fn json_reply(status: u16, v: Value) -> Reply {
        Reply {
            status,
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Cache-Control".to_owned(), "no-store".to_owned()),
            ],
            body: v.to_compact().into_bytes(),
        }
    }

    fn error(status: u16, code: &str) -> Reply {
        let mut o = Object::new();
        o.insert("error", Value::from(code));
        Reply::json_reply(status, Value::Object(o))
    }

    /// The body as JSON.
    pub fn json(&self) -> Result<Value, String> {
        fstp_json::parse(&self.body).map_err(|e| format!("reply body is not JSON: {e}"))
    }

    /// The first header named `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `error` member of a JSON body.
    pub fn error_code(&self) -> Option<String> {
        self.json()
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
    }
}

/// A consent the authorisation endpoint asks the user for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentTicket {
    /// The server's handle for the pending authorisation.
    pub handle: Vec<u8>,
    /// The digest a step-up for this consent binds to (I-78).
    pub digest: [u8; 32],
    /// The client name, untrusted text shown with an "unverified" label.
    pub client_name: Option<String>,
    /// The redirect host shown on the consent page.
    pub redirect_host: String,
    /// The scopes asked for.
    pub scopes: Vec<String>,
}

/// What the authorisation endpoint, or the consent, answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizeReply {
    /// The user is asked to consent.
    Consent(ConsentTicket),
    /// The user agent is sent to the client's registered redirect URI,
    /// with a code or an error in the query.
    Redirect(String),
    /// The request is refused to the user, with no redirect.
    Refused(Reply),
}

/// A login or step-up method (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// A passkey or the EUDI Wallet.
    PhishingResistant,
    /// An email magic link.
    MagicLink,
}

/// A completed step-up (I-78).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpProof {
    /// The account that stepped up.
    pub account: AccountRef,
    /// The digest it is bound to.
    pub digest: [u8; 32],
    /// When it completed.
    pub at: Micros,
    /// The method used.
    pub method: Method,
}

/// How the user approves a consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentAuth {
    /// The method of the session approving.
    pub session: Method,
    /// The step-up taken for the consent.
    pub step_up: Option<StepUpProof>,
}

impl ConsentAuth {
    /// A passkey session with a fresh step-up for `ticket` at `now`.
    pub fn fresh(account: AccountRef, ticket: &ConsentTicket, now: Micros) -> ConsentAuth {
        ConsentAuth {
            session: Method::PhishingResistant,
            step_up: Some(StepUpProof {
                account,
                digest: ticket.digest,
                at: now,
                method: Method::PhishingResistant,
            }),
        }
    }
}

/// What a valid access token grants, as the API core reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantView {
    /// The account.
    pub account: AccountRef,
    /// The client.
    pub client_id: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The audience.
    pub audience: String,
}

/// What a protected resource request gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// The token is valid here and now.
    Granted(GrantView),
    /// The request is refused, with this reply.
    Denied(Reply),
}

/// The endpoints of an authorisation server under test (ADR-013).
pub trait AuthServer {
    /// `POST /oauth/register` (RFC 7591) from `source`.
    fn register(
        &mut self,
        source: SourceKey,
        body: &[u8],
        now: Micros,
    ) -> Result<Reply, NotImplemented>;
    /// `GET /oauth/authorize` with this query.
    fn authorize(&mut self, query: &[u8], now: Micros) -> Result<AuthorizeReply, NotImplemented>;
    /// The user's approval of a consent, after the API core's checks.
    fn consent(
        &mut self,
        ticket: &ConsentTicket,
        account: AccountRef,
        auth: &ConsentAuth,
        now: Micros,
    ) -> Result<AuthorizeReply, NotImplemented>;
    /// `POST /oauth/token` with this form body.
    fn token(&mut self, body: &[u8], now: Micros) -> Result<Reply, NotImplemented>;
    /// `POST /oauth/revoke` (RFC 7009) with this form body.
    fn revoke(&mut self, body: &[u8], now: Micros) -> Result<Reply, NotImplemented>;
    /// `POST /api/v1/me/agents/{client}/revocation` (R-MC-03).
    fn revoke_agent(
        &mut self,
        account: AccountRef,
        client_id: &str,
        now: Micros,
    ) -> Result<(), NotImplemented>;
    /// A request to `resource` with this `Authorization` header value.
    fn resource(
        &mut self,
        authorization: Option<&[u8]>,
        resource: &str,
        now: Micros,
    ) -> Result<Access, NotImplemented>;
    /// `GET /.well-known/oauth-authorization-server` (RFC 8414).
    fn as_metadata(&mut self) -> Result<Reply, NotImplemented>;
    /// `GET /.well-known/oauth-protected-resource` (RFC 9728).
    fn resource_metadata(&mut self) -> Result<Reply, NotImplemented>;
}

/// Which server a test or the model runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// `fstp-oauth`, through [`ProductionServer`].
    Production,
    /// [`RefServer`].
    Reference,
}

/// A server of `backend` with `config`.
pub fn server(backend: Backend, config: &ServerConfig) -> Box<dyn AuthServer> {
    match backend {
        Backend::Production => Box::new(ProductionServer::new(config.clone())),
        Backend::Reference => Box::new(RefServer::new(config.clone())),
    }
}

// ---------------------------------------------------------------------------
// Production adapter
// ---------------------------------------------------------------------------

/// The adapter to `fstp-oauth`: each method hands the wire bytes to the
/// production server and converts its reply into the test surface's types.
#[derive(Debug)]
pub struct ProductionServer {
    config: ServerConfig,
    server: Result<fstp_oauth::AuthorizationServer, fstp_oauth::OauthError>,
}

impl ProductionServer {
    /// An adapter with `config`.
    pub fn new(config: ServerConfig) -> ProductionServer {
        let mut cfg = fstp_oauth::Config::new(
            &config.issuer,
            &config.resource,
            config.p72_absolute_micros,
            config.p71_micros,
        );
        cfg.registration_max = config.registration_max;
        cfg.registration_window_micros = config.registration_window_micros;
        let server = fstp_oauth::AuthorizationServer::new(cfg);
        ProductionServer { config, server }
    }

    /// The configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    fn server(&mut self) -> Result<&mut fstp_oauth::AuthorizationServer, NotImplemented> {
        self.server.as_mut().map_err(|_| {
            NotImplemented::new("fstp_oauth::AuthorizationServer::new refused the configuration")
        })
    }
}

fn reply_of(r: fstp_oauth::Reply) -> Reply {
    Reply {
        status: r.status,
        headers: r.headers,
        body: r.body,
    }
}

/// The model has two methods. A passkey stands for every phishing-resistant
/// one, and a magic link for every other one.
fn method_of(m: Method) -> fstp_oauth::LoginMethod {
    match m {
        Method::PhishingResistant => fstp_oauth::LoginMethod::Passkey,
        Method::MagicLink => fstp_oauth::LoginMethod::MagicLink,
    }
}

fn outcome_of(o: fstp_oauth::AuthorizeOutcome) -> AuthorizeReply {
    match o {
        fstp_oauth::AuthorizeOutcome::Consent(c) => AuthorizeReply::Consent(ConsentTicket {
            handle: c.handle.clone().into_bytes(),
            digest: c.digest,
            client_name: c.client_name.clone(),
            redirect_host: c.redirect_host.clone(),
            scopes: c.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
        }),
        fstp_oauth::AuthorizeOutcome::Redirect(loc) => AuthorizeReply::Redirect(loc),
        fstp_oauth::AuthorizeOutcome::Refused(r) => AuthorizeReply::Refused(reply_of(r)),
    }
}

impl AuthServer for ProductionServer {
    fn register(
        &mut self,
        source: SourceKey,
        body: &[u8],
        now: Micros,
    ) -> Result<Reply, NotImplemented> {
        let key = fstp_oauth::RateKey::from_raw(source.0);
        Ok(reply_of(self.server()?.register(key, body, now)))
    }

    fn authorize(&mut self, query: &[u8], now: Micros) -> Result<AuthorizeReply, NotImplemented> {
        Ok(outcome_of(self.server()?.authorize(query, now)))
    }

    fn consent(
        &mut self,
        ticket: &ConsentTicket,
        account: AccountRef,
        auth: &ConsentAuth,
        now: Micros,
    ) -> Result<AuthorizeReply, NotImplemented> {
        let handle = String::from_utf8_lossy(&ticket.handle).into_owned();
        let auth = fstp_oauth::ConsentAuth {
            session: method_of(auth.session),
            step_up: auth.step_up.map(|p| fstp_oauth::StepUpProof {
                account: fstp_oauth::Account::from_raw(p.account.0),
                digest: p.digest,
                at: p.at,
                method: method_of(p.method),
            }),
        };
        let account = fstp_oauth::Account::from_raw(account.0);
        Ok(outcome_of(
            self.server()?.approve(&handle, account, &auth, now),
        ))
    }

    fn token(&mut self, body: &[u8], now: Micros) -> Result<Reply, NotImplemented> {
        Ok(reply_of(self.server()?.token(body, now)))
    }

    fn revoke(&mut self, body: &[u8], now: Micros) -> Result<Reply, NotImplemented> {
        Ok(reply_of(self.server()?.revoke(body, now)))
    }

    fn revoke_agent(
        &mut self,
        account: AccountRef,
        client_id: &str,
        now: Micros,
    ) -> Result<(), NotImplemented> {
        let account = fstp_oauth::Account::from_raw(account.0);
        self.server()?.revoke_agent(account, client_id, now);
        Ok(())
    }

    fn resource(
        &mut self,
        authorization: Option<&[u8]>,
        resource: &str,
        now: Micros,
    ) -> Result<Access, NotImplemented> {
        Ok(
            match self.server()?.authenticate(authorization, resource, now) {
                Ok(g) => Access::Granted(GrantView {
                    account: AccountRef(g.account.raw()),
                    client_id: g.client_id,
                    scopes: g.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
                    audience: g.audience,
                }),
                Err(r) => Access::Denied(reply_of(r)),
            },
        )
    }

    fn as_metadata(&mut self) -> Result<Reply, NotImplemented> {
        Ok(reply_of(self.server()?.server_metadata()))
    }

    fn resource_metadata(&mut self) -> Result<Reply, NotImplemented> {
        Ok(reply_of(self.server()?.resource_metadata()))
    }
}

// ---------------------------------------------------------------------------
// Reference server
// ---------------------------------------------------------------------------

/// A redirect URI in the strict subset, split for matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectParts {
    /// `true` for `https`, `false` for loopback `http`.
    pub https: bool,
    /// The host, as written.
    pub host: String,
    /// The port, when written.
    pub port: Option<u16>,
    /// The path and query, as written.
    pub rest: String,
}

impl RedirectParts {
    /// Whether this is a loopback redirect for a native client (RFC 8252).
    pub fn loopback(&self) -> bool {
        !self.https && (self.host == "127.0.0.1" || self.host == "[::1]")
    }
}

/// Parses a redirect URI in the reference's strict subset: lowercase
/// `https://`, or `http://` to a loopback IP literal; ASCII only; no
/// userinfo; no fragment; a lowercase DNS host; an optional port.
pub fn parse_redirect(s: &str) -> Option<RedirectParts> {
    if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) || s.contains('#') {
        return None;
    }
    let (https, after) = if let Some(a) = s.strip_prefix("https://") {
        (true, a)
    } else {
        (false, s.strip_prefix("http://")?)
    };
    let end = after.find(['/', '?']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let (h, p) = authority.split_at(close.saturating_add(1));
        (h, p)
    } else {
        match authority.find(':') {
            Some(i) => authority.split_at(i),
            None => (authority, ""),
        }
    };
    let port = if port.is_empty() {
        None
    } else {
        let digits = port.strip_prefix(':')?;
        if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u16 = digits.parse().ok()?;
        if n == 0 {
            return None;
        }
        Some(n)
    };
    let dns_ok = host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if host != "[::1]" && (!dns_ok || host.is_empty()) {
        return None;
    }
    let parts = RedirectParts {
        https,
        host: host.to_owned(),
        port,
        rest: rest.to_owned(),
    };
    if !parts.https && !parts.loopback() {
        return None;
    }
    Some(parts)
}

/// Whether `presented` matches `registered`: byte for byte, except the
/// port of a loopback redirect (RFC 8252 section 7.3).
pub fn redirect_matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return parse_redirect(presented).is_some();
    }
    match (parse_redirect(registered), parse_redirect(presented)) {
        (Some(r), Some(p)) => r.loopback() && !p.https && r.host == p.host && r.rest == p.rest,
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct RefClient {
    redirect_uris: Vec<String>,
    name: Option<String>,
}

#[derive(Clone, Debug)]
struct RefTicket {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    challenge: String,
    state: Option<String>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefCodeState {
    Fresh,
    Burned,
    Redeemed(usize),
}

#[derive(Clone, Debug)]
struct RefCode {
    client_id: String,
    account: AccountRef,
    redirect_uri: String,
    scopes: Vec<String>,
    challenge: String,
    issued: Micros,
    state: RefCodeState,
}

#[derive(Clone, Debug)]
struct RefFamily {
    client_id: String,
    account: AccountRef,
    scopes: Vec<String>,
    start: Micros,
    current: u32,
    revoked: bool,
}

#[derive(Clone, Copy, Debug)]
struct RefAccessToken {
    family: usize,
    expires: Micros,
    revoked: bool,
}

/// The reference authorisation server, written from ADR-013, OAuth 2.1
/// and RFCs 7009, 7591, 7636, 8252, 8414, 8707 and 9728.
#[derive(Clone, Debug)]
pub struct RefServer {
    cfg: ServerConfig,
    clients: BTreeMap<String, RefClient>,
    next_client: u64,
    registrations: BTreeMap<SourceKey, Vec<Micros>>,
    tickets: BTreeMap<Vec<u8>, RefTicket>,
    next_ticket: u64,
    codes: BTreeMap<[u8; 32], RefCode>,
    families: Vec<RefFamily>,
    refresh: BTreeMap<[u8; 32], (usize, u32)>,
    access: BTreeMap<[u8; 32], RefAccessToken>,
    minted: u64,
}

fn json_strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

fn json_strs(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(*s)).collect())
}

fn host_of(uri: &str) -> String {
    parse_redirect(uri).map(|p| p.host).unwrap_or_default()
}

impl RefServer {
    /// A reference server with `cfg`.
    pub fn new(cfg: ServerConfig) -> RefServer {
        RefServer {
            cfg,
            clients: BTreeMap::new(),
            next_client: 0,
            registrations: BTreeMap::new(),
            tickets: BTreeMap::new(),
            next_ticket: 0,
            codes: BTreeMap::new(),
            families: Vec::new(),
            refresh: BTreeMap::new(),
            access: BTreeMap::new(),
            minted: 0,
        }
    }

    fn mint(&mut self) -> String {
        self.minted = self.minted.saturating_add(1);
        let mut h = fstp_crypto::Sha256::new();
        h.update(b"m-oauth reference token\0");
        h.update(&self.minted.to_be_bytes());
        b64url(&h.finish())
    }

    fn family_end(&self, f: &RefFamily) -> Micros {
        f.start.saturating_add(self.cfg.p72_absolute_micros)
    }

    fn revoke_family(&mut self, f: usize) {
        if let Some(fam) = self.families.get_mut(f) {
            fam.revoked = true;
        }
    }

    fn issue(&mut self, f: usize, now: Micros) -> Reply {
        let Some(fam) = self.families.get(f).cloned() else {
            return Reply::error(500, "server_error");
        };
        let refresh = self.mint();
        let access = self.mint();
        let expires = now
            .saturating_add(ACCESS_LIFETIME_MICROS)
            .min(self.family_end(&fam));
        self.refresh
            .insert(fstp_crypto::sha256(refresh.as_bytes()), (f, fam.current));
        self.access.insert(
            fstp_crypto::sha256(access.as_bytes()),
            RefAccessToken {
                family: f,
                expires,
                revoked: false,
            },
        );
        let mut o = Object::new();
        o.insert("access_token", Value::from(access.as_str()));
        o.insert("token_type", Value::from("Bearer"));
        o.insert(
            "expires_in",
            Value::from(
                expires
                    .saturating_sub(now)
                    .checked_div(1_000_000)
                    .unwrap_or(0),
            ),
        );
        o.insert("refresh_token", Value::from(refresh.as_str()));
        o.insert("scope", Value::from(fam.scopes.join(" ").as_str()));
        Reply::json_reply(200, Value::Object(o))
    }

    fn error_redirect(&self, redirect: &str, code: &str, state: Option<&String>) -> AuthorizeReply {
        let mut loc = format!("{redirect}?error={}", pct(code));
        if let Some(s) = state {
            loc.push_str("&state=");
            loc.push_str(&pct(s));
        }
        loc.push_str("&iss=");
        loc.push_str(&pct(&self.cfg.issuer));
        AuthorizeReply::Redirect(loc)
    }

    fn consent_digest(t: &RefTicket) -> [u8; 32] {
        let mut h = fstp_crypto::Sha256::new();
        h.update(b"m-oauth reference consent\0");
        for part in [
            t.client_id.as_str(),
            t.redirect_uri.as_str(),
            &t.scopes.join(" "),
            t.challenge.as_str(),
            t.state.as_deref().unwrap_or(""),
        ] {
            h.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            h.update(part.as_bytes());
        }
        h.finish()
    }

    fn validate_metadata(body: &[u8]) -> Result<RefClient, &'static str> {
        let v = fstp_json::parse(body).map_err(|_| "invalid_client_metadata")?;
        let o = v.as_object().ok_or("invalid_client_metadata")?;
        let uris = o
            .get("redirect_uris")
            .and_then(Value::as_array)
            .ok_or("invalid_redirect_uri")?;
        if uris.is_empty() {
            return Err("invalid_redirect_uri");
        }
        let mut redirect_uris = Vec::new();
        for u in uris.iter() {
            let s = u.as_str().ok_or("invalid_redirect_uri")?;
            if parse_redirect(s).is_none() {
                return Err("invalid_redirect_uri");
            }
            redirect_uris.push(s.to_owned());
        }
        let name = match o.get("client_name") {
            None => None,
            Some(n) => Some(n.as_str().ok_or("invalid_client_metadata")?.to_owned()),
        };
        let subset = |key: &str, allowed: &[&str]| -> Result<(), &'static str> {
            match o.get(key) {
                None => Ok(()),
                Some(v) => {
                    let a = v.as_array().ok_or("invalid_client_metadata")?;
                    if a.iter()
                        .all(|x| x.as_str().is_some_and(|s| allowed.contains(&s)))
                    {
                        Ok(())
                    } else {
                        Err("invalid_client_metadata")
                    }
                }
            }
        };
        subset("grant_types", &["authorization_code", "refresh_token"])?;
        subset("response_types", &["code"])?;
        match o.get("token_endpoint_auth_method") {
            None => {}
            Some(m) if m.as_str() == Some("none") => {}
            Some(_) => return Err("invalid_client_metadata"),
        }
        Ok(RefClient {
            redirect_uris,
            name,
        })
    }

    fn scopes_of(s: &str) -> Option<Vec<String>> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for part in s.split(' ') {
            if !SCOPES.contains(&part) || !seen.insert(part) {
                return None;
            }
            out.push(part.to_owned());
        }
        (!out.is_empty()).then_some(out)
    }

    fn code_grant(&mut self, p: &BTreeMap<String, String>, now: Micros) -> Reply {
        let (Some(code), Some(client_id)) = (p.get("code"), p.get("client_id")) else {
            return Reply::error(400, "invalid_request");
        };
        let key = fstp_crypto::sha256(code.as_bytes());
        let Some(c) = self.codes.get(&key).cloned() else {
            return Reply::error(400, "invalid_grant");
        };
        if &c.client_id != client_id {
            return Reply::error(400, "invalid_grant");
        }
        match c.state {
            RefCodeState::Redeemed(f) => {
                self.revoke_family(f);
                return Reply::error(400, "invalid_grant");
            }
            RefCodeState::Burned => return Reply::error(400, "invalid_grant"),
            RefCodeState::Fresh => {}
        }
        let burn = |s: &mut RefServer| {
            if let Some(c) = s.codes.get_mut(&key) {
                c.state = RefCodeState::Burned;
            }
        };
        let age = now.saturating_sub(c.issued);
        if !(0..CODE_LIFETIME_MICROS).contains(&age) {
            burn(self);
            return Reply::error(400, "invalid_grant");
        }
        if p.get("redirect_uri") != Some(&c.redirect_uri) {
            return Reply::error(400, "invalid_grant");
        }
        if let Some(r) = p.get("resource")
            && r != &self.cfg.resource
        {
            return Reply::error(400, "invalid_target");
        }
        let verified = p
            .get("code_verifier")
            .is_some_and(|v| valid_verifier(v) && s256(v) == c.challenge);
        if !verified {
            burn(self);
            return Reply::error(400, "invalid_grant");
        }
        let f = self.families.len();
        self.families.push(RefFamily {
            client_id: c.client_id.clone(),
            account: c.account,
            scopes: c.scopes.clone(),
            start: now,
            current: 0,
            revoked: false,
        });
        if let Some(c) = self.codes.get_mut(&key) {
            c.state = RefCodeState::Redeemed(f);
        }
        self.issue(f, now)
    }

    fn refresh_grant(&mut self, p: &BTreeMap<String, String>, now: Micros) -> Reply {
        let (Some(token), Some(client_id)) = (p.get("refresh_token"), p.get("client_id")) else {
            return Reply::error(400, "invalid_request");
        };
        let Some(&(f, generation)) = self.refresh.get(&fstp_crypto::sha256(token.as_bytes()))
        else {
            return Reply::error(400, "invalid_grant");
        };
        let Some(fam) = self.families.get(f).cloned() else {
            return Reply::error(400, "invalid_grant");
        };
        if fam.revoked || &fam.client_id != client_id || now >= self.family_end(&fam) {
            return Reply::error(400, "invalid_grant");
        }
        if generation != fam.current {
            self.revoke_family(f);
            return Reply::error(400, "invalid_grant");
        }
        if let Some(s) = p.get("scope") {
            match RefServer::scopes_of(s) {
                Some(asked) if asked.iter().all(|a| fam.scopes.contains(a)) => {}
                _ => return Reply::error(400, "invalid_scope"),
            }
        }
        if let Some(r) = p.get("resource")
            && r != &self.cfg.resource
        {
            return Reply::error(400, "invalid_target");
        }
        if let Some(fam) = self.families.get_mut(f) {
            fam.current = fam.current.saturating_add(1);
        }
        self.issue(f, now)
    }

    fn bearer_value(header: &[u8]) -> Option<&str> {
        let s = std::str::from_utf8(header).ok()?;
        let (scheme, token) = s.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
            return None;
        }
        let body = token.trim_end_matches('=');
        let ok = !body.is_empty()
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
        ok.then_some(token)
    }

    fn challenge(&self, error: Option<&str>) -> Reply {
        let mut v = String::from("Bearer ");
        if let Some(e) = error {
            v.push_str(&format!("error=\"{e}\", "));
        }
        v.push_str(&format!(
            "resource_metadata=\"{}{PRM_PATH}\"",
            self.cfg.issuer
        ));
        let mut r = match error {
            Some(e) => Reply::error(if e == "invalid_request" { 400 } else { 401 }, e),
            None => Reply {
                status: 401,
                headers: Vec::new(),
                body: Vec::new(),
            },
        };
        r.headers.push(("WWW-Authenticate".to_owned(), v));
        r
    }
}

impl AuthServer for RefServer {
    fn register(
        &mut self,
        source: SourceKey,
        body: &[u8],
        now: Micros,
    ) -> Result<Reply, NotImplemented> {
        let window = self.cfg.registration_window_micros;
        let max = usize::try_from(self.cfg.registration_max).unwrap_or(usize::MAX);
        let seen = self.registrations.entry(source).or_default();
        seen.retain(|&t| t <= now && now.saturating_sub(t) < window);
        if seen.len() >= max {
            return Ok(Reply::error(429, "rate_limited"));
        }
        seen.push(now);
        let client = match RefServer::validate_metadata(body) {
            Ok(c) => c,
            Err(code) => return Ok(Reply::error(400, code)),
        };
        self.next_client = self.next_client.saturating_add(1);
        let id = format!("client-{}", self.next_client);
        let mut o = Object::new();
        o.insert("client_id", Value::from(id.as_str()));
        o.insert(
            "client_id_issued_at",
            Value::from(now.checked_div(1_000_000).unwrap_or(0)),
        );
        o.insert("redirect_uris", json_strings(&client.redirect_uris));
        if let Some(n) = &client.name {
            o.insert("client_name", Value::from(n.as_str()));
        }
        o.insert(
            "grant_types",
            json_strs(&["authorization_code", "refresh_token"]),
        );
        o.insert("response_types", json_strs(&["code"]));
        o.insert("token_endpoint_auth_method", Value::from("none"));
        self.clients.insert(id, client);
        Ok(Reply::json_reply(201, Value::Object(o)))
    }

    fn authorize(&mut self, query: &[u8], _: Micros) -> Result<AuthorizeReply, NotImplemented> {
        let refused = |code: &str| Ok(AuthorizeReply::Refused(Reply::error(400, code)));
        let Ok(p) = decode_unique(query) else {
            return refused("invalid_request");
        };
        let Some(client_id) = p.get("client_id") else {
            return refused("invalid_request");
        };
        let Some(client) = self.clients.get(client_id).cloned() else {
            return refused("invalid_client");
        };
        let Some(redirect) = p.get("redirect_uri") else {
            return refused("invalid_request");
        };
        if !client
            .redirect_uris
            .iter()
            .any(|r| redirect_matches(r, redirect))
        {
            return refused("invalid_request");
        }
        let state = p.get("state");
        if p.get("response_type").map(String::as_str) != Some("code") {
            return Ok(self.error_redirect(redirect, "unsupported_response_type", state));
        }
        let Some(challenge) = p.get("code_challenge") else {
            return Ok(self.error_redirect(redirect, "invalid_request", state));
        };
        if p.get("code_challenge_method").map(String::as_str) != Some("S256")
            || challenge.len() != 43
            || b64url_decode(challenge).is_none()
        {
            return Ok(self.error_redirect(redirect, "invalid_request", state));
        }
        if p.get("resource") != Some(&self.cfg.resource) {
            return Ok(self.error_redirect(redirect, "invalid_target", state));
        }
        let Some(scopes) = p.get("scope").and_then(|s| RefServer::scopes_of(s)) else {
            return Ok(self.error_redirect(redirect, "invalid_scope", state));
        };
        let mut t = RefTicket {
            client_id: client_id.clone(),
            redirect_uri: redirect.clone(),
            scopes,
            challenge: challenge.clone(),
            state: state.cloned(),
            digest: [0; 32],
        };
        t.digest = RefServer::consent_digest(&t);
        self.next_ticket = self.next_ticket.saturating_add(1);
        let handle = format!("ticket-{}", self.next_ticket).into_bytes();
        let ticket = ConsentTicket {
            handle: handle.clone(),
            digest: t.digest,
            client_name: client.name.clone(),
            redirect_host: host_of(redirect),
            scopes: t.scopes.clone(),
        };
        self.tickets.insert(handle, t);
        Ok(AuthorizeReply::Consent(ticket))
    }

    fn consent(
        &mut self,
        ticket: &ConsentTicket,
        account: AccountRef,
        auth: &ConsentAuth,
        now: Micros,
    ) -> Result<AuthorizeReply, NotImplemented> {
        let Some(t) = self.tickets.get(&ticket.handle).cloned() else {
            return Ok(AuthorizeReply::Refused(Reply::error(
                400,
                "invalid_request",
            )));
        };
        let fresh = auth.session == Method::PhishingResistant
            && auth.step_up.is_some_and(|p| {
                p.method == Method::PhishingResistant
                    && p.account == account
                    && p.digest == t.digest
                    && p.at <= now
                    && now.saturating_sub(p.at) < self.cfg.p71_micros
            });
        if !fresh {
            return Ok(AuthorizeReply::Refused(Reply::error(
                403,
                "step_up_required",
            )));
        }
        self.tickets.remove(&ticket.handle);
        let code = self.mint();
        self.codes.insert(
            fstp_crypto::sha256(code.as_bytes()),
            RefCode {
                client_id: t.client_id.clone(),
                account,
                redirect_uri: t.redirect_uri.clone(),
                scopes: t.scopes.clone(),
                challenge: t.challenge.clone(),
                issued: now,
                state: RefCodeState::Fresh,
            },
        );
        let mut loc = format!("{}?code={}", t.redirect_uri, pct(&code));
        if let Some(s) = &t.state {
            loc.push_str("&state=");
            loc.push_str(&pct(s));
        }
        loc.push_str("&iss=");
        loc.push_str(&pct(&self.cfg.issuer));
        Ok(AuthorizeReply::Redirect(loc))
    }

    fn token(&mut self, body: &[u8], now: Micros) -> Result<Reply, NotImplemented> {
        let Ok(p) = decode_unique(body) else {
            return Ok(Reply::error(400, "invalid_request"));
        };
        Ok(match p.get("grant_type").map(String::as_str) {
            Some("authorization_code") => self.code_grant(&p, now),
            Some("refresh_token") => self.refresh_grant(&p, now),
            Some(_) => Reply::error(400, "unsupported_grant_type"),
            None => Reply::error(400, "invalid_request"),
        })
    }

    fn revoke(&mut self, body: &[u8], _: Micros) -> Result<Reply, NotImplemented> {
        let Ok(p) = decode_unique(body) else {
            return Ok(Reply::error(400, "invalid_request"));
        };
        let Some(token) = p.get("token") else {
            return Ok(Reply::error(400, "invalid_request"));
        };
        let key = fstp_crypto::sha256(token.as_bytes());
        let client = p.get("client_id");
        if let Some(&(f, _)) = self.refresh.get(&key) {
            let owned = self
                .families
                .get(f)
                .is_some_and(|fam| client.is_none_or(|c| c == &fam.client_id));
            if owned {
                self.revoke_family(f);
            }
        } else if let Some(a) = self.access.get(&key).copied() {
            let owned = self
                .families
                .get(a.family)
                .is_some_and(|fam| client.is_none_or(|c| c == &fam.client_id));
            if owned && let Some(a) = self.access.get_mut(&key) {
                a.revoked = true;
            }
        }
        Ok(Reply {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }

    fn revoke_agent(
        &mut self,
        account: AccountRef,
        client_id: &str,
        _: Micros,
    ) -> Result<(), NotImplemented> {
        for fam in &mut self.families {
            if fam.account == account && fam.client_id == client_id {
                fam.revoked = true;
            }
        }
        for c in self.codes.values_mut() {
            if c.account == account && c.client_id == client_id && c.state == RefCodeState::Fresh {
                c.state = RefCodeState::Burned;
            }
        }
        Ok(())
    }

    fn resource(
        &mut self,
        authorization: Option<&[u8]>,
        resource: &str,
        now: Micros,
    ) -> Result<Access, NotImplemented> {
        let Some(header) = authorization else {
            return Ok(Access::Denied(self.challenge(None)));
        };
        let Some(token) = RefServer::bearer_value(header) else {
            return Ok(Access::Denied(self.challenge(Some("invalid_request"))));
        };
        let denied = Ok(Access::Denied(self.challenge(Some("invalid_token"))));
        let Some(a) = self
            .access
            .get(&fstp_crypto::sha256(token.as_bytes()))
            .copied()
        else {
            return denied;
        };
        let Some(fam) = self.families.get(a.family) else {
            return denied;
        };
        if a.revoked
            || fam.revoked
            || now >= a.expires
            || now >= self.family_end(fam)
            || resource != self.cfg.resource
        {
            return denied;
        }
        Ok(Access::Granted(GrantView {
            account: fam.account,
            client_id: fam.client_id.clone(),
            scopes: fam.scopes.clone(),
            audience: self.cfg.resource.clone(),
        }))
    }

    fn as_metadata(&mut self) -> Result<Reply, NotImplemented> {
        let i = self.cfg.issuer.clone();
        let mut o = Object::new();
        o.insert("issuer", Value::from(i.as_str()));
        for (k, path) in [
            ("authorization_endpoint", "/oauth/authorize"),
            ("token_endpoint", "/oauth/token"),
            ("registration_endpoint", "/oauth/register"),
            ("revocation_endpoint", "/oauth/revoke"),
        ] {
            o.insert(k, Value::from(format!("{i}{path}")));
        }
        o.insert("response_types_supported", json_strs(&["code"]));
        o.insert(
            "grant_types_supported",
            json_strs(&["authorization_code", "refresh_token"]),
        );
        o.insert("code_challenge_methods_supported", json_strs(&["S256"]));
        o.insert(
            "token_endpoint_auth_methods_supported",
            json_strs(&["none"]),
        );
        o.insert("scopes_supported", json_strs(&SCOPES));
        o.insert(
            "authorization_response_iss_parameter_supported",
            Value::from(true),
        );
        Ok(Reply::json_reply(200, Value::Object(o)))
    }

    fn resource_metadata(&mut self) -> Result<Reply, NotImplemented> {
        let mut o = Object::new();
        o.insert("resource", Value::from(self.cfg.resource.as_str()));
        o.insert(
            "authorization_servers",
            json_strs(&[self.cfg.issuer.as_str()]),
        );
        o.insert("bearer_methods_supported", json_strs(&["header"]));
        o.insert("scopes_supported", json_strs(&SCOPES));
        Ok(Reply::json_reply(200, Value::Object(o)))
    }
}

// ---------------------------------------------------------------------------
// Flow helpers for the tests
// ---------------------------------------------------------------------------

/// The tokens of a successful token reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSet {
    /// The access token.
    pub access: String,
    /// The refresh token.
    pub refresh: String,
    /// `expires_in`, in seconds.
    pub expires_in: i64,
}

/// The tokens of `reply`, which must be a 200 Bearer token reply.
pub fn tokens(reply: &Reply) -> Result<TokenSet, String> {
    if reply.status != 200 {
        return Err(format!(
            "token reply status {} ({:?})",
            reply.status,
            reply.error_code()
        ));
    }
    let v = reply.json()?;
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("token reply has no string {k}: {v}"))
    };
    if text("token_type")? != "Bearer" {
        return Err(format!("token_type is not Bearer: {v}"));
    }
    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("token reply has no integer expires_in: {v}"))?;
    Ok(TokenSet {
        access: text("access_token")?,
        refresh: text("refresh_token")?,
        expires_in,
    })
}

/// The parameters of an authorisation request. `None` leaves a parameter
/// out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizeParams {
    /// `response_type`.
    pub response_type: Option<String>,
    /// `client_id`.
    pub client_id: Option<String>,
    /// `redirect_uri`.
    pub redirect_uri: Option<String>,
    /// `code_challenge`.
    pub code_challenge: Option<String>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
    /// `resource`.
    pub resource: Option<String>,
    /// `state`.
    pub state: Option<String>,
}

impl AuthorizeParams {
    /// A valid request for `client_id` to `redirect`, with an `S256`
    /// challenge of `verifier`.
    pub fn valid(client_id: &str, redirect: &str, verifier: &str) -> AuthorizeParams {
        AuthorizeParams {
            response_type: Some("code".to_owned()),
            client_id: Some(client_id.to_owned()),
            redirect_uri: Some(redirect.to_owned()),
            code_challenge: Some(s256(verifier)),
            code_challenge_method: Some("S256".to_owned()),
            scope: Some(MODEL_SCOPE.to_owned()),
            resource: Some(MCP_URL.to_owned()),
            state: Some("st-1".to_owned()),
        }
    }

    /// The query.
    pub fn query(&self) -> Vec<u8> {
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        for (k, v) in [
            ("response_type", &self.response_type),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.code_challenge_method),
            ("scope", &self.scope),
            ("resource", &self.resource),
            ("state", &self.state),
        ] {
            if let Some(v) = v {
                pairs.push((k, v.as_str()));
            }
        }
        form(&pairs)
    }
}

/// The JSON body of a registration with these redirect URIs and name.
pub fn registration_body(redirect_uris: &[&str], name: Option<&str>) -> Vec<u8> {
    let mut o = Object::new();
    o.insert("redirect_uris", json_strs(redirect_uris));
    if let Some(n) = name {
        o.insert("client_name", Value::from(n));
    }
    o.insert(
        "grant_types",
        json_strs(&["authorization_code", "refresh_token"]),
    );
    o.insert("response_types", json_strs(&["code"]));
    o.insert("token_endpoint_auth_method", Value::from("none"));
    Value::Object(o).to_compact().into_bytes()
}

/// The `client_id` of a 201 registration reply.
pub fn client_id_of(reply: &Reply) -> Result<String, String> {
    if reply.status != 201 {
        return Err(format!(
            "registration status {} ({:?})",
            reply.status,
            reply.error_code()
        ));
    }
    reply
        .json()?
        .get("client_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "registration reply has no client_id".to_owned())
}

/// The code of a redirect to `redirect`, `Ok(None)` for a redirect with
/// no code, or why the location is not a redirect to `redirect`.
pub fn code_of(location: &str, redirect: &str) -> Result<Option<String>, String> {
    let Some(rest) = location.strip_prefix(redirect) else {
        return Err(format!("{location} is not a redirect to {redirect}"));
    };
    if !rest.starts_with('?') {
        return Err(format!("{location} adds more than a query to {redirect}"));
    }
    Ok(location_params(location)?.get("code").cloned())
}

/// The message of a stub refusal.
pub fn ni(e: NotImplemented) -> String {
    e.to_string()
}

/// A server with one registered client, as the tests drive it.
pub struct Harness {
    server: Box<dyn AuthServer>,
    /// The configuration.
    pub config: ServerConfig,
    /// The registered client.
    pub client_id: String,
    /// Its redirect URI.
    pub redirect: String,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Harness")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Harness {
    /// A server of `backend` with `config` and one client registered from
    /// [`SOURCE_A`] at `now` with `redirect_uris`. The first is the one the
    /// helpers use.
    pub fn with(
        backend: Backend,
        config: ServerConfig,
        redirect_uris: &[&str],
        now: Micros,
    ) -> Result<Harness, String> {
        let mut server = server(backend, &config);
        let reply = server
            .register(
                SOURCE_A,
                &registration_body(redirect_uris, Some("Synthetic agent")),
                now,
            )
            .map_err(ni)?;
        let client_id = client_id_of(&reply)?;
        let redirect = redirect_uris
            .first()
            .map(|s| (*s).to_owned())
            .ok_or_else(|| "no redirect URI".to_owned())?;
        Ok(Harness {
            server,
            config,
            client_id,
            redirect,
        })
    }

    /// [`Harness::with`] with the synthetic configuration, the model's
    /// redirect URI and the clock at 0.
    pub fn start(backend: Backend) -> Result<Harness, String> {
        Harness::with(backend, ServerConfig::synthetic(), &[MODEL_REDIRECT], 0)
    }

    /// The server.
    pub fn server(&mut self) -> &mut dyn AuthServer {
        self.server.as_mut()
    }

    /// A valid request with an `S256` challenge of `verifier`.
    pub fn params(&self, verifier: &str) -> AuthorizeParams {
        AuthorizeParams::valid(&self.client_id, &self.redirect, verifier)
    }

    /// Sends `p` to the authorisation endpoint.
    pub fn authorize(
        &mut self,
        p: &AuthorizeParams,
        now: Micros,
    ) -> Result<AuthorizeReply, String> {
        self.server.authorize(&p.query(), now).map_err(ni)
    }

    /// Approves `ticket` for `account` with a fresh passkey step-up.
    pub fn approve(
        &mut self,
        ticket: &ConsentTicket,
        account: AccountRef,
        now: Micros,
    ) -> Result<AuthorizeReply, String> {
        self.server
            .consent(
                ticket,
                account,
                &ConsentAuth::fresh(account, ticket, now),
                now,
            )
            .map_err(ni)
    }

    /// Authorises with `p`, approves with a fresh step-up, and returns the
    /// code.
    pub fn connect_with(
        &mut self,
        p: &AuthorizeParams,
        account: AccountRef,
        now: Micros,
    ) -> Result<String, String> {
        let AuthorizeReply::Consent(ticket) = self.authorize(p, now)? else {
            return Err("a valid authorisation request got no consent".to_owned());
        };
        match self.approve(&ticket, account, now)? {
            AuthorizeReply::Redirect(loc) => {
                let redirect = p.redirect_uri.clone().unwrap_or_default();
                code_of(&loc, &redirect)?.ok_or_else(|| format!("no code in {loc}"))
            }
            other => Err(format!("a fresh consent got {other:?}")),
        }
    }

    /// Authorises with a valid request for `verifier` and returns the code.
    pub fn connect(
        &mut self,
        verifier: &str,
        account: AccountRef,
        now: Micros,
    ) -> Result<String, String> {
        let p = self.params(verifier);
        self.connect_with(&p, account, now)
    }

    /// Exchanges `code` with `verifier`.
    pub fn exchange(
        &mut self,
        code: &str,
        verifier: Option<&str>,
        now: Micros,
    ) -> Result<Reply, String> {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect.as_str()),
            ("client_id", self.client_id.as_str()),
            ("resource", MCP_URL),
        ];
        if let Some(v) = verifier {
            pairs.push(("code_verifier", v));
        }
        let body = form(&pairs);
        self.server.token(&body, now).map_err(ni)
    }

    /// Refreshes with `token`.
    pub fn refresh(&mut self, token: &str, now: Micros) -> Result<Reply, String> {
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", self.client_id.as_str()),
            ("resource", MCP_URL),
        ]);
        self.server.token(&body, now).map_err(ni)
    }

    /// Revokes `token` through RFC 7009, hinting a refresh token.
    pub fn revoke(&mut self, token: &str, now: Micros) -> Result<Reply, String> {
        let body = form(&[
            ("token", token),
            ("token_type_hint", "refresh_token"),
            ("client_id", self.client_id.as_str()),
        ]);
        self.server.revoke(&body, now).map_err(ni)
    }

    /// Presents `access` at `resource`.
    pub fn bearer(&mut self, access: &str, resource: &str, now: Micros) -> Result<Access, String> {
        let header = format!("Bearer {access}");
        self.server
            .resource(Some(header.as_bytes()), resource, now)
            .map_err(ni)
    }

    /// Connects and exchanges: the tokens of a new family started at `now`.
    pub fn family(
        &mut self,
        verifier: &str,
        account: AccountRef,
        now: Micros,
    ) -> Result<TokenSet, String> {
        let code = self.connect(verifier, account, now)?;
        tokens(&self.exchange(&code, Some(verifier), now)?)
    }
}

/// `Ok` when `reply` refuses an authorisation request: no consent, and
/// either a refusal shown to the user or an error redirect to `redirect`
/// that carries no code.
pub fn refused_authorization(reply: &AuthorizeReply, redirect: &str) -> Result<(), String> {
    match reply {
        AuthorizeReply::Consent(t) => Err(format!("the request reached a consent: {t:?}")),
        AuthorizeReply::Refused(_) => Ok(()),
        AuthorizeReply::Redirect(loc) => {
            let Some(rest) = loc.strip_prefix(redirect) else {
                return Err(format!("an error redirect left the registered URI: {loc}"));
            };
            if !rest.starts_with('?') {
                return Err(format!(
                    "an error redirect changed the registered URI: {loc}"
                ));
            }
            let p = location_params(loc)?;
            if p.contains_key("code") {
                return Err(format!("a refused request got a code: {loc}"));
            }
            if !p.contains_key("error") {
                return Err(format!("an error redirect names no error: {loc}"));
            }
            Ok(())
        }
    }
}

/// `Ok` when `reply` refuses without sending the user agent anywhere, as
/// an unknown client or an unmatched redirect URI must (RFC 6749 section
/// 4.1.2.1).
pub fn refused_without_redirect(reply: &AuthorizeReply) -> Result<(), String> {
    match reply {
        AuthorizeReply::Refused(_) => Ok(()),
        other => Err(format!(
            "expected a refusal with no redirect, got {other:?}"
        )),
    }
}

/// A PKCE verifier of 43 to 128 unreserved characters.
pub fn gen_verifier(g: &mut fstp_prop::Gen) -> String {
    g.vec(43..=128, |g| char::from(*g.pick(UNRESERVED)))
        .into_iter()
        .collect()
}

/// A fixed valid verifier.
pub const VERIFIER: &str = "m-oauth-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
/// A second valid verifier, which never matches [`VERIFIER`]'s challenge.
pub const WRONG_VERIFIER: &str = "m-oauth-verifier-zyxwvutsrqponmlkjihgfedcba9876543210";

// ---------------------------------------------------------------------------
// M-OAUTH
// ---------------------------------------------------------------------------

/// The state count the model's first exhaustive run records, measured on
/// the reference backend on 2026-10-31 under [`BOUNDS`]. The run bound is
/// twice this.
pub const TRIPWIRE: usize = 17_503;

/// The bounds of the universe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bounds {
    /// Connections (codes) at most.
    pub codes: usize,
    /// Refresh tokens issued at most.
    pub refresh: usize,
    /// Clock moves at most.
    pub advances: u8,
}

/// The bounds of the exit run.
pub const BOUNDS: Bounds = Bounds {
    codes: 2,
    refresh: 2,
    advances: 2,
};

/// A fault the teeth test injects through the driver. None in the plain
/// model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// No fault.
    None,
    /// An adapter that accepts reuse: it sends the family's current refresh
    /// token in place of a rotated one, as a server that matched any token
    /// of the family would behave.
    AcceptReuse,
}

/// The PKCE verifier an exchange sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verifier {
    /// The verifier of the code's challenge.
    Right,
    /// Another valid verifier.
    Wrong,
}

/// How far the clock moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Advance {
    /// One code lifetime: every earlier code is dead.
    CodeLife,
    /// Half an access token lifetime.
    HalfAccess,
    /// P-72 less half an access lifetime: a family started at 0 nears its
    /// end, so a refresh issues a capped access token.
    NearFamilyEnd,
}

impl Advance {
    /// The clock move.
    pub const fn micros(self) -> i64 {
        match self {
            Advance::CodeLife => CODE_LIFETIME_MICROS,
            Advance::HalfAccess => ACCESS_LIFETIME_MICROS / 2,
            Advance::NearFamilyEnd => P72_ABSOLUTE_MICROS - ACCESS_LIFETIME_MICROS / 2,
        }
    }
}

/// One action of M-OAUTH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OauthAction {
    /// The agent authorises and the account consents with a fresh step-up.
    Connect,
    /// The agent exchanges code `k`.
    Exchange(u8, Verifier),
    /// The agent refreshes with refresh token `j`.
    Refresh(u8),
    /// The agent presents access token `i` at the MCP URL.
    Use(u8),
    /// The agent revokes refresh token `j` (RFC 7009).
    Revoke(u8),
    /// The account ends the agent (R-MC-03).
    RevokeAgent,
    /// The clock moves.
    Advance(Advance),
}

/// What a step gave, as the model compares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Obs {
    /// A code was issued.
    Code,
    /// No code was issued.
    NoCode,
    /// Tokens were issued.
    Tokens,
    /// A token request was refused.
    Refused,
    /// A resource request was granted.
    Granted,
    /// A resource request was denied.
    Denied,
    /// A revocation or clock move completed.
    Done,
}

/// What a code is in the abstract machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeState {
    /// Redeemable.
    Fresh,
    /// Never redeemable again, and issued no family.
    Burned,
    /// Redeemed once, into this family.
    Redeemed(u8),
}

/// A code of the abstract machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsCode {
    /// When it was issued.
    pub issued: i64,
    /// What it is.
    pub state: CodeState,
}

/// Why a family was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revocation {
    /// A rotated refresh token was reused.
    Reuse,
    /// Its code was redeemed a second time.
    CodeReplay,
    /// A refresh token of it was revoked (RFC 7009).
    Revoked,
    /// The account ended the agent (R-MC-03).
    Agent,
}

/// A refresh family of the abstract machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsFamily {
    /// When its code was redeemed.
    pub start: i64,
    /// Its current refresh token.
    pub current: u8,
    /// How often it rotated.
    pub rotations: u8,
    /// Why it was revoked, if it was.
    pub revoked: Option<Revocation>,
}

impl AbsFamily {
    /// When it ends (P-72).
    pub const fn end(&self) -> i64 {
        self.start.saturating_add(P72_ABSOLUTE_MICROS)
    }
}

/// An access token of the abstract machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsAccess {
    /// Its family.
    pub family: u8,
    /// When it was issued.
    pub issued: i64,
    /// When it expires.
    pub expires: i64,
}

/// The abstract machine's state, the second reference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Abs {
    /// The clock.
    pub now: i64,
    /// The clock moves made.
    pub advances: u8,
    /// Whether the account ended the agent.
    pub agent_revoked: bool,
    /// The codes, in issue order.
    pub codes: Vec<AbsCode>,
    /// The families, in start order.
    pub families: Vec<AbsFamily>,
    /// The family of each refresh token, in issue order.
    pub refresh: Vec<u8>,
    /// The access tokens, in issue order.
    pub access: Vec<AbsAccess>,
    /// What the last step gave, as the backend observed it.
    pub last: Option<Obs>,
}

fn idx(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

impl Abs {
    /// The family of refresh token `j`.
    pub fn family_of_refresh(&self, j: u8) -> Option<(u8, AbsFamily)> {
        let f = *self.refresh.get(usize::from(j))?;
        Some((f, *self.families.get(usize::from(f))?))
    }

    /// The family of access token `i`.
    pub fn family_of_access(&self, i: u8) -> Option<(AbsAccess, AbsFamily)> {
        let a = *self.access.get(usize::from(i))?;
        Some((a, *self.families.get(usize::from(a.family))?))
    }

    fn revoke(&mut self, f: u8, why: Revocation) {
        if let Some(fam) = self.families.get_mut(usize::from(f))
            && fam.revoked.is_none()
        {
            fam.revoked = Some(why);
        }
    }

    fn issue(&mut self, f: u8) {
        let Some(fam) = self.families.get(usize::from(f)).copied() else {
            return;
        };
        self.refresh.push(f);
        self.access.push(AbsAccess {
            family: f,
            issued: self.now,
            expires: self
                .now
                .saturating_add(ACCESS_LIFETIME_MICROS)
                .min(fam.end()),
        });
    }
}

/// One outcome the abstract machine admits, with the state after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The outcome.
    pub obs: Obs,
    /// The state after it.
    pub next: Abs,
}

fn only(obs: Obs, next: Abs) -> Vec<Admitted> {
    vec![Admitted { obs, next }]
}

/// The outcomes the abstract machine admits for `a` in `s` under `b`,
/// with the state after each, or `None` when the action is not enabled.
/// The first entry is the reference's choice.
pub fn admitted(s: &Abs, a: &OauthAction, b: Bounds) -> Option<Vec<Admitted>> {
    let mut n = s.clone();
    match *a {
        OauthAction::Connect => {
            if s.agent_revoked || s.codes.len() >= b.codes {
                return None;
            }
            n.codes.push(AbsCode {
                issued: s.now,
                state: CodeState::Fresh,
            });
            Some(only(Obs::Code, n))
        }
        OauthAction::Exchange(k, v) => {
            let code = *s.codes.get(usize::from(k))?;
            let set = |n: &mut Abs, st: CodeState| {
                if let Some(c) = n.codes.get_mut(usize::from(k)) {
                    c.state = st;
                }
            };
            match code.state {
                CodeState::Redeemed(f) => {
                    n.revoke(f, Revocation::CodeReplay);
                    Some(only(Obs::Refused, n))
                }
                CodeState::Burned => Some(only(Obs::Refused, n)),
                CodeState::Fresh => {
                    if s.now.saturating_sub(code.issued) >= CODE_LIFETIME_MICROS {
                        set(&mut n, CodeState::Burned);
                        return Some(only(Obs::Refused, n));
                    }
                    if v == Verifier::Wrong {
                        let kept = s.clone();
                        set(&mut n, CodeState::Burned);
                        return Some(vec![
                            Admitted {
                                obs: Obs::Refused,
                                next: n,
                            },
                            Admitted {
                                obs: Obs::Refused,
                                next: kept,
                            },
                        ]);
                    }
                    if s.refresh.len() >= b.refresh {
                        return None;
                    }
                    let f = idx(n.families.len());
                    n.families.push(AbsFamily {
                        start: s.now,
                        current: idx(n.refresh.len()),
                        rotations: 0,
                        revoked: None,
                    });
                    set(&mut n, CodeState::Redeemed(f));
                    n.issue(f);
                    Some(only(Obs::Tokens, n))
                }
            }
        }
        OauthAction::Refresh(j) => {
            let (f, fam) = s.family_of_refresh(j)?;
            if fam.revoked.is_some() || s.now >= fam.end() {
                return Some(only(Obs::Refused, n));
            }
            if j != fam.current {
                n.revoke(f, Revocation::Reuse);
                return Some(only(Obs::Refused, n));
            }
            if s.refresh.len() >= b.refresh {
                return None;
            }
            let next_current = idx(n.refresh.len());
            if let Some(fm) = n.families.get_mut(usize::from(f)) {
                fm.current = next_current;
                fm.rotations = fm.rotations.saturating_add(1);
            }
            n.issue(f);
            Some(only(Obs::Tokens, n))
        }
        OauthAction::Use(i) => {
            let (acc, fam) = s.family_of_access(i)?;
            let ok = fam.revoked.is_none() && s.now < acc.expires && s.now < fam.end();
            Some(only(if ok { Obs::Granted } else { Obs::Denied }, n))
        }
        OauthAction::Revoke(j) => {
            let (f, _) = s.family_of_refresh(j)?;
            n.revoke(f, Revocation::Revoked);
            Some(only(Obs::Done, n))
        }
        OauthAction::RevokeAgent => {
            if s.agent_revoked {
                return None;
            }
            n.agent_revoked = true;
            for f in 0..n.families.len() {
                n.revoke(idx(f), Revocation::Agent);
            }
            for c in &mut n.codes {
                if c.state == CodeState::Fresh {
                    c.state = CodeState::Burned;
                }
            }
            Some(only(Obs::Done, n))
        }
        OauthAction::Advance(adv) => {
            if s.advances >= b.advances {
                return None;
            }
            n.advances = n.advances.saturating_add(1);
            n.now = n.now.saturating_add(adv.micros());
            Some(only(Obs::Done, n))
        }
    }
}

/// A driver failure: a stub refused, or the backend answered off-profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriveError {
    /// A stub refused.
    Stub(NotImplemented),
    /// The backend's answer does not fit the profile.
    Protocol(String),
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriveError::Stub(e) => write!(f, "stub: {e}"),
            DriveError::Protocol(e) => write!(f, "protocol: {e}"),
        }
    }
}

impl From<NotImplemented> for DriveError {
    fn from(e: NotImplemented) -> DriveError {
        DriveError::Stub(e)
    }
}

fn protocol(e: impl Into<String>) -> DriveError {
    DriveError::Protocol(e.into())
}

/// The model's backend with its client registered, and the concrete codes
/// and tokens of each abstract index.
pub struct Driver {
    server: Box<dyn AuthServer>,
    client_id: String,
    now: Micros,
    codes: Vec<String>,
    refresh: Vec<String>,
    access: Vec<String>,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("client_id", &self.client_id)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

fn pick(items: &[String], i: u8) -> Result<String, DriveError> {
    items
        .get(usize::from(i))
        .cloned()
        .ok_or_else(|| protocol(format!("the driver holds no item {i}")))
}

impl Driver {
    /// A backend with the model's client registered at 0.
    pub fn start(backend: Backend) -> Result<Driver, DriveError> {
        let mut server = server(backend, &ServerConfig::synthetic());
        let reply = server.register(
            SOURCE_A,
            &registration_body(&[MODEL_REDIRECT], Some("Synthetic agent")),
            0,
        )?;
        let client_id = client_id_of(&reply).map_err(protocol)?;
        Ok(Driver {
            server,
            client_id,
            now: 0,
            codes: Vec::new(),
            refresh: Vec::new(),
            access: Vec::new(),
        })
    }

    fn token_outcome(&mut self, reply: &Reply) -> Result<Obs, DriveError> {
        match reply.status {
            200 => {
                let t = tokens(reply).map_err(protocol)?;
                self.access.push(t.access);
                self.refresh.push(t.refresh);
                Ok(Obs::Tokens)
            }
            400 | 401 => Ok(Obs::Refused),
            s => Err(protocol(format!("token endpoint answered {s}"))),
        }
    }

    /// Runs `a` from abstract state `before` with `fault`.
    pub fn run(&mut self, before: &Abs, a: &OauthAction, fault: Fault) -> Result<Obs, DriveError> {
        let now = self.now;
        match *a {
            OauthAction::Connect => {
                let p = AuthorizeParams::valid(&self.client_id, MODEL_REDIRECT, VERIFIER);
                let AuthorizeReply::Consent(ticket) = self.server.authorize(&p.query(), now)?
                else {
                    return Ok(Obs::NoCode);
                };
                let auth = ConsentAuth::fresh(MODEL_ACCOUNT, &ticket, now);
                match self.server.consent(&ticket, MODEL_ACCOUNT, &auth, now)? {
                    AuthorizeReply::Redirect(loc) => {
                        match code_of(&loc, MODEL_REDIRECT).map_err(protocol)? {
                            Some(code) => {
                                self.codes.push(code);
                                Ok(Obs::Code)
                            }
                            None => Ok(Obs::NoCode),
                        }
                    }
                    _ => Ok(Obs::NoCode),
                }
            }
            OauthAction::Exchange(k, v) => {
                let code = pick(&self.codes, k)?;
                let verifier = match v {
                    Verifier::Right => VERIFIER,
                    Verifier::Wrong => WRONG_VERIFIER,
                };
                let body = form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", MODEL_REDIRECT),
                    ("client_id", &self.client_id),
                    ("code_verifier", verifier),
                    ("resource", MCP_URL),
                ]);
                let reply = self.server.token(&body, now)?;
                self.token_outcome(&reply)
            }
            OauthAction::Refresh(j) => {
                let sent = match (fault, before.family_of_refresh(j)) {
                    (Fault::AcceptReuse, Some((_, fam))) => fam.current,
                    _ => j,
                };
                let token = pick(&self.refresh, sent)?;
                let body = form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &token),
                    ("client_id", &self.client_id),
                    ("resource", MCP_URL),
                ]);
                let reply = self.server.token(&body, now)?;
                self.token_outcome(&reply)
            }
            OauthAction::Use(i) => {
                let token = pick(&self.access, i)?;
                let header = format!("Bearer {token}");
                match self
                    .server
                    .resource(Some(header.as_bytes()), MCP_URL, now)?
                {
                    Access::Granted(g) => {
                        if g.account != MODEL_ACCOUNT
                            || g.client_id != self.client_id
                            || g.audience != MCP_URL
                        {
                            return Err(protocol(format!("a grant names another binding: {g:?}")));
                        }
                        Ok(Obs::Granted)
                    }
                    Access::Denied(r) if r.status == 401 => Ok(Obs::Denied),
                    Access::Denied(r) => Err(protocol(format!(
                        "a dead token got status {} instead of 401",
                        r.status
                    ))),
                }
            }
            OauthAction::Revoke(j) => {
                let token = pick(&self.refresh, j)?;
                let body = form(&[
                    ("token", &token),
                    ("token_type_hint", "refresh_token"),
                    ("client_id", &self.client_id),
                ]);
                let reply = self.server.revoke(&body, now)?;
                if reply.status == 200 {
                    Ok(Obs::Done)
                } else {
                    Err(protocol(format!("revocation answered {}", reply.status)))
                }
            }
            OauthAction::RevokeAgent => {
                self.server
                    .revoke_agent(MODEL_ACCOUNT, &self.client_id, now)?;
                Ok(Obs::Done)
            }
            OauthAction::Advance(adv) => {
                self.now = self.now.saturating_add(adv.micros());
                Ok(Obs::Done)
            }
        }
    }
}

/// One M-OAUTH state.
#[derive(Clone, Debug)]
pub struct OauthState {
    /// The abstract state.
    pub abs: Abs,
    /// The trace from genesis, with the outcome the backend gave at each
    /// step.
    pub trace: Vec<(OauthAction, Obs)>,
    /// The first disagreement between the backend and the abstract
    /// machine.
    pub divergence: Option<String>,
}

impl PartialEq for OauthState {
    fn eq(&self, other: &OauthState) -> bool {
        self.abs == other.abs && self.divergence == other.divergence
    }
}

impl Eq for OauthState {}

impl Hash for OauthState {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.abs.hash(h);
        self.divergence.hash(h);
    }
}

/// The M-OAUTH model.
#[derive(Debug)]
pub struct OauthModel {
    backend: Backend,
    fault: Fault,
    bounds: Bounds,
}

impl OauthModel {
    /// Builds the model on `backend`. A stub that refuses the setup gives
    /// its refusal.
    pub fn new(backend: Backend) -> Result<OauthModel, NotImplemented> {
        OauthModel::with_fault(backend, Fault::None)
    }

    /// Builds the model on `backend` with `fault` injected by the driver.
    pub fn with_fault(backend: Backend, fault: Fault) -> Result<OauthModel, NotImplemented> {
        if let Err(DriveError::Stub(e)) = Driver::start(backend) {
            return Err(e);
        }
        Ok(OauthModel {
            backend,
            fault,
            bounds: BOUNDS,
        })
    }

    /// Replays `trace` on a new backend and runs `a`.
    fn replay(&self, trace: &[(OauthAction, Obs)], a: &OauthAction) -> Result<Obs, String> {
        let mut d = Driver::start(self.backend).map_err(|e| e.to_string())?;
        let mut abs = Abs::default();
        for (step, seen) in trace {
            let got = d.run(&abs, step, self.fault).map_err(|e| e.to_string())?;
            if got != *seen {
                return Err(format!(
                    "the backend is not deterministic: {step:?} gave {got:?}, then {seen:?}"
                ));
            }
            let options = admitted(&abs, step, self.bounds)
                .ok_or_else(|| format!("{step:?} is not enabled on replay"))?;
            abs = options
                .into_iter()
                .find(|o| o.obs == got)
                .map(|o| o.next)
                .ok_or_else(|| format!("{step:?} gave {got:?} on replay"))?;
        }
        d.run(&abs, a, self.fault).map_err(|e| e.to_string())
    }
}

/// Every action for `s`, enabled or not.
fn candidates(s: &Abs, out: &mut Vec<OauthAction>) {
    out.push(OauthAction::Connect);
    for k in 0..s.codes.len() {
        out.push(OauthAction::Exchange(idx(k), Verifier::Right));
        out.push(OauthAction::Exchange(idx(k), Verifier::Wrong));
    }
    for j in 0..s.refresh.len() {
        out.push(OauthAction::Refresh(idx(j)));
        out.push(OauthAction::Revoke(idx(j)));
    }
    for i in 0..s.access.len() {
        out.push(OauthAction::Use(idx(i)));
    }
    out.push(OauthAction::RevokeAgent);
    for adv in [
        Advance::CodeLife,
        Advance::HalfAccess,
        Advance::NearFamilyEnd,
    ] {
        out.push(OauthAction::Advance(adv));
    }
}

impl Model for OauthModel {
    type State = OauthState;
    type Action = OauthAction;

    fn init(&self) -> Vec<OauthState> {
        vec![OauthState {
            abs: Abs::default(),
            trace: Vec::new(),
            divergence: None,
        }]
    }

    fn actions(&self, s: &OauthState, out: &mut Vec<OauthAction>) {
        if s.divergence.is_none() {
            candidates(&s.abs, out);
        }
    }

    fn step(&self, s: &OauthState, a: &OauthAction) -> Option<OauthState> {
        let options = admitted(&s.abs, a, self.bounds)?;
        let mut next = s.clone();
        match self.replay(&s.trace, a) {
            Ok(obs) => {
                next.trace.push((*a, obs));
                if let Some(o) = options.iter().find(|o| o.obs == obs) {
                    next.abs = o.next.clone();
                } else {
                    let first = options.first()?;
                    next.abs = first.next.clone();
                    next.divergence = Some(format!(
                        "{a:?}: the backend gave {obs:?}, the profile admits {:?}",
                        options.iter().map(|o| o.obs).collect::<Vec<_>>()
                    ));
                }
                next.abs.last = Some(obs);
            }
            Err(e) => {
                next.divergence = Some(format!("{a:?}: {e}"));
            }
        }
        Some(next)
    }
}

/// The M-OAUTH properties (design section 8.5, TH-61, ADR-013, P-72,
/// R-MC-03).
pub fn oauth_properties<'a>() -> Vec<Property<'a, OauthModel>> {
    vec![
        Property::<OauthModel>::always_with("TH-61", |s| match &s.divergence {
            None => Ok(()),
            Some(d) => Err(d.clone()),
        }),
        Property::<OauthModel>::transition("TH-61 revocation", |b, a, n| {
            let dead = |fam: &AbsFamily| fam.revoked.is_some();
            match *a {
                OauthAction::Use(i) => match b.abs.family_of_access(i) {
                    Some((_, fam)) if dead(&fam) => n.abs.last == Some(Obs::Denied),
                    _ => true,
                },
                OauthAction::Refresh(j) => match b.abs.family_of_refresh(j) {
                    Some((_, fam)) if dead(&fam) => n.abs.last == Some(Obs::Refused),
                    _ => true,
                },
                OauthAction::Exchange(..) | OauthAction::Connect if b.abs.agent_revoked => {
                    n.abs.access.len() == b.abs.access.len()
                }
                _ => true,
            }
        }),
        Property::<OauthModel>::always("TH-61 revocation", |s| {
            !s.abs.agent_revoked || s.abs.families.iter().all(|f| f.revoked.is_some())
        }),
        Property::<OauthModel>::transition("TH-61 reuse", |b, a, n| match *a {
            OauthAction::Refresh(j) => match b.abs.family_of_refresh(j) {
                Some((f, fam))
                    if fam.revoked.is_none() && b.abs.now < fam.end() && fam.current != j =>
                {
                    n.abs.last == Some(Obs::Refused)
                        && n.abs
                            .families
                            .get(usize::from(f))
                            .is_some_and(|x| x.revoked == Some(Revocation::Reuse))
                }
                _ => true,
            },
            _ => true,
        }),
        Property::<OauthModel>::always("ADR-013 single use", |s| {
            let redeemed: Vec<u8> = s
                .abs
                .codes
                .iter()
                .filter_map(|c| match c.state {
                    CodeState::Redeemed(f) => Some(f),
                    _ => None,
                })
                .collect();
            let distinct: BTreeSet<u8> = redeemed.iter().copied().collect();
            distinct.len() == redeemed.len() && redeemed.len() == s.abs.families.len()
        }),
        Property::<OauthModel>::transition("ADR-013 single use", |b, a, n| match *a {
            OauthAction::Exchange(k, _) => match b.abs.codes.get(usize::from(k)) {
                Some(c) if c.state != CodeState::Fresh => {
                    n.abs.last == Some(Obs::Refused) && n.abs.families.len() == b.abs.families.len()
                }
                _ => true,
            },
            _ => true,
        }),
        Property::<OauthModel>::transition("ADR-013 code lifetime", |b, a, n| match *a {
            OauthAction::Exchange(k, _) if n.abs.last == Some(Obs::Tokens) => b
                .abs
                .codes
                .get(usize::from(k))
                .is_some_and(|c| b.abs.now.saturating_sub(c.issued) < CODE_LIFETIME_MICROS),
            _ => true,
        }),
        Property::<OauthModel>::always("P-72", |s| {
            s.abs.access.iter().all(|a| {
                s.abs
                    .families
                    .get(usize::from(a.family))
                    .is_some_and(|f| a.expires <= f.end())
                    && a.expires <= a.issued.saturating_add(ACCESS_LIFETIME_MICROS)
            })
        }),
        Property::<OauthModel>::transition("P-72", |b, a, n| match *a {
            OauthAction::Use(i) if n.abs.last == Some(Obs::Granted) => b
                .abs
                .family_of_access(i)
                .is_some_and(|(acc, fam)| b.abs.now < acc.expires && b.abs.now < fam.end()),
            OauthAction::Refresh(j) if n.abs.last == Some(Obs::Tokens) => b
                .abs
                .family_of_refresh(j)
                .is_some_and(|(_, fam)| b.abs.now < fam.end()),
            _ => true,
        }),
        Property::<OauthModel>::reachable("TH-61 rotation", |s| {
            s.abs.families.iter().any(|f| f.rotations >= 1)
        }),
        Property::<OauthModel>::reachable("TH-61 reuse detection", |s| {
            s.abs
                .families
                .iter()
                .any(|f| f.revoked == Some(Revocation::Reuse))
        }),
        Property::<OauthModel>::reachable("P-72 cap", |s| {
            s.abs.access.iter().any(|a| {
                s.abs.now >= a.expires
                    && s.abs.now < a.issued.saturating_add(ACCESS_LIFETIME_MICROS)
                    && s.abs
                        .families
                        .get(usize::from(a.family))
                        .is_some_and(|f| f.revoked.is_none())
            })
        }),
    ]
}

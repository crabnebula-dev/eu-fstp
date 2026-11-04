//! The authorisation server state machine (ADR-013, design section 3.8).
//!
//! The server is sans-IO: each endpoint takes the request bytes and the
//! time, and returns the reply bytes. It keeps its records in memory. Every
//! code, token and consent handle is 256 bits from
//! [`fstp_crypto::random_bytes`]. The server stores only its SHA-256 hash,
//! under a label per kind, and compares hashes with
//! [`fstp_crypto::constant_time_eq`].
//!
//! The server learns an account by its raw id only, and no reply carries
//! it (I-86). It issues no identity token, offers no userinfo endpoint and
//! names no claim.

use std::collections::{BTreeMap, BTreeSet};

use fstp_json::{Object, Value};

use crate::OauthError;
use crate::b64::{decode_base64url, encode_base64url};
use crate::form::push_encoded;
use crate::metadata::decode_client_metadata;
use crate::request::{
    TokenRequest, decode_authorize_query, decode_revocation_request, decode_token_request,
    parse_bearer_header,
};
use crate::scope::{Scope, ScopeSet};
use crate::url::{Scheme, Url, parse_url, redirect_matches};

/// Microseconds on the server's clock.
pub type Micros = i64;

/// Codes are single use and live 60 seconds (ADR-013). A code is
/// redeemable while younger than this and dead at exactly this age.
pub const CODE_LIFETIME_MICROS: Micros = 60_000_000;
/// Access tokens live 10 minutes (ADR-013, Q25), and never past the end
/// of their family (P-72).
pub const ACCESS_LIFETIME_MICROS: Micros = 600_000_000;
/// A pending consent lives 10 minutes. Interim reading: ADR-013 states no
/// lifetime, and this one equals the access token's.
pub const CONSENT_LIFETIME_MICROS: Micros = 600_000_000;
/// The longest `state` the server echoes, in bytes.
pub const MAX_STATE_BYTES: usize = 1024;

/// The path of the authorisation endpoint.
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
/// The path of the token endpoint.
pub const TOKEN_PATH: &str = "/oauth/token";
/// The path of the registration endpoint (RFC 7591).
pub const REGISTER_PATH: &str = "/oauth/register";
/// The path of the revocation endpoint (RFC 7009).
pub const REVOKE_PATH: &str = "/oauth/revoke";
/// The path of the protected resource metadata (RFC 9728).
pub const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// The path of the authorisation server metadata (RFC 8414).
pub const SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

const LABEL_CODE: &[u8] = b"fstp-oauth code v1\0";
const LABEL_ACCESS: &[u8] = b"fstp-oauth access token v1\0";
const LABEL_REFRESH: &[u8] = b"fstp-oauth refresh token v1\0";
const LABEL_CONSENT: &[u8] = b"fstp-oauth consent handle v1\0";
const LABEL_DIGEST: &[u8] = b"fstp-oauth consent digest v1\0";

/// An account of the cell, by its raw id only (I-86).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Account(u64);

impl Account {
    /// The account with raw id `raw`.
    pub const fn from_raw(raw: u64) -> Account {
        Account(raw)
    }

    /// The raw id.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The cell's number for a registered client, the raw value of the API
/// core's `AgentClientId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientNumber(u64);

impl ClientNumber {
    /// The client number with raw value `raw`, as the API core's
    /// `AgentClientId` carries it.
    pub const fn from_raw(raw: u64) -> ClientNumber {
        ClientNumber(raw)
    }

    /// The raw number.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The key a registration is rate-limited by, such as a hash of the
/// connection's source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RateKey(u64);

impl RateKey {
    /// The key with raw value `raw`.
    pub const fn from_raw(raw: u64) -> RateKey {
        RateKey(raw)
    }
}

/// The session of [`AuthorizationServer::authorize`], shared by every
/// request that names none.
const ANONYMOUS_SESSION: RateKey = RateKey(u64::MAX);

/// The strength of a login or step-up (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Strength {
    /// A passkey or the EUDI Wallet.
    PhishingResistant,
    /// Any other method, such as an email magic link.
    NotPhishingResistant,
}

/// A login or step-up method (`authentication.md`). The API core maps its
/// own method onto this one, and reads it back from a [`Grant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoginMethod {
    /// A passkey.
    Passkey,
    /// An email magic link.
    MagicLink,
    /// OPAQUE.
    Opaque,
    /// The EUDI Wallet.
    EudiWallet,
}

impl LoginMethod {
    /// The strength of the method (I-77): a passkey and the EUDI Wallet
    /// are phishing-resistant, and no other method is.
    pub const fn strength(self) -> Strength {
        match self {
            LoginMethod::Passkey | LoginMethod::EudiWallet => Strength::PhishingResistant,
            LoginMethod::MagicLink | LoginMethod::Opaque => Strength::NotPhishingResistant,
        }
    }
}

/// A completed step-up, as the API core attests it (I-78).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpProof {
    /// The account that stepped up.
    pub account: Account,
    /// The consent digest the step-up is bound to.
    pub digest: [u8; 32],
    /// When it completed.
    pub at: Micros,
    /// The method used.
    pub method: LoginMethod,
}

/// How the user approves a consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentAuth {
    /// How the session approving logged in. The grant keeps this method,
    /// and its tokens inherit its strength.
    pub session: LoginMethod,
    /// The step-up taken for this consent.
    pub step_up: Option<StepUpProof>,
}

/// An HTTP reply of an endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The headers, in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Reply {
    /// The status, the header names and the body length only. A token
    /// reply holds live tokens, and no log may hold one (R-NF-02).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("headers", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Reply {
    fn json(status: u16, v: Value) -> Reply {
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
        Reply::json(status, Value::Object(o))
    }

    fn empty(status: u16) -> Reply {
        Reply {
            status,
            headers: vec![("Cache-Control".to_owned(), "no-store".to_owned())],
            body: Vec::new(),
        }
    }
}

/// A consent the user is asked for. The consent page shows the client
/// name as untrusted text with an "unverified" label, the redirect host and
/// every scope in fixed text (TW-8).
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    /// The handle the approval names. A secret of the user's browser.
    pub handle: String,
    /// The digest a step-up for this consent binds to (I-78).
    pub digest: [u8; 32],
    /// The client.
    pub client_id: String,
    /// The client's number.
    pub client: ClientNumber,
    /// The client name, untrusted and unverified.
    pub client_name: Option<String>,
    /// The host of the redirect URI.
    pub redirect_host: String,
    /// Whether the redirect goes to a loopback host on the user's device.
    pub loopback_redirect: bool,
    /// The scopes asked for.
    pub scopes: ScopeSet,
    /// When the consent expires.
    pub expires: Micros,
}

impl std::fmt::Debug for ConsentRequest {
    /// Never shows the handle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentRequest")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("redirect_host", &self.redirect_host)
            .field("scopes", &self.scopes)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// What the authorisation endpoint, or a consent decision, answers.
///
/// Only a decision of the user redirects. A request the endpoint refuses
/// is shown to the user and never sent on (TW-4).
#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// The user is asked to consent.
    Consent(ConsentRequest),
    /// The user agent goes to this location: the client's redirect URI,
    /// with a code or an error, after the user approved or denied.
    Redirect(String),
    /// The request is refused to the user, with no redirect.
    Refused(Reply),
}

/// The scheme, host and port of `loc`, with no path, query or code.
fn origin_of(loc: &str) -> &str {
    let start = loc.find("://").map_or(0, |i| i.saturating_add(3));
    let tail = loc.get(start..).unwrap_or("");
    let end = tail
        .find(['/', '?'])
        .map_or(loc.len(), |i| start.saturating_add(i));
    loc.get(..end).unwrap_or("")
}

impl std::fmt::Debug for AuthorizeOutcome {
    /// A redirect shows its origin only, since its query holds the code.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizeOutcome::Consent(c) => f.debug_tuple("Consent").field(c).finish(),
            AuthorizeOutcome::Redirect(loc) => f
                .debug_struct("Redirect")
                .field("origin", &origin_of(loc))
                .finish_non_exhaustive(),
            AuthorizeOutcome::Refused(r) => f.debug_tuple("Refused").field(r).finish(),
        }
    }
}

/// What a valid access token grants, as the API core reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The account that consented.
    pub account: Account,
    /// The client's number.
    pub client: ClientNumber,
    /// The client.
    pub client_id: String,
    /// The scopes of this token.
    pub scopes: ScopeSet,
    /// The audience, this cell's MCP URL.
    pub audience: String,
    /// The strength of the session that consented. The token inherits it.
    pub consent_strength: Strength,
    /// How the session that consented logged in.
    pub consent_method: LoginMethod,
    /// When the token expires.
    pub expires: Micros,
}

/// One live grant of an account, for the "My agents" page (R-MC-03). The
/// client name is untrusted text, shown with an "unverified" label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGrant {
    /// The client's number.
    pub client: ClientNumber,
    /// The client.
    pub client_id: String,
    /// The client name, untrusted and unverified.
    pub client_name: Option<String>,
    /// The scopes the account consented to.
    pub scopes: ScopeSet,
    /// When the grant started: the redemption of its code.
    pub start: Micros,
    /// When it ends at the latest (P-72).
    pub end: Micros,
    /// How the session that consented logged in.
    pub consent_method: LoginMethod,
}

/// The configuration of a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The issuer (RFC 8414): an origin with no path, such as
    /// `https://cell-a.example`.
    pub issuer: String,
    /// This cell's MCP URL, the only `resource` and the audience of every
    /// token (RFC 8707).
    pub resource: String,
    /// P-72, the absolute lifetime of a refresh family.
    pub p72_absolute_micros: Micros,
    /// P-71, the freshness of a step-up.
    pub p71_micros: Micros,
    /// Registrations admitted per rate key within one window.
    pub registration_max: u32,
    /// The registration rate-limit window.
    pub registration_window_micros: Micros,
    /// The most clients the server holds.
    pub max_clients: usize,
    /// How long a client with no consent, code or grant is kept after its
    /// registration. [`AuthorizationServer::purge`] drops it after that.
    pub client_grace_micros: Micros,
    /// The most pending consents per client. When a new one would pass
    /// it, the server evicts the oldest consent of the session that holds
    /// the most, but never a session's only consent: when every session
    /// holds one, a new session's request gets 503.
    pub max_consents_per_client: usize,
    /// The most pending consents per client and session. A new one evicts
    /// that session's oldest.
    pub max_consents_per_session: usize,
    /// The most refresh tokens a family issues. A refresh past it revokes
    /// the family, which bounds the retired tokens kept for reuse
    /// detection.
    pub max_refreshes_per_family: u32,
}

impl Config {
    /// A configuration with the interim defaults: 10 registrations per
    /// rate key per hour, at most 10 000 clients, an unused client kept 24
    /// hours, 16 pending consents per client and 4 per session, and 2048
    /// refreshes per family.
    pub fn new(
        issuer: &str,
        resource: &str,
        p72_absolute_micros: Micros,
        p71_micros: Micros,
    ) -> Config {
        Config {
            issuer: issuer.to_owned(),
            resource: resource.to_owned(),
            p72_absolute_micros,
            p71_micros,
            registration_max: 10,
            registration_window_micros: 3_600_000_000,
            max_clients: 10_000,
            client_grace_micros: 86_400_000_000,
            max_consents_per_client: 16,
            max_consents_per_session: 4,
            max_refreshes_per_family: 2048,
        }
    }
}

#[derive(Clone, Debug)]
struct Client {
    number: ClientNumber,
    redirect_uris: Vec<Url>,
    name: Option<String>,
    registered: Micros,
}

#[derive(Clone, Debug)]
struct Ticket {
    hash: [u8; 32],
    session: RateKey,
    client_id: String,
    redirect_uri: String,
    scopes: ScopeSet,
    challenge: String,
    state: Option<String>,
    digest: [u8; 32],
    created: Micros,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeState {
    Fresh,
    Burned,
    Redeemed(u64),
}

#[derive(Clone, Debug)]
struct Code {
    hash: [u8; 32],
    client_id: String,
    account: Account,
    redirect_uri: String,
    scopes: ScopeSet,
    challenge: String,
    issued: Micros,
    method: LoginMethod,
    state: CodeState,
}

#[derive(Clone, Debug)]
struct Family {
    client_id: String,
    client: ClientNumber,
    account: Account,
    scopes: ScopeSet,
    start: Micros,
    end: Micros,
    current: [u8; 32],
    refreshes: u32,
    revoked: bool,
    method: LoginMethod,
}

#[derive(Clone, Debug)]
struct RefreshRecord {
    hash: [u8; 32],
    family: u64,
}

#[derive(Clone, Debug)]
struct AccessRecord {
    hash: [u8; 32],
    family: u64,
    scopes: ScopeSet,
    expires: Micros,
    revoked: bool,
}

type Selector = [u8; 16];

fn selector(hash: &[u8; 32]) -> Selector {
    let mut s = [0u8; 16];
    for (d, b) in s.iter_mut().zip(hash.iter()) {
        *d = *b;
    }
    s
}

fn labelled(label: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(label);
    h.update(raw);
    h.finish()
}

/// The hash a 256-bit token spelt `text` is stored under, or `None` when
/// `text` is not 43 characters of base64url.
fn token_hash(label: &[u8], text: &str) -> Option<[u8; 32]> {
    if text.len() != 43 {
        return None;
    }
    let raw = decode_base64url(text.as_bytes()).ok()?;
    (raw.as_bytes().len() == 32).then(|| labelled(label, raw.as_bytes()))
}

fn mint_raw() -> Result<(String, [u8; 32]), OauthError> {
    let mut raw = [0u8; 32];
    fstp_crypto::random_bytes(&mut raw).map_err(|_| OauthError::Randomness)?;
    Ok((encode_base64url(&raw), raw))
}

/// Whether `v` is a PKCE verifier: 43 to 128 unreserved characters (RFC
/// 7636 section 4.1).
fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Whether `v` is the verifier of the `S256` challenge `challenge`.
fn pkce_ok(v: Option<&str>, challenge: &str) -> bool {
    match v {
        Some(v) if valid_verifier(v) => {
            let computed = encode_base64url(&fstp_crypto::sha256(v.as_bytes()));
            fstp_crypto::constant_time_eq(computed.as_bytes(), challenge.as_bytes())
        }
        _ => false,
    }
}

fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && decode_base64url(c.as_bytes()).is_ok_and(|b| b.as_bytes().len() == 32)
}

fn with_params(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = base.to_owned();
    let mut sep = if base.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        out.push(sep);
        sep = '&';
        out.push_str(k);
        out.push('=');
        push_encoded(&mut out, v);
    }
    out
}

fn len_prefixed(h: &mut fstp_crypto::Sha256, part: &[u8]) {
    h.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(part);
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(*s)).collect())
}

fn seconds(micros: Micros) -> i64 {
    micros.checked_div(1_000_000).unwrap_or(0)
}

/// The OAuth 2.1 authorisation server of one cell (ADR-013).
pub struct AuthorizationServer {
    cfg: Config,
    issuer: Url,
    clients: BTreeMap<String, Client>,
    numbers: BTreeMap<ClientNumber, String>,
    next_client: u64,
    registrations: BTreeMap<RateKey, Vec<Micros>>,
    tickets: BTreeMap<Selector, Ticket>,
    codes: BTreeMap<Selector, Code>,
    families: BTreeMap<u64, Family>,
    next_family: u64,
    refresh: BTreeMap<Selector, RefreshRecord>,
    access: BTreeMap<Selector, AccessRecord>,
}

impl std::fmt::Debug for AuthorizationServer {
    /// Counts only: no hash, handle or client name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationServer")
            .field("issuer", &self.cfg.issuer)
            .field("resource", &self.cfg.resource)
            .field("clients", &self.clients.len())
            .field("consents", &self.tickets.len())
            .field("codes", &self.codes.len())
            .field("families", &self.families.len())
            .field("access_tokens", &self.access.len())
            .finish_non_exhaustive()
    }
}

impl AuthorizationServer {
    /// A server with `cfg` and no client.
    ///
    /// The issuer must be an `https` origin with no path. The resource must
    /// be an `https` URL with no query. Lifetimes, the rate limit and the
    /// capacities must be positive. Loopback `http` is accepted for both,
    /// for test cells on one host.
    pub fn new(cfg: Config) -> Result<AuthorizationServer, OauthError> {
        let issuer = parse_url(cfg.issuer.as_bytes())
            .map_err(|_| OauthError::InvalidConfig("the issuer is outside the URL subset"))?;
        if !issuer.path_and_query().is_empty() {
            return Err(OauthError::InvalidConfig("the issuer has a path or query"));
        }
        let resource = parse_url(cfg.resource.as_bytes())
            .map_err(|_| OauthError::InvalidConfig("the resource is outside the URL subset"))?;
        if resource.has_query() {
            return Err(OauthError::InvalidConfig("the resource has a query"));
        }
        if issuer.scheme() == Scheme::Http && !issuer.is_loopback() {
            return Err(OauthError::InvalidConfig("the issuer is not https"));
        }
        if cfg.p72_absolute_micros <= 0
            || cfg.p71_micros <= 0
            || cfg.registration_max == 0
            || cfg.registration_window_micros <= 0
            || cfg.max_clients == 0
            || cfg.client_grace_micros <= 0
            || cfg.max_consents_per_client == 0
            || cfg.max_consents_per_session == 0
            || cfg.max_refreshes_per_family == 0
        {
            return Err(OauthError::InvalidConfig(
                "a lifetime, limit or capacity is not positive",
            ));
        }
        Ok(AuthorizationServer {
            cfg,
            issuer,
            clients: BTreeMap::new(),
            numbers: BTreeMap::new(),
            next_client: 0,
            registrations: BTreeMap::new(),
            tickets: BTreeMap::new(),
            codes: BTreeMap::new(),
            families: BTreeMap::new(),
            next_family: 0,
            refresh: BTreeMap::new(),
            access: BTreeMap::new(),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer.origin())
    }

    /// The URL of the protected resource metadata, which every 401
    /// challenge names (RFC 9728 section 5.1).
    pub fn resource_metadata_url(&self) -> String {
        self.endpoint(RESOURCE_METADATA_PATH)
    }

    // -----------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------

    /// `GET /.well-known/oauth-authorization-server` (RFC 8414). It offers
    /// `S256` only, the code and refresh grants only, public clients only,
    /// and the `iss` response parameter (RFC 9207). It names no identity
    /// claim and no userinfo endpoint (I-86).
    pub fn server_metadata(&self) -> Reply {
        let mut o = Object::new();
        o.insert("issuer", Value::from(self.cfg.issuer.as_str()));
        for (k, path) in [
            ("authorization_endpoint", AUTHORIZE_PATH),
            ("token_endpoint", TOKEN_PATH),
            ("registration_endpoint", REGISTER_PATH),
            ("revocation_endpoint", REVOKE_PATH),
        ] {
            o.insert(k, Value::from(self.endpoint(path)));
        }
        o.insert("response_types_supported", strings(&["code"]));
        o.insert(
            "grant_types_supported",
            strings(&["authorization_code", "refresh_token"]),
        );
        o.insert("code_challenge_methods_supported", strings(&["S256"]));
        o.insert("token_endpoint_auth_methods_supported", strings(&["none"]));
        o.insert(
            "revocation_endpoint_auth_methods_supported",
            strings(&["none"]),
        );
        let scopes: Vec<&str> = Scope::ALL.iter().map(|s| s.as_str()).collect();
        o.insert("scopes_supported", strings(&scopes));
        o.insert(
            "authorization_response_iss_parameter_supported",
            Value::from(true),
        );
        Reply::json(200, Value::Object(o))
    }

    /// `GET /.well-known/oauth-protected-resource` (RFC 9728).
    pub fn resource_metadata(&self) -> Reply {
        let mut o = Object::new();
        o.insert("resource", Value::from(self.cfg.resource.as_str()));
        o.insert(
            "authorization_servers",
            strings(&[self.cfg.issuer.as_str()]),
        );
        o.insert("bearer_methods_supported", strings(&["header"]));
        let scopes: Vec<&str> = Scope::ALL.iter().map(|s| s.as_str()).collect();
        o.insert("scopes_supported", strings(&scopes));
        Reply::json(200, Value::Object(o))
    }

    fn challenge(&self, status: u16, error: Option<&str>, scope: Option<ScopeSet>) -> Reply {
        let mut v = String::from("Bearer ");
        if let Some(e) = error {
            v.push_str(&format!("error=\"{e}\", "));
        }
        if let Some(s) = scope {
            v.push_str(&format!("scope=\"{}\", ", s.to_wire()));
        }
        v.push_str(&format!(
            "resource_metadata=\"{}\"",
            self.resource_metadata_url()
        ));
        let mut r = match error {
            Some(e) => Reply::error(status, e),
            None => Reply::empty(status),
        };
        r.headers.push(("WWW-Authenticate".to_owned(), v));
        r
    }

    /// The 403 reply for a token that lacks `needed` (RFC 6750 section
    /// 3.1), naming every scope the operation needs.
    pub fn insufficient_scope(&self, needed: ScopeSet) -> Reply {
        self.challenge(403, Some("insufficient_scope"), Some(needed))
    }

    // -----------------------------------------------------------------
    // Registration (RFC 7591)
    // -----------------------------------------------------------------

    /// `POST /oauth/register` from `source` (RFC 7591, ADR-013 Q8).
    ///
    /// Registration is open and rate-limited per source: within one window,
    /// a source gets at most `registration_max` attempts, refused ones
    /// included, and 429 after that. A client has no right until a
    /// consent. No URL in the metadata is ever fetched.
    pub fn register(&mut self, source: RateKey, body: &[u8], now: Micros) -> Reply {
        let window = self.cfg.registration_window_micros;
        let max = usize::try_from(self.cfg.registration_max).unwrap_or(usize::MAX);
        let seen = self.registrations.entry(source).or_default();
        seen.retain(|&t| t <= now && now.saturating_sub(t) < window);
        if seen.len() >= max {
            return Reply::error(429, "temporarily_unavailable");
        }
        seen.push(now);
        if self.clients.len() >= self.cfg.max_clients {
            return Reply::error(503, "temporarily_unavailable");
        }
        let meta = match decode_client_metadata(body) {
            Ok(m) => m,
            Err(OauthError::InvalidRedirectUri) => {
                return Reply::error(400, "invalid_redirect_uri");
            }
            Err(_) => return Reply::error(400, "invalid_client_metadata"),
        };
        let mut id = None;
        for _ in 0..4 {
            let mut raw = [0u8; 16];
            if fstp_crypto::random_bytes(&mut raw).is_err() {
                return Reply::error(500, "server_error");
            }
            let candidate = encode_base64url(&raw);
            if !self.clients.contains_key(&candidate) {
                id = Some(candidate);
                break;
            }
        }
        let Some(id) = id else {
            return Reply::error(500, "server_error");
        };
        self.next_client = self.next_client.saturating_add(1);
        let client = Client {
            number: ClientNumber(self.next_client),
            redirect_uris: meta.redirect_uris().to_vec(),
            name: meta.client_name().map(str::to_owned),
            registered: now,
        };
        let mut o = Object::new();
        o.insert("client_id", Value::from(id.as_str()));
        o.insert("client_id_issued_at", Value::from(seconds(now)));
        o.insert(
            "redirect_uris",
            Value::Array(
                client
                    .redirect_uris
                    .iter()
                    .map(|u| Value::from(u.as_str()))
                    .collect(),
            ),
        );
        if let Some(n) = &client.name {
            o.insert("client_name", Value::from(n.as_str()));
        }
        o.insert(
            "grant_types",
            strings(&["authorization_code", "refresh_token"]),
        );
        o.insert("response_types", strings(&["code"]));
        o.insert("token_endpoint_auth_method", Value::from("none"));
        self.numbers.insert(client.number, id.clone());
        self.clients.insert(id, client);
        Reply::json(201, Value::Object(o))
    }

    /// The number of the client `client_id`, if registered.
    pub fn client_number(&self, client_id: &str) -> Option<ClientNumber> {
        self.clients.get(client_id).map(|c| c.number)
    }

    /// The `client_id` of the client numbered `number`, if registered.
    pub fn client_id_of(&self, number: ClientNumber) -> Option<&str> {
        self.numbers.get(&number).map(String::as_str)
    }

    /// The live grants of `account` at `now`, one per family that is
    /// neither revoked nor past its end, oldest first (R-MC-03, the
    /// `agents.list` read).
    pub fn agents_of(&self, account: Account, now: Micros) -> Vec<AgentGrant> {
        self.families
            .values()
            .filter(|f| f.account == account && !f.revoked && f.start <= now && now < f.end)
            .map(|f| AgentGrant {
                client: f.client,
                client_id: f.client_id.clone(),
                client_name: self.clients.get(&f.client_id).and_then(|c| c.name.clone()),
                scopes: f.scopes,
                start: f.start,
                end: f.end,
                consent_method: f.method,
            })
            .collect()
    }

    // -----------------------------------------------------------------
    // Authorisation and consent
    // -----------------------------------------------------------------

    fn error_redirect(&self, redirect: &str, code: &str, state: Option<&str>) -> AuthorizeOutcome {
        let mut params = vec![("error", code)];
        if let Some(s) = state {
            params.push(("state", s));
        }
        params.push(("iss", self.cfg.issuer.as_str()));
        AuthorizeOutcome::Redirect(with_params(redirect, &params))
    }

    fn consent_digest(&self, t: &Ticket) -> [u8; 32] {
        let mut h = fstp_crypto::Sha256::new();
        h.update(LABEL_DIGEST);
        len_prefixed(&mut h, &t.hash);
        len_prefixed(&mut h, t.client_id.as_bytes());
        len_prefixed(&mut h, t.redirect_uri.as_bytes());
        len_prefixed(&mut h, t.scopes.to_wire().as_bytes());
        len_prefixed(&mut h, t.challenge.as_bytes());
        len_prefixed(&mut h, t.state.as_deref().unwrap_or("").as_bytes());
        len_prefixed(&mut h, self.cfg.resource.as_bytes());
        h.finish()
    }

    /// `GET /oauth/authorize` with this query, from one shared anonymous
    /// session. A shell that knows the browser session calls
    /// [`AuthorizationServer::authorize_from`] instead.
    pub fn authorize(&mut self, query: &[u8], now: Micros) -> AuthorizeOutcome {
        self.authorize_from(ANONYMOUS_SESSION, query, now)
    }

    /// `GET /oauth/authorize` with this query (OAuth 2.1 section 4.1.1),
    /// from the browser session keyed `session`.
    ///
    /// A valid request yields a consent for the user. Every other request
    /// is refused to the user with its OAuth error code and no redirect.
    /// Registration is open, so no registered redirect URI is trusted, and
    /// the endpoint never sends the user agent to one before the user acts
    /// (TW-4, RFC 9700 section 4.11.2). Only an approval or a denial
    /// redirects. The session key bounds the pending consents one session
    /// can hold or evict.
    pub fn authorize_from(
        &mut self,
        session: RateKey,
        query: &[u8],
        now: Micros,
    ) -> AuthorizeOutcome {
        let refused = |code: &str| AuthorizeOutcome::Refused(Reply::error(400, code));
        let Ok(req) = decode_authorize_query(query) else {
            return refused("invalid_request");
        };
        let Some(client_id) = req.client_id else {
            return refused("invalid_request");
        };
        let Some(client) = self.clients.get(&client_id).cloned() else {
            return refused("invalid_client");
        };
        let Some(redirect) = req.redirect_uri else {
            return refused("invalid_request");
        };
        let Ok(presented) = parse_url(redirect.as_bytes()) else {
            return refused("invalid_request");
        };
        if !client
            .redirect_uris
            .iter()
            .any(|r| redirect_matches(r, &presented))
        {
            return refused("invalid_request");
        }
        if req
            .state
            .as_ref()
            .is_some_and(|s| s.len() > MAX_STATE_BYTES)
        {
            return refused("invalid_request");
        }
        if req.response_type.as_deref() != Some("code") {
            return refused("unsupported_response_type");
        }
        let Some(challenge) = req.code_challenge else {
            return refused("invalid_request");
        };
        if req.code_challenge_method.as_deref() != Some("S256") || !valid_challenge(&challenge) {
            return refused("invalid_request");
        }
        if req.resource.as_deref() != Some(self.cfg.resource.as_str()) {
            return refused("invalid_target");
        }
        let Some(scopes) = req.scope.as_deref().and_then(ScopeSet::parse) else {
            return refused("invalid_scope");
        };
        let Ok((handle, raw)) = mint_raw() else {
            return AuthorizeOutcome::Refused(Reply::error(500, "server_error"));
        };
        let state = req.state;
        let hash = labelled(LABEL_CONSENT, &raw);
        let mut ticket = Ticket {
            hash,
            session,
            client_id: client_id.clone(),
            redirect_uri: redirect,
            scopes,
            challenge,
            state,
            digest: [0; 32],
            created: now,
        };
        ticket.digest = self.consent_digest(&ticket);
        if !self.make_room_for_consent(&client_id, session, now) {
            return AuthorizeOutcome::Refused(Reply::error(503, "temporarily_unavailable"));
        }
        let request = ConsentRequest {
            handle,
            digest: ticket.digest,
            client_id,
            client: client.number,
            client_name: client.name.clone(),
            redirect_host: presented.host().to_owned(),
            loopback_redirect: presented.is_loopback(),
            scopes,
            expires: now.saturating_add(CONSENT_LIFETIME_MICROS),
        };
        self.tickets.insert(selector(&hash), ticket);
        AuthorizeOutcome::Consent(request)
    }

    fn ticket_live(t: &Ticket, now: Micros) -> bool {
        (0..CONSENT_LIFETIME_MICROS).contains(&now.saturating_sub(t.created))
    }

    /// Makes room for one more pending consent of `client_id` from
    /// `session`, or returns `false` when there is none to make. A session
    /// past its own cap loses its oldest consent. A client past its cap
    /// loses the oldest consent of the session that holds the most, the
    /// asking session first on a tie. Another session is evicted only when
    /// it holds at least two, so it keeps its newest. When every other
    /// session holds one and the asking session none, the request is
    /// refused instead, and no session's newest consent is ever evicted
    /// by another session.
    fn make_room_for_consent(&mut self, client_id: &str, session: RateKey, now: Micros) -> bool {
        self.tickets.retain(|_, t| Self::ticket_live(t, now));
        let mut mine: Vec<(Micros, Selector, RateKey)> = self
            .tickets
            .iter()
            .filter(|(_, t)| t.client_id == client_id)
            .map(|(k, t)| (t.created, *k, t.session))
            .collect();
        mine.sort();
        let session_cap = self.cfg.max_consents_per_session.saturating_sub(1);
        let client_cap = self.cfg.max_consents_per_client.saturating_sub(1);
        loop {
            let mut held: BTreeMap<RateKey, usize> = BTreeMap::new();
            for (_, _, s) in &mine {
                let n = held.entry(*s).or_default();
                *n = n.saturating_add(1);
            }
            let own = held.get(&session).copied().unwrap_or(0);
            let victim = if own > session_cap {
                Some(session)
            } else if mine.len() > client_cap {
                let most = held.values().copied().max().unwrap_or(0);
                if own > 0 && own == most {
                    Some(session)
                } else if most >= 2 {
                    mine.iter()
                        .map(|(_, _, s)| *s)
                        .find(|s| held.get(s).copied() == Some(most))
                } else {
                    return false;
                }
            } else {
                None
            };
            let Some(victim) = victim else {
                return true;
            };
            let Some(pos) = mine.iter().position(|(_, _, s)| *s == victim) else {
                return false;
            };
            let (_, key, _) = mine.remove(pos);
            self.tickets.remove(&key);
        }
    }

    fn find_ticket(&self, handle: &str) -> Option<(Selector, Ticket)> {
        let hash = token_hash(LABEL_CONSENT, handle)?;
        let key = selector(&hash);
        let t = self.tickets.get(&key)?;
        fstp_crypto::constant_time_eq(&t.hash, &hash).then(|| (key, t.clone()))
    }

    fn step_up_fresh(&self, t: &Ticket, account: Account, auth: &ConsentAuth, now: Micros) -> bool {
        auth.session.strength() == Strength::PhishingResistant
            && auth.step_up.is_some_and(|p| {
                p.method.strength() == Strength::PhishingResistant
                    && p.account == account
                    && fstp_crypto::constant_time_eq(&p.digest, &t.digest)
                    && p.at <= now
                    && now.saturating_sub(p.at) < self.cfg.p71_micros
            })
    }

    /// The user's approval of the consent `handle`, after the API core's
    /// checks.
    ///
    /// Approving links a device, so it needs a step-up (I-78). The server
    /// checks the proof itself, as defence in depth: a phishing-resistant
    /// session and a phishing-resistant step-up by the same account, bound
    /// to this consent's digest and younger than P-71. Otherwise it answers
    /// 403 `step_up_required` and keeps the consent for a retry. An
    /// approval issues a single-use code to the redirect URI, with the
    /// `state` and the `iss` parameter (RFC 9207).
    pub fn approve(
        &mut self,
        handle: &str,
        account: Account,
        auth: &ConsentAuth,
        now: Micros,
    ) -> AuthorizeOutcome {
        let refused =
            |status: u16, code: &str| AuthorizeOutcome::Refused(Reply::error(status, code));
        let Some((key, t)) = self.find_ticket(handle) else {
            return refused(400, "invalid_request");
        };
        if !Self::ticket_live(&t, now) || !self.clients.contains_key(&t.client_id) {
            self.tickets.remove(&key);
            return refused(400, "invalid_request");
        }
        if !self.step_up_fresh(&t, account, auth, now) {
            return refused(403, "step_up_required");
        }
        let mut minted = None;
        for _ in 0..4 {
            let Ok((code, raw)) = mint_raw() else {
                break;
            };
            let hash = labelled(LABEL_CODE, &raw);
            if !self.codes.contains_key(&selector(&hash)) {
                minted = Some((code, hash));
                break;
            }
        }
        let Some((code, hash)) = minted else {
            return refused(500, "server_error");
        };
        self.tickets.remove(&key);
        self.codes.insert(
            selector(&hash),
            Code {
                hash,
                client_id: t.client_id.clone(),
                account,
                redirect_uri: t.redirect_uri.clone(),
                scopes: t.scopes,
                challenge: t.challenge.clone(),
                issued: now,
                method: auth.session,
                state: CodeState::Fresh,
            },
        );
        let mut params = vec![("code", code.as_str())];
        if let Some(s) = &t.state {
            params.push(("state", s.as_str()));
        }
        params.push(("iss", self.cfg.issuer.as_str()));
        AuthorizeOutcome::Redirect(with_params(&t.redirect_uri, &params))
    }

    /// The user's refusal of the consent `handle`: the client gets
    /// `access_denied` at its redirect URI.
    pub fn deny(&mut self, handle: &str, now: Micros) -> AuthorizeOutcome {
        let Some((key, t)) = self.find_ticket(handle) else {
            return AuthorizeOutcome::Refused(Reply::error(400, "invalid_request"));
        };
        self.tickets.remove(&key);
        if !Self::ticket_live(&t, now) {
            return AuthorizeOutcome::Refused(Reply::error(400, "invalid_request"));
        }
        self.error_redirect(&t.redirect_uri, "access_denied", t.state.as_deref())
    }

    // -----------------------------------------------------------------
    // Token endpoint
    // -----------------------------------------------------------------

    /// `POST /oauth/token` with this form body (OAuth 2.1 section 3.2).
    ///
    /// Only the authorisation code and refresh grants exist. A code
    /// redeems once, while younger than 60 seconds, with the verifier of
    /// its `S256` challenge, by its client, to its redirect URI. Any failed
    /// redemption of a fresh code burns it. A second redemption of a
    /// redeemed code revokes the family the first one started. A refresh
    /// rotates the refresh token. Presenting a rotated one revokes the
    /// family. No family outlives P-72 from its code's redemption.
    pub fn token(&mut self, body: &[u8], now: Micros) -> Reply {
        match decode_token_request(body) {
            Err(OauthError::UnsupportedGrantType) => Reply::error(400, "unsupported_grant_type"),
            Err(_) => Reply::error(400, "invalid_request"),
            Ok(TokenRequest::AuthorizationCode {
                code,
                client_id,
                redirect_uri,
                code_verifier,
                resource,
            }) => self.code_grant(
                &code,
                &client_id,
                redirect_uri.as_deref(),
                code_verifier.as_deref(),
                resource.as_deref(),
                now,
            ),
            Ok(TokenRequest::RefreshToken {
                refresh_token,
                client_id,
                scope,
                resource,
            }) => self.refresh_grant(
                &refresh_token,
                &client_id,
                scope.as_deref(),
                resource.as_deref(),
                now,
            ),
        }
    }

    fn revoke_family(&mut self, f: u64) {
        if let Some(fam) = self.families.get_mut(&f) {
            fam.revoked = true;
        }
    }

    fn code_grant(
        &mut self,
        code: &str,
        client_id: &str,
        redirect_uri: Option<&str>,
        verifier: Option<&str>,
        resource: Option<&str>,
        now: Micros,
    ) -> Reply {
        if !self.clients.contains_key(client_id) {
            return Reply::error(401, "invalid_client");
        }
        let Some(hash) = token_hash(LABEL_CODE, code) else {
            return Reply::error(400, "invalid_grant");
        };
        let key = selector(&hash);
        let Some(c) = self.codes.get(&key).cloned() else {
            return Reply::error(400, "invalid_grant");
        };
        if !fstp_crypto::constant_time_eq(&c.hash, &hash) {
            return Reply::error(400, "invalid_grant");
        }
        match c.state {
            CodeState::Redeemed(f) => {
                self.revoke_family(f);
                return Reply::error(400, "invalid_grant");
            }
            CodeState::Burned => return Reply::error(400, "invalid_grant"),
            CodeState::Fresh => {}
        }
        let alive = (0..CODE_LIFETIME_MICROS).contains(&now.saturating_sub(c.issued));
        let failure = if c.client_id != client_id || !alive {
            Some("invalid_grant")
        } else if redirect_uri.is_none() {
            Some("invalid_request")
        } else if redirect_uri != Some(c.redirect_uri.as_str()) {
            Some("invalid_grant")
        } else if resource.is_some_and(|r| r != self.cfg.resource) {
            Some("invalid_target")
        } else if !pkce_ok(verifier, &c.challenge) {
            Some("invalid_grant")
        } else {
            None
        };
        if let Some(code) = failure {
            if let Some(stored) = self.codes.get_mut(&key) {
                stored.state = CodeState::Burned;
            }
            return Reply::error(400, code);
        }
        let Some(number) = self.clients.get(client_id).map(|cl| cl.number) else {
            return Reply::error(401, "invalid_client");
        };
        let f = self.next_family;
        self.next_family = self.next_family.saturating_add(1);
        self.families.insert(
            f,
            Family {
                client_id: c.client_id.clone(),
                client: number,
                account: c.account,
                scopes: c.scopes,
                start: now,
                end: now.saturating_add(self.cfg.p72_absolute_micros),
                current: [0; 32],
                refreshes: 0,
                revoked: false,
                method: c.method,
            },
        );
        match self.issue(f, c.scopes, now) {
            Ok(reply) => {
                if let Some(stored) = self.codes.get_mut(&key) {
                    stored.state = CodeState::Redeemed(f);
                }
                reply
            }
            Err(_) => {
                self.families.remove(&f);
                Reply::error(500, "server_error")
            }
        }
    }

    fn refresh_grant(
        &mut self,
        token: &str,
        client_id: &str,
        scope: Option<&str>,
        resource: Option<&str>,
        now: Micros,
    ) -> Reply {
        if !self.clients.contains_key(client_id) {
            return Reply::error(401, "invalid_client");
        }
        let Some(hash) = token_hash(LABEL_REFRESH, token) else {
            return Reply::error(400, "invalid_grant");
        };
        let Some(rec) = self.refresh.get(&selector(&hash)) else {
            return Reply::error(400, "invalid_grant");
        };
        if !fstp_crypto::constant_time_eq(&rec.hash, &hash) {
            return Reply::error(400, "invalid_grant");
        }
        let f = rec.family;
        let Some(fam) = self.families.get(&f) else {
            return Reply::error(400, "invalid_grant");
        };
        if fam.revoked || now >= fam.end || fam.client_id != client_id {
            return Reply::error(400, "invalid_grant");
        }
        if !fstp_crypto::constant_time_eq(&fam.current, &hash) {
            self.revoke_family(f);
            return Reply::error(400, "invalid_grant");
        }
        if fam.refreshes >= self.cfg.max_refreshes_per_family {
            self.revoke_family(f);
            return Reply::error(400, "invalid_grant");
        }
        let scopes = match scope {
            None => fam.scopes,
            Some(s) => match ScopeSet::parse(s) {
                Some(asked) if asked.is_subset(fam.scopes) => asked,
                _ => return Reply::error(400, "invalid_scope"),
            },
        };
        if resource.is_some_and(|r| r != self.cfg.resource) {
            return Reply::error(400, "invalid_target");
        }
        match self.issue(f, scopes, now) {
            Ok(reply) => {
                if let Some(fam) = self.families.get_mut(&f) {
                    fam.refreshes = fam.refreshes.saturating_add(1);
                }
                reply
            }
            Err(_) => Reply::error(500, "server_error"),
        }
    }

    fn mint_unique(&self, label: &[u8], refresh: bool) -> Result<(String, [u8; 32]), OauthError> {
        for _ in 0..4 {
            let (text, raw) = mint_raw()?;
            let hash = labelled(label, &raw);
            let taken = if refresh {
                self.refresh.contains_key(&selector(&hash))
            } else {
                self.access.contains_key(&selector(&hash))
            };
            if !taken {
                return Ok((text, hash));
            }
        }
        Err(OauthError::Randomness)
    }

    /// Issues a new refresh token, which becomes the family's current one,
    /// and an access token with `scopes`.
    fn issue(&mut self, f: u64, scopes: ScopeSet, now: Micros) -> Result<Reply, OauthError> {
        let end = self
            .families
            .get(&f)
            .map(|fam| fam.end)
            .ok_or(OauthError::Randomness)?;
        let (refresh, refresh_hash) = self.mint_unique(LABEL_REFRESH, true)?;
        let (access, access_hash) = self.mint_unique(LABEL_ACCESS, false)?;
        let expires = now.saturating_add(ACCESS_LIFETIME_MICROS).min(end);
        if let Some(fam) = self.families.get_mut(&f) {
            fam.current = refresh_hash;
        }
        self.refresh.insert(
            selector(&refresh_hash),
            RefreshRecord {
                hash: refresh_hash,
                family: f,
            },
        );
        self.access.insert(
            selector(&access_hash),
            AccessRecord {
                hash: access_hash,
                family: f,
                scopes,
                expires,
                revoked: false,
            },
        );
        let mut o = Object::new();
        o.insert("access_token", Value::from(access.as_str()));
        o.insert("token_type", Value::from("Bearer"));
        o.insert(
            "expires_in",
            Value::from(seconds(expires.saturating_sub(now).max(0))),
        );
        o.insert("refresh_token", Value::from(refresh.as_str()));
        o.insert("scope", Value::from(scopes.to_wire()));
        Ok(Reply::json(200, Value::Object(o)))
    }

    // -----------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------

    /// `POST /oauth/revoke` (RFC 7009) with this form body.
    ///
    /// A refresh token of the client revokes its whole family. An access
    /// token of the client revokes that token. Either takes effect at once
    /// (R-MC-03). An unknown token, or one of another client, changes
    /// nothing and still gets 200, as RFC 7009 section 2.2 requires.
    pub fn revoke(&mut self, body: &[u8], _now: Micros) -> Reply {
        let Ok(req) = decode_revocation_request(body) else {
            return Reply::error(400, "invalid_request");
        };
        if !self.clients.contains_key(&req.client_id) {
            return Reply::error(401, "invalid_client");
        }
        if let Some(hash) = token_hash(LABEL_REFRESH, &req.token)
            && let Some(rec) = self.refresh.get(&selector(&hash))
            && fstp_crypto::constant_time_eq(&rec.hash, &hash)
        {
            let f = rec.family;
            if self
                .families
                .get(&f)
                .is_some_and(|fam| fam.client_id == req.client_id)
            {
                self.revoke_family(f);
            }
        } else if let Some(hash) = token_hash(LABEL_ACCESS, &req.token) {
            let key = selector(&hash);
            let owned = self.access.get(&key).is_some_and(|a| {
                fstp_crypto::constant_time_eq(&a.hash, &hash)
                    && self
                        .families
                        .get(&a.family)
                        .is_some_and(|fam| fam.client_id == req.client_id)
            });
            if owned && let Some(a) = self.access.get_mut(&key) {
                a.revoked = true;
            }
        }
        Reply::empty(200)
    }

    /// `POST /api/v1/me/agents/{client}/revocation` (R-MC-03), after the
    /// API core's checks: ends every family and every unredeemed code of
    /// `client_id` for `account`, at once. Returns how many families it
    /// revoked.
    pub fn revoke_agent(&mut self, account: Account, client_id: &str, _now: Micros) -> usize {
        let mut n = 0usize;
        for fam in self.families.values_mut() {
            if fam.account == account && fam.client_id == client_id && !fam.revoked {
                fam.revoked = true;
                n = n.saturating_add(1);
            }
        }
        for c in self.codes.values_mut() {
            if c.account == account && c.client_id == client_id && c.state == CodeState::Fresh {
                c.state = CodeState::Burned;
            }
        }
        n
    }

    /// [`AuthorizationServer::revoke_agent`] for the client numbered
    /// `client`, as the API core's `Tokens::revoke` names it. An unknown
    /// number revokes nothing.
    pub fn revoke_agent_by_number(
        &mut self,
        account: Account,
        client: ClientNumber,
        now: Micros,
    ) -> usize {
        match self.numbers.get(&client).cloned() {
            Some(id) => self.revoke_agent(account, &id, now),
            None => 0,
        }
    }

    // -----------------------------------------------------------------
    // Protected resource requests
    // -----------------------------------------------------------------

    /// Validates the `Authorization` header of a request to `resource`
    /// (OAuth 2.1 section 5.2, RFC 8707, ADR-013).
    ///
    /// A missing header gets 401 with a `Bearer` challenge naming the
    /// protected resource metadata (RFC 9728 section 5.1). A malformed one
    /// gets 400 `invalid_request`. A token that is unknown, revoked,
    /// expired, past its family's end or presented at another resource
    /// gets 401 `invalid_token`. Roles are not judged here: the API core
    /// re-evaluates them on every call.
    pub fn authenticate(
        &self,
        authorization: Option<&[u8]>,
        resource: &str,
        now: Micros,
    ) -> Result<Grant, Reply> {
        let Some(header) = authorization else {
            return Err(self.challenge(401, None, None));
        };
        let Ok(bearer) = parse_bearer_header(header) else {
            return Err(self.challenge(400, Some("invalid_request"), None));
        };
        let invalid = || self.challenge(401, Some("invalid_token"), None);
        let hash = token_hash(LABEL_ACCESS, bearer.as_str()).ok_or_else(invalid)?;
        let rec = self.access.get(&selector(&hash)).ok_or_else(invalid)?;
        if !fstp_crypto::constant_time_eq(&rec.hash, &hash) {
            return Err(invalid());
        }
        let fam = self.families.get(&rec.family).ok_or_else(invalid)?;
        if rec.revoked
            || fam.revoked
            || now >= rec.expires
            || now >= fam.end
            || now < fam.start
            || resource != self.cfg.resource
        {
            return Err(invalid());
        }
        Ok(Grant {
            account: fam.account,
            client: fam.client,
            client_id: fam.client_id.clone(),
            scopes: rec.scopes,
            audience: self.cfg.resource.clone(),
            consent_strength: fam.method.strength(),
            consent_method: fam.method,
            expires: rec.expires,
        })
    }

    // -----------------------------------------------------------------
    // Housekeeping
    // -----------------------------------------------------------------

    /// Drops records that can no longer change any answer at `now`:
    /// expired consents, expired codes that redeemed nothing, expired
    /// access tokens, families past P-72 with their tokens and codes,
    /// registration attempts outside the window, and clients older than
    /// the grace period that hold no consent, code or family. The shell
    /// calls it periodically.
    pub fn purge(&mut self, now: Micros) {
        self.tickets.retain(|_, t| Self::ticket_live(t, now));
        self.access.retain(|_, a| now < a.expires);
        self.families.retain(|_, f| now < f.end);
        let families = &self.families;
        self.refresh.retain(|_, r| families.contains_key(&r.family));
        self.codes.retain(|_, c| match c.state {
            CodeState::Redeemed(f) => families.contains_key(&f),
            CodeState::Fresh | CodeState::Burned => {
                now.saturating_sub(c.issued) < CODE_LIFETIME_MICROS
            }
        });
        let window = self.cfg.registration_window_micros;
        for seen in self.registrations.values_mut() {
            seen.retain(|&t| t <= now && now.saturating_sub(t) < window);
        }
        self.registrations.retain(|_, seen| !seen.is_empty());
        let mut held: BTreeSet<&str> = BTreeSet::new();
        held.extend(self.families.values().map(|f| f.client_id.as_str()));
        held.extend(self.codes.values().map(|c| c.client_id.as_str()));
        held.extend(self.tickets.values().map(|t| t.client_id.as_str()));
        let grace = self.cfg.client_grace_micros;
        let mut dropped: Vec<ClientNumber> = Vec::new();
        self.clients.retain(|id, c| {
            let keep = held.contains(id.as_str()) || now.saturating_sub(c.registered) < grace;
            if !keep {
                dropped.push(c.number);
            }
            keep
        });
        for n in dropped {
            self.numbers.remove(&n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://cell-a.example";
    const MCP: &str = "https://cell-a.example/mcp";
    const REDIRECT: &str = "https://agent.example/cb";
    const VERIFIER: &str = "unit-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

    fn config() -> Config {
        Config::new(ISSUER, MCP, 43_200_000_000, 300_000_000)
    }

    fn json_str(r: &Reply, key: &str) -> String {
        fstp_json::parse(&r.body)
            .ok()
            .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default()
    }

    fn register(s: &mut AuthorizationServer, now: Micros) -> String {
        let r = s.register(
            RateKey::from_raw(1),
            br#"{"redirect_uris":["https://agent.example/cb"],"client_name":"Unit agent"}"#,
            now,
        );
        assert_eq!(r.status, 201);
        json_str(&r, "client_id")
    }

    fn server_with(cfg: Config) -> (AuthorizationServer, String) {
        let mut s = match AuthorizationServer::new(cfg) {
            Ok(s) => s,
            Err(e) => panic!("config refused: {e}"),
        };
        let id = register(&mut s, 0);
        (s, id)
    }

    fn server() -> (AuthorizationServer, String) {
        server_with(config())
    }

    fn query(id: &str, extra: &[(&str, &str)]) -> String {
        let challenge = encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("scope", "calls:read"),
            ("resource", MCP),
        ];
        for (k, v) in extra {
            pairs.retain(|(p, _)| p != k);
            pairs.push((k, v));
        }
        crate::form::encode_form_urlencoded(&pairs)
    }

    fn consent_from(
        s: &mut AuthorizationServer,
        id: &str,
        session: RateKey,
        now: Micros,
    ) -> ConsentRequest {
        match s.authorize_from(session, query(id, &[]).as_bytes(), now) {
            AuthorizeOutcome::Consent(c) => c,
            other => panic!("no consent: {other:?}"),
        }
    }

    fn consent(s: &mut AuthorizationServer, id: &str, now: Micros) -> ConsentRequest {
        match s.authorize(query(id, &[]).as_bytes(), now) {
            AuthorizeOutcome::Consent(c) => c,
            other => panic!("no consent: {other:?}"),
        }
    }

    fn auth_by(c: &ConsentRequest, now: Micros, method: LoginMethod) -> ConsentAuth {
        ConsentAuth {
            session: method,
            step_up: Some(StepUpProof {
                account: Account::from_raw(7),
                digest: c.digest,
                at: now,
                method,
            }),
        }
    }

    fn auth(c: &ConsentRequest, now: Micros) -> ConsentAuth {
        auth_by(c, now, LoginMethod::Passkey)
    }

    fn code_in(loc: &str) -> String {
        loc.split(['?', '&'])
            .find_map(|p| p.strip_prefix("code="))
            .unwrap_or_default()
            .to_owned()
    }

    /// Consents with `method`, approves and redeems: the token reply.
    fn grant(s: &mut AuthorizationServer, id: &str, now: Micros, method: LoginMethod) -> Reply {
        let c = consent(s, id, now);
        let AuthorizeOutcome::Redirect(loc) = s.approve(
            &c.handle,
            Account::from_raw(7),
            &auth_by(&c, now, method),
            now,
        ) else {
            panic!("no redirect");
        };
        let body = crate::form::encode_form_urlencoded(&[
            ("grant_type", "authorization_code"),
            ("code", &code_in(&loc)),
            ("client_id", id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ]);
        s.token(body.as_bytes(), now)
    }

    fn refresh(s: &mut AuthorizationServer, id: &str, token: &str, now: Micros) -> Reply {
        let body = crate::form::encode_form_urlencoded(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", id),
        ]);
        s.token(body.as_bytes(), now)
    }

    /// ADR-013: the issuer must be an origin and the resource must have no
    /// query.
    #[test]
    fn adr013_config_is_checked() {
        for (i, r) in [
            ("https://cell-a.example/x", MCP),
            (ISSUER, "https://cell-a.example/mcp?x=1"),
            ("http://cell-a.example", MCP),
        ] {
            assert!(
                AuthorizationServer::new(Config::new(i, r, 1, 1)).is_err(),
                "{i} {r} accepted"
            );
        }
        assert!(AuthorizationServer::new(Config::new(ISSUER, MCP, 0, 1)).is_err());
    }

    /// ADR-013: a consent expires, and an expired consent issues no code.
    #[test]
    fn adr013_consent_expires() {
        let (mut s, id) = server();
        let c = consent(&mut s, &id, 0);
        let late = CONSENT_LIFETIME_MICROS;
        assert!(matches!(
            s.approve(&c.handle, Account::from_raw(7), &auth(&c, late), late),
            AuthorizeOutcome::Refused(_)
        ));
    }

    /// ADR-013: a consent handle approves once.
    #[test]
    fn adr013_consent_is_single_use() {
        let (mut s, id) = server();
        let c = consent(&mut s, &id, 0);
        let a = auth(&c, 0);
        assert!(matches!(
            s.approve(&c.handle, Account::from_raw(7), &a, 0),
            AuthorizeOutcome::Redirect(_)
        ));
        assert!(matches!(
            s.approve(&c.handle, Account::from_raw(7), &a, 0),
            AuthorizeOutcome::Refused(_)
        ));
    }

    /// ADR-013: a denial sends `access_denied` with the issuer, and no code.
    #[test]
    fn adr013_denial_redirects_access_denied() {
        let (mut s, id) = server();
        let c = consent(&mut s, &id, 0);
        match s.deny(&c.handle, 0) {
            AuthorizeOutcome::Redirect(loc) => {
                assert!(loc.starts_with("https://agent.example/cb?error=access_denied"));
                assert!(!loc.contains("code="));
            }
            other => panic!("{other:?}"),
        }
    }

    /// ADR-013: pending consents per client are capped, oldest first.
    #[test]
    fn adr013_pending_consents_are_capped() {
        let (mut s, id) = server();
        let first = consent(&mut s, &id, 0);
        for t in 1..=16 {
            consent(&mut s, &id, t);
        }
        assert!(matches!(
            s.approve(&first.handle, Account::from_raw(7), &auth(&first, 20), 20),
            AuthorizeOutcome::Refused(_)
        ));
    }

    /// ADR-013, TW-4: a `state` too long to echo is refused to the user,
    /// with no redirect.
    #[test]
    fn adr013_overlong_state_is_refused() {
        let (mut s, id) = server();
        let long = "s".repeat(MAX_STATE_BYTES + 1);
        let q = query(&id, &[("state", &long)]);
        match s.authorize(q.as_bytes(), 0) {
            AuthorizeOutcome::Refused(r) => {
                assert_eq!(r.status, 400);
                assert_eq!(json_str(&r, "error"), "invalid_request");
            }
            other => panic!("{other:?}"),
        }
        let ok = "s".repeat(MAX_STATE_BYTES);
        let q = query(&id, &[("state", &ok)]);
        assert!(matches!(
            s.authorize(q.as_bytes(), 0),
            AuthorizeOutcome::Consent(_)
        ));
    }

    /// ADR-013, TW-4 (RFC 9700 section 4.11.2): every error found before
    /// the user acts is refused to the user with its OAuth error code,
    /// and never redirects to the registered URI.
    #[test]
    fn adr013_tw4_authorize_errors_never_redirect() {
        let (mut s, id) = server();
        for (extra, code) in [
            (
                &[("response_type", "token")][..],
                "unsupported_response_type",
            ),
            (&[("code_challenge", "")][..], "invalid_request"),
            (&[("code_challenge_method", "plain")][..], "invalid_request"),
            (
                &[("resource", "https://cell-b.example/mcp")][..],
                "invalid_target",
            ),
            (&[("scope", "calls:read nope:read")][..], "invalid_scope"),
        ] {
            match s.authorize(query(&id, extra).as_bytes(), 0) {
                AuthorizeOutcome::Refused(r) => {
                    assert_eq!(r.status, 400, "{extra:?}");
                    assert_eq!(json_str(&r, "error"), code, "{extra:?}");
                }
                other => panic!("{extra:?} got {other:?}"),
            }
        }
        assert!(matches!(
            s.authorize(query(&id, &[]).as_bytes(), 0),
            AuthorizeOutcome::Consent(_)
        ));
    }

    /// ADR-013: one session cannot evict another session's pending
    /// consent while some session holds more than the victim. Here ten
    /// sessions start 200 consents against a cap of 16.
    #[test]
    fn adr013_other_sessions_cannot_evict_a_pending_consent() {
        let (mut s, id) = server();
        let user = consent_from(&mut s, &id, RateKey::from_raw(100), 0);
        for (t, k) in (1i64..=200).zip((1u64..=10).cycle()) {
            consent_from(&mut s, &id, RateKey::from_raw(k), t);
        }
        assert!(matches!(
            s.approve(&user.handle, Account::from_raw(7), &auth(&user, 300), 300),
            AuthorizeOutcome::Redirect(_)
        ));
    }

    /// ADR-013: many sessions holding one consent each cannot evict a
    /// user's only pending consent. Once every place holds a session's
    /// only consent, a new session gets 503 instead.
    #[test]
    fn adr013_many_sessions_cannot_evict_an_only_consent() {
        let (mut s, id) = server();
        let user = consent_from(&mut s, &id, RateKey::from_raw(100), 0);
        let mut refused = 0usize;
        for k in 1u64..=40 {
            let t = i64::try_from(k).unwrap_or(0);
            match s.authorize_from(RateKey::from_raw(k), query(&id, &[]).as_bytes(), t) {
                AuthorizeOutcome::Consent(_) => {}
                AuthorizeOutcome::Refused(r) => {
                    assert_eq!(r.status, 503);
                    assert_eq!(json_str(&r, "error"), "temporarily_unavailable");
                    refused = refused.saturating_add(1);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(refused, 25);
        assert!(matches!(
            s.approve(&user.handle, Account::from_raw(7), &auth(&user, 50), 50),
            AuthorizeOutcome::Redirect(_)
        ));
    }

    /// ADR-013: a session past its own cap loses its oldest consent.
    #[test]
    fn adr013_session_cap_evicts_its_own_oldest() {
        let (mut s, id) = server();
        let session = RateKey::from_raw(5);
        let first = consent_from(&mut s, &id, session, 0);
        let second = consent_from(&mut s, &id, session, 1);
        for t in 2..=4 {
            consent_from(&mut s, &id, session, t);
        }
        assert!(matches!(
            s.approve(&first.handle, Account::from_raw(7), &auth(&first, 9), 9),
            AuthorizeOutcome::Refused(_)
        ));
        assert!(matches!(
            s.approve(&second.handle, Account::from_raw(7), &auth(&second, 9), 9),
            AuthorizeOutcome::Redirect(_)
        ));
    }

    /// ADR-013: a family issues at most its cap of refresh tokens. The
    /// refresh past the cap revokes the family, so the retired tokens kept
    /// for reuse detection stay bounded.
    #[test]
    fn adr013_refresh_cap_revokes_the_family() {
        let mut cfg = config();
        cfg.max_refreshes_per_family = 3;
        let (mut s, id) = server_with(cfg);
        let first = grant(&mut s, &id, 0, LoginMethod::Passkey);
        assert_eq!(first.status, 200);
        let mut token = json_str(&first, "refresh_token");
        for t in 1..=3 {
            let r = refresh(&mut s, &id, &token, t);
            assert_eq!(r.status, 200, "refresh {t}");
            token = json_str(&r, "refresh_token");
        }
        let access = {
            let r = refresh(&mut s, &id, &token, 4);
            assert_eq!(r.status, 400);
            assert_eq!(json_str(&r, "error"), "invalid_grant");
            json_str(&first, "access_token")
        };
        let header = format!("Bearer {access}");
        assert!(s.authenticate(Some(header.as_bytes()), MCP, 5).is_err());
        assert!(s.agents_of(Account::from_raw(7), 5).is_empty());
    }

    /// ADR-013: a client older than the grace period with no consent,
    /// code or family is purged, which frees its place under the cap. A
    /// client with a family is kept.
    #[test]
    fn adr013_unused_clients_are_purged_after_the_grace_period() {
        let mut cfg = config();
        cfg.max_clients = 2;
        let (mut s, used) = server_with(cfg);
        let idle = register(&mut s, 0);
        let full = s.register(
            RateKey::from_raw(2),
            br#"{"redirect_uris":["https://a.example/cb"]}"#,
            1,
        );
        assert_eq!(full.status, 503);
        let grace = s.config().client_grace_micros;
        // The family starts late enough to outlive the grace period.
        let late = grace.saturating_sub(1_000_000);
        assert_eq!(grant(&mut s, &used, late, LoginMethod::Passkey).status, 200);
        s.purge(grace.saturating_sub(1));
        assert!(s.client_number(&idle).is_some());
        s.purge(grace);
        assert!(s.client_number(&idle).is_none());
        assert!(s.client_number(&used).is_some());
        let again = s.register(
            RateKey::from_raw(3),
            br#"{"redirect_uris":["https://a.example/cb"]}"#,
            grace,
        );
        assert_eq!(again.status, 201);
    }

    /// R-MC-03: the live grants of an account are listed with their
    /// scopes, and revoking by client number ends them at once.
    #[test]
    fn r_mc_03_agents_listed_and_revoked_by_number() {
        let (mut s, id) = server();
        let r = grant(&mut s, &id, 0, LoginMethod::EudiWallet);
        assert_eq!(r.status, 200);
        let Some(number) = s.client_number(&id) else {
            panic!("no number");
        };
        assert_eq!(s.client_id_of(number), Some(id.as_str()));
        let agents = s.agents_of(Account::from_raw(7), 1);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].client, number);
        assert_eq!(agents[0].client_name.as_deref(), Some("Unit agent"));
        assert_eq!(agents[0].scopes.to_wire(), "calls:read");
        assert_eq!(agents[0].consent_method, LoginMethod::EudiWallet);
        assert!(s.agents_of(Account::from_raw(8), 1).is_empty());
        assert_eq!(s.revoke_agent_by_number(Account::from_raw(8), number, 1), 0);
        assert_eq!(
            s.revoke_agent_by_number(Account::from_raw(7), ClientNumber::from_raw(999), 1),
            0
        );
        assert_eq!(s.revoke_agent_by_number(Account::from_raw(7), number, 1), 1);
        assert!(s.agents_of(Account::from_raw(7), 1).is_empty());
        let header = format!("Bearer {}", json_str(&r, "access_token"));
        assert!(s.authenticate(Some(header.as_bytes()), MCP, 1).is_err());
    }

    /// ADR-013 (Strength row): a grant keeps the consenting method, and a
    /// token inherits its strength.
    #[test]
    fn adr013_grant_keeps_the_consent_method() {
        let (mut s, id) = server();
        let r = grant(&mut s, &id, 0, LoginMethod::EudiWallet);
        let header = format!("Bearer {}", json_str(&r, "access_token"));
        let Ok(g) = s.authenticate(Some(header.as_bytes()), MCP, 1) else {
            panic!("no grant");
        };
        assert_eq!(g.consent_method, LoginMethod::EudiWallet);
        assert_eq!(g.consent_strength, Strength::PhishingResistant);
    }

    /// I-78: a magic-link or OPAQUE session cannot approve a consent.
    #[test]
    fn i78_weak_methods_cannot_approve() {
        for method in [LoginMethod::MagicLink, LoginMethod::Opaque] {
            let (mut s, id) = server();
            let c = consent(&mut s, &id, 0);
            assert!(matches!(
                s.approve(&c.handle, Account::from_raw(7), &auth_by(&c, 0, method), 0),
                AuthorizeOutcome::Refused(_)
            ));
        }
    }

    /// R-NF-02 (design section 5.4): the Debug text of a token reply and
    /// of a code redirect holds no code and no token.
    #[test]
    fn r_nf_02_debug_hides_codes_and_tokens() {
        let (mut s, id) = server();
        let c = consent(&mut s, &id, 0);
        let outcome = s.approve(&c.handle, Account::from_raw(7), &auth(&c, 0), 0);
        let AuthorizeOutcome::Redirect(loc) = &outcome else {
            panic!("no redirect");
        };
        let code = code_in(loc);
        let shown = format!("{outcome:?}");
        assert!(!code.is_empty() && !shown.contains(&code), "{shown}");
        assert!(shown.contains("https://agent.example"));
        let body = crate::form::encode_form_urlencoded(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ]);
        let r = s.token(body.as_bytes(), 0);
        let shown = format!("{r:?}");
        for key in ["access_token", "refresh_token"] {
            let t = json_str(&r, key);
            assert!(!t.is_empty() && !shown.contains(&t), "{shown}");
        }
        assert!(shown.contains("200"));
    }

    /// ADR-013, RFC 6750: a token without a scope gets 403 naming it.
    #[test]
    fn adr013_insufficient_scope_names_the_scope() {
        let (s, _) = server();
        let r = s.insufficient_scope(ScopeSet::EMPTY.with(Scope::AuditRead));
        assert_eq!(r.status, 403);
        let www = r
            .headers
            .iter()
            .find(|(k, _)| k == "WWW-Authenticate")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(www.contains("error=\"insufficient_scope\""));
        assert!(www.contains("scope=\"audit:read\""));
    }

    /// ADR-013: purging keeps every record that can still change an answer.
    #[test]
    fn adr013_purge_keeps_live_records() {
        let (mut s, id) = server();
        let c = consent(&mut s, &id, 0);
        let AuthorizeOutcome::Redirect(loc) =
            s.approve(&c.handle, Account::from_raw(7), &auth(&c, 0), 0)
        else {
            panic!("no redirect");
        };
        let code = loc
            .split("code=")
            .nth(1)
            .and_then(|r| r.split('&').next())
            .unwrap_or_default()
            .to_owned();
        let body = crate::form::encode_form_urlencoded(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &id),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ]);
        let r = s.token(body.as_bytes(), 1);
        assert_eq!(r.status, 200);
        let access = fstp_json::parse(&r.body)
            .ok()
            .and_then(|v| {
                v.get("access_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        s.purge(2 * CODE_LIFETIME_MICROS);
        let header = format!("Bearer {access}");
        assert!(
            s.authenticate(Some(header.as_bytes()), MCP, 2 * CODE_LIFETIME_MICROS)
                .is_ok()
        );
        // The redeemed code is kept, so a late replay still revokes.
        let again = s.token(body.as_bytes(), 3 * CODE_LIFETIME_MICROS);
        assert_eq!(again.status, 400);
        assert!(
            s.authenticate(Some(header.as_bytes()), MCP, 3 * CODE_LIFETIME_MICROS)
                .is_err()
        );
    }
}

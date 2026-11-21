//! The operator page of the pilot `fstp-control`: passkey login, step-up
//! approval of route changes, and staff passkey enrolment (ADR-009
//! "Pilot route feed", rows "Operator page" and "Staff passkey
//! enrolment"; decided by Daniel on 2026-11-21, lane L15).
//!
//! It serves HTTPS for `https://<operator_host>` with no port, since a
//! WebAuthn origin carries none. The page itself is compiled from
//! `web/src/routefeed` by tsc (ADR-003) and reuses the ceremony code of
//! `web/src/auth/webauthn.ts`. Its JSON routes:
//!
//! | Route | Session | Does |
//! | --- | --- | --- |
//! | `POST /api/login/options` | none | a login challenge |
//! | `POST /api/login` | none | verifies the assertion, sets the cookie |
//! | `GET /api/state` | yes | version, routes and waiting changes |
//! | `POST /api/changes/{id}/options` | yes | a step-up challenge bound to the change |
//! | `POST /api/changes/{id}/approve` | yes | verifies and consumes the step-up, signs the table |
//! | `POST /api/register/options` | none | a creation challenge |
//! | `POST /api/register` | none | verifies the attestation, answers the staff entry to pin |
//!
//! Every POST needs `X-FSTP-Request: 1` and an `Origin` of exactly
//! `https://<operator_host>`. The session cookie is `__Host-fstp-operator`,
//! `Secure`, `HttpOnly`, `SameSite=Strict`. Bodies are closed JSON
//! objects with lowercase hex members. The body and cookie decoders are
//! fuzzed (`route_feed_decode`). No reply or event quotes input
//! (R-NF-02).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_edge::{CellEndpoint, PinnedRoute};
use fstp_http::{Handler, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use fstp_json::{Array, Object, ParseLimits, Value};
use fstp_obs::LogEvent;
use fstp_webauthn::{AssertionResponse, CoseKey, RegistrationExpect, RegistrationResponse};

use crate::ControlError;
use crate::operator::{OperatorSession, Purpose};
use crate::route_change::RouteChanges;
use crate::route_feed::{OperatorRequest, now_secs};

/// The session cookie.
pub const COOKIE: &str = "__Host-fstp-operator";

/// The longest JSON body.
pub const MAX_BODY: usize = 16 * 1024;

/// The longest credential id, client data, authenticator data, signature
/// or attestation object a body carries.
pub const MAX_FIELD: usize = 4096;

/// How long a registration challenge may be answered, in seconds.
pub const REGISTRATION_LIFETIME_SECS: i64 = 120;

/// The most registration challenges that may wait.
pub const MAX_REGISTRATIONS: usize = 64;

/// The longest asset served.
pub const MAX_ASSET: usize = 1024 * 1024;

/// The ceremony timeout the options name, in milliseconds.
const TIMEOUT_MS: u64 = 120_000;

/// The route template the page logs under.
const ROUTE: &str = "/operator/api";

const PAGE: &str = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>fstp-control routes</title></head><body><main id=\"app\"><h1>Routes</h1><p>Loading.</p></main><script type=\"module\" src=\"/assets/routefeed/main.js\"></script></body></html>\n";

const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// An assertion body and the challenge it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionBody {
    /// The challenge.
    pub challenge: [u8; 32],
    /// The assertion.
    pub assertion: AssertionResponse,
}

/// A registration body and the challenge it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationBody {
    /// The challenge.
    pub challenge: [u8; 32],
    /// The registration.
    pub registration: RegistrationResponse,
}

fn body_object(bytes: &[u8], members: &[&str]) -> Result<Object, ControlError> {
    let refused = || ControlError::Request("body");
    if bytes.len() > MAX_BODY {
        return Err(refused());
    }
    let limits = ParseLimits::default()
        .with_max_input_bytes(MAX_BODY)
        .with_max_depth(1)
        .with_max_container_len(8)
        .with_max_string_bytes(MAX_FIELD.saturating_mul(2));
    let value = fstp_json::parse_with(bytes, &limits).map_err(|_| refused())?;
    let o = value.as_object().ok_or_else(refused)?.clone();
    if o.len() != members.len() || o.keys().any(|k| !members.contains(&k)) {
        return Err(refused());
    }
    Ok(o)
}

fn hex_field(o: &Object, name: &str, max: usize) -> Result<Vec<u8>, ControlError> {
    o.get(name)
        .and_then(Value::as_str)
        .and_then(|s| crate::config::lower_hex(s, max))
        .ok_or(ControlError::Request("body"))
}

fn challenge_field(o: &Object) -> Result<[u8; 32], ControlError> {
    <[u8; 32]>::try_from(hex_field(o, "challenge_id", 32)?)
        .map_err(|_| ControlError::Request("body"))
}

/// Decodes `{}`. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] for anything else.
pub fn decode_empty_body(bytes: &[u8]) -> Result<(), ControlError> {
    body_object(bytes, &[]).map(|_| ())
}

/// Decodes an assertion body: `challenge_id`, `authenticator_data`,
/// `client_data_json`, `credential_id` and `signature`, each lowercase
/// hex. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] for any other form.
pub fn decode_assertion_body(bytes: &[u8]) -> Result<AssertionBody, ControlError> {
    let o = body_object(
        bytes,
        &[
            "authenticator_data",
            "challenge_id",
            "client_data_json",
            "credential_id",
            "signature",
        ],
    )?;
    Ok(AssertionBody {
        challenge: challenge_field(&o)?,
        assertion: AssertionResponse {
            credential_id: hex_field(&o, "credential_id", MAX_FIELD)?,
            client_data_json: hex_field(&o, "client_data_json", MAX_FIELD)?,
            authenticator_data: hex_field(&o, "authenticator_data", MAX_FIELD)?,
            signature: hex_field(&o, "signature", MAX_FIELD)?,
        },
    })
}

/// Decodes a registration body: `challenge_id`, `attestation_object`,
/// `client_data_json` and `credential_id`, each lowercase hex. Fuzzed
/// (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] for any other form.
pub fn decode_registration_body(bytes: &[u8]) -> Result<RegistrationBody, ControlError> {
    let o = body_object(
        bytes,
        &[
            "attestation_object",
            "challenge_id",
            "client_data_json",
            "credential_id",
        ],
    )?;
    hex_field(&o, "credential_id", MAX_FIELD)?;
    Ok(RegistrationBody {
        challenge: challenge_field(&o)?,
        registration: RegistrationResponse {
            client_data_json: hex_field(&o, "client_data_json", MAX_FIELD)?,
            attestation_object: hex_field(&o, "attestation_object", MAX_FIELD)?,
        },
    })
}

/// The session token in a `Cookie` header value: the one cookie named
/// [`COOKIE`] with 64 lowercase hex digits. Fuzzed (`route_feed_decode`).
#[must_use]
pub fn session_from_cookie(header: &[u8]) -> Option<OperatorSession> {
    if header.len() > 4096 {
        return None;
    }
    let text = std::str::from_utf8(header).ok()?;
    let mut found = None;
    for part in text.split(';') {
        let Some((name, value)) = part.trim_start_matches(' ').split_once('=') else {
            continue;
        };
        if name == COOKIE {
            if found.is_some() {
                return None;
            }
            let token = <[u8; 32]>::try_from(crate::config::lower_hex(value, 32)?).ok()?;
            found = Some(OperatorSession(token));
        }
    }
    found
}

/// The COSE key bytes of `key`, as the `staff` entries of a configuration
/// pin them. An encoder only: ES256 and Ed25519. RS256 is refused, so the
/// entry stays short.
///
/// # Errors
///
/// [`ControlError::Request`] for an RS256 key.
pub fn cose_key_bytes(key: &CoseKey) -> Result<Vec<u8>, ControlError> {
    match key {
        CoseKey::Ed25519 { x } => {
            let mut out = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
            out.extend_from_slice(x);
            Ok(out)
        }
        CoseKey::Es256 { x, y } => {
            let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
            out.extend_from_slice(x);
            out.extend_from_slice(&[0x22, 0x58, 0x20]);
            out.extend_from_slice(y);
            Ok(out)
        }
        CoseKey::Rs256 { .. } => Err(ControlError::Request("cose")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Unpadded base64url (RFC 4648 section 5). An encoder only.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for k in 0..chunk.len().saturating_add(1) {
            let shift = 18usize.saturating_sub(k.saturating_mul(6));
            let idx = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            if let Some(c) = ALPHABET.get(idx) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

fn s(v: &str) -> Value {
    Value::from(v)
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

fn endpoint_json(e: &CellEndpoint, pin: &[u8; 32]) -> Value {
    obj(vec![
        ("address", s(&e.address.to_string())),
        ("cert_sha256", s(&hex(pin))),
        ("server_name", s(&e.tls_name)),
    ])
}

/// One route as the route file spells it.
#[must_use]
pub fn route_json(r: &PinnedRoute) -> Value {
    obj(vec![
        ("app", endpoint_json(&r.route.app, &r.app_pin)),
        ("cell", s(&hex(&r.route.app.cell))),
        ("host", s(r.route.host.as_str())),
        ("vault", endpoint_json(&r.route.vault, &r.vault_pin)),
    ])
}

fn header(name: &str, value: &str) -> Option<(HeaderName, HeaderValue)> {
    Some((HeaderName::new(name).ok()?, HeaderValue::new(value).ok()?))
}

fn with(mut r: Response, name: &str, value: &str) -> Response {
    if let Some((n, v)) = header(name, value) {
        r = r.with_header(n, v);
    }
    r
}

fn secured(r: Response) -> Response {
    let r = with(r, "cache-control", "no-store");
    let r = with(r, "x-content-type-options", "nosniff");
    let r = with(r, "referrer-policy", "no-referrer");
    let r = with(r, "strict-transport-security", "max-age=31536000");
    with(r, "content-security-policy", CSP)
}

fn json(status: StatusCode, v: &Value) -> Response {
    secured(Response::with_body(
        status,
        "application/json",
        v.to_compact().into_bytes(),
    ))
}

fn refused(status: StatusCode, rule: &'static str) -> Response {
    let _ = fstp_obs::log_to_stderr(&LogEvent::Refused {
        method: fstp_obs::Method::Other,
        route: ROUTE,
        rule,
        status: status.as_u16(),
    });
    json(status, &obj(vec![("error", s("refused"))]))
}

fn status_of(e: &ControlError) -> StatusCode {
    match e {
        ControlError::Request(_) => StatusCode::BAD_REQUEST,
        ControlError::Operator(
            crate::operator::OperatorRefusal::Session
            | crate::operator::OperatorRefusal::SessionExpired,
        ) => StatusCode::UNAUTHORIZED,
        ControlError::Operator(_) => StatusCode::FORBIDDEN,
        _ => StatusCode::CONFLICT,
    }
}

/// The operator page of one process (module documentation).
pub struct OperatorPage {
    changes: Arc<RouteChanges>,
    host: String,
    origin: String,
    assets: PathBuf,
    registrations: Mutex<BTreeMap<[u8; 32], i64>>,
}

impl std::fmt::Debug for OperatorPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorPage")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl OperatorPage {
    /// The page for `host`, over `changes`, with the compiled page in
    /// `assets` (`web/dist`).
    #[must_use]
    pub fn new(changes: Arc<RouteChanges>, host: &str, assets: PathBuf) -> OperatorPage {
        OperatorPage {
            changes,
            host: host.to_owned(),
            origin: format!("https://{host}"),
            assets,
            registrations: Mutex::new(BTreeMap::new()),
        }
    }

    fn request_options(&self, challenge: &[u8; 32]) -> Value {
        let allow: Array = self
            .changes
            .login()
            .credential_ids()
            .iter()
            .map(|id| obj(vec![("id", s(&base64url(id))), ("type", s("public-key"))]))
            .collect();
        obj(vec![
            ("challenge_id", s(&hex(challenge))),
            (
                "public_key",
                obj(vec![
                    ("allowCredentials", Value::from(allow)),
                    ("challenge", s(&base64url(challenge))),
                    ("rpId", s(&self.host)),
                    ("timeout", Value::from(TIMEOUT_MS)),
                    ("userVerification", s("required")),
                ]),
            ),
        ])
    }

    fn creation_options(&self, challenge: &[u8; 32], user: &[u8; 16]) -> Value {
        let alg = |a: i64| obj(vec![("alg", Value::from(a)), ("type", s("public-key"))]);
        obj(vec![
            ("challenge_id", s(&hex(challenge))),
            (
                "public_key",
                obj(vec![
                    ("attestation", s("none")),
                    (
                        "authenticatorSelection",
                        obj(vec![
                            ("residentKey", s("discouraged")),
                            ("userVerification", s("required")),
                        ]),
                    ),
                    ("challenge", s(&base64url(challenge))),
                    ("pubKeyCredParams", Value::from(vec![alg(-7), alg(-8)])),
                    (
                        "rp",
                        obj(vec![("id", s(&self.host)), ("name", s("fstp-control"))]),
                    ),
                    ("timeout", Value::from(TIMEOUT_MS)),
                    (
                        "user",
                        obj(vec![
                            ("displayName", s("operator")),
                            ("id", s(&base64url(user))),
                            ("name", s("operator")),
                        ]),
                    ),
                ]),
            ),
        ])
    }

    fn session(req: &Request) -> Option<OperatorSession> {
        session_from_cookie(req.headers.get("cookie")?.as_bytes())
    }

    /// Whether a POST carries the CSRF header and the page's own origin.
    fn same_origin(&self, req: &Request) -> bool {
        let csrf = req
            .headers
            .get("x-fstp-request")
            .is_some_and(|v| v.as_bytes() == b"1");
        let origin = req
            .headers
            .get("origin")
            .is_some_and(|v| v.as_bytes() == self.origin.as_bytes());
        csrf && origin
    }

    fn state(&self, now: i64) -> Value {
        let p = self.changes.publisher();
        let routes: Vec<Value> = p.routes().iter().map(route_json).collect();
        let pending: Vec<Value> = self
            .changes
            .pending(now)
            .iter()
            .map(|c| {
                let (op, cell, route) = match &c.request {
                    OperatorRequest::Add(r) => ("add", r.route.app.cell, route_json(r)),
                    OperatorRequest::Remove(cell) => ("remove", *cell, Value::Null),
                    OperatorRequest::List => ("list", [0; 16], Value::Null),
                };
                obj(vec![
                    ("cell", s(&hex(&cell))),
                    ("digest", s(&hex(&c.digest))),
                    ("id", s(&hex(&c.id))),
                    ("op", s(op)),
                    ("route", route),
                ])
            })
            .collect();
        obj(vec![
            ("pending", Value::from(pending)),
            ("routes", Value::from(routes)),
            ("version", Value::from(p.version())),
        ])
    }

    fn asset(&self, dir: &str, file: &str) -> Response {
        let ok_name = file.len() <= 64
            && file.strip_suffix(".js").is_some_and(|stem| {
                !stem.is_empty()
                    && stem
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            });
        if !ok_name || !(dir == "auth" || dir == "routefeed") {
            return refused(StatusCode::NOT_FOUND, "TH-26");
        }
        match std::fs::read(self.assets.join(dir).join(file)) {
            Ok(b) if b.len() <= MAX_ASSET => {
                secured(Response::with_body(StatusCode::OK, "text/javascript", b))
            }
            _ => refused(StatusCode::NOT_FOUND, "TH-26"),
        }
    }

    fn change_id(seg: &str) -> Option<[u8; 16]> {
        <[u8; 16]>::try_from(crate::config::lower_hex(seg, 16)?).ok()
    }

    /// Answers one request at `now` (module documentation).
    pub fn answer(&self, req: &Request, now: i64) -> Response {
        let path: Vec<&str> = req.path().trim_start_matches('/').split('/').collect();
        let get = req.method == Method::GET;
        let post = req.method == Method::POST;
        if post && !self.same_origin(req) {
            return refused(StatusCode::FORBIDDEN, "TH-26");
        }
        match (get, post, path.as_slice()) {
            (true, _, [""]) => secured(Response::with_body(
                StatusCode::OK,
                "text/html; charset=utf-8",
                PAGE.as_bytes().to_vec(),
            )),
            (true, _, ["assets", dir, file]) => self.asset(dir, file),
            (_, true, ["api", "login", "options"]) => {
                if decode_empty_body(&req.body).is_err() {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                }
                let begun = self.changes.login().begin(Purpose::Login, now);
                match begun {
                    Ok(c) => json(StatusCode::OK, &self.request_options(&c)),
                    Err(e) => refused(status_of(&e), "I-77"),
                }
            }
            (_, true, ["api", "login"]) => {
                let Ok(b) = decode_assertion_body(&req.body) else {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                };
                let opened = self
                    .changes
                    .login()
                    .finish_login(b.challenge, &b.assertion, now);
                match opened {
                    Ok((session, _)) => with(
                        json(StatusCode::OK, &obj(vec![("ok", Value::from(true))])),
                        "set-cookie",
                        &format!(
                            "{COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                            hex(&session.0),
                            crate::operator::SESSION_LIFETIME_SECS
                        ),
                    ),
                    Err(e) => refused(status_of(&e), "I-77"),
                }
            }
            (true, _, ["api", "state"]) => {
                let open = Self::session(req)
                    .is_some_and(|session| self.changes.login().session_open(session, now));
                if open {
                    json(StatusCode::OK, &self.state(now))
                } else {
                    refused(StatusCode::UNAUTHORIZED, "I-77")
                }
            }
            (_, true, ["api", "changes", id, "options"]) => {
                let (Some(session), Some(id)) = (Self::session(req), Self::change_id(id)) else {
                    return refused(StatusCode::UNAUTHORIZED, "I-78");
                };
                if decode_empty_body(&req.body).is_err() {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                }
                match self.changes.begin_approval(session, id, now) {
                    Ok(c) => json(StatusCode::OK, &self.request_options(&c)),
                    Err(e) => refused(status_of(&e), "I-78"),
                }
            }
            (_, true, ["api", "changes", id, "approve"]) => {
                let (Some(session), Some(id)) = (Self::session(req), Self::change_id(id)) else {
                    return refused(StatusCode::UNAUTHORIZED, "I-78");
                };
                let Ok(b) = decode_assertion_body(&req.body) else {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                };
                match self
                    .changes
                    .approve(session, id, b.challenge, &b.assertion, now)
                {
                    Ok(version) => {
                        let _ = fstp_obs::log_to_stderr(&LogEvent::Request {
                            method: fstp_obs::Method::Post,
                            route: ROUTE,
                            status: 200,
                            elapsed: std::time::Duration::ZERO,
                        });
                        json(
                            StatusCode::OK,
                            &obj(vec![("version", Value::from(version))]),
                        )
                    }
                    Err(e) => refused(status_of(&e), "I-78"),
                }
            }
            (_, true, ["api", "register", "options"]) => {
                if decode_empty_body(&req.body).is_err() {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                }
                let (Ok(c), Ok(user)) = (
                    fstp_crypto::random_array::<32>(),
                    fstp_crypto::random_array::<16>(),
                ) else {
                    return refused(StatusCode::CONFLICT, "I-77");
                };
                let mut regs = self
                    .registrations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                regs.retain(|_, at| {
                    now >= *at && now.saturating_sub(*at) <= REGISTRATION_LIFETIME_SECS
                });
                if regs.len() >= MAX_REGISTRATIONS {
                    return refused(StatusCode::CONFLICT, "I-77");
                }
                regs.insert(c, now);
                json(StatusCode::OK, &self.creation_options(&c, &user))
            }
            (_, true, ["api", "register"]) => {
                let Ok(b) = decode_registration_body(&req.body) else {
                    return refused(StatusCode::BAD_REQUEST, "TH-26");
                };
                let issued = self
                    .registrations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&b.challenge);
                let fresh = issued.is_some_and(|at| {
                    now >= at && now.saturating_sub(at) <= REGISTRATION_LIFETIME_SECS
                });
                if !fresh {
                    return refused(StatusCode::FORBIDDEN, "I-77");
                }
                let rp = self.changes.login().relying_party().clone();
                let expect = RegistrationExpect {
                    rp,
                    challenge: b.challenge,
                    user_verification: true,
                };
                let entry = fstp_webauthn::verify_registration(&b.registration, &expect)
                    .ok()
                    .and_then(|c| Some((c.id, cose_key_bytes(&c.key).ok()?)));
                let (Some((id, cose)), Ok(staff)) = (entry, fstp_crypto::random_array::<16>())
                else {
                    return refused(StatusCode::FORBIDDEN, "I-77");
                };
                json(
                    StatusCode::OK,
                    &obj(vec![
                        ("cose_key", s(&hex(&cose))),
                        ("credential_id", s(&hex(&id))),
                        ("staff", s(&hex(&staff))),
                    ]),
                )
            }
            _ => refused(StatusCode::NOT_FOUND, "TH-26"),
        }
    }
}

impl Handler for OperatorPage {
    async fn handle(&self, req: Request) -> Response {
        self.answer(&req, now_secs())
    }
}

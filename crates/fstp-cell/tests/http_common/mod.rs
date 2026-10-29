//! Shared helpers of the `fstp-cell` route and HTTP tests (lane W3a,
//! agent one, test author).
//!
//! The tests were written before the routes and the HTTP layer exist.
//! They reach production only through the seams in this module. Each seam
//! refuses with a [`Seam`] that names the production API it waits for, so
//! every test that needs one is red for that reason only. The production
//! agent of lane W3a replaces each seam body with one call into
//! `fstp_cell`, and the tests then run unchanged.
//!
//! The production agent of lane W3a has closed every seam. Each body now
//! calls `fstp_cell`, and only a failed `TestCell` start or login still
//! refuses with a [`Seam`].
//!
//! `fstp-celltest` cannot be a dev-dependency here, since it depends on
//! `fstp-cell`. So [`SECTION_8_7`] transcribes design section 8.7 again,
//! from the design text and not from the `fstp-celltest` reference. It
//! names no production predicate.
//!
//! # Readings the HTTP tests share
//!
//! The design fixes the rules but not the status codes or the order of
//! the checks. These tests read them as follows, and say so where they
//! rely on it.
//!
//! - The cell's tunnel listener runs a front before any handler, session
//!   lookup or body decode: route match (404, or 405 for another method),
//!   then `Origin` on POST and DELETE (403), then `Content-Type` on POST
//!   (415), then the body limit (413). A session lookup follows (401),
//!   then the body decode (400), then the gate (403). Status codes follow
//!   RFC 9110.
//! - Body grammars the design leaves open are built in one place each:
//!   [`magic_request_body`] for `POST /auth/magic/request`. If production
//!   picks another grammar, only that function changes.
//! - `GET /healthz` lives on the loopback health listener only (design
//!   section 2.3, ADR-009). The tunnel listener does not serve it.
//! - The only accepted `Origin` is the cell origin, byte for byte:
//!   `https://<cell host>`. The vault origin `https://id.<cell host>` is
//!   same-site with the cell, so `SameSite=Strict` does not stop its
//!   requests. Only the `Origin` check does.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

use std::fmt;

use fstp_cell::routes::Route;
use fstp_cell_core::gate::HighRiskAction;
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_obs::LogEvent;

// ---------------------------------------------------------------------------
// Seams.

/// A seam that refuses until the production API it names exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seam(pub(crate) &'static str);

impl fmt::Display for Seam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seam (lane W3a, NotImplemented): {}", self.0)
    }
}

/// The seam of [`production_routes`].
pub(crate) const ROUTE_TABLE_SEAM: &str = "fstp_cell::routes exposes no route table yet; \
     proposed: `pub fn table() -> &'static [Route]` (design sections 5.4 and 8.7)";

/// The seam of [`TestCell::start`] and every [`TestCell`] call.
pub(crate) const CELL_SEAM: &str = "fstp_cell::http has no in-process cell front for tests yet; \
     proposed: a test front for one cell id and host, with its tunnel and health listeners \
     as `Request -> Response` handlers, a typed log sink, and seeded sessions \
     (design sections 2.3, 8.2 and 8.7)";

/// The seam of [`set_cookie`].
pub(crate) const SET_COOKIE_SEAM: &str = "fstp_cell::http writes no Set-Cookie value yet; \
     proposed: `set_session_cookie(cell: [u8; 16], token: &[u8; 32]) -> HeaderValue` \
     (design section 8.2, ADR-008 \"Sessions\")";

/// The seam of [`read_cookie`].
pub(crate) const READ_COOKIE_SEAM: &str = "fstp_cell::http reads no session cookie yet; \
     proposed: `read_session_cookie(cell: [u8; 16], headers: &Headers) -> \
     Result<Option<SessionCookie>, CookieRefusal>` (design section 8.2, B11)";

/// Every route of the production cell with its risk class.
///
/// Seam, now closed: `fstp_cell::routes::table()`. It never refuses.
pub(crate) fn production_routes() -> Result<Vec<Route>, Seam> {
    Ok(fstp_cell::routes::table().to_vec())
}

/// The `Set-Cookie` field value the cell writes for a session of `cell`
/// whose token is `token`.
///
/// Seam, now closed: `fstp_cell::http::set_session_cookie`.
pub(crate) fn set_cookie(cell: [u8; 16], token: &[u8; 32]) -> Result<Vec<u8>, Seam> {
    Ok(fstp_cell::http::set_session_cookie(cell, token)
        .as_bytes()
        .to_vec())
}

/// What the cell `own` reads from the `Cookie` field lines of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CookieRead {
    /// No session cookie.
    Absent,
    /// A session cookie of this cell id and token.
    Session {
        /// The cell id.
        cell: [u8; 16],
        /// The token.
        token: [u8; 32],
    },
    /// The cookie was refused before any lookup. This covers another cell's
    /// cookie (B11), a malformed value and an ambiguous header.
    Refused,
}

/// Reads the session cookie of a request to the cell `own`. `fields` are
/// the values of every `Cookie` field line, in order.
///
/// Seam, now closed: `fstp_cell::http::read_session_cookie_values`. A
/// refusal of any kind reads as [`CookieRead::Refused`].
pub(crate) fn read_cookie(own: [u8; 16], fields: &[&[u8]]) -> Result<CookieRead, Seam> {
    Ok(
        match fstp_cell::http::read_session_cookie_values(own, fields.iter().copied()) {
            Ok(None) => CookieRead::Absent,
            Ok(Some(c)) => CookieRead::Session {
                cell: c.cell(),
                token: c.token().0,
            },
            Err(_) => CookieRead::Refused,
        },
    )
}

/// Who a seeded session belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Who {
    /// A tenant admin with a passkey (UV), logged in by passkey. The
    /// account has no identity verification fact and no other role.
    Admin,
    /// A Receiving-only account, logged in by magic link. P-70 enables
    /// magic links for Receiving accounts.
    Applicant,
}

/// One in-process cell, as the production test front gives it.
///
/// Seam, now closed: `fstp_cell::routes::memory::LocalCell`, the
/// production front over the in-memory backend. A refusal of
/// [`TestCell::start`] names [`CELL_SEAM`].
#[derive(Debug)]
pub(crate) struct TestCell {
    id: [u8; 16],
    host: &'static str,
    cell: fstp_cell::routes::memory::LocalCell,
}

impl TestCell {
    /// Starts the cell `id` served at `host`.
    pub(crate) fn start(id: [u8; 16], host: &'static str) -> Result<TestCell, Seam> {
        let cell =
            fstp_cell::routes::memory::LocalCell::start(id, host).map_err(|_| Seam(CELL_SEAM))?;
        Ok(TestCell { id, host, cell })
    }

    /// The cell id.
    pub(crate) fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The cell host.
    pub(crate) fn host(&self) -> &'static str {
        self.host
    }

    /// Serves one request on the tunnel listener, after the edge.
    pub(crate) fn serve(&self, req: Request) -> Result<Response, Seam> {
        Ok(self.cell.serve(req))
    }

    /// Serves one request on the loopback health listener.
    pub(crate) fn serve_health(&self, req: Request) -> Result<Response, Seam> {
        Ok(self.cell.serve_health(req))
    }

    /// The `Cookie` field value of a fresh session of `who`, as a browser
    /// sends it back after the login that set it.
    pub(crate) fn session(&self, who: Who) -> Result<Vec<u8>, Seam> {
        match who {
            Who::Admin => self.cell.admin_session(),
            Who::Applicant => self.cell.applicant_session(),
        }
        .map_err(|_| Seam(CELL_SEAM))
    }

    /// The login email of the seeded [`Who::Applicant`] account. It is a
    /// synthetic value.
    pub(crate) fn applicant_email(&self) -> Result<String, Seam> {
        Ok(self.cell.applicant_email().to_owned())
    }

    /// Every log event the cell wrote so far, in order.
    pub(crate) fn logs(&self) -> Result<Vec<LogEvent>, Seam> {
        Ok(self.cell.logs())
    }
}

/// Starts cell A, or panics with the seam.
pub(crate) fn cell_a() -> TestCell {
    TestCell::start(CELL_A, HOST_A).unwrap_or_else(|e| panic!("{e}"))
}

/// Starts cell B, or panics with the seam.
pub(crate) fn cell_b() -> TestCell {
    TestCell::start(CELL_B, HOST_B).unwrap_or_else(|e| panic!("{e}"))
}

/// Serves `req` on `cell`'s tunnel listener, or panics with the seam.
pub(crate) fn serve(cell: &TestCell, req: Request) -> Response {
    cell.serve(req).unwrap_or_else(|e| panic!("{e}"))
}

/// A seeded session cookie of `who` on `cell`, or panics with the seam.
pub(crate) fn session(cell: &TestCell, who: Who) -> Vec<u8> {
    cell.session(who).unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------
// Constants.

/// The id of cell A. Synthetic.
pub(crate) const CELL_A: [u8; 16] = [0xA1; 16];
/// The id of cell B. Synthetic.
pub(crate) const CELL_B: [u8; 16] = [0xB2; 16];
/// The host of cell A. `.test` is reserved (RFC 2606).
pub(crate) const HOST_A: &str = "tenant-a.fstp.test";
/// The host of cell B.
pub(crate) const HOST_B: &str = "tenant-b.fstp.test";

/// The CSP of the cell origin, verbatim from design section 11.2.
pub(crate) const CELL_CSP: &str = "default-src 'self'; script-src 'self'; object-src 'none'; \
     base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The session cookie name (design section 8.2, ADR-008).
pub(crate) const COOKIE_NAME: &str = "__Host-fstp";

/// A body size that no M3 cell route takes. The largest M3 body is a
/// WebAuthn registration, whose CBOR is at most 64 KiB (ADR-008
/// "Constants"). Its JSON text armour stays far below this size.
pub(crate) const OVERSIZE_BODY: usize = (1 << 20) + 1;

/// The value put in each `{param}` of a path template.
pub(crate) const PARAM: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// Design section 8.7, transcribed.

/// The risk class of a route in design section 8.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// No session.
    Public,
    /// A first-passkey ceremony (design section 8.3). No session.
    Ceremony,
    /// A session, with no step-up.
    Session,
    /// A session and a step-up for this action (I-78).
    HighRisk(HighRiskAction),
    /// A session. Each command is classed through `HighRiskAction::of`.
    PerCommand,
    /// A session, with `IdentityDownload` for the download scope.
    SessionOrIdentityDownload,
    /// A session of an Auditor or a tenant admin.
    AuditorOrAdmin,
    /// A session of a tenant admin with a verified identity (ADR-008).
    VerificationTicket,
    /// The loopback health listener only.
    Loopback,
}

impl Class {
    /// Whether the route needs a session.
    pub(crate) fn needs_session(self) -> bool {
        !matches!(self, Class::Public | Class::Ceremony | Class::Loopback)
    }

    /// The step-up action a route of this class always needs, if any.
    pub(crate) fn high_risk(self) -> Option<HighRiskAction> {
        match self {
            Class::HighRisk(a) => Some(a),
            _ => None,
        }
    }
}

/// One row of design section 8.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Spec {
    /// The method.
    pub(crate) method: &'static str,
    /// The path template.
    pub(crate) path: &'static str,
    /// The risk class.
    pub(crate) class: Class,
}

const fn row(method: &'static str, path: &'static str, class: Class) -> Spec {
    Spec {
        method,
        path,
        class,
    }
}

/// Every route of design section 8.7. A `...` in the design continues the
/// path of the row's first route.
pub(crate) const SECTION_8_7: &[Spec] = &[
    row(
        "POST",
        "/auth/invitations/{token}/register/options",
        Class::Ceremony,
    ),
    row(
        "POST",
        "/auth/invitations/{token}/register",
        Class::Ceremony,
    ),
    row("POST", "/auth/signup/options", Class::Ceremony),
    row("POST", "/auth/signup", Class::Ceremony),
    row("POST", "/auth/passkey/login/options", Class::Public),
    row("POST", "/auth/passkey/login", Class::Public),
    row("POST", "/auth/magic/request", Class::Public),
    row("GET", "/auth/magic", Class::Public),
    row("POST", "/auth/magic/consume", Class::Public),
    row("POST", "/auth/stepup/options", Class::Session),
    row("POST", "/auth/stepup", Class::Session),
    row(
        "POST",
        "/auth/passkeys/options",
        Class::HighRisk(HighRiskAction::AddPasskey),
    ),
    row(
        "POST",
        "/auth/passkeys",
        Class::HighRisk(HighRiskAction::AddPasskey),
    ),
    row("GET", "/auth/sessions", Class::Session),
    row("DELETE", "/auth/sessions/{id}", Class::Session),
    row("GET", "/auth/devices", Class::Session),
    row(
        "DELETE",
        "/auth/devices/{id}",
        Class::HighRisk(HighRiskAction::ChangeLoginMethods),
    ),
    row("POST", "/auth/recovery", Class::Public),
    row("POST", "/auth/recovery/{case}/email", Class::Public),
    row(
        "POST",
        "/auth/recovery/{case}/approve",
        Class::HighRisk(HighRiskAction::ApproveRecovery),
    ),
    row("POST", "/auth/recovery/{case}/complete", Class::Ceremony),
    row("POST", "/api/v1/commands", Class::PerCommand),
    row(
        "POST",
        "/api/v1/vault-tickets",
        Class::SessionOrIdentityDownload,
    ),
    row("POST", "/api/v1/verifications", Class::VerificationTicket),
    row("GET", "/api/v1/audit/anchors", Class::AuditorOrAdmin),
    row("GET", "/api/v1/erasures", Class::AuditorOrAdmin),
    row("GET", "/healthz", Class::Loopback),
];

/// The rows served on the tunnel listener: every row but `/healthz`.
pub(crate) fn tunnel_rows() -> impl Iterator<Item = &'static Spec> {
    SECTION_8_7.iter().filter(|s| s.class != Class::Loopback)
}

/// Whether a request of `method` changes state (ADR-008 "Sessions").
pub(crate) fn state_changing(method: &str) -> bool {
    matches!(method, "POST" | "DELETE" | "PUT" | "PATCH")
}

// ---------------------------------------------------------------------------
// Requests and responses.

/// `path` with every `{param}` segment replaced by [`PARAM`].
pub(crate) fn concrete(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                PARAM
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The origin of `host`: `https://<host>`.
pub(crate) fn origin_of(host: &str) -> String {
    format!("https://{host}")
}

/// A bare request: method, origin-form target and `Host`, nothing else.
pub(crate) fn bare(method: &str, path_and_query: &str, host: &str) -> Request {
    let m = Method::from_bytes(method.as_bytes()).unwrap_or_else(|e| panic!("{method}: {e}"));
    let t =
        RequestTarget::origin(path_and_query).unwrap_or_else(|e| panic!("{path_and_query}: {e}"));
    Request::new(m, t)
        .try_with_header("host", host)
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A request that passes the front checks of the module readings for a
/// route of `cell`: the cell `Origin` on a state-changing method, and a
/// small JSON body with `Content-Type: application/json` on POST.
pub(crate) fn through_front(method: &str, path_and_query: &str, host: &str) -> Request {
    with_body(method, path_and_query, host, b"{}")
}

/// [`through_front`] with `body` on POST.
pub(crate) fn with_body(method: &str, path_and_query: &str, host: &str, body: &[u8]) -> Request {
    let mut req = bare(method, path_and_query, host);
    if state_changing(method) {
        req = req
            .try_with_header("origin", origin_of(host))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    if method == "POST" {
        req = req
            .try_with_header("content-type", "application/json")
            .unwrap_or_else(|e| panic!("{e}"));
        req.body = body.to_vec();
    }
    req
}

/// The body of `POST /auth/magic/request` for `email`. Reading: one
/// member, `email`, as a JSON string.
pub(crate) fn magic_request_body(email: &str) -> Vec<u8> {
    format!("{{\"email\":\"{email}\"}}").into_bytes()
}

/// `req` with a `Cookie` field line holding `cookie`.
pub(crate) fn with_cookie(req: Request, cookie: &[u8]) -> Request {
    req.try_with_header("cookie", cookie.to_vec())
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Every value of the response field `name`, case-insensitively.
pub(crate) fn field_values<'a>(resp: &'a Response, name: &'a str) -> Vec<&'a [u8]> {
    resp.headers
        .get_all(name)
        .map(fstp_http::HeaderValue::as_bytes)
        .collect()
}

/// The status of `resp` as a number.
pub(crate) fn status(resp: &Response) -> u16 {
    resp.status.as_u16()
}

/// `METHOD path` for messages.
pub(crate) fn label(s: &Spec) -> String {
    format!("{} {}", s.method, s.path)
}

/// Whether `haystack` holds `needle` as a byte substring.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Lowercase hexadecimal of `b`.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

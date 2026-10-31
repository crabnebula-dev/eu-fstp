//! The CrabNebula licence and update services (M3 design section 10).
//!
//! Each service accepts only the request template that
//! `fstp_release::egress` builds (I-38). A decoder parses the closed
//! fields, rebuilds the template from them and compares byte for byte.
//! So a request with any other header, body, spelling or trailing byte
//! is refused, and no tenant data can reach a service through it.
//!
//! The service cores are pure: [`licence_response`] and
//! [`update_response`] map request bytes to response bytes. The licence
//! service stores only holder name, contact address and licence type
//! (`gdpr.md`, ADR-005). A refresh reads only the licence id and version.
//!
//! Status: the network listeners are not wired. [`run_licence_service`]
//! and [`run_update_service`] refuse with
//! [`ServiceError::NotImplemented`]. The licence signing key lives in
//! control-plane custody (ADR-004), which layering rule 7 keeps out of
//! this crate's reach. The lead routes that key and the listeners.

use fstp_migrate::catalogue::TableSpec;
use fstp_release::ReleaseError;
use fstp_release::egress::{self, Channel, LicenceRefresh, ProductVersion, UpdateCheck};
use fstp_release::licence::{self, Ed25519SigningKey, LicenceId, LicenceKind, VerifiedToken};

/// The tables of the licence database. Empty until the licence registry
/// gets its migrations.
pub const CATALOGUE: &[TableSpec] = &[];

/// The longest request either decoder reads, in bytes. The longest
/// template is under 256 bytes.
pub const MAX_REQUEST_LEN: usize = 1024;

/// Why a service operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The operation is not wired yet. It names the operation.
    NotImplemented(&'static str),
    /// The request is longer than [`MAX_REQUEST_LEN`].
    TooLarge,
    /// The request is not exactly the permitted template.
    Grammar,
    /// A token policy whose instants would be out of order.
    Policy,
    /// Signing a token failed.
    Signing,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            ServiceError::TooLarge => f.write_str("request too large"),
            ServiceError::Grammar => f.write_str("request outside the permitted grammar"),
            ServiceError::Policy => f.write_str("token policy out of order"),
            ServiceError::Signing => f.write_str("token signing failed"),
        }
    }
}

impl std::error::Error for ServiceError {}

// ---------------------------------------------------------------------------
// Request decoders.

/// A decoded licence refresh request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRequest {
    /// The licence id.
    pub licence: [u8; 16],
    /// The running version.
    pub version: (u16, u16, u16),
}

/// A decoded update query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateQuery {
    /// The channel, as its closed metadata code (1 is stable).
    pub channel: u8,
    /// The running version.
    pub version: (u16, u16, u16),
}

/// `bytes` after `prefix`, or a grammar refusal.
fn after<'a>(bytes: &'a [u8], prefix: &[u8]) -> Result<&'a [u8], ServiceError> {
    bytes.strip_prefix(prefix).ok_or(ServiceError::Grammar)
}

/// The bytes of `bytes` up to the first `delimiter`, and the rest after it.
fn split_at_first<'a>(bytes: &'a [u8], delimiter: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let at = bytes
        .windows(delimiter.len())
        .position(|w| w == delimiter)?;
    let (head, tail) = bytes.split_at_checked(at)?;
    Some((head, tail.get(delimiter.len()..)?))
}

/// Decodes a refresh request; only the permitted grammar passes. Fuzzed
/// (`refresh_request_decode`).
///
/// # Errors
///
/// Returns [`ServiceError::TooLarge`] past [`MAX_REQUEST_LEN`], and
/// [`ServiceError::Grammar`] for any byte outside the template of
/// `fstp_release::egress::refresh_request`.
pub fn decode_refresh_request(bytes: &[u8]) -> Result<RefreshRequest, ServiceError> {
    if bytes.len() > MAX_REQUEST_LEN {
        return Err(ServiceError::TooLarge);
    }
    let rest = after(bytes, b"POST /v1/licences/")?;
    let (id, rest) = split_at_first(rest, b"/refresh HTTP/1.1\r\n").ok_or(ServiceError::Grammar)?;
    let licence = LicenceId::from_hex(id).ok_or(ServiceError::Grammar)?;
    let (_, body) = split_at_first(rest, b"\r\n\r\n").ok_or(ServiceError::Grammar)?;
    let version = after(body, b"{\"version\":\"")?
        .strip_suffix(b"\"}".as_slice())
        .and_then(ProductVersion::parse)
        .ok_or(ServiceError::Grammar)?;
    let template = egress::refresh_request(&LicenceRefresh { licence, version });
    if template != bytes {
        return Err(ServiceError::Grammar);
    }
    Ok(RefreshRequest {
        licence: licence.0,
        version: (version.0, version.1, version.2),
    })
}

/// Decodes an update query; only the permitted grammar passes. Fuzzed
/// (`update_query_decode`).
///
/// # Errors
///
/// Returns [`ServiceError::TooLarge`] past [`MAX_REQUEST_LEN`], and
/// [`ServiceError::Grammar`] for any byte outside the template of
/// `fstp_release::egress::update_request`.
pub fn decode_update_query(bytes: &[u8]) -> Result<UpdateQuery, ServiceError> {
    if bytes.len() > MAX_REQUEST_LEN {
        return Err(ServiceError::TooLarge);
    }
    let rest = after(bytes, b"GET /v1/updates/")?;
    let (target, _) = split_at_first(rest, b" HTTP/1.1\r\n").ok_or(ServiceError::Grammar)?;
    let (label, version) = split_at_first(target, b"/").ok_or(ServiceError::Grammar)?;
    let channel = Channel::from_label(label).ok_or(ServiceError::Grammar)?;
    let version = ProductVersion::parse(version).ok_or(ServiceError::Grammar)?;
    let template = egress::update_request(&UpdateCheck { version, channel });
    if template != bytes {
        return Err(ServiceError::Grammar);
    }
    Ok(UpdateQuery {
        channel: channel.code(),
        version: (version.0, version.1, version.2),
    })
}

// ---------------------------------------------------------------------------
// Responses.

/// A status the services send. Closed, so every status line they build
/// is one that `fstp_release::egress::decode_response` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpStatus {
    /// 200 OK.
    Ok,
    /// 400 Bad Request.
    BadRequest,
    /// 404 Not Found.
    NotFound,
    /// 500 Internal Server Error.
    InternalServerError,
}

impl HttpStatus {
    /// Every status.
    pub const ALL: [HttpStatus; 4] = [
        HttpStatus::Ok,
        HttpStatus::BadRequest,
        HttpStatus::NotFound,
        HttpStatus::InternalServerError,
    ];

    /// The status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            HttpStatus::Ok => 200,
            HttpStatus::BadRequest => 400,
            HttpStatus::NotFound => 404,
            HttpStatus::InternalServerError => 500,
        }
    }

    /// The reason phrase.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            HttpStatus::Ok => "OK",
            HttpStatus::BadRequest => "Bad Request",
            HttpStatus::NotFound => "Not Found",
            HttpStatus::InternalServerError => "Internal Server Error",
        }
    }
}

/// An HTTP/1.1 response with an `application/octet-stream` body of
/// exactly `Content-Length` bytes, the framing that
/// `fstp_release::egress::decode_response` accepts.
#[must_use]
pub fn http_response(status: HttpStatus, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        status.code(),
        status.reason(),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// The licence service.

/// What the licence registry holds about one licence that a refresh may
/// read. Holder name and contact address stay in the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenceRecord {
    /// The kind.
    pub kind: LicenceKind,
}

/// The licence registry, as the refresh path reads it.
pub trait LicenceRegistry {
    /// The record of an active licence, or `None` for an unknown or
    /// revoked one.
    fn lookup(&self, licence: &LicenceId) -> Option<LicenceRecord>;
}

/// How long an issued token lasts, in seconds from its issue instant.
/// The fields are private, so every policy passed [`TokenPolicy::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenPolicy {
    refresh_after_s: i64,
    valid_for_s: i64,
}

impl TokenPolicy {
    /// A policy with `0 <= refresh_after_s <= valid_for_s`.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Policy`] otherwise.
    pub const fn new(refresh_after_s: i64, valid_for_s: i64) -> Result<TokenPolicy, ServiceError> {
        if refresh_after_s < 0 || refresh_after_s > valid_for_s {
            return Err(ServiceError::Policy);
        }
        Ok(TokenPolicy {
            refresh_after_s,
            valid_for_s,
        })
    }

    /// Seconds until the cell should refresh.
    #[must_use]
    pub const fn refresh_after_s(&self) -> i64 {
        self.refresh_after_s
    }

    /// Seconds until the token's `not_after`.
    #[must_use]
    pub const fn valid_for_s(&self) -> i64 {
        self.valid_for_s
    }
}

/// Issues the signed token of `licence` at `now` under `policy`. The
/// registration page and the refresh path both use it. Sums saturate, so
/// the instants stay ordered near the end of time.
///
/// # Errors
///
/// Returns [`ServiceError::Policy`] when the instants would be out of
/// order, which [`TokenPolicy::new`] rules out, and
/// [`ServiceError::Signing`] when signing fails.
pub fn issue_token(
    licence: LicenceId,
    kind: LicenceKind,
    now: i64,
    policy: TokenPolicy,
    key: &Ed25519SigningKey,
) -> Result<Vec<u8>, ServiceError> {
    let fields = VerifiedToken {
        licence,
        kind,
        issued_at: now,
        refresh_after: now.saturating_add(policy.refresh_after_s),
        not_after: now.saturating_add(policy.valid_for_s),
    };
    licence::sign_token(&fields, key).map_err(|e| match e {
        ReleaseError::Order => ServiceError::Policy,
        _ => ServiceError::Signing,
    })
}

/// The signing side of the licence service.
pub struct Issuer<'a> {
    /// The current licence token key.
    pub key: &'a Ed25519SigningKey,
    /// The lifetime of issued tokens.
    pub policy: TokenPolicy,
    /// A signed key transition every refresh response carries while a
    /// rotation runs, or `None`.
    pub transition: Option<&'a [u8]>,
}

/// The response of the licence service to `request` at `now`.
///
/// A request outside the template gets 400, and an unknown or revoked
/// licence 404. Otherwise a fresh token, with the issuer's transition if
/// any, goes back as a refresh response body (W1g proposal). The response
/// never echoes request bytes.
#[must_use]
pub fn licence_response(
    request: &[u8],
    registry: &impl LicenceRegistry,
    issuer: &Issuer<'_>,
    now: i64,
) -> Vec<u8> {
    let Ok(refresh) = decode_refresh_request(request) else {
        return http_response(HttpStatus::BadRequest, &[]);
    };
    let licence = LicenceId(refresh.licence);
    let Some(record) = registry.lookup(&licence) else {
        return http_response(HttpStatus::NotFound, &[]);
    };
    match issue_token(licence, record.kind, now, issuer.policy, issuer.key) {
        Ok(token) => http_response(
            HttpStatus::Ok,
            &licence::refresh_response(issuer.transition, &token),
        ),
        Err(_) => http_response(HttpStatus::InternalServerError, &[]),
    }
}

// ---------------------------------------------------------------------------
// The update service.

/// The release metadata the update service serves, signed offline by a
/// release signing key.
pub trait MetadataSource {
    /// The signed metadata of the newest release on `channel`, if any.
    fn latest(&self, channel: Channel) -> Option<Vec<u8>>;
}

/// The response of the update service to `request`.
///
/// A request outside the template gets 400, and a channel without
/// metadata 404. Otherwise the signed metadata goes back unchanged. The
/// check is anonymous by design, so nothing about the caller is kept.
#[must_use]
pub fn update_response(request: &[u8], source: &impl MetadataSource) -> Vec<u8> {
    let Ok(query) = decode_update_query(request) else {
        return http_response(HttpStatus::BadRequest, &[]);
    };
    let Some(channel) = Channel::from_code(query.channel) else {
        return http_response(HttpStatus::BadRequest, &[]);
    };
    match source.latest(channel) {
        Some(metadata) => http_response(HttpStatus::Ok, &metadata),
        None => http_response(HttpStatus::NotFound, &[]),
    }
}

// ---------------------------------------------------------------------------
// Binaries.

/// Runs the licence service until shutdown.
///
/// # Errors
///
/// Returns [`ServiceError::NotImplemented`]: the listener and the
/// licence key route are not wired yet.
pub fn run_licence_service() -> Result<(), ServiceError> {
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::run_licence_service",
    ))
}

/// Runs the update service until shutdown.
///
/// # Errors
///
/// Returns [`ServiceError::NotImplemented`]: the listener is not wired
/// yet.
pub fn run_update_service() -> Result<(), ServiceError> {
    Err(ServiceError::NotImplemented(
        "fstp_release_svc::run_update_service",
    ))
}

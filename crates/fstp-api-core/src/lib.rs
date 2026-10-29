//! The API core and its one dispatch (I-84, I-85, M4 design section 3.7).
//!
//! Adapters receive an opaque [`ApiCore`] and call [`ApiCore::dispatch`].
//! `ApiCore` has no accessor for its ports. Only `fstp-cell` builds one,
//! through [`port::api_core`] (layering rules A2 and A2b). Id types reach
//! adapters only through [`ids`], and tool metadata only through [`meta`].
//! No public item here re-exports an engine, domain command or creator
//! command type, or the `fstp_access` principal.
//!
//! Status: W0 stub. Lane W3b (L-API) owns every file here except
//! `port.rs`, which the lead holds after W0. Every operation refuses with
//! [`ApiError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod decode;
pub mod ids;
pub mod meta;
pub mod port;

use std::future::Future;
use std::pin::Pin;

/// Why a call failed. It maps a domain refusal to a stable code and the
/// rule text only, and never names an account (R-CF-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for ApiError {}

/// One operation with its decoded request.
///
/// W0 placeholder with no fields. Lane W3b writes one variant per
/// operation of the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    _w0: (),
}

/// What an adapter extracted from the request. The adapter attests
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// No credential.
    None,
    /// The `__Host-` session cookie value.
    SessionCookie(Vec<u8>),
    /// An OAuth bearer token.
    Bearer(Vec<u8>),
}

/// The request head that dispatch reads.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    _w0: (),
}

/// The result of one call.
///
/// W0 placeholder with no fields. Lane W3b writes the designed variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpResult {
    _w0: (),
}

/// SHA-256 of the RFC 8785 text of the operation, its canonical request,
/// target, tenant and account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionDigest(pub [u8; 32]);

/// Implemented by hand for identity-free read models only. MCP response
/// construction requires it (I-86).
pub trait McpSafe: fstp_json::ToJson {}

/// The future that a dispatch returns.
type DispatchFuture<'a> = Pin<Box<dyn Future<Output = Result<OpResult, ApiError>> + Send + 'a>>;

/// The opaque API core. It holds the cell's ports behind a private trait
/// object and offers no accessor for them.
pub struct ApiCore {
    inner: Box<dyn port::Dispatch>,
}

impl std::fmt::Debug for ApiCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiCore(..)")
    }
}

impl ApiCore {
    /// Runs one call through every step of design section 3.7.
    pub async fn dispatch(
        &self,
        cred: Credential,
        head: &RequestHead,
        op: Op,
    ) -> Result<OpResult, ApiError> {
        self.inner.dispatch(cred, head, op).await
    }
}

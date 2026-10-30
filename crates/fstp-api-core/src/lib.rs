//! The API core and its one dispatch (I-84, I-85, M4 design section 3.7).
//!
//! Adapters receive an opaque [`ApiCore`] and call [`ApiCore::dispatch`].
//! `ApiCore` has no accessor for its ports. Only `fstp-cell` builds one,
//! through [`port::api_core`] (layering rules A2 and A2b). Id types reach
//! adapters only through [`ids`], and tool metadata only through [`meta`].
//! No public item here re-exports an engine, domain command or creator
//! command type, or the `fstp_access` principal.
//!
//! An adapter builds an [`Op`] only through the strict decoders of
//! [`decode`]: [`decode::decode_route`] for a web route and
//! [`decode::decode_tool`] for an MCP tool call. `Op` is opaque, so an
//! adapter cannot name or build an engine command (I-84).
//!
//! Lane W3b (L-API) owns every file here except `port.rs`, which the lead
//! holds. The dispatch steps live in the crate-private `dispatch` module.
//! `port.rs` wires them into [`ApiCore`] (see the module documentation of
//! `dispatch` for the seams the lead closes there).
//!
//! Every recommendation of the M4 design is built here as an interim
//! reading, pending Daniel (design section 15.0). Each module names the
//! readings it builds.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod action;
mod content;
pub mod decode;
mod dispatch;
mod forms;
pub mod ids;
mod journal;
pub mod meta;
pub mod model;
mod pageforms;
pub mod pending;
pub mod port;
pub mod rate;
pub mod views;

use std::future::Future;
use std::pin::Pin;

use fstp_json::{Object, ToJson, Value};
use fstp_ledger::Seq;

pub use model::ReadModel;
pub use pending::{PendingReceipt, PendingStatus, PendingView};

/// Why a call failed. It maps a domain refusal to a stable code and the
/// rule text only, and never names an account (R-CF-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The operation waits for a seam of another lane or of the lead. It
    /// names the seam. Nothing was recorded or executed.
    NotImplemented(&'static str),
    /// The call was refused. `code` is the stable class and `rule` the
    /// rule text only, such as `{"code":"refused","rule":"I-03"}` (design
    /// section 3.7).
    Refused {
        /// The stable class of the refusal.
        code: ErrorCode,
        /// The rule text, such as `"I-85"` or `"P-77"`.
        rule: &'static str,
    },
}

impl ApiError {
    /// A refusal of class `code` naming `rule`.
    pub(crate) const fn refused(code: ErrorCode, rule: &'static str) -> ApiError {
        ApiError::Refused { code, rule }
    }

    /// A request that did not decode. `rule` names the rule it broke.
    pub(crate) const fn bad_request(rule: &'static str) -> ApiError {
        ApiError::Refused {
            code: ErrorCode::BadRequest,
            rule,
        }
    }

    /// The HTTP status an adapter answers with (interim, pending Daniel).
    pub fn http_status(&self) -> u16 {
        match self {
            ApiError::NotImplemented(_) => 501,
            ApiError::Refused { code, .. } => code.http_status(),
        }
    }
}

/// The stable class of a refusal (design sections 3.6 and 3.7).
///
/// Interim, pending Daniel: the design names the `refused` code and the
/// channel denials. The other classes are this lane's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// The request did not decode under the operation's strict decoder.
    BadRequest,
    /// No credential, or one that resolves to no principal, for an
    /// operation that needs one.
    Unauthenticated,
    /// `ChannelVerdict::Deny(NotExposed)`: the operation has no tool.
    NotExposed,
    /// `ChannelVerdict::Deny(Scope)`: the token lacks the tool's scope.
    Scope,
    /// `ChannelVerdict::Deny(P74)`: the tenant's MCP settings refuse it.
    P74,
    /// The session's login method is too weak for the operation (I-77).
    LoginStrength,
    /// A rate limit refused the call (design section 3.7 step 4, H-07).
    RateLimited,
    /// The target does not exist for this caller.
    NotFound,
    /// The pending action expired (I-85).
    Expired,
    /// The digest the user was shown differs from the stored one (I-85).
    DigestMismatch,
    /// The domain refused the command, or an authorisation rule refused
    /// the read.
    Refused,
    /// A port could not answer, so the call failed closed and recorded
    /// nothing (`overview.md` NOTE 2).
    Unavailable,
}

impl ErrorCode {
    /// The stable code as JSON spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::NotExposed => "not_exposed",
            ErrorCode::Scope => "scope",
            ErrorCode::P74 => "p74",
            ErrorCode::LoginStrength => "login_strength",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Expired => "expired",
            ErrorCode::DigestMismatch => "digest_mismatch",
            ErrorCode::Refused => "refused",
            ErrorCode::Unavailable => "unavailable",
        }
    }

    /// The HTTP status of the class (interim, pending Daniel).
    pub const fn http_status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthenticated => 401,
            ErrorCode::NotExposed
            | ErrorCode::Scope
            | ErrorCode::P74
            | ErrorCode::LoginStrength
            | ErrorCode::Refused => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Expired => 410,
            ErrorCode::DigestMismatch => 409,
            ErrorCode::RateLimited => 429,
            ErrorCode::Unavailable => 503,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            ApiError::Refused { code, rule } => write!(f, "refused ({code:?}, rule {rule})"),
        }
    }
}

impl std::error::Error for ApiError {}

/// `{"code": "...", "rule": "..."}`. It holds the stable code and the rule
/// text only, never an account or request content (R-CF-03).
impl ToJson for ApiError {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            ApiError::NotImplemented(_) => {
                let _ = o.insert("code", Value::from("not_implemented"));
            }
            ApiError::Refused { code, rule } => {
                let _ = o.insert("code", Value::from(code.as_str()));
                let _ = o.insert("rule", Value::from(*rule));
            }
        }
        Value::Object(o)
    }
}

/// One operation with its decoded request.
///
/// Opaque: only the decoders of [`decode`] build one, so no adapter can
/// name a domain or engine command (I-84, rule A2). The request is the
/// canonical JSON object of the operation's path parameters and body
/// members, as the client sent them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// The registry entry.
    pub(crate) spec: &'static fstp_access::OpSpec,
    /// The request: path parameters and body members.
    pub(crate) request: Object,
    /// Whether the op arrived as an MCP tool call.
    pub(crate) from_tool: bool,
}

impl Op {
    /// The operation name in the registry, such as `call.publish`.
    pub fn name(&self) -> &'static str {
        self.spec.name
    }
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
/// Interim, pending Daniel: dispatch reads no header in M4. The M3
/// session port receives the head with the credential, so the adapter
/// passes the head it parsed. Fields arrive with the public rate-limit key
/// (Q19).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RequestHead {
    _private: (),
}

impl RequestHead {
    /// A head with no header the dispatch reads.
    pub fn new() -> RequestHead {
        RequestHead { _private: () }
    }
}

/// The result of one call (design section 3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpResult {
    /// The call completed. `seq` is the ledger head after a command.
    Done {
        /// The read model, or [`ReadModel::Accepted`] for a command.
        body: ReadModel,
        /// The ledger head after an appended command.
        seq: Option<Seq>,
    },
    /// The call was stored as a pending action for a web confirmation
    /// (I-85, design section 3.7 step 6).
    Pending(PendingReceipt),
    /// The high-risk call needs a step-up bound to this digest (I-78).
    StepUpRequired(port::StepUpChallenge),
    /// The account has no phishing-resistant method yet, so it adds a
    /// passkey first (`authentication.md`).
    StrongMethodRequired,
}

impl OpResult {
    /// The HTTP status an adapter answers with (interim, pending Daniel):
    /// 200 for a completed call, 202 for a pending action, and 401 for a
    /// step-up the client runs before it retries.
    pub fn http_status(&self) -> u16 {
        match self {
            OpResult::Done { .. } => 200,
            OpResult::Pending(_) => 202,
            OpResult::StepUpRequired(_) | OpResult::StrongMethodRequired => 401,
        }
    }
}

/// How long the browser may take for a step-up assertion, in
/// milliseconds, as the request options state it. P-71 bounds the proof
/// itself (interim, pending Daniel).
const STEP_UP_TIMEOUT_MS: u32 = 120_000;

/// The wire id of a step-up challenge: the first 16 bytes of the SHA-256
/// of its bytes. The M3 route that takes the assertion names the
/// challenge by this id (`POST /auth/stepup {challenge_id}`), so the
/// challenge bytes never travel as a key (interim, pending Daniel and the
/// M3 step-up port).
pub fn step_up_challenge_id(challenge: &[u8]) -> [u8; 16] {
    let h = fstp_crypto::sha256(challenge);
    let mut id = [0u8; 16];
    for (slot, b) in id.iter_mut().zip(h.iter()) {
        *slot = *b;
    }
    id
}

/// The response body of a call, as `web/src/core/api.ts` reads it:
///
/// - `Done`: the read model itself;
/// - `Pending`: `{"status":"awaiting_confirmation","confirm_path","expires"}`;
/// - `StepUpRequired`: `{"code":"step_up_required","challenge":C}`, where
///   `C` is `{"challenge_id","digest","public_key"}`: the challenge's wire
///   id, the action digest it binds, and WebAuthn request options in their
///   JSON form, with user verification required;
/// - `StrongMethodRequired`: `{"code":"strong_method_required"}`.
///
/// Ids, instants and amounts are decimal strings, digests and ids
/// lowercase hex, and the challenge unpadded base64url (interim, pending
/// Daniel). The ledger head of a command stays with the adapter.
impl ToJson for OpResult {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            OpResult::Done { body, .. } => return body.to_json(),
            OpResult::Pending(r) => {
                let _ = o.insert("status", Value::from("awaiting_confirmation"));
                let _ = o.insert("confirm_path", Value::from(r.confirm_path.as_str()));
                let _ = o.insert("expires", Value::String(r.expires.micros().to_string()));
            }
            OpResult::StepUpRequired(ch) => {
                let mut options = Object::new();
                let _ = options.insert("challenge", Value::String(action::b64url(&ch.challenge)));
                let _ = options.insert("userVerification", Value::from("required"));
                let _ = options.insert(
                    "timeout",
                    fstp_json::Number::from_lexeme(&STEP_UP_TIMEOUT_MS.to_string())
                        .map_or(Value::Null, Value::from),
                );
                let mut c = Object::new();
                let _ = c.insert(
                    "challenge_id",
                    Value::String(action::hex(&step_up_challenge_id(&ch.challenge))),
                );
                let _ = c.insert("digest", Value::String(ch.action.hex()));
                let _ = c.insert("public_key", Value::Object(options));
                let _ = o.insert("code", Value::from("step_up_required"));
                let _ = o.insert("challenge", Value::Object(c));
            }
            OpResult::StrongMethodRequired => {
                let _ = o.insert("code", Value::from("strong_method_required"));
            }
        }
        Value::Object(o)
    }
}

/// SHA-256 of the RFC 8785 text of the operation, its canonical request,
/// target, tenant and account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionDigest(pub [u8; 32]);

impl ActionDigest {
    /// The digest as 64 lowercase hexadecimal digits.
    pub fn hex(&self) -> String {
        action::hex(&self.0)
    }

    /// The digest of 64 lowercase hexadecimal digits, or `None`.
    pub fn from_hex(s: &str) -> Option<ActionDigest> {
        action::from_hex::<32>(s).map(ActionDigest)
    }
}

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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// I-78, ADR-014 "Step-up": a step-up answer is the code and a
    /// challenge of exactly `challenge_id`, `digest` and `public_key`, whose
    /// id is the first 16 bytes of the SHA-256 of the challenge, as
    /// `web/src/core/api.ts` reads it.
    #[test]
    fn i78_step_up_answer_names_its_challenge_and_digest() {
        let ch = port::StepUpChallenge {
            action: ActionDigest([7; 32]),
            challenge: b"challenge".to_vec(),
        };
        let v = OpResult::StepUpRequired(ch).to_json();
        let o = v.as_object().unwrap();
        assert_eq!(
            o.get("code").and_then(Value::as_str),
            Some("step_up_required")
        );
        let c = o.get("challenge").and_then(Value::as_object).unwrap();
        let keys: Vec<&str> = c.keys().collect();
        assert_eq!(keys, ["challenge_id", "digest", "public_key"]);
        let id = action::hex(&step_up_challenge_id(b"challenge"));
        assert_eq!(
            c.get("challenge_id").and_then(Value::as_str),
            Some(id.as_str())
        );
        assert_eq!(id.len(), 32);
        assert_eq!(
            c.get("digest").and_then(Value::as_str),
            Some(ActionDigest([7; 32]).hex().as_str())
        );
        let pk = c.get("public_key").and_then(Value::as_object).unwrap();
        assert_eq!(
            pk.get("challenge").and_then(Value::as_str),
            Some("Y2hhbGxlbmdl")
        );
        assert_eq!(
            pk.get("userVerification").and_then(Value::as_str),
            Some("required")
        );
    }

    /// I-85, design section 3.7: a completed call answers with its read
    /// model itself, and a pending one with exactly its status, path and
    /// expiry.
    #[test]
    fn i85_done_and_pending_answers() {
        let done = OpResult::Done {
            body: ReadModel::Accepted,
            seq: None,
        };
        assert_eq!(done.to_json().to_compact(), r#"{"accepted":true}"#);
        let pending = OpResult::Pending(PendingReceipt {
            id: port::PendingId::from_raw(5),
            confirm_path: "/app/pending/5".to_owned(),
            expires: fstp_domain::time::Timestamp::from_micros(9),
        });
        let v = pending.to_json();
        let keys: Vec<&str> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["status", "confirm_path", "expires"]);
    }
}

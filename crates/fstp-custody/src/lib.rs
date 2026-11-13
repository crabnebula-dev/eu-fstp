//! The `Custody` trait and its backends' clients (I-80, M3 design section
//! 3.3, ADR-004 part 2 "Custody interface" and "Backends").
//!
//! Custody never exports root material. A caller holds only references,
//! wrapped seal keys and receipts. The trait has exactly the six
//! operations of ADR-004 part 2, and none returns a root. A caller makes a call under
//! its [`RequestId`] with [`with_request`], so a keystore can record the
//! call before it makes it (ADR-004 "Reconciliation").
//!
//! - [`keyd`]: the framed protocol of the file custody server `fstp-keyd`
//!   and its client [`KeydCustody`] (Q32 A).
//! - [`usage`]: the usage record of a backend, and the reconciliation of
//!   a usage log with a chain's `KeyOp` records (ADR-004
//!   "Reconciliation").
//! - [`okms`]: the OVHcloud KMS client [`OkmsCustody`] and its response
//!   decoder. Its network calls wait on Q11 (ADR-004 part 2).
//!
//! [`SealKey`] holds an epoch seal key `S(e)` in `Zeroizing` memory. It
//! wipes on drop and implements no `Clone`, `Debug` or `ToJson`
//! (ADR-004 part 2, ADR-001 A1).

use std::future::Future;

use zeroize::{ZeroizeOnDrop, Zeroizing};

pub mod keyd;
pub mod okms;
pub mod usage;

pub use fstp_keys::{CellId, Chain, Epoch};
pub use keyd::KeydCustody;
pub use okms::OkmsCustody;

/// A custody backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackendId {
    /// OVHcloud KMS.
    Okms,
    /// File custody through `fstp-keyd`.
    Keyd,
    /// The test simulator in `fstp-celltest`.
    Simulator,
}

/// A request id (ADR-004 "Reconciliation"). Every custody call carries
/// one, and a backend with a usage log records it ([`usage`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub [u8; keyd::REQUEST_ID_LEN]);

impl RequestId {
    /// A fresh random request id.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Crypto`] when the generator fails.
    pub fn generate() -> Result<RequestId, CustodyError> {
        fstp_crypto::random_array()
            .map(RequestId)
            .map_err(CustodyError::Crypto)
    }
}

/// An opaque handle that a backend gives a root or signing key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustodyHandle(pub Vec<u8>);

/// A reference to a custody root. It never holds root material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRef {
    /// The backend.
    pub backend: BackendId,
    /// The cell, or `None` for a shared chain.
    pub cell: Option<CellId>,
    /// The chain.
    pub chain: Chain,
    /// The root epoch.
    pub epoch: Epoch,
    /// The backend handle.
    pub handle: CustodyHandle,
}

/// The label a new root is created with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootLabel {
    /// The cell, or `None` for a shared chain.
    pub cell: Option<CellId>,
    /// The chain.
    pub chain: Chain,
    /// The root epoch.
    pub epoch: Epoch,
}

/// A 32-byte epoch seal key `S(e)`. It implements no `Clone`, no `Debug`
/// and no `ToJson`, and wipes its bytes on drop (ADR-004 part 2).
pub struct SealKey(Zeroizing<[u8; 32]>);

impl ZeroizeOnDrop for SealKey {}

impl SealKey {
    /// Wraps key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> SealKey {
        SealKey(Zeroizing::new(bytes))
    }

    /// A fresh seal key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Crypto`] when the generator fails.
    pub fn generate() -> Result<SealKey, CustodyError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fstp_crypto::random_bytes(&mut bytes[..]).map_err(CustodyError::Crypto)?;
        Ok(SealKey(bytes))
    }

    /// The key bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A seal key wrapped by a backend. Opaque and backend-specific.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSealKey(pub Vec<u8>);

/// A reference to a custody signing key (EC secp256r1, CA use only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignKeyRef {
    /// The backend.
    pub backend: BackendId,
    /// The backend handle.
    pub handle: CustodyHandle,
}

/// Associated data bound into a wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aad(pub Vec<u8>);

/// The backend's receipt for a destroyed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestroyReceipt(pub Vec<u8>);

/// A DER-encoded ECDSA signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSignature(pub Vec<u8>);

/// A position in a backend's usage log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageCursor(pub Vec<u8>);

/// One page of a backend's usage log, for reconciliation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsagePage {
    /// The operations, as opaque records in the layout of [`usage`].
    /// [`usage::decode_entry`] reads one.
    pub operations: Vec<Vec<u8>>,
    /// The cursor after this page.
    pub next: UsageCursor,
}

/// Why a backend refused a request it understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request did not decode.
    BadRequest,
    /// The backend holds no root or key under this handle.
    UnknownRoot,
    /// The root is destroyed.
    Destroyed,
    /// The wrapped key did not unwrap under this root and AAD.
    UnwrapFailed,
    /// The epoch is older than one the chain already has.
    StaleEpoch,
    /// The backend holds no signing key for this handle.
    NoSignKey,
    /// The backend reached a limit, such as a seal count.
    LimitReached,
    /// The backend failed on its own side, such as its key volume.
    Internal,
    /// The client may not use this chain or key. Each `fstp-keyd` socket
    /// serves a fixed set of chains (ADR-004 part 2, R-NF-08).
    NotPermitted,
}

impl Refusal {
    /// The one-byte code of the refusal on the keyd wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Refusal::BadRequest => 1,
            Refusal::UnknownRoot => 2,
            Refusal::Destroyed => 3,
            Refusal::UnwrapFailed => 4,
            Refusal::StaleEpoch => 5,
            Refusal::NoSignKey => 6,
            Refusal::LimitReached => 7,
            Refusal::Internal => 8,
            Refusal::NotPermitted => 9,
        }
    }

    /// The refusal of a wire code, if the code is known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Refusal> {
        match code {
            1 => Some(Refusal::BadRequest),
            2 => Some(Refusal::UnknownRoot),
            3 => Some(Refusal::Destroyed),
            4 => Some(Refusal::UnwrapFailed),
            5 => Some(Refusal::StaleEpoch),
            6 => Some(Refusal::NoSignKey),
            7 => Some(Refusal::LimitReached),
            8 => Some(Refusal::Internal),
            9 => Some(Refusal::NotPermitted),
            _ => None,
        }
    }

    const fn text(self) -> &'static str {
        match self {
            Refusal::BadRequest => "the backend could not decode the request",
            Refusal::UnknownRoot => "the backend holds no such root",
            Refusal::Destroyed => "the root is destroyed",
            Refusal::UnwrapFailed => "the wrapped key did not unwrap",
            Refusal::StaleEpoch => "the epoch is older than the chain's newest",
            Refusal::NoSignKey => "the backend holds no such signing key",
            Refusal::LimitReached => "the backend reached a limit",
            Refusal::Internal => "the backend failed on its side",
            Refusal::NotPermitted => "the client may not use this chain or key",
        }
    }
}

/// Why a custody operation failed. Its display never holds key bytes or
/// input bytes: every variant carries static text or a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// Kept for the stub backends that still refuse with it.
    NotImplemented(&'static str),
    /// The backend refused the request.
    Refused(Refusal),
    /// The link to the backend failed. It names the stage.
    Transport(&'static str),
    /// The backend's answer broke the protocol. It names the rule.
    Protocol(&'static str),
    /// The client configuration is refused. It names the rule.
    InvalidConfig(&'static str),
    /// The backend waits on a decision that is not recorded yet. It names
    /// the decision.
    AwaitingDecision(&'static str),
    /// The crypto layer refused.
    Crypto(fstp_crypto::CryptoError),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            CustodyError::Refused(r) => write!(f, "custody refused: {}", r.text()),
            CustodyError::Transport(s) => write!(f, "custody link failed: {s}"),
            CustodyError::Protocol(s) => write!(f, "custody protocol: {s}"),
            CustodyError::InvalidConfig(s) => write!(f, "custody client refused: {s}"),
            CustodyError::AwaitingDecision(s) => write!(f, "custody waits on a decision: {s}"),
            CustodyError::Crypto(e) => write!(f, "custody crypto: {e}"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// A custody backend. It creates, uses and destroys roots, and never
/// exports one (I-80).
pub trait Custody: Send + Sync + 'static {
    /// Creates a new root.
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send;
    /// Wraps a seal key under a root.
    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send;
    /// Unwraps a seal key under a root.
    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send;
    /// Destroys a root and returns the backend's receipt.
    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send;
    /// Signs a SHA-256 digest with a CA key.
    fn sign(
        &self,
        key: &SignKeyRef,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send;
    /// Reads the backend's usage log from `cursor`.
    fn usage_since(
        &self,
        root: &RootRef,
        cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send;
}

// ---------------------------------------------------------------------------
// The request id of a call (ADR-004 "Reconciliation").
//
// The `Custody` trait keeps exactly the six operations of ADR-004 part 2
// (I-80). A caller that has recorded a call under a request id makes the
// call inside `with_request`, and a backend with a usage log reads the id
// with `current_request` when it builds the call. A backend reads it at
// the call, at a poll of its future, or both, and `with_request` holds
// the id over each.

std::thread_local! {
    static CURRENT_REQUEST: std::cell::Cell<Option<RequestId>> =
        const { std::cell::Cell::new(None) };
}

/// The request id of the custody call being made on this thread, if the
/// caller gave one ([`with_request`]).
#[must_use]
pub fn current_request() -> Option<RequestId> {
    CURRENT_REQUEST.with(std::cell::Cell::get)
}

/// The caller's request id, or a fresh one: what a backend with a usage
/// log sends.
///
/// # Errors
///
/// Returns [`CustodyError::Crypto`] when the generator fails.
pub fn request_or_fresh() -> Result<RequestId, CustodyError> {
    current_request().map_or_else(RequestId::generate, Ok)
}

/// Sets the current request id until dropped, then restores the one
/// before.
struct RequestScope(Option<RequestId>);

impl RequestScope {
    fn enter(id: RequestId) -> RequestScope {
        RequestScope(CURRENT_REQUEST.with(|c| c.replace(Some(id))))
    }
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        let before = self.0;
        CURRENT_REQUEST.with(|c| c.set(before));
    }
}

/// A custody call made under a request id ([`with_request`]).
pub struct WithRequest<F> {
    id: RequestId,
    call: std::pin::Pin<Box<F>>,
}

impl<F: Future> Future for WithRequest<F> {
    type Output = F::Output;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        let _scope = RequestScope::enter(self.id);
        self.call.as_mut().poll(cx)
    }
}

/// Makes the custody call `call` under the request id `id`. The id is
/// current while `call` runs and while its future is polled, so the
/// backend logs it (ADR-004 "Reconciliation").
pub fn with_request<F: Future>(id: RequestId, call: impl FnOnce() -> F) -> WithRequest<F> {
    let scope = RequestScope::enter(id);
    let call = Box::pin(call());
    drop(scope);
    WithRequest { id, call }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod request_tests {
    use super::*;

    /// ADR-004 "Reconciliation": the caller's request id is current while
    /// the call is made and while its future is polled, and only then.
    #[test]
    fn adr004_with_request_holds_the_id_over_the_call_and_its_polls() {
        let id = RequestId([3; 16]);
        let inner = RequestId([4; 16]);
        assert_eq!(current_request(), None);
        let mut at_call = None;
        let fut = with_request(id, || {
            at_call = current_request();
            async {
                let first = current_request();
                let nested = with_request(inner, || async { current_request() }).await;
                (first, nested, current_request())
            }
        });
        assert_eq!(at_call, Some(id));
        assert_eq!(current_request(), None, "the id leaked out of the call");
        let got = fstp_rt::future::block_on(fut);
        assert_eq!(got, (Some(id), Some(inner), Some(id)));
        assert_eq!(current_request(), None, "the id leaked out of the poll");
        assert_eq!(request_or_fresh().map(|r| r == id), Ok(false));
    }
}

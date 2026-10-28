//! The `Custody` trait and its backends' clients (I-80, M3 design section
//! 3.3, ADR-004).
//!
//! Custody never exports root material. A caller holds only references,
//! wrapped seal keys and receipts.
//!
//! Status: W0 stub. Lane W2f fills the crate. Every operation refuses with
//! [`CustodyError::NotImplemented`].
//!
//! Seam: [`SealKey`] is designed as `Zeroizing<[u8; 32]>`. zeroize is not
//! a dependency until Daniel accepts ADR-001 A1, so the type holds a plain
//! array and does not wipe it yet (`docs/handoff/m3-base.md`).

use std::future::Future;

pub mod keyd;
pub mod okms;

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

/// A 32-byte seal key. It implements no `Clone`, no `Debug` and no
/// `ToJson`.
pub struct SealKey([u8; 32]);

impl SealKey {
    /// Wraps key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> SealKey {
        SealKey(bytes)
    }

    /// The key bytes.
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
    /// The operations, as opaque records.
    pub operations: Vec<Vec<u8>>,
    /// The cursor after this page.
    pub next: UsageCursor,
}

/// Why a custody operation failed. Its display never holds key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
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

/// Implements every [`Custody`] method of a stub client as a refusal.
macro_rules! refusing_custody {
    ($ty:ty, $name:literal) => {
        impl $crate::Custody for $ty {
            fn create_root(
                &self,
                label: $crate::RootLabel,
            ) -> impl std::future::Future<Output = Result<$crate::RootRef, $crate::CustodyError>>
            + Send {
                let _ = label;
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name,
                    "::create_root"
                ))))
            }
            fn wrap(
                &self,
                root: &$crate::RootRef,
                key: &$crate::SealKey,
                aad: &$crate::Aad,
            ) -> impl std::future::Future<
                Output = Result<$crate::WrappedSealKey, $crate::CustodyError>,
            > + Send {
                let _ = (root, key, aad);
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name, "::wrap"
                ))))
            }
            fn unwrap(
                &self,
                root: &$crate::RootRef,
                w: &$crate::WrappedSealKey,
                aad: &$crate::Aad,
            ) -> impl std::future::Future<Output = Result<$crate::SealKey, $crate::CustodyError>>
            + Send {
                let _ = (root, w, aad);
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name, "::unwrap"
                ))))
            }
            fn destroy(
                &self,
                root: &$crate::RootRef,
            ) -> impl std::future::Future<
                Output = Result<$crate::DestroyReceipt, $crate::CustodyError>,
            > + Send {
                let _ = root;
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name,
                    "::destroy"
                ))))
            }
            fn sign(
                &self,
                key: &$crate::SignKeyRef,
                digest: &[u8; 32],
            ) -> impl std::future::Future<
                Output = Result<$crate::EcdsaSignature, $crate::CustodyError>,
            > + Send {
                let _ = (key, digest);
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name, "::sign"
                ))))
            }
            fn usage_since(
                &self,
                root: &$crate::RootRef,
                cursor: $crate::UsageCursor,
            ) -> impl std::future::Future<Output = Result<$crate::UsagePage, $crate::CustodyError>>
            + Send {
                let _ = (root, cursor);
                std::future::ready(Err($crate::CustodyError::NotImplemented(concat!(
                    $name,
                    "::usage_since"
                ))))
            }
        }
    };
}
pub(crate) use refusing_custody;

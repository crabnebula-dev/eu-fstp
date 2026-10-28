//! Licence token and release metadata formats, licence state,
//! `may_apply`, and the I-38 egress client (M3 design section 10).
//!
//! Only `fstp-cell` and `fstp-release-svc` reach this crate, so no command
//! path depends on the licence (I-39, layering rule 6).
//!
//! Status: W0 stub. Lane W2j fills the crate. Every operation refuses with
//! [`ReleaseError::NotImplemented`]. The designed `encode`, `licence_state`
//! and `permits` are infallible; they return a `Result` until the lane
//! lands them, so a stub never answers a licence question.

pub mod egress;
pub mod licence;
pub mod metadata;

/// Why a release operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

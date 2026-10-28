//! Licence tokens and licence state (design section 10.2, Q18).

use crate::ReleaseError;

/// A licence, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LicenceId(pub [u8; 16]);

/// A licence kind. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenceKind {
    /// A self-hosted licence.
    SelfHosted,
}

/// A licence token whose signature verified under a pinned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The licence.
    pub licence: LicenceId,
    /// The kind.
    pub kind: LicenceKind,
    /// UTC seconds.
    pub issued_at: i64,
    /// UTC seconds.
    pub refresh_after: i64,
    /// UTC seconds.
    pub not_after: i64,
}

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Public(pub [u8; 32]);

/// The licence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenceState {
    /// Valid until a time.
    Valid {
        /// UTC seconds.
        until: i64,
    },
    /// In the P-43 grace period.
    Grace {
        /// UTC seconds.
        since: i64,
        /// UTC seconds.
        ends: i64,
    },
    /// Expired.
    Expired {
        /// UTC seconds.
        since: i64,
    },
    /// No licence.
    Missing,
}

/// What a licence check gates. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateKind {
    /// Applying an update.
    ApplyUpdate,
}

/// Verifies a token's signature before any field is used. Fuzzed
/// (`licence_token_decode`).
pub fn verify_token(bytes: &[u8], key: &Ed25519Public) -> Result<VerifiedToken, ReleaseError> {
    let _ = (bytes, key);
    Err(ReleaseError::NotImplemented(
        "fstp_release::licence::verify_token",
    ))
}

/// Decodes an imported licence file. Fuzzed (`licence_file_import_decode`).
pub fn decode_licence_file(bytes: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    let _ = bytes;
    Err(ReleaseError::NotImplemented(
        "fstp_release::licence::decode_licence_file",
    ))
}

/// Decodes a licence key transition, accepted only when signed by a pinned
/// key (I-39). Fuzzed (`key_transition_decode`).
pub fn decode_key_transition(bytes: &[u8]) -> Result<Ed25519Public, ReleaseError> {
    let _ = bytes;
    Err(ReleaseError::NotImplemented(
        "fstp_release::licence::decode_key_transition",
    ))
}

/// The licence state at `now`, with a grace period of `p43_days`.
pub fn licence_state(
    token: Option<&VerifiedToken>,
    last_ok: Option<i64>,
    now: i64,
    p43_days: u16,
) -> Result<LicenceState, ReleaseError> {
    let _ = (token, last_ok, now, p43_days);
    Err(ReleaseError::NotImplemented(
        "fstp_release::licence::licence_state",
    ))
}

/// Whether the state permits `kind`. True for every kind in M3 (Q18).
pub fn permits(state: LicenceState, kind: GateKind) -> Result<bool, ReleaseError> {
    let _ = (state, kind);
    Err(ReleaseError::NotImplemented(
        "fstp_release::licence::permits",
    ))
}

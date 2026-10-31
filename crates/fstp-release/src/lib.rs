//! Licence token and release metadata formats, licence state,
//! `may_apply`, and the I-38 egress client (M3 design section 10).
//!
//! Only `fstp-cell` and `fstp-release-svc` reach this crate, so no command
//! path depends on the licence (I-39, layering rule 6). The crate reaches
//! no crate that decodes tenant data (layering rule 4), so no request it
//! builds can carry tenant data (I-38).
//!
//! Every decoder checks lengths, magic and the signature before it reads
//! any field (design section 15). Every function is total: none panics,
//! and time sums saturate, so an overflow never wraps into the past.
//!
//! The wire formats are the W1g proposal of
//! `crates/fstp-celltest/src/reference/licence.rs`.

pub mod egress;
pub mod licence;
pub mod metadata;
mod wire;

/// Why a release operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseError {
    /// A W0 stub refusal. No operation of this crate returns it now. It
    /// stays so that callers which name the stub refusal still compile.
    NotImplemented(&'static str),
    /// The input has another length than its format fixes.
    Length,
    /// The input does not start with its format's magic.
    Magic,
    /// No key the caller trusts signed the input.
    Signature,
    /// A signed token carries an unknown licence kind.
    Kind,
    /// A signed token's instants are not
    /// `issued_at <= refresh_after <= not_after`.
    Order,
    /// A refresh response or licence file is not framed as its format
    /// says.
    Framing,
    /// A refreshed token names another licence than the stored one.
    OtherLicence,
    /// A refreshed token is older than the stored one, or another token
    /// with the same issue instant.
    Stale,
    /// The key set already holds [`licence::MAX_KEYS`] keys.
    KeySetFull,
    /// A key set names the same key twice.
    DuplicateKey,
    /// A key to pin encodes an Ed25519 point of small order, which would
    /// let anyone forge signatures under it.
    WeakKey,
    /// Signing failed in `fstp-crypto`.
    Signing,
    /// The HTTP response is not framed as the egress decoder accepts.
    Http,
    /// The input is larger than its decoder accepts.
    TooLarge,
    /// Release metadata cannot be verified yet: no release key is
    /// certified by the release root until I-91 lands in M9.
    NotYetVerifiable,
    /// Signed release metadata names an unknown channel.
    Channel,
    /// Release metadata expired at or before `now`.
    Expired,
    /// Release metadata has a lower metadata version than the highest
    /// accepted.
    Rollback,
    /// Release metadata has the highest accepted metadata version but
    /// another body.
    Conflict,
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ReleaseError::NotImplemented(op) => return write!(f, "{op} is not implemented"),
            ReleaseError::Length => "wrong length",
            ReleaseError::Magic => "wrong magic",
            ReleaseError::Signature => "no trusted key signed the input",
            ReleaseError::Kind => "unknown licence kind",
            ReleaseError::Order => "token instants out of order",
            ReleaseError::Framing => "malformed framing",
            ReleaseError::OtherLicence => "token for another licence",
            ReleaseError::Stale => "token older than the stored one",
            ReleaseError::KeySetFull => "licence key set full",
            ReleaseError::DuplicateKey => "licence key set names a key twice",
            ReleaseError::WeakKey => "licence key of small order",
            ReleaseError::Signing => "signing failed",
            ReleaseError::Http => "malformed HTTP response",
            ReleaseError::TooLarge => "input too large",
            ReleaseError::NotYetVerifiable => "release metadata not yet verifiable",
            ReleaseError::Channel => "unknown channel",
            ReleaseError::Expired => "release metadata expired",
            ReleaseError::Rollback => "release metadata rollback",
            ReleaseError::Conflict => "release metadata conflict",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ReleaseError {}

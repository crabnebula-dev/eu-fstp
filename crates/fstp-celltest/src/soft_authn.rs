//! The software authenticator: real WebAuthn registrations and assertions
//! with ES256 and Ed25519 keys, and faults (design section 14.3). Lane W1a.

use crate::NotImplemented;

/// A fault the authenticator can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A wrong origin.
    WrongOrigin,
    /// A wrong RP id hash.
    WrongRpIdHash,
    /// User verification off.
    NoUserVerification,
    /// A replayed challenge.
    ReplayedChallenge,
    /// A counter regression.
    CounterRegression,
}

/// The software authenticator.
#[derive(Debug)]
pub struct SoftAuthenticator {
    credentials: usize,
}

impl SoftAuthenticator {
    /// A new authenticator.
    pub fn new() -> Result<SoftAuthenticator, NotImplemented> {
        Err(NotImplemented::new(
            "fstp_celltest::soft_authn::SoftAuthenticator::new",
        ))
    }

    /// The number of credentials it holds.
    pub fn credentials(&self) -> usize {
        self.credentials
    }
}

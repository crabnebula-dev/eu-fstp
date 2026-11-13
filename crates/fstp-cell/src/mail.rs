//! The cell's proof mail port (design section 8.3 ceremony 2, lane
//! F-CYCLE3).
//!
//! A self-registration proves its email address with a single-use token
//! that the cell sends to that address. The token never enters the
//! ledger: the route stores only its SHA-256 digest (`auth.token`), and
//! hands the token to a [`ProofMail`].
//!
//! [`NoProofMail`] is the port of a serving cell today. It refuses every
//! send, so `POST /auth/signup/options {email}` answers 503 and no account
//! is created. M6 delivery (the tenant's mail relay through
//! `crate::egress::MailEgress`) is the planned production port. A test
//! world passes a port of its own through `crate::process::StartOptions`
//! that captures each proof, and says so in its claims.

/// What a proof mail proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// The email proof of a self-registration.
    Signup,
}

/// Why a proof mail was not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailRefused {
    /// The cell has no mail delivery.
    NoDelivery,
}

/// Sends a proof token to an email address (module documentation).
pub trait ProofMail: Send + Sync + 'static {
    /// Sends `token` of `kind` to `to`.
    ///
    /// # Errors
    ///
    /// [`MailRefused`] when the mail was not handed on.
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused>;
}

/// The port of a serving cell before M6 delivery: it sends nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoProofMail;

impl ProofMail for NoProofMail {
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused> {
        let _ = (kind, to, token);
        Err(MailRefused::NoDelivery)
    }
}

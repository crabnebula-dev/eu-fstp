//! The in-house WebAuthn subset (ADR-001 A4, ADR-008, M3 design section
//! 8.1). Pure.
//!
//! It parses a strict CBOR subset, COSE keys, authenticator data and client
//! data, and verifies registrations and assertions with ES256, EdDSA and
//! RS256 through `fstp-crypto`. Attestation format `none` only.
//!
//! Status: W0 stub. Lane W2a fills the crate. Every parser and verifier
//! refuses with [`WebAuthnError::NotImplemented`]. Each parser has a fuzz
//! target from this first commit (TH-26).

pub mod cbor;

/// Why a WebAuthn operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// A decoded attestation object (format `none`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationObject {
    /// The authenticator data.
    pub auth_data: AuthenticatorData,
}

/// Decoded authenticator data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP id.
    pub rp_id_hash: [u8; 32],
    /// The flags byte.
    pub flags: u8,
    /// The signature counter.
    pub sign_count: u32,
}

/// A COSE public key of an allowed algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseKey {
    /// ES256: an uncompressed P-256 point.
    Es256 {
        /// The x coordinate.
        x: [u8; 32],
        /// The y coordinate.
        y: [u8; 32],
    },
    /// EdDSA over Ed25519.
    Ed25519 {
        /// The public key.
        x: [u8; 32],
    },
    /// RS256 with a modulus of at least 2048 bits.
    Rs256 {
        /// The modulus.
        n: Vec<u8>,
        /// The public exponent.
        e: Vec<u8>,
    },
}

/// Decoded client data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientData {
    /// `webauthn.create` or `webauthn.get`.
    pub kind: String,
    /// The challenge bytes.
    pub challenge: Vec<u8>,
    /// The origin.
    pub origin: String,
}

/// The relying party: the exact cell host and its origin (I-20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    id: String,
    origin: String,
}

impl RelyingParty {
    /// The relying party for `host`. A registrable parent domain is refused.
    pub fn new(host: &str) -> Result<RelyingParty, WebAuthnError> {
        let _ = host;
        Err(WebAuthnError::NotImplemented(
            "fstp_webauthn::RelyingParty::new",
        ))
    }

    /// The RP id and origin.
    pub fn parts(&self) -> (&str, &str) {
        (&self.id, &self.origin)
    }
}

/// A registration response from the browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationResponse {
    /// The client data JSON bytes.
    pub client_data_json: Vec<u8>,
    /// The attestation object bytes.
    pub attestation_object: Vec<u8>,
}

/// What a registration must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationExpect {
    /// The relying party.
    pub rp: RelyingParty,
    /// The challenge.
    pub challenge: [u8; 32],
}

/// A verified new credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCredential {
    /// The credential id.
    pub id: Vec<u8>,
    /// The public key.
    pub key: CoseKey,
    /// The signature counter.
    pub sign_count: u32,
}

/// An assertion response from the browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionResponse {
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The client data JSON bytes.
    pub client_data_json: Vec<u8>,
    /// The authenticator data bytes.
    pub authenticator_data: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// A stored credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCredential {
    /// The credential id.
    pub id: Vec<u8>,
    /// The public key.
    pub key: CoseKey,
    /// The last signature counter.
    pub sign_count: u32,
}

/// What an assertion must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionExpect {
    /// The relying party.
    pub rp: RelyingParty,
    /// The challenge.
    pub challenge: [u8; 32],
    /// Whether user verification is required.
    pub user_verification: bool,
}

/// A verified assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssertionOk {
    /// The new signature counter.
    pub sign_count: u32,
    /// Whether the user was verified.
    pub user_verified: bool,
}

/// Parses an attestation object (CBOR). Fuzzed (`attestation_object_decode`).
pub fn parse_attestation_object(b: &[u8]) -> Result<AttestationObject, WebAuthnError> {
    let _ = b;
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::parse_attestation_object",
    ))
}

/// Parses authenticator data. Fuzzed (`authenticator_data_decode`).
pub fn parse_authenticator_data(b: &[u8]) -> Result<AuthenticatorData, WebAuthnError> {
    let _ = b;
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::parse_authenticator_data",
    ))
}

/// Parses a COSE key. Fuzzed (`cose_key_decode`).
pub fn parse_cose_key(b: &[u8]) -> Result<CoseKey, WebAuthnError> {
    let _ = b;
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::parse_cose_key",
    ))
}

/// Parses client data JSON through `fstp-json`. Fuzzed (`client_data_decode`).
pub fn parse_client_data(b: &[u8]) -> Result<ClientData, WebAuthnError> {
    let _ = b;
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::parse_client_data",
    ))
}

/// Verifies a registration. Fuzzed (`registration_verify`).
pub fn verify_registration(
    r: &RegistrationResponse,
    x: &RegistrationExpect,
) -> Result<NewCredential, WebAuthnError> {
    let _ = (r, x);
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::verify_registration",
    ))
}

/// Verifies an assertion. Fuzzed (`assertion_verify`).
pub fn verify_assertion(
    a: &AssertionResponse,
    c: &StoredCredential,
    x: &AssertionExpect,
) -> Result<AssertionOk, WebAuthnError> {
    let _ = (a, c, x);
    Err(WebAuthnError::NotImplemented(
        "fstp_webauthn::verify_assertion",
    ))
}

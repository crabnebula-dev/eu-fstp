//! The in-house WebAuthn subset (ADR-001 A4, ADR-008, M3 design section
//! 8.1). Pure: no I/O, no floats, no panics, checked arithmetic and
//! bounded allocation.
//!
//! It parses a strict CBOR subset ([`cbor`]), COSE keys, authenticator
//! data and client data. It verifies registrations (WebAuthn Level 2
//! section 7.1) and assertions (section 7.2) with ES256, EdDSA and RS256.
//! Every signature is checked through `fstp_crypto::sig`, and no
//! primitive lives here. The attestation format is `none` only.
//!
//! Each parser and verifier has a fuzz target under `fuzz/` (TH-26,
//! design section 15).
//!
//! Readings this crate builds, beyond the text of ADR-008:
//!
//! - The RP id is the exact cell host in one spelling: lower-case LDH
//!   labels or A-labels, at least three labels, and a top label that is
//!   not all digits. Without a public suffix list, a host of one or two
//!   labels counts as a registrable domain and is refused. So is
//!   `localhost`.
//! - `crossOrigin` true is refused, since a cell never embeds a ceremony
//!   in another origin's frame.
//! - A sign count equal to the stored one, or zero after a non-zero one,
//!   is refused (WebAuthn Level 2 section 7.2 step 21).
//! - The backup flags BE and BS are accepted. BS without BE is refused
//!   by the verifiers (WebAuthn Level 3).
//! - An assertion whose authenticator data carries attested credential
//!   data is refused.
//! - The CBOR subset also refuses the simple values `false`, `true`,
//!   `null` and `undefined`. No field this crate reads takes one, and the
//!   platform requests no authenticator extension whose output would.

pub mod cbor;

mod attestation;
mod auth_data;
mod client_data;
mod cose;

use std::fmt;

pub use cbor::CborError;

/// The authenticator data flags (WebAuthn Level 2 section 6.1, Level 3
/// for BE and BS).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible (Level 3).
    pub const BE: u8 = 0x08;
    /// Backed up (Level 3).
    pub const BS: u8 = 0x10;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
    /// Extension data included.
    pub const ED: u8 = 0x80;
}

/// Why a WebAuthn operation failed. No variant carries input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    /// Kept from the W0 stub so that callers written against it still
    /// compile. No operation of this crate returns it any more.
    NotImplemented(&'static str),
    /// The bytes are not one item of the strict CBOR subset.
    Cbor(CborError),
    /// The COSE key is malformed or outside the ADR-008 algorithms.
    CoseKey,
    /// The authenticator data is malformed.
    AuthenticatorData,
    /// The client data is not the JSON object WebAuthn defines.
    ClientData,
    /// The attestation object does not have exactly its three members of
    /// the right types.
    AttestationObject,
    /// The attestation format is not `none`, or its statement is not the
    /// empty map.
    AttestationFormat,
    /// The host is not a cell host in its one spelling, or it is a
    /// registrable parent domain.
    RelyingPartyHost,
    /// The client data type is not the one the ceremony needs.
    CeremonyType,
    /// The client data carries another challenge.
    Challenge,
    /// The client data carries another origin.
    Origin,
    /// The client data says the ceremony ran in a cross-origin frame.
    CrossOrigin,
    /// The authenticator data is for another RP id.
    RpIdHash,
    /// The UP flag is clear.
    UserPresence,
    /// User verification is required and the UV flag is clear.
    UserVerification,
    /// The BS flag is set without the BE flag.
    BackupState,
    /// A registration carries no attested credential data, or an
    /// assertion carries some.
    AttestedCredential,
    /// The credential id is empty, longer than 1023 bytes, or not the
    /// stored credential's id.
    CredentialId,
    /// The signature does not verify under the stored key.
    Signature,
    /// The signature verifies, but the sign count did not grow while a
    /// count is non-zero. The caller records `CredentialSuspect`
    /// (ADR-008 "Sign counts").
    SignCountRegression {
        /// The stored count.
        stored: u32,
        /// The asserted count.
        asserted: u32,
    },
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented(op) => write!(f, "{op} is not implemented"),
            Self::Cbor(e) => write!(f, "CBOR outside the strict subset: {e:?}"),
            Self::CoseKey => f.write_str("COSE key refused"),
            Self::AuthenticatorData => f.write_str("authenticator data malformed"),
            Self::ClientData => f.write_str("client data malformed"),
            Self::AttestationObject => f.write_str("attestation object malformed"),
            Self::AttestationFormat => f.write_str("attestation other than none"),
            Self::RelyingPartyHost => f.write_str("host refused as RP id"),
            Self::CeremonyType => f.write_str("wrong client data type"),
            Self::Challenge => f.write_str("wrong challenge"),
            Self::Origin => f.write_str("wrong origin"),
            Self::CrossOrigin => f.write_str("cross-origin ceremony"),
            Self::RpIdHash => f.write_str("wrong RP id hash"),
            Self::UserPresence => f.write_str("user not present"),
            Self::UserVerification => f.write_str("user not verified"),
            Self::BackupState => f.write_str("backed up without backup eligibility"),
            Self::AttestedCredential => f.write_str("attested credential data misplaced"),
            Self::CredentialId => f.write_str("credential id refused"),
            Self::Signature => f.write_str("signature did not verify"),
            Self::SignCountRegression { stored, asserted } => {
                write!(f, "sign count {asserted} after {stored}")
            }
        }
    }
}

impl std::error::Error for WebAuthnError {}

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

/// The longest host name (RFC 1035 section 2.3.4).
const MAX_HOST: usize = 253;
/// The longest label (RFC 1035 section 2.3.4).
const MAX_LABEL: usize = 63;
/// The fewest labels of a host below a registrable domain.
const MIN_LABELS: usize = 3;

impl RelyingParty {
    /// The relying party for `host`. A registrable parent domain is refused.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::RelyingPartyHost`] unless `host` is a host name of
    /// at least three lower-case LDH labels whose top label is not all
    /// digits. Schemes, ports, paths, IP literals, wildcards, upper case,
    /// U-labels and a trailing dot are refused.
    pub fn new(host: &str) -> Result<RelyingParty, WebAuthnError> {
        if host.is_empty() || host.len() > MAX_HOST {
            return Err(WebAuthnError::RelyingPartyHost);
        }
        let mut labels = 0usize;
        let mut top = "";
        for label in host.split('.') {
            if !ldh_label(label) {
                return Err(WebAuthnError::RelyingPartyHost);
            }
            labels = labels.saturating_add(1);
            top = label;
        }
        if labels < MIN_LABELS || top.bytes().all(|c| c.is_ascii_digit()) {
            return Err(WebAuthnError::RelyingPartyHost);
        }
        Ok(RelyingParty {
            id: host.to_owned(),
            origin: format!("https://{host}"),
        })
    }

    /// The RP id and origin.
    pub fn parts(&self) -> (&str, &str) {
        (&self.id, &self.origin)
    }
}

/// Whether `label` is 1 to 63 lower-case letters, digits and hyphens,
/// neither starting nor ending with a hyphen.
fn ldh_label(label: &str) -> bool {
    let b = label.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
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
    /// Whether user verification is required, as for the first passkey
    /// of an account with holdings (ADR-008 "User verification").
    pub user_verification: bool,
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
    /// Whether the UV flag was set. The cell records it for applicant
    /// passkeys (ADR-008 "User verification").
    pub user_verified: bool,
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
///
/// # Errors
///
/// A [`WebAuthnError`] naming the first rule the bytes break.
pub fn parse_attestation_object(b: &[u8]) -> Result<AttestationObject, WebAuthnError> {
    attestation::parse(b).map(|p| AttestationObject { auth_data: p.data })
}

/// Parses authenticator data. Fuzzed (`authenticator_data_decode`).
///
/// # Errors
///
/// A [`WebAuthnError`] naming the first rule the bytes break.
pub fn parse_authenticator_data(b: &[u8]) -> Result<AuthenticatorData, WebAuthnError> {
    auth_data::parse(b).map(|p| p.data)
}

/// Parses a COSE key. Fuzzed (`cose_key_decode`).
///
/// # Errors
///
/// [`WebAuthnError::Cbor`] for bytes outside the strict CBOR subset, and
/// [`WebAuthnError::CoseKey`] for a key outside ADR-008.
pub fn parse_cose_key(b: &[u8]) -> Result<CoseKey, WebAuthnError> {
    cose::parse(b)
}

/// Parses client data JSON through `fstp-json`. Fuzzed (`client_data_decode`).
///
/// # Errors
///
/// [`WebAuthnError::ClientData`] unless `b` is one JSON object with
/// string members `type`, `challenge` (unpadded base64url) and `origin`.
pub fn parse_client_data(b: &[u8]) -> Result<ClientData, WebAuthnError> {
    client_data::parse(b).map(|p| p.data)
}

/// The checks the two ceremonies share on client data: type, challenge,
/// origin and `crossOrigin` (WebAuthn Level 2 section 7.1 steps 7 to 9,
/// section 7.2 steps 11 to 13).
fn check_client_data(
    b: &[u8],
    kind: &str,
    rp: &RelyingParty,
    challenge: &[u8; 32],
) -> Result<(), WebAuthnError> {
    let cd = client_data::parse(b)?;
    if cd.data.kind != kind {
        return Err(WebAuthnError::CeremonyType);
    }
    if !fstp_crypto::constant_time_eq(&cd.data.challenge, challenge) {
        return Err(WebAuthnError::Challenge);
    }
    if cd.data.origin != rp.origin {
        return Err(WebAuthnError::Origin);
    }
    if cd.cross_origin {
        return Err(WebAuthnError::CrossOrigin);
    }
    Ok(())
}

/// The checks the two ceremonies share on authenticator data: RP id
/// hash, UP and the backup flags (WebAuthn Level 2 section 7.1 steps 13
/// and 14, section 7.2 steps 15 and 16, Level 3 for BE and BS).
fn check_auth_data(ad: &AuthenticatorData, rp: &RelyingParty) -> Result<(), WebAuthnError> {
    let want = fstp_crypto::sha256(rp.id.as_bytes());
    if !fstp_crypto::constant_time_eq(&ad.rp_id_hash, &want) {
        return Err(WebAuthnError::RpIdHash);
    }
    if ad.flags & flags::UP == 0 {
        return Err(WebAuthnError::UserPresence);
    }
    if ad.flags & flags::BS != 0 && ad.flags & flags::BE == 0 {
        return Err(WebAuthnError::BackupState);
    }
    Ok(())
}

/// Verifies a registration. Fuzzed (`registration_verify`).
///
/// It checks the client data type `webauthn.create`, the challenge, the
/// origin, `crossOrigin`, the format `none`, the RP id hash, UP, UV when
/// required and the attested credential data. It returns the attested
/// id, key and count, and whether the UV flag was set.
///
/// # Errors
///
/// A [`WebAuthnError`] naming the first check that fails.
pub fn verify_registration(
    r: &RegistrationResponse,
    x: &RegistrationExpect,
) -> Result<NewCredential, WebAuthnError> {
    check_client_data(&r.client_data_json, "webauthn.create", &x.rp, &x.challenge)?;
    let ad = attestation::parse(&r.attestation_object)?;
    check_auth_data(&ad.data, &x.rp)?;
    let user_verified = ad.data.flags & flags::UV != 0;
    if x.user_verification && !user_verified {
        return Err(WebAuthnError::UserVerification);
    }
    let attested = ad.attested.ok_or(WebAuthnError::AttestedCredential)?;
    Ok(NewCredential {
        id: attested.id,
        key: attested.key,
        sign_count: ad.data.sign_count,
        user_verified,
    })
}

/// Verifies an assertion. Fuzzed (`assertion_verify`).
///
/// It checks the credential id, the client data type `webauthn.get`, the
/// challenge, the origin, `crossOrigin`, the RP id hash, UP, UV when
/// required, the signature over the authenticator data and the SHA-256
/// of the client data, and then the sign count rule. The count is
/// checked after the signature, so only a signed regression reports
/// [`WebAuthnError::SignCountRegression`].
///
/// # Errors
///
/// A [`WebAuthnError`] naming the first check that fails.
pub fn verify_assertion(
    a: &AssertionResponse,
    c: &StoredCredential,
    x: &AssertionExpect,
) -> Result<AssertionOk, WebAuthnError> {
    if a.credential_id.is_empty() || a.credential_id != c.id {
        return Err(WebAuthnError::CredentialId);
    }
    check_client_data(&a.client_data_json, "webauthn.get", &x.rp, &x.challenge)?;
    let ad = auth_data::parse(&a.authenticator_data)?;
    if ad.attested.is_some() {
        return Err(WebAuthnError::AttestedCredential);
    }
    check_auth_data(&ad.data, &x.rp)?;
    let user_verified = ad.data.flags & flags::UV != 0;
    if x.user_verification && !user_verified {
        return Err(WebAuthnError::UserVerification);
    }

    let mut message = a.authenticator_data.clone();
    message.extend_from_slice(&fstp_crypto::sha256(&a.client_data_json));
    verify_signature(&c.key, &message, &a.signature)?;

    let (stored, asserted) = (c.sign_count, ad.data.sign_count);
    if (stored != 0 || asserted != 0) && asserted <= stored {
        return Err(WebAuthnError::SignCountRegression { stored, asserted });
    }
    Ok(AssertionOk {
        sign_count: asserted,
        user_verified,
    })
}

/// Verifies `signature` over `message` under `key` through
/// `fstp_crypto::sig`.
fn verify_signature(key: &CoseKey, message: &[u8], signature: &[u8]) -> Result<(), WebAuthnError> {
    let r = match key {
        CoseKey::Es256 { x, y } => fstp_crypto::sig::ecdsa_p256_sha256_verify_point(
            &cose::p256_point(x, y),
            message,
            signature,
        ),
        CoseKey::Ed25519 { x } => fstp_crypto::sig::ed25519_verify(x, message, signature),
        CoseKey::Rs256 { n, e } => {
            fstp_crypto::sig::rsa_pkcs1_sha256_verify(n, e, message, signature)
        }
    };
    r.map_err(|_| WebAuthnError::Signature)
}

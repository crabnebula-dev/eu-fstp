//! The software authenticator: real WebAuthn registrations and assertions
//! with ES256 and Ed25519 keys, and faults (design section 14.3). Lane W1a.
//!
//! The authenticator writes the byte formats of WebAuthn Level 2 itself:
//! the client data JSON, the authenticator data, the COSE public key and
//! a `none` attestation object in canonical CBOR (the CTAP2 key order).
//! These builders are public, so the `fstp-webauthn` parsers can be fed
//! exact inputs. A builder refuses a fault it cannot apply with
//! [`FaultRefused`], so no faulted call returns a valid value. Each
//! [`Fault`] changes exactly one thing:
//!
//! | Fault | Change |
//! | --- | --- |
//! | `WrongOrigin` | The client data origin is `https://wrong.<rp id>` |
//! | `WrongRpIdHash` | The authenticator data hashes `wrong.<rp id>` |
//! | `NoUserVerification` | The UV flag is clear |
//! | `ReplayedChallenge` | The client data carries the previous challenge |
//! | `CounterRegression` | The counter is one below the last one used |
//!
//! [`SoftAuthenticator::register`] makes a new credential with a fresh
//! key pair from `fstp_crypto::sig`: an ECDSA P-256 key for ES256, or an
//! Ed25519 key. Its registration is a `none` attestation over the
//! builders above. [`SoftAuthenticator::assert`] signs the authenticator
//! data and the SHA-256 of the client data with the credential's key
//! (WebAuthn Level 2 section 6.3.3). Both take the faults of the table,
//! each through the builder that writes its field. `CounterRegression`
//! has no meaning for a registration, whose counter is 0, so `register`
//! refuses it. A refused call leaves the authenticator unchanged.
//!
//! The keys never leave the authenticator, and its `Debug` form shows no
//! key.

use fstp_crypto::sig::{EcdsaP256KeyPair, Ed25519SigningKey, P256_POINT_LEN};

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

impl Fault {
    /// Whether [`SoftAuthenticator::client_data`] applies the fault. The
    /// others are faults of [`SoftAuthenticator::assertion_data`].
    #[must_use]
    pub const fn in_client_data(self) -> bool {
        matches!(self, Fault::WrongOrigin | Fault::ReplayedChallenge)
    }
}

/// Why a requested fault was not produced. A builder refuses a fault it
/// cannot apply rather than return a value without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultRefused {
    /// [`Fault::ReplayedChallenge`] with no earlier challenge that differs
    /// from the current one.
    NoEarlierChallenge,
    /// [`Fault::CounterRegression`] with the counter at 0.
    CounterAtZero,
    /// A fault the builder called does not write, such as
    /// [`Fault::WrongOrigin`] for the authenticator data. A call that
    /// returned would carry no such fault.
    NotThisBuilder(Fault),
}

impl std::fmt::Display for FaultRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaultRefused::NoEarlierChallenge => {
                write!(f, "a replayed challenge needs an earlier, other challenge")
            }
            FaultRefused::CounterAtZero => {
                write!(f, "a counter regression needs a counter above 0")
            }
            FaultRefused::NotThisBuilder(fault) => {
                write!(f, "this builder cannot apply the fault {fault:?}")
            }
        }
    }
}

impl std::error::Error for FaultRefused {}

/// A credential's signature algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256, COSE algorithm -7.
    Es256,
    /// Ed25519, COSE algorithm -8.
    Ed25519,
}

impl Alg {
    /// The COSE algorithm identifier.
    #[must_use]
    pub const fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::Ed25519 => -8,
        }
    }
}

/// The ceremony a client data JSON belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    /// `webauthn.create`.
    Create,
    /// `webauthn.get`.
    Get,
}

/// The authenticator data flags (WebAuthn Level 2, section 6.1).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
}

/// Why [`SoftAuthenticator::register`] or [`SoftAuthenticator::assert`]
/// returned no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftAuthnError {
    /// A requested fault could not be applied.
    Fault(FaultRefused),
    /// The authenticator holds no credential with the given id.
    UnknownCredential,
    /// `fstp_crypto` could not make a key, an id or a signature.
    Crypto,
}

impl std::fmt::Display for SoftAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoftAuthnError::Fault(r) => write!(f, "{r}"),
            SoftAuthnError::UnknownCredential => {
                write!(f, "the authenticator holds no such credential")
            }
            SoftAuthnError::Crypto => write!(f, "fstp_crypto could not make a key or signature"),
        }
    }
}

impl std::error::Error for SoftAuthnError {}

impl From<FaultRefused> for SoftAuthnError {
    fn from(r: FaultRefused) -> Self {
        SoftAuthnError::Fault(r)
    }
}

/// A registration the authenticator made: the browser's response and
/// the new credential's id, which the attested data also carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftRegistration {
    /// The response a browser would send.
    pub response: fstp_webauthn::RegistrationResponse,
    /// The new credential id, 16 random bytes.
    pub credential_id: Vec<u8>,
}

/// A credential's private key.
enum SoftKey {
    Es256(EcdsaP256KeyPair),
    Ed25519(Ed25519SigningKey),
}

impl SoftKey {
    /// A fresh key for `alg` and its COSE public key.
    fn generate(alg: Alg) -> Result<(SoftKey, Vec<u8>), SoftAuthnError> {
        match alg {
            Alg::Ed25519 => {
                let key = Ed25519SigningKey::generate().map_err(|_| SoftAuthnError::Crypto)?;
                let cose = cose_key(alg, &key.public_key(), None);
                Ok((SoftKey::Ed25519(key), cose))
            }
            Alg::Es256 => {
                let key = EcdsaP256KeyPair::generate().map_err(|_| SoftAuthnError::Crypto)?;
                let spki = key.spki_der().map_err(|_| SoftAuthnError::Crypto)?;
                // The SPKI ends with the uncompressed point 0x04 || x || y.
                let point = spki
                    .len()
                    .checked_sub(P256_POINT_LEN)
                    .and_then(|at| spki.get(at..))
                    .ok_or(SoftAuthnError::Crypto)?;
                let (Some(x), Some(y)) = (point.get(1..33), point.get(33..65)) else {
                    return Err(SoftAuthnError::Crypto);
                };
                let cose = cose_key(alg, x, Some(y));
                Ok((SoftKey::Es256(key), cose))
            }
        }
    }

    /// The WebAuthn signature over `message`: an ASN.1 DER ECDSA value for
    /// ES256, 64 bytes for Ed25519.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SoftAuthnError> {
        match self {
            SoftKey::Es256(k) => k.sign(message).map_err(|_| SoftAuthnError::Crypto),
            SoftKey::Ed25519(k) => k
                .sign(message)
                .map(|s| s.to_vec())
                .map_err(|_| SoftAuthnError::Crypto),
        }
    }
}

/// A credential the authenticator holds.
struct SoftCredential {
    id: Vec<u8>,
    key: SoftKey,
}

/// The software authenticator.
pub struct SoftAuthenticator {
    rp_id: String,
    credentials: Vec<SoftCredential>,
    counter: u32,
    last_challenge: Option<[u8; 32]>,
}

impl std::fmt::Debug for SoftAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The keys are secret: the form names how many there are only.
        f.debug_struct("SoftAuthenticator")
            .field("rp_id", &self.rp_id)
            .field("credentials", &self.credentials.len())
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SoftAuthenticator {
    /// A new authenticator for the relying party `localhost`.
    ///
    /// # Errors
    ///
    /// Never fails. The `Result` keeps the W0 signature.
    pub fn new() -> Result<SoftAuthenticator, NotImplemented> {
        Ok(SoftAuthenticator::for_rp("localhost"))
    }

    /// A new authenticator for the relying party id `rp_id`, whose origin
    /// is `https://<rp_id>` (B11: the exact tenant host).
    #[must_use]
    pub fn for_rp(rp_id: &str) -> SoftAuthenticator {
        SoftAuthenticator {
            rp_id: rp_id.to_owned(),
            credentials: Vec::new(),
            counter: 0,
            last_challenge: None,
        }
    }

    /// The number of credentials it holds.
    pub fn credentials(&self) -> usize {
        self.credentials.len()
    }

    /// The ids of the credentials it holds, in registration order.
    #[must_use]
    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.credentials.iter().map(|c| c.id.clone()).collect()
    }

    /// The relying party id.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The origin its client data names without a fault.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("https://{}", self.rp_id)
    }

    /// The client data JSON for `ceremony` and `challenge`, with `faults`
    /// applied. It records the challenge for a later replay.
    ///
    /// # Errors
    ///
    /// Refuses a fault of the authenticator data
    /// ([`Fault::in_client_data`] false) with
    /// [`FaultRefused::NotThisBuilder`]. Refuses
    /// [`Fault::ReplayedChallenge`] before any earlier challenge, or when
    /// the earlier challenge equals `challenge`, since the result would
    /// carry no fault. The state is unchanged then.
    pub fn client_data(
        &mut self,
        ceremony: Ceremony,
        challenge: [u8; 32],
        faults: &[Fault],
    ) -> Result<Vec<u8>, FaultRefused> {
        if let Some(f) = faults.iter().find(|f| !f.in_client_data()) {
            return Err(FaultRefused::NotThisBuilder(*f));
        }
        let used = if faults.contains(&Fault::ReplayedChallenge) {
            match self.last_challenge {
                Some(last) if last != challenge => last,
                _ => return Err(FaultRefused::NoEarlierChallenge),
            }
        } else {
            challenge
        };
        self.last_challenge = Some(challenge);
        let origin = if faults.contains(&Fault::WrongOrigin) {
            format!("https://wrong.{}", self.rp_id)
        } else {
            self.origin()
        };
        Ok(client_data_json(ceremony, &used, &origin))
    }

    /// The authenticator data for an assertion, with `faults` applied. It
    /// advances the signature counter, or steps it back for
    /// [`Fault::CounterRegression`].
    ///
    /// # Errors
    ///
    /// Refuses a fault of the client data ([`Fault::in_client_data`]
    /// true) with [`FaultRefused::NotThisBuilder`]. Refuses
    /// [`Fault::CounterRegression`] while the counter is 0. A
    /// regression from 0 cannot be written, and a relying party accepts a
    /// zero counter when its stored counter is also zero (WebAuthn Level 2
    /// section 6.1.1). The state is unchanged then.
    pub fn assertion_data(&mut self, faults: &[Fault]) -> Result<Vec<u8>, FaultRefused> {
        if let Some(f) = faults.iter().find(|f| f.in_client_data()) {
            return Err(FaultRefused::NotThisBuilder(*f));
        }
        let counter = if faults.contains(&Fault::CounterRegression) {
            if self.counter == 0 {
                return Err(FaultRefused::CounterAtZero);
            }
            self.counter.saturating_sub(1)
        } else {
            self.counter = self.counter.saturating_add(1);
            self.counter
        };
        let rp = if faults.contains(&Fault::WrongRpIdHash) {
            format!("wrong.{}", self.rp_id)
        } else {
            self.rp_id.clone()
        };
        let mut f = flags::UP;
        if !faults.contains(&Fault::NoUserVerification) {
            f |= flags::UV;
        }
        Ok(authenticator_data(&rp, f, counter, None))
    }

    /// A registration of a new `alg` credential for `challenge`: a fresh
    /// key pair from `fstp_crypto::sig`, a random 16-byte credential id,
    /// and a `none` attestation object whose authenticator data carries
    /// UP, UV and the counter 0 (WebAuthn Level 2 sections 6.1 and 6.5).
    /// The authenticator keeps the credential for [`Self::assert`].
    ///
    /// `WrongOrigin` and `ReplayedChallenge` change the client data,
    /// `WrongRpIdHash` and `NoUserVerification` the authenticator data.
    /// A faulted registration still adds its credential, so a test can
    /// show that the relying party refused a key the authenticator holds.
    ///
    /// # Errors
    ///
    /// [`SoftAuthnError::Fault`] with [`FaultRefused::NotThisBuilder`] for
    /// `CounterRegression`, and as [`Self::client_data`] refuses
    /// `ReplayedChallenge`. [`SoftAuthnError::Crypto`] when no key or id
    /// can be drawn. The authenticator is unchanged then.
    pub fn register(
        &mut self,
        alg: Alg,
        challenge: [u8; 32],
        faults: &[Fault],
    ) -> Result<SoftRegistration, SoftAuthnError> {
        if faults.contains(&Fault::CounterRegression) {
            return Err(FaultRefused::NotThisBuilder(Fault::CounterRegression).into());
        }
        let (key, cose) = SoftKey::generate(alg)?;
        let id = fstp_crypto::random_array::<16>()
            .map_err(|_| SoftAuthnError::Crypto)?
            .to_vec();
        let client: Vec<Fault> = faults
            .iter()
            .copied()
            .filter(|f| f.in_client_data())
            .collect();
        let client_data_json = self.client_data(Ceremony::Create, challenge, &client)?;
        let rp = if faults.contains(&Fault::WrongRpIdHash) {
            format!("wrong.{}", self.rp_id)
        } else {
            self.rp_id.clone()
        };
        let mut f = flags::UP;
        if !faults.contains(&Fault::NoUserVerification) {
            f |= flags::UV;
        }
        let attested = AttestedCredential {
            aaguid: [0; 16],
            id: id.clone(),
            cose_key: cose,
        };
        let auth_data = authenticator_data(&rp, f, 0, Some(&attested));
        self.credentials.push(SoftCredential {
            id: id.clone(),
            key,
        });
        Ok(SoftRegistration {
            response: fstp_webauthn::RegistrationResponse {
                client_data_json,
                attestation_object: none_attestation_object(&auth_data),
            },
            credential_id: id,
        })
    }

    /// An assertion with the credential `id` for `challenge`: the client
    /// data of [`Self::client_data`], the authenticator data of
    /// [`Self::assertion_data`] with the next counter, and the credential
    /// key's signature over the authenticator data and the SHA-256 of the
    /// client data (WebAuthn Level 2 section 6.3.3).
    ///
    /// Each fault goes to the builder that writes its field.
    ///
    /// # Errors
    ///
    /// [`SoftAuthnError::UnknownCredential`] for an id it does not hold.
    /// [`SoftAuthnError::Fault`] as the builders refuse: a replay with no
    /// earlier, other challenge, or a counter regression from 0.
    /// [`SoftAuthnError::Crypto`] when signing fails. The authenticator is
    /// unchanged by a fault or id refusal.
    pub fn assert(
        &mut self,
        id: &[u8],
        challenge: [u8; 32],
        faults: &[Fault],
    ) -> Result<fstp_webauthn::AssertionResponse, SoftAuthnError> {
        if !self.credentials.iter().any(|c| c.id == id) {
            return Err(SoftAuthnError::UnknownCredential);
        }
        // Checked first, so a refused regression changes no challenge.
        if faults.contains(&Fault::CounterRegression) && self.counter == 0 {
            return Err(FaultRefused::CounterAtZero.into());
        }
        let (client, data): (Vec<Fault>, Vec<Fault>) =
            faults.iter().copied().partition(|f| f.in_client_data());
        let client_data_json = self.client_data(Ceremony::Get, challenge, &client)?;
        let authenticator_data = self.assertion_data(&data)?;
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client_data_json));
        let signature = self
            .credentials
            .iter()
            .find(|c| c.id == id)
            .ok_or(SoftAuthnError::UnknownCredential)?
            .key
            .sign(&message)?;
        Ok(fstp_webauthn::AssertionResponse {
            credential_id: id.to_vec(),
            client_data_json,
            authenticator_data,
            signature,
        })
    }
}

/// Base64url without padding (RFC 4648 section 5), as client data uses.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0).wrapping_shl(16) | u32::from(b1).wrapping_shl(8) | u32::from(b2);
        let chars = chunk.len().saturating_add(1);
        for shift in [18u32, 12, 6, 0].into_iter().take(chars) {
            let index = usize::try_from(n.wrapping_shr(shift) & 0x3f).unwrap_or(0);
            if let Some(c) = ALPHABET.get(index) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

/// The client data JSON of WebAuthn Level 2 section 5.8.1, with members in
/// the order browsers write them and `crossOrigin` false.
#[must_use]
pub fn client_data_json(ceremony: Ceremony, challenge: &[u8], origin: &str) -> Vec<u8> {
    let kind = match ceremony {
        Ceremony::Create => "webauthn.create",
        Ceremony::Get => "webauthn.get",
    };
    let mut escaped = String::new();
    for c in origin.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            c if u32::from(c) < 0x20 => escaped.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => escaped.push(c),
        }
    }
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{escaped}\",\"crossOrigin\":false}}",
        base64url(challenge)
    )
    .into_bytes()
}

/// Attested credential data: an AAGUID, a credential id and its COSE key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedCredential {
    /// The authenticator model id. All zero for a `none` attestation.
    pub aaguid: [u8; 16],
    /// The credential id, at most 1023 bytes.
    pub id: Vec<u8>,
    /// The COSE public key, CBOR.
    pub cose_key: Vec<u8>,
}

/// The authenticator data of WebAuthn Level 2 section 6.1: the SHA-256 of
/// `rp_id`, the flags, the counter and, when given, the attested
/// credential data (and then the AT flag).
#[must_use]
pub fn authenticator_data(
    rp_id: &str,
    flag_bits: u8,
    counter: u32,
    attested: Option<&AttestedCredential>,
) -> Vec<u8> {
    let mut out = fstp_crypto::sha256(rp_id.as_bytes()).to_vec();
    let at = if attested.is_some() { flags::AT } else { 0 };
    out.push(flag_bits | at);
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some(cred) = attested {
        out.extend_from_slice(&cred.aaguid);
        let len = u16::try_from(cred.id.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&cred.id);
        out.extend_from_slice(&cred.cose_key);
    }
    out
}

/// A COSE_Key in canonical CBOR (RFC 9053). ES256 takes the 32-byte `x`
/// and `y` coordinates. Ed25519 takes the 32-byte public key as `x` and
/// no `y`.
#[must_use]
pub fn cose_key(alg: Alg, x: &[u8], y: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    match alg {
        Alg::Es256 => {
            cbor_head(&mut out, 5, 5);
            cbor_int(&mut out, 1);
            cbor_int(&mut out, 2); // kty EC2
            cbor_int(&mut out, 3);
            cbor_int(&mut out, alg.cose());
            cbor_int(&mut out, -1);
            cbor_int(&mut out, 1); // crv P-256
            cbor_int(&mut out, -2);
            cbor_bytes(&mut out, x);
            cbor_int(&mut out, -3);
            cbor_bytes(&mut out, y.unwrap_or_default());
        }
        Alg::Ed25519 => {
            cbor_head(&mut out, 5, 4);
            cbor_int(&mut out, 1);
            cbor_int(&mut out, 1); // kty OKP
            cbor_int(&mut out, 3);
            cbor_int(&mut out, alg.cose());
            cbor_int(&mut out, -1);
            cbor_int(&mut out, 6); // crv Ed25519
            cbor_int(&mut out, -2);
            cbor_bytes(&mut out, x);
        }
    }
    out
}

/// A `none` attestation object: `{"fmt": "none", "attStmt": {},
/// "authData": <bytes>}` in canonical CBOR key order.
#[must_use]
pub fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_head(&mut out, 5, 3);
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    cbor_head(&mut out, 5, 0);
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

/// A CBOR head of major type `major` with argument `value`, shortest form.
fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major.wrapping_shl(5);
    if let Ok(v) = u8::try_from(value)
        && v < 24
    {
        out.push(m | v);
    } else if let Ok(v) = u8::try_from(value) {
        out.push(m | 24);
        out.push(v);
    } else if let Ok(v) = u16::try_from(value) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(value) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn cbor_int(out: &mut Vec<u8>, value: i64) {
    if let Ok(v) = u64::try_from(value) {
        cbor_head(out, 0, v);
    } else {
        // -1 - n encodes as major type 1 with argument n.
        let n = u64::try_from(value.wrapping_add(1).wrapping_neg()).unwrap_or(0);
        cbor_head(out, 1, n);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, u64::try_from(text.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    //! Self-tests of the keyed calls against the production verifier
    //! `fstp_webauthn` (design section 14.3).

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_webauthn::{
        AssertionExpect, RegistrationExpect, RelyingParty, StoredCredential, WebAuthnError,
        verify_assertion, verify_registration,
    };

    const RP: &str = "cell.fstp.test";
    const CHALLENGE: [u8; 32] = [0x11; 32];

    fn rp() -> RelyingParty {
        RelyingParty::new(RP).unwrap()
    }

    fn reg_expect(challenge: [u8; 32]) -> RegistrationExpect {
        RegistrationExpect {
            rp: rp(),
            challenge,
            user_verification: true,
        }
    }

    fn asn_expect(challenge: [u8; 32]) -> AssertionExpect {
        AssertionExpect {
            rp: rp(),
            challenge,
            user_verification: true,
        }
    }

    /// A registered credential of `alg` and its stored form.
    fn enrolled(alg: Alg) -> (SoftAuthenticator, StoredCredential) {
        let mut a = SoftAuthenticator::for_rp(RP);
        let reg = a.register(alg, CHALLENGE, &[]).unwrap();
        let cred = verify_registration(&reg.response, &reg_expect(CHALLENGE)).unwrap();
        assert_eq!(cred.id, reg.credential_id);
        let stored = StoredCredential {
            id: cred.id,
            key: cred.key,
            sign_count: cred.sign_count,
        };
        (a, stored)
    }

    /// Design section 14.3, ADR-008: an ES256 and an Ed25519 registration
    /// verify through `fstp_webauthn::verify_registration` with UV, and the
    /// authenticator then holds the credential.
    #[test]
    fn harness_soft_authn_registrations_verify_for_both_algorithms() {
        for alg in [Alg::Es256, Alg::Ed25519] {
            let mut a = SoftAuthenticator::for_rp(RP);
            let reg = a.register(alg, CHALLENGE, &[]).unwrap();
            let cred = verify_registration(&reg.response, &reg_expect(CHALLENGE))
                .unwrap_or_else(|e| panic!("{alg:?}: {e:?}"));
            assert!(cred.user_verified, "{alg:?}");
            assert_eq!(cred.sign_count, 0, "{alg:?}");
            assert_eq!(a.credential_ids(), vec![reg.credential_id], "{alg:?}");
        }
    }

    /// Design section 14.3: assertions with both key kinds verify through
    /// `fstp_webauthn::verify_assertion`, with a rising counter.
    #[test]
    fn harness_soft_authn_assertions_verify_for_both_algorithms() {
        for alg in [Alg::Es256, Alg::Ed25519] {
            let (mut a, mut stored) = enrolled(alg);
            for round in 1..=2u8 {
                let challenge = [round; 32];
                let asn = a.assert(&stored.id, challenge, &[]).unwrap();
                let ok = verify_assertion(&asn, &stored, &asn_expect(challenge))
                    .unwrap_or_else(|e| panic!("{alg:?} round {round}: {e:?}"));
                assert_eq!(ok.sign_count, u32::from(round), "{alg:?}");
                stored.sign_count = ok.sign_count;
            }
        }
    }

    /// Design section 14.3: each registration fault is refused by the
    /// production verifier with the error of the field it changes.
    #[test]
    fn harness_soft_authn_registration_faults_are_refused() {
        let cases = [
            (Fault::WrongOrigin, WebAuthnError::Origin),
            (Fault::WrongRpIdHash, WebAuthnError::RpIdHash),
            (Fault::NoUserVerification, WebAuthnError::UserVerification),
        ];
        for (fault, want) in cases {
            let mut a = SoftAuthenticator::for_rp(RP);
            let reg = a.register(Alg::Ed25519, CHALLENGE, &[fault]).unwrap();
            assert_eq!(
                verify_registration(&reg.response, &reg_expect(CHALLENGE)),
                Err(want),
                "{fault:?}"
            );
        }
        let mut a = SoftAuthenticator::for_rp(RP);
        a.register(Alg::Ed25519, [1; 32], &[]).unwrap();
        let replay = a
            .register(Alg::Ed25519, [2; 32], &[Fault::ReplayedChallenge])
            .unwrap();
        assert_eq!(
            verify_registration(&replay.response, &reg_expect([2; 32])),
            Err(WebAuthnError::Challenge)
        );
        assert_eq!(
            a.register(Alg::Ed25519, CHALLENGE, &[Fault::CounterRegression])
                .map(|_| ()),
            Err(SoftAuthnError::Fault(FaultRefused::NotThisBuilder(
                Fault::CounterRegression
            )))
        );
        assert_eq!(a.credentials(), 2, "a refused registration added a key");
    }

    /// Design section 14.3: each assertion fault is refused by the
    /// production verifier with the error of the field it changes.
    #[test]
    fn harness_soft_authn_assertion_faults_are_refused() {
        let cases = [
            (Fault::WrongOrigin, WebAuthnError::Origin),
            (Fault::WrongRpIdHash, WebAuthnError::RpIdHash),
            (Fault::NoUserVerification, WebAuthnError::UserVerification),
        ];
        for (fault, want) in cases {
            let (mut a, stored) = enrolled(Alg::Es256);
            let asn = a.assert(&stored.id, CHALLENGE, &[fault]).unwrap();
            assert_eq!(
                verify_assertion(&asn, &stored, &asn_expect(CHALLENGE)),
                Err(want),
                "{fault:?}"
            );
        }
        let (mut a, mut stored) = enrolled(Alg::Ed25519);
        let first = a.assert(&stored.id, [1; 32], &[]).unwrap();
        stored.sign_count = verify_assertion(&first, &stored, &asn_expect([1; 32]))
            .unwrap()
            .sign_count;
        let replay = a
            .assert(&stored.id, [2; 32], &[Fault::ReplayedChallenge])
            .unwrap();
        assert_eq!(
            verify_assertion(&replay, &stored, &asn_expect([2; 32])),
            Err(WebAuthnError::Challenge)
        );
        let back = a
            .assert(&stored.id, [3; 32], &[Fault::CounterRegression])
            .unwrap();
        assert!(
            matches!(
                verify_assertion(&back, &stored, &asn_expect([3; 32])),
                Err(WebAuthnError::SignCountRegression { .. })
            ),
            "a regressed counter verified"
        );
    }

    /// Design section 14.3: an unknown credential and a regression from 0
    /// are refused, and neither changes the authenticator.
    #[test]
    fn harness_soft_authn_assert_refusals_leave_the_authenticator_unchanged() {
        let (mut a, stored) = enrolled(Alg::Ed25519);
        let before = format!("{a:?}");
        assert_eq!(
            a.assert(b"unknown", CHALLENGE, &[]).map(|_| ()),
            Err(SoftAuthnError::UnknownCredential)
        );
        assert_eq!(
            a.assert(&stored.id, CHALLENGE, &[Fault::CounterRegression])
                .map(|_| ()),
            Err(SoftAuthnError::Fault(FaultRefused::CounterAtZero))
        );
        assert_eq!(format!("{a:?}"), before);
        // The refused regression recorded no challenge either.
        assert_eq!(
            a.assert(&stored.id, CHALLENGE, &[Fault::ReplayedChallenge])
                .map(|_| ()),
            Err(SoftAuthnError::Fault(FaultRefused::NoEarlierChallenge))
        );
    }

    /// Design section 14.3: the `Debug` form names no key material.
    #[test]
    fn harness_soft_authn_debug_shows_no_key() {
        let (a, _) = enrolled(Alg::Es256);
        let text = format!("{a:?}");
        assert_eq!(
            text,
            format!("SoftAuthenticator {{ rp_id: \"{RP}\", credentials: 1, counter: 0, .. }}")
        );
    }
}

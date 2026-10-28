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
//! Seam: key pairs and signatures need `fstp_crypto::sig` (lane W1h), so
//! [`SoftAuthenticator::register`] and [`SoftAuthenticator::assert`]
//! refuse with [`NotImplemented`] until it lands. The builders do not
//! need it.

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

/// The software authenticator.
#[derive(Debug)]
pub struct SoftAuthenticator {
    rp_id: String,
    credentials: usize,
    counter: u32,
    last_challenge: Option<[u8; 32]>,
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
            credentials: 0,
            counter: 0,
            last_challenge: None,
        }
    }

    /// The number of credentials it holds.
    pub fn credentials(&self) -> usize {
        self.credentials
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

    /// A registration of a new `alg` credential for `challenge`.
    ///
    /// # Errors
    ///
    /// Refuses until `fstp_crypto::sig` lands (lane W1h).
    pub fn register(
        &mut self,
        alg: Alg,
        challenge: [u8; 32],
        faults: &[Fault],
    ) -> Result<fstp_webauthn::RegistrationResponse, NotImplemented> {
        let _ = (alg, challenge, faults);
        Err(NotImplemented::new(
            "fstp_celltest::soft_authn: credential keys need fstp_crypto::sig (lane W1h)",
        ))
    }

    /// An assertion with the credential `id` for `challenge`.
    ///
    /// # Errors
    ///
    /// Refuses until `fstp_crypto::sig` lands (lane W1h).
    pub fn assert(
        &mut self,
        id: &[u8],
        challenge: [u8; 32],
        faults: &[Fault],
    ) -> Result<fstp_webauthn::AssertionResponse, NotImplemented> {
        let _ = (id, challenge, faults);
        Err(NotImplemented::new(
            "fstp_celltest::soft_authn: signatures need fstp_crypto::sig (lane W1h)",
        ))
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

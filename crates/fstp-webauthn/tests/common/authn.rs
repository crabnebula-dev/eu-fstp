//! A test authenticator for the `fstp-webauthn` verifier tests.
//!
//! It writes the byte formats of WebAuthn Level 2: the client data JSON
//! (section 5.8.1), the authenticator data (section 6.1), the COSE public
//! key (RFC 9053) and a `none` attestation object in CTAP2 key order. It
//! signs through `fstp_crypto::sig`, so no primitive is written here.
//!
//! It mirrors `fstp_celltest::soft_authn` (design section 14.3), which
//! this crate cannot depend on (see `common/mod.rs`). Each field of
//! [`Reg`] and [`Asn`] is one knob, and a test changes exactly one of
//! them. The SoftAuthenticator faults map to knobs as follows:
//!
//! | SoftAuthenticator fault | Knob |
//! | --- | --- |
//! | `WrongOrigin` | `origin` is `https://wrong.<rp id>` |
//! | `WrongRpIdHash` | `rp_hash_host` is `wrong.<rp id>` |
//! | `NoUserVerification` | `flags` without UV |
//! | `ReplayedChallenge` | `challenge` is the previous challenge |
//! | `CounterRegression` | `counter` below the stored count |
//!
//! The lane scope adds a bad signature and a wrong algorithm, which the
//! SoftAuthenticator does not offer. [`Asn::signed_by`] takes the signing
//! key apart from the stored credential, and [`Asn::with_signature`]
//! replaces the signature.

use fstp_crypto::sig::{EcdsaP256KeyPair, Ed25519SigningKey};
use fstp_webauthn::{
    AssertionExpect, AssertionResponse, CoseKey, RegistrationExpect, RegistrationResponse,
    RelyingParty, StoredCredential,
};

use super::{b64, cbor};

/// The cell host of the tests. It is the RP id (I-20, B11).
pub(crate) const HOST: &str = "c0ffee.cells.fstp.example";

/// Another cell's host.
pub(crate) const OTHER_CELL: &str = "beef00.cells.fstp.example";

/// The challenge the relying party issued.
pub(crate) const CHALLENGE: [u8; 32] = [0x52; 32];

/// An earlier challenge, for the replay fault.
pub(crate) const PREVIOUS_CHALLENGE: [u8; 32] = [0x51; 32];

/// The credential id the tests register.
pub(crate) const CRED_ID: [u8; 32] = [0xc1; 32];

/// The authenticator data flags (WebAuthn Level 2 section 6.1, Level 3
/// for BE and BS).
pub(crate) mod flags {
    /// User present.
    pub(crate) const UP: u8 = 0x01;
    /// User verified.
    pub(crate) const UV: u8 = 0x04;
    /// Backup eligible (Level 3).
    pub(crate) const BE: u8 = 0x08;
    /// Backed up (Level 3).
    pub(crate) const BS: u8 = 0x10;
    /// Attested credential data included.
    pub(crate) const AT: u8 = 0x40;
    /// Extension data included.
    pub(crate) const ED: u8 = 0x80;
}

/// The origin of `host`.
pub(crate) fn origin_of(host: &str) -> String {
    format!("https://{host}")
}

/// The relying party of [`HOST`]. Panics while `RelyingParty::new` is the
/// W0 stub, which makes every verifier test red for that reason.
pub(crate) fn rp() -> RelyingParty {
    match RelyingParty::new(HOST) {
        Ok(rp) => rp,
        Err(e) => panic!("RelyingParty::new({HOST:?}) refused: {e:?}"),
    }
}

/// A credential key pair of an admitted algorithm.
pub(crate) enum Key {
    /// ES256 (COSE -7).
    Es256(EcdsaP256KeyPair),
    /// EdDSA over Ed25519 (COSE -8).
    Ed25519(Ed25519SigningKey),
}

impl Key {
    /// A fresh ES256 key.
    pub(crate) fn es256() -> Key {
        Key::Es256(EcdsaP256KeyPair::generate().expect("P-256 key"))
    }

    /// The Ed25519 key of seed `[seed; 32]`.
    pub(crate) fn ed25519(seed: u8) -> Key {
        Key::Ed25519(Ed25519SigningKey::from_seed(&[seed; 32]).expect("Ed25519 key"))
    }

    /// The P-256 coordinates `x` and `y`.
    pub(crate) fn point(&self) -> ([u8; 32], [u8; 32]) {
        match self {
            Key::Es256(k) => {
                let spki = k.spki_der().expect("SPKI");
                // The SPKI is a 26-byte prefix, 0x04, x and y.
                assert_eq!(spki.len(), 91);
                assert_eq!(spki[26], 0x04);
                (
                    spki[27..59].try_into().expect("x"),
                    spki[59..91].try_into().expect("y"),
                )
            }
            Key::Ed25519(_) => panic!("an Ed25519 key has no P-256 point"),
        }
    }

    /// The COSE_Key, in CTAP2 canonical key order.
    pub(crate) fn cose(&self) -> Vec<u8> {
        match self {
            Key::Es256(_) => {
                let (x, y) = self.point();
                es256_cose(&x, &y)
            }
            Key::Ed25519(k) => ed25519_cose(&k.public_key()),
        }
    }

    /// The [`CoseKey`] that [`Key::cose`] must decode to.
    pub(crate) fn expected(&self) -> CoseKey {
        match self {
            Key::Es256(_) => {
                let (x, y) = self.point();
                CoseKey::Es256 { x, y }
            }
            Key::Ed25519(k) => CoseKey::Ed25519 { x: k.public_key() },
        }
    }

    /// The WebAuthn signature over `message`: a DER `ECDSA-Sig-Value` for
    /// ES256, the 64 raw bytes for Ed25519.
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Key::Es256(k) => k.sign(message).expect("ES256 signature"),
            Key::Ed25519(k) => k.sign(message).expect("Ed25519 signature").to_vec(),
        }
    }
}

/// An ES256 COSE_Key: kty 2, alg -7, crv 1, x, y.
pub(crate) fn es256_cose(x: &[u8], y: &[u8]) -> Vec<u8> {
    cbor::map(&[
        (cbor::int(1), cbor::int(2)),
        (cbor::int(3), cbor::int(-7)),
        (cbor::int(-1), cbor::int(1)),
        (cbor::int(-2), cbor::bytes(x)),
        (cbor::int(-3), cbor::bytes(y)),
    ])
}

/// An EdDSA COSE_Key: kty 1, alg -8, crv 6, x.
pub(crate) fn ed25519_cose(x: &[u8]) -> Vec<u8> {
    cbor::map(&[
        (cbor::int(1), cbor::int(1)),
        (cbor::int(3), cbor::int(-8)),
        (cbor::int(-1), cbor::int(6)),
        (cbor::int(-2), cbor::bytes(x)),
    ])
}

/// An RS256 COSE_Key: kty 3, alg -257, n, e (RFC 8230).
pub(crate) fn rs256_cose(n: &[u8], e: &[u8]) -> Vec<u8> {
    cbor::map(&[
        (cbor::int(1), cbor::int(3)),
        (cbor::int(3), cbor::int(-257)),
        (cbor::int(-1), cbor::bytes(n)),
        (cbor::int(-2), cbor::bytes(e)),
    ])
}

/// The client data JSON, members in browser order. `cross_origin` sets
/// the `crossOrigin` member.
pub(crate) fn client_data(
    kind: &str,
    challenge: &[u8],
    origin: &str,
    cross_origin: bool,
) -> Vec<u8> {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin}}}",
        b64::url(challenge)
    )
    .into_bytes()
}

/// Attested credential data (WebAuthn Level 2 section 6.5.1).
pub(crate) struct Attested<'a> {
    /// The AAGUID. All zero for `none`.
    pub(crate) aaguid: [u8; 16],
    /// The credential id.
    pub(crate) id: &'a [u8],
    /// The COSE public key.
    pub(crate) cose: &'a [u8],
}

/// Authenticator data: SHA-256 of `rp_id`, the flags byte as given, the
/// counter, then the attested credential data when given. The AT flag is
/// not set here, so a test can write it apart from the data.
pub(crate) fn auth_data(
    rp_id: &str,
    flag_bits: u8,
    counter: u32,
    attested: Option<&Attested<'_>>,
) -> Vec<u8> {
    let mut out = fstp_crypto::sha256(rp_id.as_bytes()).to_vec();
    out.push(flag_bits);
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some(a) = attested {
        out.extend_from_slice(&a.aaguid);
        out.extend_from_slice(&(a.id.len() as u16).to_be_bytes());
        out.extend_from_slice(a.id);
        out.extend_from_slice(a.cose);
    }
    out
}

/// An attestation object `{fmt, attStmt, authData}` in CTAP2 key order.
/// `att_stmt` is an encoded CBOR item.
pub(crate) fn attestation_object(fmt: &str, att_stmt: &[u8], auth_data: &[u8]) -> Vec<u8> {
    cbor::map(&[
        (cbor::text("fmt"), cbor::text(fmt)),
        (cbor::text("attStmt"), att_stmt.to_vec()),
        (cbor::text("authData"), cbor::bytes(auth_data)),
    ])
}

/// A `none` attestation object.
pub(crate) fn none_attestation(auth_data: &[u8]) -> Vec<u8> {
    attestation_object("none", &cbor::map(&[]), auth_data)
}

/// One registration ceremony. Every field is a knob.
pub(crate) struct Reg {
    /// The client data type.
    pub(crate) kind: String,
    /// The challenge in the client data.
    pub(crate) challenge: [u8; 32],
    /// The origin in the client data.
    pub(crate) origin: String,
    /// The `crossOrigin` member.
    pub(crate) cross_origin: bool,
    /// The host whose SHA-256 the authenticator data carries.
    pub(crate) rp_hash_host: String,
    /// The flags byte.
    pub(crate) flags: u8,
    /// The signature counter.
    pub(crate) counter: u32,
    /// The attestation format.
    pub(crate) fmt: String,
    /// The attestation statement, encoded.
    pub(crate) att_stmt: Vec<u8>,
    /// The credential id.
    pub(crate) credential_id: Vec<u8>,
    /// The COSE public key, encoded.
    pub(crate) cose: Vec<u8>,
}

impl Reg {
    /// A valid registration of `key` for [`HOST`] and [`CHALLENGE`], with
    /// UP and UV set.
    pub(crate) fn valid(key: &Key) -> Reg {
        Reg {
            kind: "webauthn.create".to_owned(),
            challenge: CHALLENGE,
            origin: origin_of(HOST),
            cross_origin: false,
            rp_hash_host: HOST.to_owned(),
            flags: flags::UP | flags::UV | flags::AT,
            counter: 0,
            fmt: "none".to_owned(),
            att_stmt: cbor::map(&[]),
            credential_id: CRED_ID.to_vec(),
            cose: key.cose(),
        }
    }

    /// The authenticator data of this ceremony.
    pub(crate) fn auth_data(&self) -> Vec<u8> {
        let attested = Attested {
            aaguid: [0; 16],
            id: &self.credential_id,
            cose: &self.cose,
        };
        auth_data(
            &self.rp_hash_host,
            self.flags,
            self.counter,
            Some(&attested),
        )
    }

    /// The client data JSON of this ceremony.
    pub(crate) fn client_data(&self) -> Vec<u8> {
        client_data(&self.kind, &self.challenge, &self.origin, self.cross_origin)
    }

    /// The browser's response.
    pub(crate) fn response(&self) -> RegistrationResponse {
        RegistrationResponse {
            client_data_json: self.client_data(),
            attestation_object: attestation_object(&self.fmt, &self.att_stmt, &self.auth_data()),
        }
    }
}

/// What a registration for [`HOST`] and [`CHALLENGE`] must match, with
/// UV requested but not required, as for an applicant passkey.
pub(crate) fn reg_expect() -> RegistrationExpect {
    reg_expect_uv(false)
}

/// What a registration for [`HOST`] and [`CHALLENGE`] must match, with
/// UV required when `user_verification` is set.
pub(crate) fn reg_expect_uv(user_verification: bool) -> RegistrationExpect {
    RegistrationExpect {
        rp: rp(),
        challenge: CHALLENGE,
        user_verification,
    }
}

/// One assertion ceremony. Every field is a knob.
pub(crate) struct Asn {
    /// The client data type.
    pub(crate) kind: String,
    /// The challenge in the client data.
    pub(crate) challenge: [u8; 32],
    /// The origin in the client data.
    pub(crate) origin: String,
    /// The `crossOrigin` member.
    pub(crate) cross_origin: bool,
    /// The host whose SHA-256 the authenticator data carries.
    pub(crate) rp_hash_host: String,
    /// The flags byte.
    pub(crate) flags: u8,
    /// The signature counter.
    pub(crate) counter: u32,
    /// The credential id the browser reports.
    pub(crate) credential_id: Vec<u8>,
}

impl Asn {
    /// A valid assertion for [`HOST`] and [`CHALLENGE`] with UP and UV
    /// set and counter `counter`.
    pub(crate) fn valid(counter: u32) -> Asn {
        Asn {
            kind: "webauthn.get".to_owned(),
            challenge: CHALLENGE,
            origin: origin_of(HOST),
            cross_origin: false,
            rp_hash_host: HOST.to_owned(),
            flags: flags::UP | flags::UV,
            counter,
            credential_id: CRED_ID.to_vec(),
        }
    }

    /// The authenticator data of this ceremony.
    pub(crate) fn auth_data(&self) -> Vec<u8> {
        auth_data(&self.rp_hash_host, self.flags, self.counter, None)
    }

    /// The client data JSON of this ceremony.
    pub(crate) fn client_data(&self) -> Vec<u8> {
        client_data(&self.kind, &self.challenge, &self.origin, self.cross_origin)
    }

    /// The signed bytes: authenticator data, then SHA-256 of the client
    /// data (WebAuthn Level 2 section 6.3.3).
    pub(crate) fn message(&self) -> Vec<u8> {
        let mut m = self.auth_data();
        m.extend_from_slice(&fstp_crypto::sha256(&self.client_data()));
        m
    }

    /// The browser's response, signed by `key`.
    pub(crate) fn signed_by(&self, key: &Key) -> AssertionResponse {
        self.with_signature(key.sign(&self.message()))
    }

    /// The browser's response with `signature` as given.
    pub(crate) fn with_signature(&self, signature: Vec<u8>) -> AssertionResponse {
        AssertionResponse {
            credential_id: self.credential_id.clone(),
            client_data_json: self.client_data(),
            authenticator_data: self.auth_data(),
            signature,
        }
    }
}

/// The stored credential of `key` under [`CRED_ID`] with `sign_count`.
pub(crate) fn stored(key: &Key, sign_count: u32) -> StoredCredential {
    StoredCredential {
        id: CRED_ID.to_vec(),
        key: key.expected(),
        sign_count,
    }
}

/// What an assertion for [`HOST`] and [`CHALLENGE`] must match.
pub(crate) fn asn_expect(user_verification: bool) -> AssertionExpect {
    AssertionExpect {
        rp: rp(),
        challenge: CHALLENGE,
        user_verification,
    }
}

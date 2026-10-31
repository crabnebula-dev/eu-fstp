//! A software passkey for the lane W2b production tests: an Ed25519 key
//! that signs WebAuthn assertions for one relying party. Synthetic keys
//! only.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures build known-good values"
)]

use fstp_crypto::sig::Ed25519SigningKey;
use fstp_webauthn::{
    AssertionResponse, CoseKey, RegistrationResponse, RelyingParty, StoredCredential, flags,
};

/// The cell host of the fixtures.
pub(crate) const HOST: &str = "cell-1.tenant.example";

/// The relying party of [`HOST`].
pub(crate) fn rp() -> RelyingParty {
    RelyingParty::new(HOST).unwrap()
}

/// Base64url without padding.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(URL[((n >> shift) & 0x3f) as usize]));
            }
        }
    }
    out
}

/// A software passkey.
pub(crate) struct Passkey {
    key: Ed25519SigningKey,
    /// The credential id.
    pub(crate) id: Vec<u8>,
}

impl Passkey {
    /// The passkey of seed byte `seed`.
    pub(crate) fn new(seed: u8) -> Passkey {
        Passkey {
            key: Ed25519SigningKey::from_seed(&[seed; 32]).unwrap(),
            id: vec![seed; 16],
        }
    }

    /// The stored credential with sign count `count`.
    pub(crate) fn stored(&self, count: u32) -> StoredCredential {
        StoredCredential {
            id: self.id.clone(),
            key: CoseKey::Ed25519 {
                x: self.key.public_key(),
            },
            sign_count: count,
        }
    }

    /// The public key.
    pub(crate) fn key(&self) -> CoseKey {
        CoseKey::Ed25519 {
            x: self.key.public_key(),
        }
    }

    /// A registration response over `challenge`, format `none`, with sign
    /// count 0, with user verification when `uv`.
    pub(crate) fn register(&self, challenge: &[u8; 32], uv: bool) -> RegistrationResponse {
        let client_data_json = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
            b64url(challenge)
        )
        .into_bytes();
        let mut auth_data = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        let uv_flag = if uv { flags::UV } else { 0 };
        auth_data.push(flags::UP | flags::AT | uv_flag);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.id);
        auth_data.extend_from_slice(&fstp_auth::codec::cose_key_bytes(&self.key()));
        let mut attestation_object = vec![0xa3, 0x63];
        attestation_object.extend_from_slice(b"fmt");
        attestation_object.push(0x64);
        attestation_object.extend_from_slice(b"none");
        attestation_object.push(0x67);
        attestation_object.extend_from_slice(b"attStmt");
        attestation_object.push(0xa0);
        attestation_object.push(0x68);
        attestation_object.extend_from_slice(b"authData");
        attestation_object.push(0x58);
        attestation_object.push(auth_data.len() as u8);
        attestation_object.extend_from_slice(&auth_data);
        RegistrationResponse {
            client_data_json,
            attestation_object,
        }
    }

    /// An assertion over `challenge` with sign count `count`, with user
    /// verification when `uv`.
    pub(crate) fn assert(&self, challenge: &[u8; 32], count: u32, uv: bool) -> AssertionResponse {
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
            b64url(challenge)
        )
        .into_bytes();
        let mut authenticator_data = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        authenticator_data.push(if uv { flags::UP | flags::UV } else { flags::UP });
        authenticator_data.extend_from_slice(&count.to_be_bytes());
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client_data_json));
        let signature = self.key.sign(&message).unwrap().to_vec();
        AssertionResponse {
            credential_id: self.id.clone(),
            client_data_json,
            authenticator_data,
            signature,
        }
    }
}

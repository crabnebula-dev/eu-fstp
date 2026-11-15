//! A minimal software authenticator for `me.add_passkey` (R-LG-04): one
//! WebAuthn registration with a fresh Ed25519 key from `fstp_crypto`, in
//! the byte formats of WebAuthn Level 2 (client data JSON, authenticator
//! data with attested credential data, a COSE key and a `none`
//! attestation object in canonical CBOR).
//!
//! It writes only what a browser sends. `fstp-webauthn` verifies it, in
//! the cell's ceremony that [`super::FakeSessions`] runs. The fuller
//! authenticator with faults lives in `fstp-celltest` (design section
//! 14.3), which this test-only crate does not depend on.

use fstp_webauthn::RegistrationResponse;

/// A registration of a new credential for the relying party `rp_id` over
/// `challenge`, with user presence and user verification set. Returns the
/// browser's response and the new credential id.
///
/// # Errors
///
/// When `fstp_crypto` cannot make a key or an id.
pub fn register(
    rp_id: &str,
    challenge: &[u8; 32],
) -> Result<(RegistrationResponse, Vec<u8>), String> {
    let key = fstp_crypto::sig::Ed25519SigningKey::generate().map_err(|e| format!("{e:?}"))?;
    let id = fstp_crypto::random_array::<16>()
        .map_err(|e| format!("{e:?}"))?
        .to_vec();
    let client_data_json = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{rp_id}\",\"crossOrigin\":false}}",
        fstp_oauth::encode_base64url(challenge)
    )
    .into_bytes();
    // COSE_Key: {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}.
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    cbor_bytes(&mut cose, &key.public_key());
    let mut auth_data = fstp_crypto::sha256(rp_id.as_bytes()).to_vec();
    // UP, UV and AT.
    auth_data.push(0x01 | 0x04 | 0x40);
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0; 16]);
    let len = u16::try_from(id.len()).map_err(|_| "credential id length".to_owned())?;
    auth_data.extend_from_slice(&len.to_be_bytes());
    auth_data.extend_from_slice(&id);
    auth_data.extend_from_slice(&cose);
    // {"fmt": "none", "attStmt": {}, "authData": bytes}.
    let mut attestation_object = vec![0xa3];
    cbor_text(&mut attestation_object, "fmt");
    cbor_text(&mut attestation_object, "none");
    cbor_text(&mut attestation_object, "attStmt");
    attestation_object.push(0xa0);
    cbor_text(&mut attestation_object, "authData");
    cbor_bytes(&mut attestation_object, &auth_data);
    Ok((
        RegistrationResponse {
            client_data_json,
            attestation_object,
        },
        id,
    ))
}

/// A CBOR head of major type `major` with argument `n` (RFC 8949).
fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major.wrapping_shl(5);
    match (u8::try_from(n), u16::try_from(n)) {
        (Ok(v), _) if v < 24 => out.push(m | v),
        (Ok(v), _) => out.extend_from_slice(&[m | 24, v]),
        (_, Ok(v)) => {
            out.push(m | 25);
            out.extend_from_slice(&v.to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, t: &str) {
    cbor_head(out, 3, t.len());
    out.extend_from_slice(t.as_bytes());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use fstp_webauthn::{RegistrationExpect, RelyingParty, verify_registration};

    /// R-LG-04, design section 14.3: `fstp-webauthn` verifies the
    /// registration the harness sends, with user verification.
    #[test]
    fn r_lg_04_soft_registration_verifies_in_fstp_webauthn() {
        let rp = "cell.fstp.test";
        let challenge = [0x5a; 32];
        let (response, id) = register(rp, &challenge).unwrap();
        let expect = RegistrationExpect {
            rp: RelyingParty::new(rp).unwrap(),
            challenge,
            user_verification: true,
        };
        let cred = verify_registration(&response, &expect).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(cred.id, id);
        assert!(cred.user_verified);
    }
}

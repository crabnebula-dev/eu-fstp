//! Review reproducer (design section 4.2, ADR-008 "User verification").
//!
//! Design section 4.2 says credential public keys are ledger records, and
//! sessions, challenges, sign counts and tokens are the only operational
//! rows. So `CredentialRegistered` must carry the new passkey's public key.
//! Otherwise no later login can build the `StoredCredential` that
//! `verify_passkey_login` needs from ledger state. The current record
//! holds only the account and the credential id, and the decoder refuses
//! a record that names a key.
//!
//! The member name `public_key` (lowercase hexadecimal of the COSE key
//! bytes) is the reviewer's suggestion for the fix. The fix this finding
//! names also adds a `user_verified` boolean, so the record below carries
//! it (adapted by lane W2b, fix round 1).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::codec::decode_auth_record;

/// A synthetic COSE Ed25519 key: kty OKP, alg EdDSA, crv Ed25519, x.
const COSE_KEY_HEX: &str = "a4010103272006215820\
     1111111111111111111111111111111111111111111111111111111111111111";

/// Design section 4.2: the registration record carries the credential's
/// public key, so the ledger holds it (I-23, append-only).
#[test]
fn review_credential_registered_carries_the_public_key() {
    let key: String = COSE_KEY_HEX.split_whitespace().collect();
    let text = format!(
        "{{\"account\":\"5\",\"credential\":\"c1c1c1c1\",\"public_key\":\"{key}\",\
         \"type\":\"CredentialRegistered\",\"user_verified\":true}}"
    );
    let got = decode_auth_record(text.as_bytes());
    assert!(
        got.is_ok(),
        "a CredentialRegistered record cannot carry the public key: {got:?}"
    );
}

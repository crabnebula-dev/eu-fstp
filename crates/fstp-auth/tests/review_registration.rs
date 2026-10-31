//! Review reproducer (independent review of lane W2b).
//!
//! Design section 4.2 says credential public keys are ledger records
//! (section 5.1). The auth fold's only registration record is
//! `AuthRecord::CredentialRegistered`, and it carries the credential id
//! alone. So a replay of the ledger cannot rebuild the
//! `fstp_webauthn::StoredCredential` that a later login or step-up
//! verifies against.
//!
//! The test enrols a first passkey through an invitation and looks for a
//! member beyond `type`, `account` and `credential` in the encoded
//! registration record. It fails today. Once the record carries the
//! verified credential (public key and the UV flag of ADR-008), it
//! passes, with the call adapted to the widened builder.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::AuthRecord;
use fstp_auth::ceremony::{Invitation, invitation_records};
use fstp_auth::codec::encode_auth_record;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

#[test]
fn review_enrolment_record_carries_the_credential_public_key() {
    let inv = Invitation {
        id: [0x1D; 16],
        account: AccountId::from_raw(5),
        token_digest: [0x11; 32],
        first_admin: false,
        split: false,
        issued_at: Timestamp::from_micros(1_700_000_000_000_000),
        consumed: false,
    };
    // Adapted to the widened builder, as the header anticipates: it takes
    // the credential that `fstp_webauthn::verify_registration` returned.
    let credential = fstp_webauthn::NewCredential {
        id: vec![0x07; 16],
        key: fstp_webauthn::CoseKey::Ed25519 { x: [0x11; 32] },
        sign_count: 0,
        user_verified: true,
    };
    let records = invitation_records(&inv, &credential);
    let registered: Vec<&AuthRecord> = records
        .iter()
        .filter(|r| matches!(r, AuthRecord::CredentialRegistered { .. }))
        .collect();
    assert_eq!(registered.len(), 1, "one registration record");
    let bytes = encode_auth_record(registered[0]).unwrap();
    let value = fstp_json::parse(&bytes).unwrap();
    let object = value.as_object().unwrap();
    let extra: Vec<&str> = object
        .keys()
        .filter(|k| !matches!(*k, "type" | "account" | "credential"))
        .collect();
    assert!(
        !extra.is_empty(),
        "CredentialRegistered holds only the credential id, so no ledger record \
         carries the public key that design section 4.2 places in the ledger: {}",
        String::from_utf8_lossy(&bytes)
    );
}

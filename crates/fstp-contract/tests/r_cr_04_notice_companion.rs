//! R-CR-04 (M9 design D6, lane C2): contractual notices carry a
//! composite companion signature next to the eIDAS seal. The I-90 half
//! sweep of the verifier is a row of `fstp-celltest`'s
//! `i90_every_verifier`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_contract::digest::{Digest, sha256};
use fstp_contract::notice_companion::{
    CompanionError, NOTICE_COMPANION_CONTEXT, NoticeCompanionKey, NoticeId, companion_message,
    sign_notice_companion, verify_notice_companion,
};
use fstp_crypto::composite;
use fstp_keys::Purpose;

fn key() -> NoticeCompanionKey {
    NoticeCompanionKey::from_custody(Purpose::NoticeCompanion, composite::generate().unwrap())
        .unwrap()
}

/// R-CR-04, D6: only the `NoticeCompanion` key signs a notice companion.
/// Custody keys of every other purpose, the anchor key among them, are
/// refused.
#[test]
fn r_cr_04_only_the_notice_companion_purpose_signs() {
    assert_eq!(NOTICE_COMPANION_CONTEXT, b"fstp-notice-companion-v1");
    for p in Purpose::ALL {
        let r = NoticeCompanionKey::from_custody(p, composite::generate().unwrap());
        if p == Purpose::NoticeCompanion {
            assert!(r.is_ok());
        } else {
            assert_eq!(r.err(), Some(CompanionError::WrongPurpose(p)), "{p:?}");
        }
    }
}

/// R-CR-04: the companion signature verifies over its notice and digest
/// under its key, and fails for another notice, another digest, another
/// key, a record naming another key and another context.
#[test]
fn r_cr_04_companion_signature_binds_notice_digest_and_key() {
    let k = key();
    let pk = k.public_key();
    let pdf = sha256(b"synthetic sealed notice PDF");
    let rec = sign_notice_companion(&k, NoticeId(7), pdf).unwrap();
    assert_eq!(rec.key, sha256(&pk));
    assert!(verify_notice_companion(&rec, &pk));

    let mut other = rec.clone();
    other.notice = NoticeId(8);
    assert!(!verify_notice_companion(&other, &pk), "another notice");
    let mut other = rec.clone();
    other.notice_digest = Digest::from_bytes([0; 32]);
    assert!(!verify_notice_companion(&other, &pk), "another digest");
    let other_pk = key().public_key();
    let mut other = rec.clone();
    other.key = sha256(&other_pk);
    assert!(!verify_notice_companion(&other, &other_pk), "another key");
    let mut other = rec.clone();
    other.key = Digest::from_bytes([1; 32]);
    assert!(
        !verify_notice_companion(&other, &pk),
        "a record naming another key"
    );
    let mut other = rec.clone();
    other.signature.truncate(10);
    assert!(!verify_notice_companion(&other, &pk), "a short signature");
    assert!(!verify_notice_companion(&rec, &pk[1..]), "a short key");
    // The context binds: the same message signed under the anchor
    // context does not verify as a companion signature.
    let raw = composite::generate().unwrap();
    let raw_pk = raw.public_key().to_bytes();
    let sig = raw
        .sign_with_context(
            &companion_message(NoticeId(7), pdf),
            b"fstp-audit-anchor-v1",
        )
        .unwrap();
    let mut other = rec;
    other.key = sha256(&raw_pk);
    other.signature = sig.to_bytes().to_vec();
    assert!(!verify_notice_companion(&other, &raw_pk), "another context");
}

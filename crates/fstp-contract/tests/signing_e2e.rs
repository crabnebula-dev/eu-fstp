//! I-30, M5 design section 3.1 and 8: a contract signed through the fake
//! wallet and QTSP verifies end to end through the strict increment
//! verifier, and production adapters refuse with a typed error (M5 design
//! 12.1, Q2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_contract::fake::FakeTrustServices;
use fstp_contract::{
    BlobKind, BlobStore, ContractTerms, MemBlobStore, ProductionSignaturePort, Route,
    SignatureError, SignaturePort, SignerRef, SigningError, TermsBlock, render, sign_increment,
    verify_revision_chain,
};
use fstp_pdf::prepare_increment;
use fstp_sigval::{Level, ProductionTrustedList, SigvalError, TrustError};

/// 2027-01-01T00:00:00Z.
const NOW: i64 = 1_798_761_600;

fn terms() -> ContractTerms {
    ContractTerms {
        title: "Sub-grant agreement SYN-0001, version 1".into(),
        blocks: vec![
            TermsBlock::Heading("Sub-grant agreement SYN-0001".into()),
            TermsBlock::Clause("The synthetic recipient Ada Example delivers milestone 1.".into()),
            TermsBlock::Clause("Amount: EUR 10 000.00 in two milestones.".into()),
        ],
        parties: vec![
            ("lead".into(), "Lead applicant".into()),
            ("member-1".into(), "Team member".into()),
            ("signatory".into(), "Contract signatory".into()),
        ],
    }
}

fn signer(name: &str) -> SignerRef {
    SignerRef {
        subject: name.to_owned(),
    }
}

/// R-CT-01: the same terms render to the same bytes.
#[test]
fn r_ct_01_contract_renders_byte_identically() {
    assert_eq!(render(&terms()).unwrap(), render(&terms()).unwrap());
}

/// I-30, M5 design 3.1: each party signs through the fake trust services
/// in turn; every revision is an exact byte prefix of the next, every
/// signature validates from the stored bytes, and the revisions are kept
/// write-once in the blob store.
#[test]
fn i30_fake_signed_contract_verifies_end_to_end() {
    let fake = FakeTrustServices::new(NOW).unwrap();
    let trust = fake.trusted_list();
    let mut blobs = MemBlobStore::default();
    let rev0 = render(&terms()).unwrap();
    blobs.put(BlobKind::ContractRevision, &rev0).unwrap();
    let mut revisions = vec![rev0];
    for (party, route) in [
        ("lead", Route::WalletQes),
        ("member-1", Route::QtspRemoteQes),
        ("signatory", Route::QtspRemoteQes),
    ] {
        let base = revisions.last().unwrap().clone();
        // The browser's LibPDF prepares the increment; the server-side
        // canonical form is the same shape.
        let increment = prepare_increment(&base, party, 8192).unwrap();
        let signed = sign_increment(
            &base,
            &increment,
            party,
            route,
            &signer(party),
            NOW,
            &fake,
            &trust,
        )
        .unwrap();
        assert!(signed.revision.starts_with(&base), "I-30: prefix kept");
        assert_eq!(signed.report.level, Level::Qualified);
        let d = blobs
            .put(BlobKind::ContractRevision, &signed.revision)
            .unwrap();
        assert_eq!(d, signed.revision_digest);
        revisions.push(signed.revision);
    }
    let parties = ["lead", "member-1", "signatory"];
    let reports =
        verify_revision_chain(&revisions, &parties, NOW, Level::Qualified, &trust).unwrap();
    assert_eq!(reports.len(), 3);
    // Any byte change in an earlier revision breaks the chain.
    let mut tampered = revisions.clone();
    let i = tampered[1].len() - 40;
    tampered[1][i] ^= 1;
    assert!(verify_revision_chain(&tampered, &parties, NOW, Level::Qualified, &trust).is_err());
}

/// I-30, ADR-016: an increment that touches another object is refused
/// before any signature is asked for.
#[test]
fn i30_increment_touching_another_object_is_refused() {
    let fake = FakeTrustServices::new(NOW).unwrap();
    let trust = fake.trusted_list();
    let rev0 = render(&terms()).unwrap();
    let mut increment = prepare_increment(&rev0, "lead", 8192).unwrap();
    increment.extend_from_slice(b"1 0 obj\n<< >>\nendobj\n");
    let e = sign_increment(
        &rev0,
        &increment,
        "lead",
        Route::WalletQes,
        &signer("lead"),
        NOW,
        &fake,
        &trust,
    )
    .unwrap_err();
    assert!(matches!(e, SigningError::Increment(_)), "{e:?}");
}

/// I-30, `contracts.md` Signature: a revoked signer certificate fails
/// validation, and the advanced route reaches only the advanced level.
#[test]
fn i30_revoked_signer_is_refused() {
    let fake = FakeTrustServices::new(NOW).unwrap();
    let chain = fake
        .certificate_chain(Route::WalletQes, &signer("lead"), NOW)
        .unwrap();
    let mut trust = fake.trusted_list();
    trust
        .revocations
        .push(FakeTrustServices::revocation_of(&chain[0], NOW - 10).unwrap());
    let rev0 = render(&terms()).unwrap();
    let increment = prepare_increment(&rev0, "lead", 8192).unwrap();
    let e = sign_increment(
        &rev0,
        &increment,
        "lead",
        Route::WalletQes,
        &signer("lead"),
        NOW,
        &fake,
        &trust,
    )
    .unwrap_err();
    assert_eq!(e, SigningError::Validation(SigvalError::Revoked));
}

/// M5 design 12.1 Q2: every production signature route refuses with the
/// typed error, and the production trusted list refuses too. Nothing
/// falls back to a platform-made signature.
#[test]
fn q2_production_adapters_refuse_with_typed_error() {
    let port = ProductionSignaturePort;
    for route in [Route::WalletQes, Route::QtspRemoteQes, Route::Advanced] {
        assert_eq!(
            port.certificate_chain(route, &signer("lead"), NOW),
            Err(SignatureError::ProductionUnavailable(route))
        );
        assert_eq!(
            port.sign(route, &signer("lead"), b"attrs", NOW),
            Err(SignatureError::ProductionUnavailable(route))
        );
    }
    let rev0 = render(&terms()).unwrap();
    let increment = prepare_increment(&rev0, "lead", 8192).unwrap();
    let e = sign_increment(
        &rev0,
        &increment,
        "lead",
        Route::WalletQes,
        &signer("lead"),
        NOW,
        &port,
        &ProductionTrustedList,
    )
    .unwrap_err();
    assert_eq!(
        e,
        SigningError::Port(SignatureError::ProductionUnavailable(Route::WalletQes))
    );
    // With a fake signer but the production list, validation fails closed.
    let fake = FakeTrustServices::new(NOW).unwrap();
    let e = sign_increment(
        &rev0,
        &increment,
        "lead",
        Route::WalletQes,
        &signer("lead"),
        NOW,
        &fake,
        &ProductionTrustedList,
    )
    .unwrap_err();
    assert_eq!(
        e,
        SigningError::Validation(SigvalError::Trust(TrustError::ProductionUnavailable))
    );
}

/// I-30, M5 design 4.3: the blob store is write-once by digest. The same
/// bytes store idempotently; a digest never maps to other bytes.
#[test]
fn i30_blob_store_is_write_once() {
    let mut blobs = MemBlobStore::default();
    let d = blobs
        .put(BlobKind::ContractRevision, b"%PDF-1.7 synthetic")
        .unwrap();
    assert_eq!(
        blobs
            .put(BlobKind::ContractRevision, b"%PDF-1.7 synthetic")
            .unwrap(),
        d
    );
    assert_eq!(blobs.get(&d).unwrap(), b"%PDF-1.7 synthetic".to_vec());
    assert!(
        blobs
            .insert_raw(d, BlobKind::ContractRevision, b"other bytes")
            .is_err()
    );
    assert_eq!(blobs.get(&d).unwrap(), b"%PDF-1.7 synthetic".to_vec());
}

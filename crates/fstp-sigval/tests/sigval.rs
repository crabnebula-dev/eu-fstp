//! `contracts.md` Signature, M5 design section 3.1 step 7, I-30: the
//! in-house validation of a signature over a verified increment.
//!
//! The test plays a QTSP: a synthetic CA and signer made with aws-lc-rs
//! through `fstp-crypto` and `fstp-pki`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_crypto::sig::EcdsaP256KeyPair;
use fstp_pdf::{
    Block, BlockKind, Document, SignatureField, embed_signature, prepare_increment,
    verify_increment, write,
};
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_pki::cms::{signed_attributes, signed_data};
use fstp_sigval::{
    FakeTrustedList, Level, ProductionTrustedList, SigvalError, TrustAnchor, TrustError,
    der_tlv_len, issuer_and_serial, verify_signed_revision,
};

const NOW: i64 = 1_798_761_600;

struct Pki {
    ca: Vec<u8>,
    signer_key: EcdsaP256KeyPair,
    signer: Vec<u8>,
}

fn cert(
    key: &EcdsaP256KeyPair,
    issuer_key: &EcdsaP256KeyPair,
    issuer: &str,
    subject: &str,
    kind: CertKind,
    validity: (i64, i64),
) -> Vec<u8> {
    let spec = CertSpec {
        serial: vec![if kind == CertKind::Ca { 1 } else { 7 }],
        issuer: DistinguishedName::new(issuer),
        subject: DistinguishedName::new(subject),
        validity: Validity {
            not_before: validity.0,
            not_after: validity.1,
        },
        spki_der: key.spki_der().unwrap(),
        issuer_key_id: (kind != CertKind::Ca)
            .then(|| key_identifier(&issuer_key.spki_der().unwrap()).unwrap()),
        kind,
        dns_names: vec![],
        ip_addrs: vec![],
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let t = tbs(&spec).unwrap();
    assemble(&t, &issuer_key.sign(t.as_der()).unwrap()).unwrap()
}

fn pki(signer_validity: (i64, i64)) -> Pki {
    let ca_key = EcdsaP256KeyPair::generate().unwrap();
    let ca = cert(
        &ca_key,
        &ca_key,
        "Synthetic CA",
        "Synthetic CA",
        CertKind::Ca,
        (NOW - 86_400, NOW + 86_400 * 365),
    );
    let signer_key = EcdsaP256KeyPair::generate().unwrap();
    let signer = cert(
        &signer_key,
        &ca_key,
        "Synthetic CA",
        "Synthetic Signer",
        CertKind::Client,
        signer_validity,
    );
    Pki {
        ca,
        signer_key,
        signer,
    }
}

fn base() -> Vec<u8> {
    write(&Document {
        title: "Sub-grant agreement SYN-0002".into(),
        lang: "en".into(),
        blocks: vec![Block {
            kind: BlockKind::Paragraph,
            text: "Synthetic clause.".into(),
        }],
        signature_fields: vec![
            SignatureField {
                name: "lead".into(),
                label: "Lead".into(),
            },
            SignatureField {
                name: "signatory".into(),
                label: "Signatory".into(),
            },
        ],
    })
    .unwrap()
}

fn signed(p: &Pki, base: &[u8]) -> Vec<u8> {
    let inc = prepare_increment(base, "lead", 4096).unwrap();
    let v = verify_increment(base, &inc, "lead").unwrap();
    let attrs = signed_attributes(&v.digest, &p.signer).unwrap();
    let sig = p.signer_key.sign(attrs.der()).unwrap();
    let cms = signed_data(&attrs, &sig, &[&p.signer, &p.ca]).unwrap();
    embed_signature(base, &inc, &v, &cms).unwrap()
}

fn list(p: &Pki, qualified: bool) -> FakeTrustedList {
    FakeTrustedList {
        anchors: vec![TrustAnchor {
            certificate: p.ca.clone(),
            qualified,
        }],
        revocations: vec![],
    }
}

/// `contracts.md` Signature, I-30: a signed revision validates from its
/// bytes, and the report digest is stable.
#[test]
fn contracts_signature_validates_from_stored_bytes() {
    let p = pki((NOW - 60, NOW + 86_400));
    let b = base();
    let rev = signed(&p, &b);
    let r =
        verify_signed_revision(&b, &rev, "lead", NOW, Level::Qualified, &list(&p, true)).unwrap();
    assert_eq!(r.level, Level::Qualified);
    assert_eq!(r.path_len, 2);
    assert_eq!(r.signer_certificate_digest, fstp_crypto::sha256(&p.signer));
    let again =
        verify_signed_revision(&b, &rev, "lead", NOW, Level::Qualified, &list(&p, true)).unwrap();
    assert_eq!(r.digest(), again.digest());
}

/// `contracts.md` Signature: the chain must end at a listed anchor, at
/// the level the route needs, inside every validity period, unrevoked.
#[test]
fn contracts_signature_chain_rules() {
    let p = pki((NOW - 60, NOW + 86_400));
    let other = pki((NOW - 60, NOW + 86_400));
    let b = base();
    let rev = signed(&p, &b);
    let run = |l: &FakeTrustedList, at: i64, lvl: Level| {
        verify_signed_revision(&b, &rev, "lead", at, lvl, l)
    };
    assert_eq!(
        run(&list(&other, true), NOW, Level::Qualified),
        Err(SigvalError::Untrusted)
    );
    assert_eq!(
        run(&list(&p, false), NOW, Level::Qualified),
        Err(SigvalError::LevelTooLow)
    );
    assert_eq!(
        run(&list(&p, false), NOW, Level::Advanced).unwrap().level,
        Level::Advanced
    );
    assert_eq!(
        run(&list(&p, true), NOW + 2 * 86_400, Level::Qualified),
        Err(SigvalError::OutsideValidity)
    );
    let mut revoked = list(&p, true);
    let (i, s) = issuer_and_serial(&p.signer).unwrap();
    revoked.revocations.push((i, s, NOW - 1));
    assert_eq!(
        run(&revoked, NOW, Level::Qualified),
        Err(SigvalError::Revoked)
    );
    // A revocation after the signing time does not reach back.
    let (i, s) = issuer_and_serial(&p.signer).unwrap();
    revoked.revocations = vec![(i, s, NOW + 1)];
    assert!(run(&revoked, NOW, Level::Qualified).is_ok());
}

/// M5 design 12.1 Q2: the production trusted list refuses with the
/// typed error, and validation fails closed.
#[test]
fn q2_production_trusted_list_fails_closed() {
    let p = pki((NOW - 60, NOW + 86_400));
    let b = base();
    let rev = signed(&p, &b);
    assert_eq!(
        verify_signed_revision(
            &b,
            &rev,
            "lead",
            NOW,
            Level::Advanced,
            &ProductionTrustedList
        ),
        Err(SigvalError::Trust(TrustError::ProductionUnavailable))
    );
}

/// I-30, ADR-016: a byte change anywhere in the signed revision, covered
/// or in `/Contents`, is refused.
#[test]
fn i30_tampered_revision_is_refused() {
    let p = pki((NOW - 60, NOW + 86_400));
    let b = base();
    let rev = signed(&p, &b);
    let l = list(&p, true);
    for at in [b.len() - 20, b.len() + 10, rev.len() - 30] {
        let mut t = rev.clone();
        t[at] ^= 0x01;
        assert!(
            verify_signed_revision(&b, &t, "lead", NOW, Level::Qualified, &l).is_err(),
            "byte {at}"
        );
    }
    // Another party's field name does not fit the increment.
    assert!(verify_signed_revision(&b, &rev, "signatory", NOW, Level::Qualified, &l).is_err());
}

/// TH-26: the DER length reader bounds every header.
#[test]
fn th_26_der_length_reader_is_bounded() {
    assert_eq!(der_tlv_len(&[0x30, 0x00]), Some(2));
    assert_eq!(der_tlv_len(&[0x30, 0x81, 0x01, 0xff]), Some(4));
    assert_eq!(der_tlv_len(&[0x30, 0x82, 0x01]), None);
    assert_eq!(der_tlv_len(&[0x30, 0x85, 1, 1, 1, 1, 1]), None);
    assert_eq!(der_tlv_len(&[0x30, 0x05, 0]), None);
    assert_eq!(der_tlv_len(&[]), None);
}

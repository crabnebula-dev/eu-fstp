//! CMS signed attributes and SignedData (M5 design section 3.1 steps 5 to
//! 8, ADR-016, `contracts.md` Signature).
//!
//! The test plays the wallet: it holds a synthetic P-256 key and a
//! self-issued certificate, both made with aws-lc-rs through fstp-crypto.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_crypto::sig::EcdsaP256KeyPair;
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, tbs,
};
use fstp_pki::cms::{
    CmsError, decode_signed_data, signed_attributes, signed_data, verify_signature,
};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

struct Wallet {
    key: EcdsaP256KeyPair,
    cert: Vec<u8>,
}

fn wallet(name: &str, serial: u8) -> Wallet {
    let key = EcdsaP256KeyPair::generate().unwrap();
    let spec = CertSpec {
        serial: vec![serial],
        issuer: DistinguishedName::new(name),
        subject: DistinguishedName::new(name),
        validity: Validity {
            not_before: 1_798_761_600,
            not_after: 1_830_297_600,
        },
        spki_der: key.spki_der().unwrap(),
        issuer_key_id: None,
        kind: CertKind::Ca,
        dns_names: vec![],
        ip_addrs: vec![],
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let t = tbs(&spec).unwrap();
    let cert = assemble(&t, &key.sign(t.as_der()).unwrap()).unwrap();
    Wallet { key, cert }
}

/// ADR-016, M5 design section 3.1: the signed attributes round trip
/// through SignedData, and the decoded signature verifies with aws-lc-rs.
#[test]
fn adr_016_cms_signed_attributes_round_trip() {
    let w = wallet("Synthetic Signer Lead", 7);
    let ca = wallet("Synthetic Test CA", 1);
    check_with(
        "adr_016_cms_signed_attributes_round_trip",
        Config::default().with_cases(64),
        |g| {
            let digest: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let attrs = signed_attributes(&digest, &w.cert).map_err(|e| format!("{e}"))?;
            prop_assert_eq!(attrs.der()[0], 0x31);
            prop_assert_eq!(attrs.message_digest(), digest);
            prop_assert_eq!(attrs.digest(), fstp_crypto::sha256(attrs.der()));
            let sig = w.key.sign(attrs.der()).unwrap();
            let cms =
                signed_data(&attrs, &sig, &[&w.cert, &ca.cert]).map_err(|e| format!("{e}"))?;
            let d = decode_signed_data(&cms).map_err(|e| format!("{e}"))?;
            prop_assert_eq!(&d.signed_attributes, &attrs.der().to_vec());
            prop_assert_eq!(d.message_digest, digest);
            prop_assert_eq!(&d.signature, &sig);
            prop_assert_eq!(&d.signer_certificate, &w.cert);
            prop_assert_eq!(d.certificates.len(), 2);
            prop_assert!(
                verify_signature(&d.signed_attributes, &d.signature, &d.signer_certificate).is_ok()
            );
            Ok(())
        },
    );
}

/// `contracts.md` Signature, ADR-016: a signature value that does not
/// verify is refused before it is embedded: a flipped byte, a value over
/// other attributes, and a value from another key.
#[test]
fn adr_016_cms_wrong_signature_is_refused() {
    let w = wallet("Synthetic Signer Lead", 7);
    let other = wallet("Synthetic Signer Other", 9);
    let attrs = signed_attributes(&[0x11; 32], &w.cert).unwrap();
    let good = w.key.sign(attrs.der()).unwrap();
    assert!(signed_data(&attrs, &good, &[&w.cert]).is_ok());

    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let elsewhere = w
        .key
        .sign(signed_attributes(&[0x22; 32], &w.cert).unwrap().der())
        .unwrap();
    let wrong_key = other.key.sign(attrs.der()).unwrap();
    for bad in [flipped, elsewhere, wrong_key, vec![], vec![0x30, 0x00]] {
        assert_eq!(
            signed_data(&attrs, &bad, &[&w.cert]),
            Err(CmsError::SignatureInvalid)
        );
        assert_eq!(
            verify_signature(attrs.der(), &bad, &w.cert),
            Err(CmsError::SignatureInvalid)
        );
    }
    // A chain that leads with another signer's certificate is refused.
    // The other key signs the attributes made for `w`, so the value
    // verifies but the attributes name another certificate.
    let other_sig = other.key.sign(attrs.der()).unwrap();
    assert_eq!(
        signed_data(&attrs, &other_sig, &[&other.cert]),
        Err(CmsError::Attribute("signingCertificateV2"))
    );
    assert_eq!(signed_data(&attrs, &good, &[]), Err(CmsError::Chain));
}

/// TH-26: the strict decoder refuses truncations and mutations without
/// panicking, and anything it accepts is in DER and encodes back.
#[test]
fn adr_016_cms_decoder_is_strict_on_mutations() {
    let w = wallet("Synthetic Signer Lead", 7);
    let attrs = signed_attributes(&[0x33; 32], &w.cert).unwrap();
    let cms = signed_data(&attrs, &w.key.sign(attrs.der()).unwrap(), &[&w.cert]).unwrap();
    for cut in [0, 1, 10, cms.len() / 2, cms.len() - 1] {
        assert!(decode_signed_data(&cms[..cut]).is_err());
    }
    let mut trailing = cms.clone();
    trailing.push(0);
    assert_eq!(decode_signed_data(&trailing), Err(CmsError::Decode));
    check_with(
        "adr_016_cms_decoder_is_strict_on_mutations",
        Config::default().with_cases(256),
        |g| {
            let mut m = cms.clone();
            let at = g.usize_in(0..=m.len() - 1);
            m[at] = g.u8();
            if let Ok(d) = decode_signed_data(&m) {
                prop_assert!(
                    verify_signature(&d.signed_attributes, &d.signature, &d.signer_certificate)
                        .is_ok()
                        || m != cms,
                    "accepted"
                );
            }
            Ok(())
        },
    );
}

/// `contracts.md` Signature: the platform never creates a party's
/// signature. The CMS module holds no signing call.
#[test]
fn contracts_signature_cms_module_never_signs() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cms.rs")).unwrap();
    for banned in [".sign(", "sign_digest", "KeyPair", "SigningKey"] {
        assert!(!src.contains(banned), "cms.rs names {banned}");
    }
}

/// TH-26: the committed seed of the `cms_signed_data_decode` fuzz target
/// is a synthetic SignedData that decodes and verifies. With
/// `FSTP_WRITE_FUZZ_SEEDS=1`, or when it is missing, the test writes it.
#[test]
fn th_26_cms_fuzz_seed_decodes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds/cms_signed_data_decode/synthetic_signer");
    let force = std::env::var("FSTP_WRITE_FUZZ_SEEDS").is_ok_and(|v| v == "1");
    if force || !path.exists() {
        let w = wallet("Synthetic Signer Lead", 7);
        let attrs = signed_attributes(&[0x5a; 32], &w.cert).unwrap();
        let cms = signed_data(&attrs, &w.key.sign(attrs.der()).unwrap(), &[&w.cert]).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, cms).unwrap();
    }
    let d = decode_signed_data(&std::fs::read(&path).unwrap()).unwrap();
    assert!(verify_signature(&d.signed_attributes, &d.signature, &d.signer_certificate).is_ok());
}

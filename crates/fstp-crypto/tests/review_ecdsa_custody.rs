//! Review reproducer (ADR-004 part 2 "Custody interface" and "CA keys in
//! custody", M3 design section 3.9).
//!
//! `fstp_custody::Custody::sign` takes a 32-byte SHA-256 digest and
//! returns a DER ECDSA P-256 signature. `fstp-keyd` holds the cluster CA
//! sign keys on its key volume, so it must reload a stored key and sign a
//! digest. `SimCustody` in `fstp-celltest` needs the same.
//!
//! `fstp_crypto::sig::EcdsaP256KeyPair` has only `generate`, `spki_der`,
//! `pkcs8_der` and `sign(message)`. It has no import and no digest
//! signing, so neither backend can be built on it.
//!
//! This file fails to compile against the current code. It compiles and
//! passes once the key pair imports PKCS#8 and signs a digest.

use fstp_crypto::sig::{self, EcdsaP256KeyPair};

/// A stored CA key reloads and signs a digest that verifies over the
/// message it hashes (ADR-004 part 2, ADR-005).
#[test]
fn review_ecdsa_p256_key_reloads_and_signs_a_digest() {
    let key = EcdsaP256KeyPair::generate().expect("generate");
    let spki = key.spki_der().expect("spki");
    let pkcs8 = key.pkcs8_der().expect("pkcs8");
    let reloaded = EcdsaP256KeyPair::from_pkcs8(&pkcs8[..]).expect("reload");
    assert_eq!(reloaded.spki_der().expect("spki"), spki);
    let tbs = b"tbsCertificate bytes";
    let digest = fstp_crypto::sha256(tbs);
    let signature = reloaded.sign_digest(&digest).expect("sign digest");
    assert!(sig::ecdsa_p256_sha256_verify(&spki, tbs, &signature).is_ok());
}

/// Review reproducer (ADR-004 part 2, design section 15
/// `custody_file_decode`). A stored CA key has one spelling: the PKCS#8
/// export with one trailing byte, or with any other byte appended, is
/// refused with the typed error. Before the fix the import accepted it.
#[test]
fn review_adr005_ecdsa_p256_from_pkcs8_refuses_trailing_bytes() {
    let key = EcdsaP256KeyPair::generate().expect("generate");
    let pkcs8 = key.pkcs8_der().expect("pkcs8");
    for tail in [&[0x00][..], &[0xff][..], &[0x04, 0x00][..]] {
        let mut long = pkcs8.to_vec();
        long.extend_from_slice(tail);
        assert_eq!(
            EcdsaP256KeyPair::from_pkcs8(&long).err(),
            Some(fstp_crypto::CryptoError::InvalidKey),
            "trailing {tail:02x?} accepted"
        );
    }
    assert!(EcdsaP256KeyPair::from_pkcs8(&pkcs8[..]).is_ok());
}

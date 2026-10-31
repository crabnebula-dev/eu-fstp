//! Known answers and round trips for the M3 `sig` module (design section
//! 2.2): Ed25519 sign and verify, ECDSA P-256 for the certificates of
//! design section 1.3 (ADR-005), and RSA PKCS#1 SHA-256 verify for
//! WebAuthn RS256 (ADR-008).
//!
//! The API under test, as this file expects it:
//!
//! ```text
//! fstp_crypto::sig::ED25519_PUBLIC_KEY_LEN: usize   // 32
//! fstp_crypto::sig::ED25519_SIGNATURE_LEN: usize    // 64
//! fstp_crypto::sig::Ed25519SigningKey::generate() -> Result<Ed25519SigningKey, CryptoError>
//! fstp_crypto::sig::Ed25519SigningKey::from_seed(&[u8; 32]) -> Result<Ed25519SigningKey, CryptoError>
//! fstp_crypto::sig::Ed25519SigningKey::public_key(&self) -> [u8; 32]
//! fstp_crypto::sig::Ed25519SigningKey::sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError>
//! fstp_crypto::sig::Ed25519SigningKey::seed(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError>
//! fstp_crypto::sig::ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::generate() -> Result<EcdsaP256KeyPair, CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::spki_der(&self) -> Result<Vec<u8>, CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::from_pkcs8(&[u8]) -> Result<EcdsaP256KeyPair, CryptoError>
//! fstp_crypto::sig::EcdsaP256KeyPair::sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, CryptoError>
//! fstp_crypto::sig::ecdsa_p256_sha256_verify(spki_der: &[u8], message: &[u8], signature_der: &[u8])
//!     -> Result<(), CryptoError>
//! fstp_crypto::sig::ecdsa_p256_sha256_verify_point(point: &[u8; 65], message: &[u8], signature_der: &[u8])
//!     -> Result<(), CryptoError>
//! fstp_crypto::sig::p256_point_check(point: &[u8; 65]) -> Result<(), CryptoError>
//! fstp_crypto::sig::p256_spki_check(spki_der: &[u8]) -> Result<(), CryptoError>
//! fstp_crypto::sig::P256_SPKI_PREFIX: [u8; 26]
//! fstp_crypto::sig::rsa_pkcs1_sha256_verify(n: &[u8], e: &[u8], message: &[u8], signature: &[u8])
//!     -> Result<(), CryptoError>
//! ```
//!
//! An ECDSA signature is the DER `ECDSA-Sig-Value` that X.509 carries, so
//! `fstp_pki::cert::assemble` takes it as it is. The PKCS#8 export may be
//! a plain `Vec<u8>` or a `Zeroizing<Vec<u8>>`; this file only derefs it.
//!
//! The RFC 8032 values were checked on 2026-10-28 with OpenSSL 3.6.4
//! (`openssl pkeyutl -sign -rawin`) and, for the empty message, with the
//! Ed25519 of Node.js 24.11.1. The fixed ECDSA and RSA vectors were made
//! with OpenSSL 3.6.4 from throwaway keys generated for this file; the
//! commands are next to them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use common::{arr, hex};
use fstp_crypto::CryptoError;
use fstp_crypto::sig::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, EcdsaP256KeyPair, Ed25519SigningKey,
    P256_POINT_LEN, ecdsa_p256_sha256_verify, ecdsa_p256_sha256_verify_point, ed25519_verify,
    p256_point_check, p256_spki_check, rsa_pkcs1_sha256_verify,
};
use fstp_prop::{Config, check_with, prop_assert};

// ---------------------------------------------------------------- Ed25519

struct Rfc8032 {
    seed: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}

/// RFC 8032 section 7.1, TEST 1 to TEST 3.
const RFC8032: [Rfc8032; 3] = [
    Rfc8032 {
        seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                    5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Rfc8032 {
        seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                    085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    Rfc8032 {
        seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                    18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
];

/// RFC 8032 section 7.1: the public key and the deterministic signature
/// for each seed, and the signature verifies.
#[test]
fn adr001_ed25519_rfc8032_vectors() {
    assert_eq!(ED25519_PUBLIC_KEY_LEN, 32);
    assert_eq!(ED25519_SIGNATURE_LEN, 64);
    for (n, v) in RFC8032.iter().enumerate() {
        let key = Ed25519SigningKey::from_seed(&arr::<32>(v.seed)).unwrap();
        assert_eq!(key.public_key().to_vec(), hex(v.public), "TEST {}", n + 1);
        let msg = hex(v.message);
        let sig = key.sign(&msg).unwrap();
        assert_eq!(sig.to_vec(), hex(v.signature), "TEST {}", n + 1);
        assert!(
            ed25519_verify(&hex(v.public), &msg, &hex(v.signature)).is_ok(),
            "TEST {}",
            n + 1
        );
    }
}

/// ADR-004 part 2: an Ed25519 level 2 key exports its RFC 8032 seed for
/// sealing, and the seed rebuilds the same key.
#[test]
fn adr001_ed25519_seed_round_trips() {
    for v in &RFC8032 {
        let key = Ed25519SigningKey::from_seed(&arr::<32>(v.seed)).unwrap();
        assert_eq!(key.seed().unwrap().to_vec(), hex(v.seed));
    }
    let key = Ed25519SigningKey::generate().unwrap();
    let back = Ed25519SigningKey::from_seed(&key.seed().unwrap()).unwrap();
    assert_eq!(back.public_key(), key.public_key());
    assert_eq!(back.sign(b"t").unwrap(), key.sign(b"t").unwrap());
}

/// A signature verifies only for its own key and message, and only at
/// exactly 64 bytes.
#[test]
fn adr001_ed25519_verify_refuses_other_keys_messages_and_lengths() {
    let v = &RFC8032[2];
    let public = hex(v.public);
    let msg = hex(v.message);
    let sig = hex(v.signature);
    assert!(ed25519_verify(&hex(RFC8032[1].public), &msg, &sig).is_err());
    assert!(ed25519_verify(&public, b"\xaf\x83", &sig).is_err());
    assert!(ed25519_verify(&public, &msg, &sig[..63]).is_err());
    let mut long = sig.clone();
    long.push(0);
    assert!(ed25519_verify(&public, &msg, &long).is_err());
    assert!(ed25519_verify(&public[..31], &msg, &sig).is_err());
    assert!(ed25519_verify(&public, &msg, &[]).is_err());
}

/// Flipping any bit of a signature, a public key or the message makes
/// verification fail.
#[test]
fn adr001_ed25519_any_flipped_bit_is_refused() {
    let key = Ed25519SigningKey::generate().unwrap();
    let public = key.public_key();
    let msg = b"fstp ticket body".to_vec();
    let sig = key.sign(&msg).unwrap();
    assert!(ed25519_verify(&public, &msg, &sig).is_ok());
    check_with(
        "adr001_ed25519_any_flipped_bit_is_refused",
        Config::default().with_cases(256),
        |g| {
            let which = g.usize_in(0..=2);
            let (mut p, mut m, mut s) = (public.to_vec(), msg.clone(), sig.to_vec());
            let target = match which {
                0 => &mut p,
                1 => &mut m,
                _ => &mut s,
            };
            let bit = g.usize_in(0..=target.len() * 8 - 1);
            g.note("which", &which);
            g.note("bit", &bit);
            target[bit / 8] ^= 1 << (bit % 8);
            prop_assert!(ed25519_verify(&p, &m, &s).is_err());
            Ok(())
        },
    );
}

// ----------------------------------------------------------- ECDSA P-256

/// The DER prefix of a P-256 SubjectPublicKeyInfo (RFC 5480): the
/// id-ecPublicKey and prime256v1 identifiers, then a 66-byte BIT STRING
/// that holds an uncompressed point.
const P256_SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

/// A throwaway OpenSSL key and its signature over [`OPENSSL_MESSAGE`].
/// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.pem`
/// `openssl pkey -in ec.pem -pubout -outform DER | xxd -p`
const OPENSSL_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004055f274a732d79a4\
     4eae042d0955ef3f291a3d66ff603b5c8a54ea34dc412c69616c56b140d04d234883f1dbe5401f73732bc803\
     a3d7dfa2e19beaaaff099d43";
const OPENSSL_MESSAGE: &[u8] = b"fstp-crypto ecdsa p-256 vector";
/// `printf 'fstp-crypto ecdsa p-256 vector' | openssl dgst -sha256 -sign ec.pem | xxd -p`
const OPENSSL_SIGNATURE: &str = "304402204627490c329cb8a5e33d0bf9b400892da845de9b5b02bce7406785ff9093\
     171d022000cd9cac002bbc17aad95f99e01f163438cca8c9a13a40244c4e845d9d7e611a";

/// Splits a DER `ECDSA-Sig-Value` into its two INTEGER contents, checking
/// the minimal form. Returns `None` for anything else.
fn ecdsa_sig_value(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = der.split_first()?;
    let (&len, body) = rest.split_first()?;
    if tag != 0x30 || len >= 0x80 || usize::from(len) != body.len() {
        return None;
    }
    let mut ints = Vec::new();
    let mut cur = body;
    while !cur.is_empty() {
        let (&t, r) = cur.split_first()?;
        let (&l, r) = r.split_first()?;
        let l = usize::from(l);
        if t != 0x02 || l == 0 || l > 33 || r.len() < l {
            return None;
        }
        let (v, r) = r.split_at(l);
        // Positive and minimal: no needless leading zero, high bit clear.
        if v[0] & 0x80 != 0 || (v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0) {
            return None;
        }
        ints.push(v.to_vec());
        cur = r;
    }
    if ints.len() != 2 {
        return None;
    }
    let s = ints.pop()?;
    let r = ints.pop()?;
    Some((r, s))
}

/// The OpenSSL vector verifies, and its mutations do not (ADR-005 proof of
/// possession and role certificates rest on this verifier).
#[test]
fn adr005_ecdsa_p256_verifies_an_openssl_signature() {
    let spki = hex(OPENSSL_SPKI);
    let sig = hex(OPENSSL_SIGNATURE);
    assert!(ecdsa_p256_sha256_verify(&spki, OPENSSL_MESSAGE, &sig).is_ok());
    assert!(ecdsa_p256_sha256_verify(&spki, b"fstp-crypto ecdsa p-256 vectoR", &sig).is_err());
    let mut bad = sig.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(ecdsa_p256_sha256_verify(&spki, OPENSSL_MESSAGE, &bad).is_err());
    assert!(ecdsa_p256_sha256_verify(&spki[1..], OPENSSL_MESSAGE, &sig).is_err());
    assert!(ecdsa_p256_sha256_verify(&spki, OPENSSL_MESSAGE, &[]).is_err());
}

/// Design section 1.3: a generated key exports a P-256 SPKI and a PKCS#8
/// document for the same key, and its signatures are DER
/// `ECDSA-Sig-Value`s that the aws-lc-rs ASN.1 verifier accepts.
#[test]
fn adr005_ecdsa_p256_key_exports_and_signs_der() {
    let kp = EcdsaP256KeyPair::generate().unwrap();
    let spki = kp.spki_der().unwrap();
    assert_eq!(spki.len(), 91);
    assert_eq!(spki[..26].to_vec(), hex(P256_SPKI_PREFIX));
    assert_eq!(spki[26], 0x04, "uncompressed point");
    let point = &spki[26..];

    let pkcs8 = kp.pkcs8_der().unwrap();
    let pkcs8: &[u8] = &pkcs8;
    let imported = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
        .expect("aws-lc-rs refused the exported PKCS#8");
    assert_eq!(imported.public_key().as_ref(), point);

    let msg = b"tbsCertificate bytes";
    let sig = kp.sign(msg).unwrap();
    let (r, s) = ecdsa_sig_value(&sig).expect("signature is not a DER ECDSA-Sig-Value");
    assert!(r.len() <= 33 && s.len() <= 33);
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(msg, &sig)
            .is_ok()
    );
    assert!(ecdsa_p256_sha256_verify(&spki, msg, &sig).is_ok());
    assert!(ecdsa_p256_sha256_verify(&spki, b"other bytes", &sig).is_err());
}

/// Two generated keys differ, and the PKCS#8 export carries the private
/// key (it differs between keys).
#[test]
fn adr005_ecdsa_p256_generated_keys_differ() {
    let a = EcdsaP256KeyPair::generate().unwrap();
    let b = EcdsaP256KeyPair::generate().unwrap();
    assert_ne!(a.spki_der().unwrap(), b.spki_der().unwrap());
    let (pa, pb) = (a.pkcs8_der().unwrap(), b.pkcs8_der().unwrap());
    let (pa, pb): (&[u8], &[u8]) = (&pa, &pb);
    assert_ne!(pa, pb);
}

/// Every flipped bit of a fresh signature is refused.
#[test]
fn adr005_ecdsa_p256_any_flipped_signature_bit_is_refused() {
    let kp = EcdsaP256KeyPair::generate().unwrap();
    let spki = kp.spki_der().unwrap();
    let msg = b"proof of possession".to_vec();
    let sig = kp.sign(&msg).unwrap();
    check_with(
        "adr005_ecdsa_p256_any_flipped_signature_bit_is_refused",
        Config::default().with_cases(256),
        |g| {
            let bit = g.usize_in(0..=sig.len() * 8 - 1);
            g.note("bit", &bit);
            let mut bad = sig.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            prop_assert!(ecdsa_p256_sha256_verify(&spki, &msg, &bad).is_err());
            Ok(())
        },
    );
}

/// ADR-004 part 2 and ADR-005: a stored CA key reloads from its PKCS#8
/// export and signs a digest. The result verifies over the message whose
/// SHA-256 it signed, and over no other.
#[test]
fn adr005_ecdsa_p256_reloaded_key_signs_a_digest() {
    let kp = EcdsaP256KeyPair::generate().unwrap();
    let spki = kp.spki_der().unwrap();
    let pkcs8 = kp.pkcs8_der().unwrap();
    let reloaded = EcdsaP256KeyPair::from_pkcs8(&pkcs8).unwrap();
    assert_eq!(reloaded.spki_der().unwrap(), spki);
    let tbs = b"tbsCertificate bytes";
    let sig = reloaded.sign_digest(&fstp_crypto::sha256(tbs)).unwrap();
    assert!(ecdsa_sig_value(&sig).is_some(), "not a DER ECDSA-Sig-Value");
    assert!(ecdsa_p256_sha256_verify(&spki, tbs, &sig).is_ok());
    assert!(ecdsa_p256_sha256_verify(&spki, b"other bytes", &sig).is_err());
    let original = kp.sign_digest(&fstp_crypto::sha256(tbs)).unwrap();
    assert!(ecdsa_p256_sha256_verify(&spki, tbs, &original).is_ok());
}

/// ADR-005: a PKCS#8 import refuses anything but a P-256 key, with the
/// typed error.
#[test]
fn adr005_ecdsa_p256_from_pkcs8_refuses_other_documents() {
    let ed = Ed25519SigningKey::generate().unwrap();
    let seed = ed.seed().unwrap();
    let mut ed_pkcs8 = hex("302e020100300506032b657004220420");
    ed_pkcs8.extend_from_slice(&seed[..]);
    let p384 = EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING)
        .unwrap()
        .to_pkcs8v1()
        .unwrap();
    let good = EcdsaP256KeyPair::generate().unwrap().pkcs8_der().unwrap();
    let mut truncated = good.to_vec();
    truncated.pop();
    for bad in [
        &ed_pkcs8[..],
        p384.as_ref(),
        &truncated[..],
        &[][..],
        &[0x30][..],
    ] {
        assert_eq!(
            EcdsaP256KeyPair::from_pkcs8(bad).err(),
            Some(CryptoError::InvalidKey)
        );
    }
}

/// ADR-008 ES256: a SubjectPublicKeyInfo of the right length and prefix
/// whose point is off the curve is an invalid key, not an invalid
/// signature. The key checks refuse it on their own too.
#[test]
fn adr008_es256_off_curve_point_is_an_invalid_key() {
    let mut spki = hex(OPENSSL_SPKI);
    let sig = hex(OPENSSL_SIGNATURE);
    assert_eq!(p256_spki_check(&spki), Ok(()));
    *spki.last_mut().unwrap() ^= 1;
    assert_eq!(
        ecdsa_p256_sha256_verify(&spki, OPENSSL_MESSAGE, &sig),
        Err(CryptoError::InvalidKey)
    );
    assert_eq!(p256_spki_check(&spki), Err(CryptoError::InvalidKey));
    let point: [u8; P256_POINT_LEN] = spki[26..].try_into().unwrap();
    assert_eq!(p256_point_check(&point), Err(CryptoError::InvalidKey));
    assert_eq!(
        ecdsa_p256_sha256_verify_point(&point, OPENSSL_MESSAGE, &sig),
        Err(CryptoError::InvalidKey)
    );
}

/// ADR-008 ES256: the raw point `0x04 || x || y` of a COSE key verifies
/// as its SubjectPublicKeyInfo does, and the published prefix rebuilds
/// that SubjectPublicKeyInfo. A compressed or infinity point is refused.
#[test]
fn adr008_es256_verifies_under_a_raw_point() {
    let spki = hex(OPENSSL_SPKI);
    let sig = hex(OPENSSL_SIGNATURE);
    assert_eq!(
        spki[..26].to_vec(),
        fstp_crypto::sig::P256_SPKI_PREFIX.to_vec()
    );
    let point: [u8; P256_POINT_LEN] = spki[26..].try_into().unwrap();
    assert_eq!(p256_point_check(&point), Ok(()));
    assert_eq!(
        ecdsa_p256_sha256_verify_point(&point, OPENSSL_MESSAGE, &sig),
        Ok(())
    );
    assert_eq!(
        ecdsa_p256_sha256_verify_point(&point, b"other bytes", &sig),
        Err(CryptoError::InvalidSignature)
    );
    let mut compressed = point;
    compressed[0] = 0x02;
    assert_eq!(p256_point_check(&compressed), Err(CryptoError::InvalidKey));
    assert_eq!(
        p256_point_check(&[0u8; P256_POINT_LEN]),
        Err(CryptoError::InvalidKey)
    );
}

// ------------------------------------------------- RSA PKCS#1 SHA-256

/// A throwaway 2048-bit OpenSSL key.
/// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem`
/// `openssl rsa -in rsa.pem -noout -modulus`
const RSA_N: &str = "B2BDFF89E6EC8D6E4BB69747BCA212CC7782BA36BD9E855FABAF405520002139D5580D4E0E6B0FA5\
    2D359016F5F52DF4AC1C5E4655E1616E48DB86E94FB3C818A7BD0D7D4FB6EA76A077D025761EBF17FCDE71D4CC\
    3D21815D5B984322EF9E2820022883C2E4F041E9E716937DAB9DF555D95FBECCCD9C97B2EB57DB2E4C9CD522A2\
    054AAA2591C12090D8857C2575F779CF76ABDF8FD150AE9B059E20B91275843BC75C489F30F792E397ACDA4E53\
    D212133077075D1845E81F2AB812D6803F4649681E0A27DB4BC1C6A8D0E54126B4FB36A451F0F7AC3F4154E643\
    76002FF0773856437256A618AD3AFF050FD0567AE3AFEE80032F3EE7FC2EDD34F740AE15";
const RSA_E: &str = "010001";
const RSA_MESSAGE: &[u8] = b"fstp-crypto rs256 vector";
/// `printf 'fstp-crypto rs256 vector' | openssl dgst -sha256 -sign rsa.pem | xxd -p`
const RSA_SIGNATURE: &str = "a02014237f78e5adea75b7bd6f59a958aee753d47a61dd6cf39dd2010d57f44f1e52d934\
    7b10e46e7564f23f8268d8c0445ff739b532823fac2580fc94cc78d23a0e94ea0ba9f2772e6a3ac04d921f0f3d\
    4360564d8a97aec7f38ad0b6b982d28c88c00efce6d08dfa65607edc33f16abf98bac110b13c6a8a0a39eb7170\
    f3bd9bc9fe292ae2185a011847f5619afd038b852a95af9273b81e4c8a6279ae6a70b5a4fd7c0b4ea7213aff74\
    524349b926106adba781b7931576fd770ed5ff3aeed3a0fa23d0b416a127f68629e1a86b5289996251cb1daf0d\
    104d36e3b8958865a0294cef6dea85c80614fa8168b3e286e35cf262a0edc7dca948b7c4255507ef";

/// ADR-008: WebAuthn RS256 assertions verify through RSA PKCS#1 v1.5 with
/// SHA-256 over the COSE key's modulus and exponent.
#[test]
fn adr008_rs256_verifies_an_openssl_signature() {
    let (n, e, sig) = (hex(RSA_N), hex(RSA_E), hex(RSA_SIGNATURE));
    assert_eq!(n.len(), 256);
    assert!(rsa_pkcs1_sha256_verify(&n, &e, RSA_MESSAGE, &sig).is_ok());
    assert!(rsa_pkcs1_sha256_verify(&n, &e, b"fstp-crypto rs256 vectoR", &sig).is_err());
    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    assert!(rsa_pkcs1_sha256_verify(&n, &e, RSA_MESSAGE, &bad).is_err());
    assert!(rsa_pkcs1_sha256_verify(&n, &hex("03"), RSA_MESSAGE, &sig).is_err());
    assert!(rsa_pkcs1_sha256_verify(&n, &e, RSA_MESSAGE, &sig[..255]).is_err());
}

/// A throwaway 1024-bit OpenSSL key and its valid signature over
/// [`RSA_MESSAGE`]. OpenSSL verifies it (`Verified OK`).
/// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1k.pem`
const RSA_1024_N: &str = "CD4E8D864E4AA85CC69F0602556415B725FA9C7B139602D11D6F5363466071B614C633CAD8BA\
    A3B4EA72FD1F2D7C79E78998A767F73C399975499FED6ECA46F395CB9A4B6EA7537CE9AE6F39120938E0C307DECED7\
    1FC5D70815E538A3C92C34E3AFC63D1E5D9EFE2CA689484E1ACE6CA914B11FB538F581A3A1407D0C0C0E93";
/// `printf 'fstp-crypto rs256 vector' | openssl dgst -sha256 -sign rsa1k.pem | xxd -p`
const RSA_1024_SIGNATURE: &str = "25f54c2eabf2fc74b090c87b5ee10760f980347d6654d8ed7d8a5a65d97f4f950ca8\
    435cff9222cc21f8d8a15d689a5ec8c26f4222abfd478c26130aa571083fd11bf75a9642489b9250e089f902722bac9c\
    82453bae1b3cf3ebefe8db8a336526522d34229b9fec30efb13dea094250c6e555387c9a8d1693d04ec89ec4d40e";

/// ADR-008 "Algorithms": RS256 needs a modulus of at least 2048 bits. A
/// valid signature under a 1024-bit key is refused.
#[test]
fn adr008_rs256_refuses_a_modulus_below_2048_bits() {
    let n = hex(RSA_1024_N);
    assert_eq!(n.len(), 128);
    assert!(
        rsa_pkcs1_sha256_verify(&n, &hex(RSA_E), RSA_MESSAGE, &hex(RSA_1024_SIGNATURE)).is_err()
    );
}

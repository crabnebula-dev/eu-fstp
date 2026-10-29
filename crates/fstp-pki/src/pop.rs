//! Proof of possession for certificate requests (M3 design sections 1.3
//! and 9.1, ADR-005 "Role certificates").
//!
//! A component generates its own P-256 key pair. It proves that it holds
//! the private key by signing a fresh challenge from the issuer, bound to
//! the request it makes. No certificate signing request is parsed. The
//! signed message is
//!
//! `"fstp-pki-pop-v1\0" || purpose || scope_id || len(name) || name ||
//! SHA-256(spki_der) || challenge`
//!
//! and the signature is ASN.1 DER ECDSA P-256 with SHA-256. The prefix
//! separates this signature from every other use of the key. `purpose` is
//! one octet, `scope_id` is 16 octets, and `name` follows its one-octet
//! length, so the message has one reading. The SPKI digest is the
//! `SpkiDigest` that `RoleCredential` and `CertRenewal` carry.
//!
//! The context binds the proof to one request. A proof made for
//! `c_<cell>_app` therefore never verifies for `c_<cell>_keys`, for
//! another cell or cluster, or for a `CertRenewal`.
//!
//! The issuer keeps each challenge single-use: it draws the challenge at
//! random, hands it to one requester for one context, and consumes it
//! once, whether the proof verifies or not. [`verify`] therefore takes the
//! challenge as its own argument, from that single-use record. The proof
//! carries none, so a replayed proof never brings its old challenge along.
//! `RoleCredential` and `CertRenewal` carry no challenge either (design
//! section 9.1).

use crate::PkiError;
use crate::cert::is_p256_spki;

/// The domain separation prefix of the signed message.
pub const POP_DOMAIN: &[u8; 16] = b"fstp-pki-pop-v1\0";

/// The length of the issuer's challenge, in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// The length of the scope id of a [`PopContext`], in bytes: a `CellId` or
/// a `ClusterId`, each 128 bits.
pub const SCOPE_ID_LEN: usize = 16;

/// The longest role or component name of a [`PopContext`], in bytes. The
/// name becomes the certificate CN, which holds at most 64 characters.
pub const MAX_CONTEXT_NAME_LEN: usize = 64;

/// The longest signed message, in bytes.
pub const MAX_MESSAGE_LEN: usize =
    POP_DOMAIN.len() + 1 + SCOPE_ID_LEN + 1 + MAX_CONTEXT_NAME_LEN + 32 + CHALLENGE_LEN;

/// The shortest ASN.1 DER ECDSA signature: `SEQUENCE { INTEGER, INTEGER }`
/// with one content octet in each INTEGER.
const MIN_SIGNATURE_LEN: usize = 8;

/// The longest ASN.1 DER ECDSA P-256 signature: two 33-octet INTEGERs.
const MAX_SIGNATURE_LEN: usize = 72;

/// The request a proof of possession is for (design section 9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PopPurpose {
    /// A `RoleCredential` message: a role certificate from a cluster CA.
    RoleCredential,
    /// A `CertRenewal` message: a renewed component certificate.
    CertRenewal,
}

impl PopPurpose {
    /// The octet that stands for the purpose in the signed message.
    pub fn tag(self) -> u8 {
        match self {
            PopPurpose::RoleCredential => 1,
            PopPurpose::CertRenewal => 2,
        }
    }
}

/// The request context a proof of possession is bound to. The issuer
/// builds it from its own record of the request, never from bytes the
/// requester chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopContext {
    /// The message the proof is for.
    pub purpose: PopPurpose,
    /// The `CellId` of the requesting cell, or the `ClusterId` for a role
    /// of the cluster itself, such as `fstp_super`.
    pub scope_id: [u8; SCOPE_ID_LEN],
    /// The role (`RoleCredential`) or component (`CertRenewal`) the
    /// certificate is for, 1 to 64 bytes. It becomes the certificate CN.
    pub name: String,
}

/// A proof that the requester holds the private key of `spki_der`. It
/// holds no challenge: the issuer passes its own to [`verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfPossession {
    /// The subject public key info, DER, of an uncompressed P-256 key.
    pub spki_der: Vec<u8>,
    /// The ASN.1 DER ECDSA P-256 SHA-256 signature over [`message`].
    pub signature: Vec<u8>,
}

/// The SHA-256 digest of `spki_der`, as `RoleCredential` and
/// `CertRenewal` carry it (design section 9.1).
pub fn spki_digest(spki_der: &[u8]) -> [u8; 32] {
    fstp_crypto::sha256(spki_der)
}

/// The bytes the requester signs to prove possession of the key of
/// `spki_der` against `challenge`, for the request `ctx`.
///
/// # Errors
///
/// [`PkiError::SpkiNotP256`] when `spki_der` is not the SPKI of an
/// uncompressed P-256 key. [`PkiError::PopContextInvalid`] when the name
/// of `ctx` is empty or longer than 64 bytes.
pub fn message(
    spki_der: &[u8],
    ctx: &PopContext,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<Vec<u8>, PkiError> {
    if !is_p256_spki(spki_der) {
        return Err(PkiError::SpkiNotP256);
    }
    let name = ctx.name.as_bytes();
    let name_len = match u8::try_from(name.len()) {
        Ok(n) if (1..=MAX_CONTEXT_NAME_LEN).contains(&name.len()) => n,
        _ => return Err(PkiError::PopContextInvalid),
    };
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    out.extend_from_slice(POP_DOMAIN);
    out.push(ctx.purpose.tag());
    out.extend_from_slice(&ctx.scope_id);
    out.push(name_len);
    out.extend_from_slice(name);
    out.extend_from_slice(&spki_digest(spki_der));
    out.extend_from_slice(challenge);
    Ok(out)
}

/// Checks a proof of possession for the request `ctx` against
/// `challenge`. A forged proof, a proof made for another context, or a
/// proof over another challenge is refused.
///
/// The issuer passes `challenge` from its own single-use record of the
/// request, never from bytes the requester sent. It consumes that record
/// once, whatever the result.
///
/// # Errors
///
/// [`PkiError::SpkiNotP256`] for an SPKI outside the profile, including
/// one whose point does not lie on the curve.
/// [`PkiError::PopContextInvalid`] for a malformed context, and
/// [`PkiError::PopSignatureInvalid`] for a signature that does not verify.
pub fn verify(
    proof: &ProofOfPossession,
    ctx: &PopContext,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<(), PkiError> {
    verify_with(proof, ctx, challenge, ecdsa_p256_sha256_verify)
}

/// The checks of [`verify`], with the signature verifier passed in.
/// `verifier` takes the SPKI, the message and the signature.
fn verify_with(
    proof: &ProofOfPossession,
    ctx: &PopContext,
    challenge: &[u8; CHALLENGE_LEN],
    verifier: impl FnOnce(&[u8], &[u8], &[u8]) -> Result<(), PkiError>,
) -> Result<(), PkiError> {
    let msg = message(&proof.spki_der, ctx, challenge)?;
    let len = proof.signature.len();
    if !(MIN_SIGNATURE_LEN..=MAX_SIGNATURE_LEN).contains(&len) {
        return Err(PkiError::PopSignatureInvalid);
    }
    verifier(&proof.spki_der, &msg, &proof.signature)
}

/// The ECDSA P-256 SHA-256 check of design section 2.2, through
/// [`fstp_crypto::sig::ecdsa_p256_sha256_verify`]. `fstp-pki` implements
/// no primitive and names no third-party crate.
///
/// A key that `fstp-crypto` refuses, such as a point off the curve, maps
/// to [`PkiError::SpkiNotP256`]. Every other failure maps to
/// [`PkiError::PopSignatureInvalid`], so the step fails closed.
fn ecdsa_p256_sha256_verify(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PkiError> {
    fstp_crypto::sig::ecdsa_p256_sha256_verify(spki_der, message, signature).map_err(|e| match e {
        fstp_crypto::CryptoError::InvalidKey => PkiError::SpkiNotP256,
        _ => PkiError::PopSignatureInvalid,
    })
}

#[cfg(test)]
mod tests {
    //! The checks of `verify_with` against aws-lc-rs as the verifier, a
    //! dev-dependency, and of [`verify`] through `fstp-crypto`. Signing
    //! with aws-lc-rs directly lets the tests make proofs in the wrong
    //! algorithm or encoding, which `fstp_crypto::sig` cannot produce.

    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P256K1_SHA256_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair,
        KeyPair as _, UnparsedPublicKey,
    };
    use fstp_crypto::sig::{EcdsaP256KeyPair, P256_SPKI_LEN, P256_SPKI_PREFIX};
    use fstp_prop::{Config, check_with, prop_assert};

    use super::*;

    const CHALLENGE: [u8; CHALLENGE_LEN] = [0x5a; CHALLENGE_LEN];

    fn ctx() -> PopContext {
        PopContext {
            purpose: PopPurpose::RoleCredential,
            scope_id: [0x01; SCOPE_ID_LEN],
            name: "c_0123456789abcdef0123456789abcdef_app".to_owned(),
        }
    }

    fn key() -> EcdsaKeyPair {
        key_for(&ECDSA_P256_SHA256_ASN1_SIGNING)
    }

    /// An aws-lc-rs key pair for `alg`, which fixes the curve, the hash
    /// and the signature encoding.
    fn key_for(alg: &'static EcdsaSigningAlgorithm) -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("aws-lc-rs generates a key");
        EcdsaKeyPair::from_pkcs8(alg, doc.as_ref()).expect("aws-lc-rs reads its key")
    }

    fn spki(k: &EcdsaKeyPair) -> Vec<u8> {
        k.public_key()
            .as_der()
            .expect("aws-lc-rs encodes the SPKI")
            .as_ref()
            .to_vec()
    }

    fn sign(k: &EcdsaKeyPair, msg: &[u8]) -> Vec<u8> {
        k.sign(&SystemRandom::new(), msg)
            .expect("aws-lc-rs signs")
            .as_ref()
            .to_vec()
    }

    /// The aws-lc-rs verifier over the uncompressed point of the SPKI.
    fn aws(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), PkiError> {
        let point = &spki_der[26..];
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(msg, sig)
            .map_err(|_| PkiError::PopSignatureInvalid)
    }

    fn proof(k: &EcdsaKeyPair) -> ProofOfPossession {
        let spki_der = spki(k);
        let msg = message(&spki_der, &ctx(), &CHALLENGE).expect("a P-256 SPKI");
        ProofOfPossession {
            signature: sign(k, &msg),
            spki_der,
        }
    }

    #[test]
    fn adr005_pop_valid_proof_verifies_with_a_real_verifier() {
        let k = key();
        assert_eq!(verify_with(&proof(&k), &ctx(), &CHALLENGE, aws), Ok(()));
    }

    #[test]
    fn adr005_pop_mismatches_are_refused_with_a_real_verifier() {
        let k = key();
        let other = key();
        let good = proof(&k);

        let mut fresh = CHALLENGE;
        fresh[0] ^= 1;
        assert_eq!(
            verify_with(&good, &ctx(), &fresh, aws),
            Err(PkiError::PopSignatureInvalid)
        );

        let mut p = good.clone();
        p.spki_der = spki(&other);
        assert_eq!(
            verify_with(&p, &ctx(), &CHALLENGE, aws),
            Err(PkiError::PopSignatureInvalid)
        );

        let mut p = good.clone();
        let last = p.signature.len() - 1;
        p.signature[last] ^= 1;
        assert_eq!(
            verify_with(&p, &ctx(), &CHALLENGE, aws),
            Err(PkiError::PopSignatureInvalid)
        );

        let mut p = good.clone();
        p.signature.push(0);
        assert!(verify_with(&p, &ctx(), &CHALLENGE, aws).is_err());

        let mut p = good.clone();
        p.signature.clear();
        assert_eq!(
            verify_with(&p, &ctx(), &CHALLENGE, aws),
            Err(PkiError::PopSignatureInvalid)
        );

        let mut p = good;
        p.spki_der.push(0);
        assert_eq!(
            verify_with(&p, &ctx(), &CHALLENGE, aws),
            Err(PkiError::SpkiNotP256)
        );
    }

    #[test]
    fn adr005_pop_proof_for_another_context_is_refused_with_a_real_verifier() {
        let good = proof(&key());
        let mut role = ctx();
        role.name = "c_0123456789abcdef0123456789abcdef_keys".to_owned();
        let mut scope = ctx();
        scope.scope_id[15] ^= 1;
        let mut purpose = ctx();
        purpose.purpose = PopPurpose::CertRenewal;
        for other in [role, scope, purpose] {
            assert_eq!(
                verify_with(&good, &other, &CHALLENGE, aws),
                Err(PkiError::PopSignatureInvalid),
                "{other:?}"
            );
        }
    }

    /// Review round 2, finding 6: the issuer passes its own fresh
    /// challenge. A proof replayed from an earlier request for the same
    /// context, key and SPKI is refused, since its signature covers the
    /// old challenge and the proof cannot name which challenge it used.
    #[test]
    fn review_adr005_pop_replayed_proof_is_refused_for_the_issuers_fresh_challenge() {
        let k = key();
        let old = proof(&k);
        let fresh = [0xa5; CHALLENGE_LEN];
        assert_eq!(
            verify_with(&old, &ctx(), &fresh, aws),
            Err(PkiError::PopSignatureInvalid)
        );
        let msg = message(&old.spki_der, &ctx(), &fresh).expect("a P-256 SPKI");
        let answer = ProofOfPossession {
            signature: sign(&k, &msg),
            spki_der: old.spki_der,
        };
        assert_eq!(verify_with(&answer, &ctx(), &fresh, aws), Ok(()));
    }

    #[test]
    fn adr005_pop_message_has_the_fixed_layout() {
        let spki_der = spki(&key());
        let c = ctx();
        let msg = message(&spki_der, &c, &CHALLENGE).expect("a P-256 SPKI");
        let n = c.name.len();
        assert_eq!(msg.len(), 16 + 1 + 16 + 1 + n + 32 + 32);
        assert_eq!(&msg[..16], POP_DOMAIN);
        assert_eq!(msg[16], 1);
        assert_eq!(&msg[17..33], &c.scope_id);
        assert_eq!(usize::from(msg[33]), n);
        assert_eq!(&msg[34..34 + n], c.name.as_bytes());
        assert_eq!(&msg[34 + n..66 + n], &fstp_crypto::sha256(&spki_der));
        assert_eq!(&msg[66 + n..], &CHALLENGE);
    }

    #[test]
    fn adr005_pop_context_name_of_0_or_65_bytes_is_refused() {
        let spki_der = spki(&key());
        for len in [0, MAX_CONTEXT_NAME_LEN + 1] {
            let mut c = ctx();
            c.name = "a".repeat(len);
            assert_eq!(
                message(&spki_der, &c, &CHALLENGE),
                Err(PkiError::PopContextInvalid)
            );
        }
        let mut c = ctx();
        c.name = "a".repeat(MAX_CONTEXT_NAME_LEN);
        assert_eq!(
            message(&spki_der, &c, &CHALLENGE).map(|m| m.len()),
            Ok(MAX_MESSAGE_LEN)
        );
    }

    /// The reference layout of the signed message, written without the
    /// SPKI check of [`message`], so a test can sign it for any key.
    fn layout(spki_der: &[u8], c: &PopContext, challenge: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
        let mut out = POP_DOMAIN.to_vec();
        out.push(c.purpose.tag());
        out.extend_from_slice(&c.scope_id);
        out.push(u8::try_from(c.name.len()).expect("a short name"));
        out.extend_from_slice(c.name.as_bytes());
        out.extend_from_slice(&fstp_crypto::sha256(spki_der));
        out.extend_from_slice(challenge);
        out
    }

    /// A key pair from `fstp_crypto::sig`, as a requester holds it, and
    /// its proof for [`ctx`] against [`CHALLENGE`].
    fn crypto_proof() -> (EcdsaP256KeyPair, ProofOfPossession) {
        let k = EcdsaP256KeyPair::generate().expect("fstp-crypto generates a key");
        let spki_der = k.spki_der().expect("fstp-crypto encodes the SPKI");
        let msg = message(&spki_der, &ctx(), &CHALLENGE).expect("a P-256 SPKI");
        let signature = k.sign(&msg).expect("fstp-crypto signs");
        (
            k,
            ProofOfPossession {
                spki_der,
                signature,
            },
        )
    }

    /// ADR-005, design section 2.2: [`verify`] reaches the `fstp-crypto`
    /// verifier and accepts a proof signed through `fstp_crypto::sig`.
    #[test]
    fn adr005_pop_verify_accepts_a_proof_signed_through_fstp_crypto() {
        let (_, p) = crypto_proof();
        assert_eq!(verify(&p, &ctx(), &CHALLENGE), Ok(()));
    }

    /// ADR-005: [`verify`] accepts a DER ECDSA P-256 SHA-256 proof from
    /// another implementation, aws-lc-rs called directly.
    #[test]
    fn adr005_pop_verify_accepts_a_proof_signed_by_aws_lc_rs() {
        assert_eq!(verify(&proof(&key()), &ctx(), &CHALLENGE), Ok(()));
    }

    /// Design section 1.3: every component key is P-256, so an Ed25519
    /// proof is the wrong algorithm. Its 64-byte signature fits the length
    /// bound, and the SPKI refuses it with a typed error.
    #[test]
    fn adr005_pop_ed25519_proof_is_refused_as_not_p256() {
        let k = Ed25519KeyPair::generate().expect("aws-lc-rs generates a key");
        let mut spki_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki_der.extend_from_slice(k.public_key().as_ref());
        let p = ProofOfPossession {
            signature: k
                .sign(&layout(&spki_der, &ctx(), &CHALLENGE))
                .as_ref()
                .to_vec(),
            spki_der,
        };
        assert_eq!(verify(&p, &ctx(), &CHALLENGE), Err(PkiError::SpkiNotP256));
    }

    /// Design section 1.3: a secp256k1 key is another curve under the
    /// same ECDSA SHA-256 scheme. Its SPKI is refused as not P-256.
    #[test]
    fn adr005_pop_secp256k1_proof_is_refused_as_not_p256() {
        let k = key_for(&ECDSA_P256K1_SHA256_ASN1_SIGNING);
        let spki_der = spki(&k);
        let p = ProofOfPossession {
            signature: sign(&k, &layout(&spki_der, &ctx(), &CHALLENGE)),
            spki_der,
        };
        assert_eq!(verify(&p, &ctx(), &CHALLENGE), Err(PkiError::SpkiNotP256));
    }

    /// ADR-005: the signature is the DER `ECDSA-Sig-Value`. A fixed-length
    /// `r || s` signature by the right key over the right message is the
    /// wrong encoding and is refused.
    #[test]
    fn adr005_pop_fixed_length_signature_is_refused() {
        let k = key_for(&ECDSA_P256_SHA256_FIXED_SIGNING);
        let spki_der = spki(&k);
        let msg = message(&spki_der, &ctx(), &CHALLENGE).expect("a P-256 SPKI");
        let p = ProofOfPossession {
            signature: sign(&k, &msg),
            spki_der,
        };
        assert_eq!(p.signature.len(), 64);
        assert_eq!(
            verify(&p, &ctx(), &CHALLENGE),
            Err(PkiError::PopSignatureInvalid)
        );
    }

    /// Design section 1.3: an SPKI of any length but 91 bytes is refused,
    /// whether truncated, extended, or the 59-byte compressed form.
    #[test]
    fn adr005_pop_spki_of_the_wrong_length_is_refused() {
        let (_, good) = crypto_proof();
        let mut spkis: Vec<Vec<u8>> = [0, 1, P256_SPKI_PREFIX.len(), P256_SPKI_LEN - 1]
            .iter()
            .map(|&n| good.spki_der[..n].to_vec())
            .collect();
        let mut longer = good.spki_der.clone();
        longer.push(0);
        spkis.push(longer);
        let mut compressed = vec![0x30, 0x39];
        compressed.extend_from_slice(&P256_SPKI_PREFIX[2..23]);
        compressed.extend_from_slice(&[0x03, 0x22, 0x00, 0x02 | (good.spki_der[90] & 1)]);
        compressed.extend_from_slice(&good.spki_der[27..59]);
        assert_eq!(compressed.len(), 59);
        spkis.push(compressed);
        for spki_der in spkis {
            let n = spki_der.len();
            let p = ProofOfPossession {
                spki_der,
                signature: good.signature.clone(),
            };
            assert_eq!(
                verify(&p, &ctx(), &CHALLENGE),
                Err(PkiError::SpkiNotP256),
                "length {n}"
            );
        }
    }

    /// Design section 1.3: a 91-byte SPKI whose point carries the
    /// compressed marker `0x02` is refused as not P-256, even with a
    /// signature over the layout for those exact bytes.
    #[test]
    fn adr005_pop_spki_with_a_compressed_point_marker_is_refused_as_not_p256() {
        let (k, good) = crypto_proof();
        let mut spki_der = good.spki_der;
        spki_der[P256_SPKI_PREFIX.len()] = 0x02;
        let p = ProofOfPossession {
            signature: k
                .sign(&layout(&spki_der, &ctx(), &CHALLENGE))
                .expect("fstp-crypto signs"),
            spki_der,
        };
        assert_eq!(verify(&p, &ctx(), &CHALLENGE), Err(PkiError::SpkiNotP256));
    }

    /// Design section 1.3: an SPKI with the P-256 header and an
    /// uncompressed point off the curve passes the header check, reaches
    /// `fstp-crypto`, and is refused there as not P-256.
    #[test]
    fn adr005_pop_spki_with_a_point_off_the_curve_is_refused_as_not_p256() {
        let (k, _) = crypto_proof();
        let mut spki_der = P256_SPKI_PREFIX.to_vec();
        spki_der.push(0x04);
        spki_der.extend_from_slice(&[0; 64]);
        assert!(is_p256_spki(&spki_der));
        let msg = message(&spki_der, &ctx(), &CHALLENGE).expect("the P-256 header");
        let p = ProofOfPossession {
            signature: k.sign(&msg).expect("fstp-crypto signs"),
            spki_der,
        };
        assert_eq!(verify(&p, &ctx(), &CHALLENGE), Err(PkiError::SpkiNotP256));
    }

    /// ADR-005: a signature by the right key over a message other than
    /// the exact signed bytes is refused. This covers the message with a
    /// byte more or less, its SHA-256 digest, and an empty message.
    #[test]
    fn adr005_pop_signature_over_a_different_message_is_refused() {
        let (k, good) = crypto_proof();
        let msg = message(&good.spki_der, &ctx(), &CHALLENGE).expect("a P-256 SPKI");
        let mut longer = msg.clone();
        longer.push(0);
        let shorter = msg[..msg.len() - 1].to_vec();
        let digest = fstp_crypto::sha256(&msg).to_vec();
        for other in [longer, shorter, digest, Vec::new()] {
            let p = ProofOfPossession {
                signature: k.sign(&other).expect("fstp-crypto signs"),
                spki_der: good.spki_der.clone(),
            };
            assert_eq!(
                verify(&p, &ctx(), &CHALLENGE),
                Err(PkiError::PopSignatureInvalid),
                "message of {} bytes",
                other.len()
            );
        }
    }

    /// ADR-005: a signature by the right key over the signed message with
    /// any one bit flipped is refused.
    #[test]
    fn adr005_pop_signature_over_a_message_with_a_flipped_bit_is_refused() {
        let (k, good) = crypto_proof();
        let msg = message(&good.spki_der, &ctx(), &CHALLENGE).expect("a P-256 SPKI");
        check_with(
            "adr005_pop_signature_over_a_message_with_a_flipped_bit_is_refused",
            Config::default().with_cases(256),
            |g| {
                let bit = g.usize_in(0..=msg.len() * 8 - 1);
                g.note("bit", &bit);
                let mut other = msg.clone();
                other[bit / 8] ^= 1 << (bit % 8);
                let p = ProofOfPossession {
                    signature: k.sign(&other).map_err(|e| format!("{e:?}"))?,
                    spki_der: good.spki_der.clone(),
                };
                let r = verify(&p, &ctx(), &CHALLENGE);
                prop_assert!(r == Err(PkiError::PopSignatureInvalid), "{r:?}");
                Ok(())
            },
        );
    }
}

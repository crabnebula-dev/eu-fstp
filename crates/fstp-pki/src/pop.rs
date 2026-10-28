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
/// [`PkiError::SpkiNotP256`] for an SPKI outside the profile,
/// [`PkiError::PopContextInvalid`] for a malformed context, and
/// [`PkiError::PopSignatureInvalid`] for a signature that does not verify.
/// Until `fstp-crypto` exposes ECDSA P-256 verification (design section
/// 2.2, lane W1h), a well-formed proof gets [`PkiError::NotImplemented`]
/// from the signature step.
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

/// The seam to the `fstp-crypto` ECDSA P-256 SHA-256 verifier of design
/// section 2.2 (`sig` module, lane W1h). `fstp-pki` implements no
/// primitive and may name no third-party crate, so it refuses until that
/// module lands. The call then becomes one line that maps a failed
/// verification to [`PkiError::PopSignatureInvalid`].
fn ecdsa_p256_sha256_verify(
    _spki_der: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), PkiError> {
    Err(PkiError::NotImplemented(
        "fstp_crypto ECDSA P-256 verify (design section 2.2, lane W1h)",
    ))
}

#[cfg(test)]
mod tests {
    //! The checks of `verify_with` against aws-lc-rs as the verifier, a
    //! dev-dependency. This exercises every step but the `fstp-crypto`
    //! seam, which waits on lane W1h.

    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
        UnparsedPublicKey,
    };

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
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("aws-lc-rs generates a key");
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref())
            .expect("aws-lc-rs reads its key")
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
}

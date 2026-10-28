//! Proof of possession for certificate requests (M3 design section 1.3).

use crate::PkiError;

/// A proof that the requester holds the private key of `spki_der`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfPossession {
    /// The subject public key info, DER.
    pub spki_der: Vec<u8>,
    /// The challenge the issuer handed out.
    pub challenge: [u8; 32],
    /// The signature over the challenge.
    pub signature: Vec<u8>,
}

/// Checks a proof of possession. A forged proof is refused.
pub fn verify(proof: &ProofOfPossession) -> Result<(), PkiError> {
    let _ = proof;
    Err(PkiError::NotImplemented("fstp_pki::pop::verify"))
}

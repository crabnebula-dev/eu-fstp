//! The `SignaturePort` (M5 design sections 3.1 step 6 and 3.2).
//!
//! The signer's wallet or the tenant's QTSP creates the signature value,
//! never the platform (`contracts.md` Signature). The port first returns
//! the signer's certificate chain, so the server can encode the signed
//! attributes, then the value over them.
//!
//! [`ProductionSignaturePort`] refuses every route with
//! [`SignatureError::ProductionUnavailable`] until a real wallet or QTSP
//! adapter lands (M5 design 12.1, Q2). Nothing falls back to a
//! platform-made signature. Tests and the demo use
//! [`crate::fake::FakeTrustServices`].

use crate::model::Route;

/// Who signs, as the wallet or QTSP knows them: a pseudonymous subject
/// reference, never a name from the vault.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignerRef {
    /// The subject reference.
    pub subject: String,
}

/// Why the port gave no certificate or signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureError {
    /// No production adapter exists for this route yet (Q2).
    ProductionUnavailable(Route),
    /// The adapter does not serve this route.
    RouteUnsupported(Route),
    /// The signer declined or did not authorise in time.
    Declined,
    /// The wallet or QTSP did not answer.
    Unavailable,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::ProductionUnavailable(r) => {
                write!(f, "no production signature adapter for {r:?}")
            }
            SignatureError::RouteUnsupported(r) => write!(f, "route {r:?} is not served"),
            SignatureError::Declined => f.write_str("the signer declined"),
            SignatureError::Unavailable => f.write_str("the signature service did not answer"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// A wallet or QTSP as the contract service sees it.
pub trait SignaturePort {
    /// The signer's certificate chain at `at` (Unix seconds), DER, the
    /// signer certificate first.
    ///
    /// # Errors
    ///
    /// A [`SignatureError`].
    fn certificate_chain(
        &self,
        route: Route,
        signer: &SignerRef,
        at: i64,
    ) -> Result<Vec<Vec<u8>>, SignatureError>;

    /// The signature value over the DER signed attributes, after the
    /// signer authorised it.
    ///
    /// # Errors
    ///
    /// A [`SignatureError`].
    fn sign(
        &self,
        route: Route,
        signer: &SignerRef,
        signed_attributes: &[u8],
        at: i64,
    ) -> Result<Vec<u8>, SignatureError>;
}

impl<T: SignaturePort + ?Sized> SignaturePort for &T {
    fn certificate_chain(
        &self,
        route: Route,
        signer: &SignerRef,
        at: i64,
    ) -> Result<Vec<Vec<u8>>, SignatureError> {
        (**self).certificate_chain(route, signer, at)
    }

    fn sign(
        &self,
        route: Route,
        signer: &SignerRef,
        signed_attributes: &[u8],
        at: i64,
    ) -> Result<Vec<u8>, SignatureError> {
        (**self).sign(route, signer, signed_attributes, at)
    }
}

/// The production port: every route refuses with
/// [`SignatureError::ProductionUnavailable`] (Q2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionSignaturePort;

impl SignaturePort for ProductionSignaturePort {
    fn certificate_chain(
        &self,
        route: Route,
        _signer: &SignerRef,
        _at: i64,
    ) -> Result<Vec<Vec<u8>>, SignatureError> {
        Err(SignatureError::ProductionUnavailable(route))
    }

    fn sign(
        &self,
        route: Route,
        _signer: &SignerRef,
        _signed_attributes: &[u8],
        _at: i64,
    ) -> Result<Vec<u8>, SignatureError> {
        Err(SignatureError::ProductionUnavailable(route))
    }
}

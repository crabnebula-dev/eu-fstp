//! The fake wallet, QTSP and trusted list for tests and the demo (M5
//! design section 3.2, 12.1 Q2).
//!
//! It holds a test CA made with aws-lc-rs and issues each signer a short
//! client certificate under it, as the fake passkey port does for login.
//! Every route signs with the signer's own test key, after the demo's
//! "Authorise signature" step. The fake trusted list names the test CA as
//! a qualified service. It never runs in production: the production
//! wiring uses [`crate::port::ProductionSignaturePort`] and
//! `fstp_sigval::ProductionTrustedList`, which refuse.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fstp_crypto::sig::EcdsaP256KeyPair;
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_sigval::{FakeTrustedList, TrustAnchor};

use crate::model::Route;
use crate::port::{SignatureError, SignaturePort, SignerRef};

/// How long before `at` a signer certificate starts, in seconds.
const LEAD_IN: i64 = 3_600;
/// How long after `at` a signer certificate ends, in seconds (under the
/// 7-day client limit of `fstp-pki`).
const LIFETIME: i64 = 6 * 86_400;

/// Why the fake could not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeError {
    /// Key generation or certificate encoding failed.
    Setup,
}

impl std::fmt::Display for FakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the fake trust services could not start")
    }
}

impl std::error::Error for FakeError {}

struct Issued {
    key: EcdsaP256KeyPair,
    cert: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

struct Signers {
    next_serial: u32,
    by_subject: BTreeMap<String, Issued>,
}

/// The fake trust services.
pub struct FakeTrustServices {
    ca_key: EcdsaP256KeyPair,
    ca_cert: Vec<u8>,
    ca_key_id: fstp_pki::KeyIdentifier,
    signers: Mutex<Signers>,
}

impl std::fmt::Debug for FakeTrustServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTrustServices").finish_non_exhaustive()
    }
}

const CA_NAME: &str = "FSTP Synthetic Test QTSP CA";

impl FakeTrustServices {
    /// A new fake whose CA is valid from a year before `now` (Unix
    /// seconds) to ten years after.
    ///
    /// # Errors
    ///
    /// [`FakeError::Setup`] when aws-lc-rs or the certificate writer fails.
    pub fn new(now: i64) -> Result<FakeTrustServices, FakeError> {
        let ca_key = EcdsaP256KeyPair::generate().map_err(|_| FakeError::Setup)?;
        let spki = ca_key.spki_der().map_err(|_| FakeError::Setup)?;
        let ca_key_id = key_identifier(&spki).map_err(|_| FakeError::Setup)?;
        let spec = CertSpec {
            serial: vec![1],
            issuer: DistinguishedName::new(CA_NAME),
            subject: DistinguishedName::new(CA_NAME),
            validity: Validity {
                not_before: now.saturating_sub(365 * 86_400),
                not_after: now.saturating_add(3_650 * 86_400),
            },
            spki_der: spki,
            issuer_key_id: None,
            kind: CertKind::Ca,
            dns_names: vec![],
            ip_addrs: vec![],
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).map_err(|_| FakeError::Setup)?;
        let sig = ca_key.sign(t.as_der()).map_err(|_| FakeError::Setup)?;
        let ca_cert = assemble(&t, &sig).map_err(|_| FakeError::Setup)?;
        Ok(FakeTrustServices {
            ca_key,
            ca_cert,
            ca_key_id,
            signers: Mutex::new(Signers {
                next_serial: 2,
                by_subject: BTreeMap::new(),
            }),
        })
    }

    /// The test CA certificate, DER.
    #[must_use]
    pub fn ca_certificate(&self) -> &[u8] {
        &self.ca_cert
    }

    /// The fake trusted list: the test CA as a qualified service, and no
    /// revocation.
    #[must_use]
    pub fn trusted_list(&self) -> FakeTrustedList {
        FakeTrustedList {
            anchors: vec![TrustAnchor {
                certificate: self.ca_cert.clone(),
                qualified: true,
            }],
            revocations: Vec::new(),
        }
    }

    /// The revocation entry for `cert_der`, revoked at `at`, to push onto
    /// a fake trusted list.
    ///
    /// # Errors
    ///
    /// The `fstp-sigval` error when the certificate does not parse.
    pub fn revocation_of(
        cert_der: &[u8],
        at: i64,
    ) -> Result<(Vec<u8>, Vec<u8>, i64), fstp_sigval::SigvalError> {
        let (issuer, serial) = fstp_sigval::issuer_and_serial(cert_der)?;
        Ok((issuer, serial, at))
    }

    fn issue(&self, signers: &mut Signers, subject: &str, at: i64) -> Result<(), SignatureError> {
        let reuse = signers
            .by_subject
            .get(subject)
            .is_some_and(|i| i.not_before <= at && at <= i.not_after);
        if reuse {
            return Ok(());
        }
        let key = match signers.by_subject.remove(subject) {
            Some(old) => old.key,
            None => EcdsaP256KeyPair::generate().map_err(|_| SignatureError::Unavailable)?,
        };
        let serial = signers.next_serial;
        signers.next_serial = serial.saturating_add(1);
        let short: String = subject.chars().take(40).collect();
        let not_before = at.saturating_sub(LEAD_IN);
        let not_after = at.saturating_add(LIFETIME);
        let spec = CertSpec {
            serial: serial.to_be_bytes().to_vec(),
            issuer: DistinguishedName::new(CA_NAME),
            subject: DistinguishedName::new(&format!("Synthetic signer {short}")),
            validity: Validity {
                not_before,
                not_after,
            },
            spki_der: key.spki_der().map_err(|_| SignatureError::Unavailable)?,
            issuer_key_id: Some(self.ca_key_id),
            kind: CertKind::Client,
            dns_names: vec![],
            ip_addrs: vec![],
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).map_err(|_| SignatureError::Unavailable)?;
        let sig = self
            .ca_key
            .sign(t.as_der())
            .map_err(|_| SignatureError::Unavailable)?;
        let cert = assemble(&t, &sig).map_err(|_| SignatureError::Unavailable)?;
        signers.by_subject.insert(
            subject.to_owned(),
            Issued {
                key,
                cert,
                not_before,
                not_after,
            },
        );
        Ok(())
    }
}

impl SignaturePort for FakeTrustServices {
    fn certificate_chain(
        &self,
        _route: Route,
        signer: &SignerRef,
        at: i64,
    ) -> Result<Vec<Vec<u8>>, SignatureError> {
        let mut s = self
            .signers
            .lock()
            .map_err(|_| SignatureError::Unavailable)?;
        self.issue(&mut s, &signer.subject, at)?;
        let issued = s
            .by_subject
            .get(&signer.subject)
            .ok_or(SignatureError::Unavailable)?;
        Ok(vec![issued.cert.clone(), self.ca_cert.clone()])
    }

    fn sign(
        &self,
        _route: Route,
        signer: &SignerRef,
        signed_attributes: &[u8],
        at: i64,
    ) -> Result<Vec<u8>, SignatureError> {
        let mut s = self
            .signers
            .lock()
            .map_err(|_| SignatureError::Unavailable)?;
        self.issue(&mut s, &signer.subject, at)?;
        let issued = s
            .by_subject
            .get(&signer.subject)
            .ok_or(SignatureError::Unavailable)?;
        issued
            .key
            .sign(signed_attributes)
            .map_err(|_| SignatureError::Unavailable)
    }
}

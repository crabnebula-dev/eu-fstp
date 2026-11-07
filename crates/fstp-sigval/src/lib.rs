//! Signature validation for contracts (M5 design section 3.1 step 7,
//! `SPEC/02-domain/contracts.md` Signature, I-30).
//!
//! The crate checks a signature value that a wallet or a QTSP returned,
//! and a stored signed revision read back from bytes:
//!
//! - [`validate_cms`] decodes the detached CMS strictly through
//!   `fstp-pki::cms`, checks that its `messageDigest` is the `/ByteRange`
//!   digest, verifies the value with aws-lc-rs, and validates the chain;
//! - [`verify_signed_revision`] reads a stored revision, zeroes its
//!   `/Contents`, re-runs the strict increment verifier of `fstp-pdf`
//!   over it, and then calls [`validate_cms`].
//!
//! Chain validation is in-house, as `contracts.md` asks: the signer chain
//! must end at an anchor of the [`TrustedList`], every certificate must be
//! valid at the signing time, none may be revoked, and each issuer
//! signature must verify. Certificates are parsed through the ADR-001
//! Tier B formats crates. Production trusted-list access refuses with a
//! typed error until a real source lands (M5 design 12.1, Q2).
//!
//! `TODO(legal)`: which signature and seal levels the SuperSAFE MoU needs,
//! and which qualified-certificate statements a qualified signature must
//! carry. The fake list marks its test CA as qualified.

use der::{Decode, Encode};
use fstp_pdf::object::{Object, Ref};
use fstp_pdf::{IncrementError, ParseError, PdfFile, verify_increment};
use fstp_pki::cms::{CmsError, decode_signed_data, verify_signature};
use x509_cert::Certificate;
use x509_cert::ext::pkix::BasicConstraints;

/// Most certificates on one path, the anchor included.
pub const MAX_PATH: usize = 8;

/// The `ecdsa-with-SHA256` signature algorithm.
const ECDSA_WITH_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The level a signature reached (P-30).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// An advanced signature: its anchor is trusted but not qualified.
    Advanced,
    /// A qualified signature: its anchor is a qualified trust service.
    Qualified,
}

/// One trust anchor of a trusted list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The anchor certificate, DER.
    pub certificate: Vec<u8>,
    /// Whether the list names it as a qualified service.
    pub qualified: bool,
}

/// Why the trusted list could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// No production trusted-list source exists yet (M5 design 12.1, Q2).
    /// Nothing falls back to another source.
    ProductionUnavailable,
    /// The source did not answer.
    Unavailable,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::ProductionUnavailable => {
                f.write_str("no production trusted-list source is configured")
            }
            TrustError::Unavailable => f.write_str("the trusted list did not answer"),
        }
    }
}

impl std::error::Error for TrustError {}

/// The trusted list and revocation source as validation sees it.
pub trait TrustedList {
    /// Every anchor of the list.
    ///
    /// # Errors
    ///
    /// A [`TrustError`] when the list cannot answer.
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustError>;

    /// Whether the certificate with this DER issuer name and DER serial
    /// was revoked at or before `at` (Unix seconds).
    ///
    /// # Errors
    ///
    /// A [`TrustError`] when the source cannot answer. Validation then
    /// fails closed.
    fn revoked(&self, issuer: &[u8], serial: &[u8], at: i64) -> Result<bool, TrustError>;
}

impl<T: TrustedList + ?Sized> TrustedList for &T {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustError> {
        (**self).anchors()
    }

    fn revoked(&self, issuer: &[u8], serial: &[u8], at: i64) -> Result<bool, TrustError> {
        (**self).revoked(issuer, serial, at)
    }
}

/// The production trusted list. It refuses every question with
/// [`TrustError::ProductionUnavailable`] until EU trusted-list parsing
/// lands (M5 design 12.1, Q2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionTrustedList;

impl TrustedList for ProductionTrustedList {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustError> {
        Err(TrustError::ProductionUnavailable)
    }

    fn revoked(&self, _issuer: &[u8], _serial: &[u8], _at: i64) -> Result<bool, TrustError> {
        Err(TrustError::ProductionUnavailable)
    }
}

/// A fake trusted list for tests and the demo: fixed anchors and a fixed
/// set of revocations, each with its time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeTrustedList {
    /// The anchors.
    pub anchors: Vec<TrustAnchor>,
    /// Revoked certificates: DER issuer name, DER serial and revocation
    /// time in Unix seconds.
    pub revocations: Vec<(Vec<u8>, Vec<u8>, i64)>,
}

impl TrustedList for FakeTrustedList {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustError> {
        Ok(self.anchors.clone())
    }

    fn revoked(&self, issuer: &[u8], serial: &[u8], at: i64) -> Result<bool, TrustError> {
        Ok(self
            .revocations
            .iter()
            .any(|(i, s, when)| i == issuer && s == serial && *when <= at))
    }
}

/// Why a signature was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigvalError {
    /// The stored revision does not parse.
    Pdf(ParseError),
    /// The revision is not the base followed by one accepted increment.
    Increment(IncrementError),
    /// `/Contents` is missing, malformed or holds bytes after the DER.
    Contents,
    /// The CMS does not decode or the value does not verify.
    Cms(CmsError),
    /// The signed `messageDigest` is not the `/ByteRange` digest.
    DigestMismatch,
    /// A certificate on the path does not parse.
    Certificate,
    /// No path to a trust anchor within [`MAX_PATH`] certificates.
    Untrusted,
    /// A certificate on the path is not valid at the signing time.
    OutsideValidity,
    /// An issuer on the path is not a CA.
    NotCa,
    /// An issuer signature on the path does not verify, or uses an
    /// algorithm other than ECDSA P-256 with SHA-256.
    IssuerSignature,
    /// A certificate on the path was revoked at the signing time.
    Revoked,
    /// The signature is below the level the route needs (P-30).
    LevelTooLow,
    /// The signer certificate is not the one the port named.
    SignerMismatch,
    /// The trusted list could not answer; validation fails closed.
    Trust(TrustError),
}

impl std::fmt::Display for SigvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature refused: {self:?}")
    }
}

impl std::error::Error for SigvalError {}

/// What a successful validation established. Its [`digest`] goes into
/// the `SignatureApplied` record.
///
/// [`digest`]: ValidationReport::digest
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReport {
    /// The level reached.
    pub level: Level,
    /// The `/ByteRange` digest the signature covers.
    pub byte_range_digest: [u8; 32],
    /// SHA-256 of the signer certificate, DER.
    pub signer_certificate_digest: [u8; 32],
    /// SHA-256 of the anchor certificate, DER.
    pub anchor_digest: [u8; 32],
    /// The signing time the chain was checked at, Unix seconds.
    pub checked_at: i64,
    /// The number of certificates on the path, the anchor included.
    pub path_len: u8,
}

impl ValidationReport {
    /// The canonical bytes: a version byte, the level, the three digests,
    /// the time as eight big-endian bytes and the path length.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 96 + 8 + 1);
        out.push(1);
        out.push(match self.level {
            Level::Advanced => 1,
            Level::Qualified => 2,
        });
        out.extend_from_slice(&self.byte_range_digest);
        out.extend_from_slice(&self.signer_certificate_digest);
        out.extend_from_slice(&self.anchor_digest);
        out.extend_from_slice(&self.checked_at.to_be_bytes());
        out.push(self.path_len);
        out
    }

    /// SHA-256 of [`ValidationReport::canonical`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.canonical())
    }
}

fn parse(der_bytes: &[u8]) -> Result<Certificate, SigvalError> {
    Certificate::from_der(der_bytes).map_err(|_| SigvalError::Certificate)
}

fn unix(t: x509_cert::time::Time) -> i64 {
    i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

fn valid_at(c: &Certificate, at: i64) -> bool {
    let v = &c.tbs_certificate.validity;
    unix(v.not_before) <= at && at <= unix(v.not_after)
}

fn is_ca(c: &Certificate) -> bool {
    matches!(
        c.tbs_certificate.get::<BasicConstraints>(),
        Ok(Some((_, BasicConstraints { ca: true, .. })))
    )
}

/// Whether `issuer` signed `subject`: names chain and the ECDSA P-256
/// signature over the DER `TBSCertificate` verifies under the issuer key.
fn issued_by(subject: &Certificate, issuer: &Certificate) -> Result<bool, SigvalError> {
    if subject.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Ok(false);
    }
    if subject.signature_algorithm.oid != ECDSA_WITH_SHA256 {
        return Err(SigvalError::IssuerSignature);
    }
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    let sig = subject
        .signature
        .as_bytes()
        .ok_or(SigvalError::IssuerSignature)?;
    Ok(fstp_crypto::sig::ecdsa_p256_sha256_verify(&spki, &tbs, sig).is_ok())
}

fn revoked(c: &Certificate, at: i64, trust: &dyn TrustedList) -> Result<bool, SigvalError> {
    let issuer = c
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    let serial = c
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    trust
        .revoked(&issuer, &serial, at)
        .map_err(SigvalError::Trust)
}

/// Validates the path from `signer_der` through the intermediates in
/// `pool` to an anchor of `trust`, at `at` (Unix seconds). Returns the
/// anchor, its DER and the path length.
///
/// # Errors
///
/// A [`SigvalError`] naming the first fault. It fails closed when the
/// trusted list does not answer.
pub fn validate_chain(
    signer_der: &[u8],
    pool: &[Vec<u8>],
    at: i64,
    trust: &dyn TrustedList,
) -> Result<(TrustAnchor, u8), SigvalError> {
    let anchors = trust.anchors().map_err(SigvalError::Trust)?;
    let parsed_anchors: Vec<(TrustAnchor, Certificate)> = anchors
        .into_iter()
        .filter_map(|a| parse(&a.certificate).ok().map(|c| (a, c)))
        .collect();
    let pool: Vec<Certificate> = pool.iter().filter_map(|d| parse(d).ok()).collect();
    let mut current = parse(signer_der)?;
    for depth in 1..MAX_PATH {
        if !valid_at(&current, at) {
            return Err(SigvalError::OutsideValidity);
        }
        if revoked(&current, at, trust)? {
            return Err(SigvalError::Revoked);
        }
        for (anchor, cert) in &parsed_anchors {
            if issued_by(&current, cert)? {
                if !valid_at(cert, at) {
                    return Err(SigvalError::OutsideValidity);
                }
                if !is_ca(cert) {
                    return Err(SigvalError::NotCa);
                }
                let len = u8::try_from(depth.saturating_add(1)).unwrap_or(u8::MAX);
                return Ok((anchor.clone(), len));
            }
        }
        let mut next = None;
        for candidate in &pool {
            if candidate != &current && issued_by(&current, candidate)? {
                next = Some(candidate.clone());
                break;
            }
        }
        let Some(issuer) = next else {
            return Err(SigvalError::Untrusted);
        };
        if !is_ca(&issuer) {
            return Err(SigvalError::NotCa);
        }
        current = issuer;
    }
    Err(SigvalError::Untrusted)
}

/// Validates the detached CMS `cms_der` over the `/ByteRange` digest
/// `byte_range_digest` at signing time `at` (Unix seconds). The level
/// reached must be at least `required`. When `expected_signer` is given,
/// the signer certificate must be exactly it.
///
/// # Errors
///
/// A [`SigvalError`] naming the first fault.
pub fn validate_cms(
    cms_der: &[u8],
    byte_range_digest: &[u8; 32],
    at: i64,
    required: Level,
    expected_signer: Option<&[u8]>,
    trust: &dyn TrustedList,
) -> Result<ValidationReport, SigvalError> {
    let d = decode_signed_data(cms_der).map_err(SigvalError::Cms)?;
    if &d.message_digest != byte_range_digest {
        return Err(SigvalError::DigestMismatch);
    }
    if expected_signer.is_some_and(|s| s != d.signer_certificate.as_slice()) {
        return Err(SigvalError::SignerMismatch);
    }
    verify_signature(&d.signed_attributes, &d.signature, &d.signer_certificate)
        .map_err(SigvalError::Cms)?;
    let (anchor, path_len) = validate_chain(&d.signer_certificate, &d.certificates, at, trust)?;
    let level = if anchor.qualified {
        Level::Qualified
    } else {
        Level::Advanced
    };
    if level < required {
        return Err(SigvalError::LevelTooLow);
    }
    Ok(ValidationReport {
        level,
        byte_range_digest: *byte_range_digest,
        signer_certificate_digest: fstp_crypto::sha256(&d.signer_certificate),
        anchor_digest: fstp_crypto::sha256(&anchor.certificate),
        checked_at: at,
        path_len,
    })
}

/// The length of the DER TLV at the start of `bytes`, if its header is
/// well formed and the whole TLV fits. Only definite lengths of at most
/// four length octets are read.
#[must_use]
pub fn der_tlv_len(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.get(1)?;
    let (header, body) = if first < 0x80 {
        (2usize, usize::from(first))
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let octets = bytes.get(2..2usize.checked_add(n)?)?;
        let mut len = 0usize;
        for &o in octets {
            len = len.checked_mul(256)?.checked_add(usize::from(o))?;
        }
        (2usize.checked_add(n)?, len)
    };
    let total = header.checked_add(body)?;
    (total <= bytes.len()).then_some(total)
}

/// The signed revision `revision`, read back from bytes: it must be
/// `base` followed by one increment for the field `party` that the strict
/// verifier accepts once its `/Contents` is zeroed, and the CMS in
/// `/Contents` must validate at `at` (Unix seconds) to at least
/// `required`.
///
/// # Errors
///
/// A [`SigvalError`] naming the first fault.
pub fn verify_signed_revision(
    base: &[u8],
    revision: &[u8],
    party: &str,
    at: i64,
    required: Level,
    trust: &dyn TrustedList,
) -> Result<ValidationReport, SigvalError> {
    let increment = revision
        .strip_prefix(base)
        .ok_or(SigvalError::Increment(IncrementError::PlaceholderMismatch))?;
    let base_file = PdfFile::open(base).map_err(SigvalError::Pdf)?;
    let sig_ref = Ref {
        num: base_file.size(),
        generation: 0,
    };
    let file = PdfFile::open(revision).map_err(SigvalError::Pdf)?;
    let sig = file.dict(sig_ref).map_err(SigvalError::Pdf)?;
    let Some(Object::String(contents)) = sig.get(b"Contents") else {
        return Err(SigvalError::Contents);
    };
    let span = contents.span.clone();
    if !contents.hex || span.start < base.len() || span.end > revision.len() {
        return Err(SigvalError::Contents);
    }
    let mut zeroed = increment.to_vec();
    let inner_start = span
        .start
        .checked_sub(base.len())
        .and_then(|s| s.checked_add(1))
        .ok_or(SigvalError::Contents)?;
    let inner_end = span
        .end
        .checked_sub(base.len())
        .and_then(|e| e.checked_sub(1))
        .ok_or(SigvalError::Contents)?;
    zeroed
        .get_mut(inner_start..inner_end)
        .ok_or(SigvalError::Contents)?
        .fill(b'0');
    let verified = verify_increment(base, &zeroed, party).map_err(SigvalError::Increment)?;
    if verified.contents != span {
        return Err(SigvalError::Contents);
    }
    let raw = &contents.bytes;
    let len = der_tlv_len(raw).ok_or(SigvalError::Contents)?;
    let (cms, padding) = raw.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(SigvalError::Contents);
    }
    validate_cms(cms, &verified.digest, at, required, None, trust)
}

/// The DER issuer name and DER serial of `cert_der`, as
/// [`TrustedList::revoked`] takes them.
///
/// # Errors
///
/// [`SigvalError::Certificate`] when the certificate does not parse.
pub fn issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SigvalError> {
    let c = parse(cert_der)?;
    let issuer = c
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    let serial = c
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|_| SigvalError::Certificate)?;
    Ok((issuer, serial))
}

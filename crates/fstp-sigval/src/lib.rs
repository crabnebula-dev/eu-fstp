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
//! Issuer and signer rules (H-15, RFC 5280 section 6 over the parsed
//! fields): keyCertSign, pathLenConstraint, signer keyUsage, name
//! constraints, and refusal of critical extensions not processed.
//!
//! Name constraints (RFC 5280 sections 4.2.1.10 and 6.1, issue 6 M1) are
//! enforced for the directoryName, rfc822Name and dNSName forms, critical or
//! not. The constraints of every CA on the path bind every certificate
//! below it, the anchor's included, which the RFC leaves optional. A
//! constraint of another form is refused, and so is a malformed one.
//! Directory attribute values compare as strings after trimming, folding
//! white space and lowering case, so a respelt name cannot leave an
//! excluded subtree. That is a simplified form of the RFC 4518 rules.
//!
//! `TODO(legal)`: which signature and seal levels the SuperSAFE MoU needs,
//! and which qualified-certificate statements a qualified signature must
//! carry. The fake list marks its test CA as qualified.

use der::Tagged;
use der::{Decode, Encode};
use fstp_pdf::object::{Object, Ref};
use fstp_pdf::{IncrementError, ParseError, PdfFile, verify_increment};
use fstp_pki::cms::{CmsError, decode_signed_data, verify_signature};
use x509_cert::Certificate;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, KeyUsage, KeyUsages, NameConstraints, SubjectAltName,
};
use x509_cert::name::{Name, RelativeDistinguishedName};

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
    /// An issuer carries keyUsage without `keyCertSign` (RFC 5280 4.2.1.3).
    IssuerKeyUsage,
    /// An issuer's `pathLenConstraint` is shorter than the path below it.
    PathLength,
    /// The signer's keyUsage does not allow signing a document.
    SignerPurpose,
    /// A certificate carries a critical extension this validator does not
    /// process.
    CriticalExtension,
    /// A name on the path is outside a permitted subtree or inside an
    /// excluded subtree of a CA above it, or a name constraints extension
    /// is malformed (RFC 5280 section 4.2.1.10, issue 6 M1).
    NameConstraints,
    /// A name constraint names a form this validator does not enforce. Only
    /// directoryName, rfc822Name and dNSName are enforced.
    UnsupportedNameConstraint,
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

/// Critical extensions the validator processes: basicConstraints,
/// keyUsage, extKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier and
/// subjectAltName (read for name constraints), and nameConstraints. Any
/// other critical extension is refused, as RFC 5280 section 4.2 requires
/// of a validator that cannot process it. Policy extensions are not
/// processed.
const PROCESSED_CRITICAL: [der::asn1::ObjectIdentifier; 7] = [
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19"),
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15"),
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37"),
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14"),
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35"),
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17"),
    NAME_CONSTRAINTS,
];

/// The nameConstraints extension.
const NAME_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.30");
/// The subjectAltName extension.
const SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");
/// The emailAddress attribute of a distinguished name (PKCS #9).
const EMAIL_ADDRESS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// Refuses a certificate with a critical extension not in
/// [`PROCESSED_CRITICAL`].
fn check_critical(c: &Certificate) -> Result<(), SigvalError> {
    let exts = c.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    if exts
        .iter()
        .any(|e| e.critical && !PROCESSED_CRITICAL.contains(&e.extn_id))
    {
        return Err(SigvalError::CriticalExtension);
    }
    Ok(())
}

/// The issuer rules of RFC 5280 section 6.1.4 over the parsed fields:
/// keyUsage `keyCertSign` when keyUsage is present, and
/// `pathLenConstraint` against `below`, the number of intermediate
/// certificates between this CA and the signer. Self-issued certificates
/// are counted too, which is stricter than the RFC.
fn check_issuer(c: &Certificate, below: usize) -> Result<(), SigvalError> {
    check_critical(c)?;
    if let Ok(Some((_, KeyUsage(flags)))) = c.tbs_certificate.get::<KeyUsage>() {
        if !flags.contains(KeyUsages::KeyCertSign) {
            return Err(SigvalError::IssuerKeyUsage);
        }
    } else if c
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|e| e.extn_id == const_oid_key_usage())
    {
        // Present but undecodable: fail closed.
        return Err(SigvalError::IssuerKeyUsage);
    }
    if let Ok(Some((
        _,
        BasicConstraints {
            path_len_constraint: Some(max),
            ..
        },
    ))) = c.tbs_certificate.get::<BasicConstraints>()
        && below > usize::from(max)
    {
        return Err(SigvalError::PathLength);
    }
    Ok(())
}

fn const_oid_key_usage() -> der::asn1::ObjectIdentifier {
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15")
}

/// The signer rules: keyUsage `digitalSignature` or `nonRepudiation`
/// when present.
fn check_signer(c: &Certificate) -> Result<(), SigvalError> {
    check_critical(c)?;
    let exts = c.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    if exts.iter().any(|e| e.extn_id == const_oid_key_usage()) {
        let Ok(Some((_, KeyUsage(flags)))) = c.tbs_certificate.get::<KeyUsage>() else {
            return Err(SigvalError::SignerPurpose);
        };
        if !flags.contains(KeyUsages::DigitalSignature)
            && !flags.contains(KeyUsages::NonRepudiation)
        {
            return Err(SigvalError::SignerPurpose);
        }
    }
    // TODO(legal): extended key usage of the signer is not checked. The
    // fake QTSP of fstp-contract issues clientAuth-only signers, so a check
    // here needs a product decision on the accepted purposes first.
    Ok(())
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

/// The one extension `oid` of `c`, if present. Two copies are malformed
/// (RFC 5280 section 4.2).
fn single_extension<'a>(
    c: &'a Certificate,
    oid: &der::asn1::ObjectIdentifier,
) -> Result<Option<&'a [u8]>, SigvalError> {
    let mut found = c
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|e| &e.extn_id == oid);
    let first = found.next();
    if found.next().is_some() {
        return Err(SigvalError::NameConstraints);
    }
    Ok(first.map(|e| e.extn_value.as_bytes()))
}

/// The name constraints of `c`, checked for shape: at least one subtree,
/// every subtree of a supported form, with minimum 0 and no maximum, as
/// RFC 5280 section 4.2.1.10 requires.
fn name_constraints(c: &Certificate) -> Result<Option<NameConstraints>, SigvalError> {
    let Some(bytes) = single_extension(c, &NAME_CONSTRAINTS)? else {
        return Ok(None);
    };
    let nc = NameConstraints::from_der(bytes).map_err(|_| SigvalError::NameConstraints)?;
    let lists = [&nc.permitted_subtrees, &nc.excluded_subtrees];
    if lists.iter().all(|l| l.is_none())
        || lists.iter().any(|l| l.as_ref().is_some_and(Vec::is_empty))
    {
        return Err(SigvalError::NameConstraints);
    }
    for t in lists.into_iter().flatten().flatten() {
        if t.minimum != 0 || t.maximum.is_some() {
            return Err(SigvalError::NameConstraints);
        }
        if !matches!(
            t.base,
            GeneralName::DirectoryName(_) | GeneralName::Rfc822Name(_) | GeneralName::DnsName(_)
        ) {
            return Err(SigvalError::UnsupportedNameConstraint);
        }
    }
    Ok(Some(nc))
}

/// The names of `c` that name constraints bind: its subject and the
/// directoryName entries of subjectAltName, its rfc822Name entries and any
/// emailAddress attribute of the subject, and its dNSName entries.
struct Names {
    directory: Vec<Name>,
    mailbox: Vec<String>,
    dns: Vec<String>,
}

fn names_of(c: &Certificate) -> Result<Names, SigvalError> {
    let subject = &c.tbs_certificate.subject;
    let mut n = Names {
        directory: Vec::new(),
        mailbox: Vec::new(),
        dns: Vec::new(),
    };
    if !subject.0.is_empty() {
        n.directory.push(subject.clone());
    }
    for rdn in &subject.0 {
        for atv in rdn.0.iter().filter(|a| a.oid == EMAIL_ADDRESS) {
            n.mailbox
                .push(attribute_text(atv).ok_or(SigvalError::NameConstraints)?);
        }
    }
    if let Some(bytes) = single_extension(c, &SUBJECT_ALT_NAME)? {
        let san = SubjectAltName::from_der(bytes).map_err(|_| SigvalError::NameConstraints)?;
        for g in san.0 {
            match g {
                GeneralName::DirectoryName(d) => n.directory.push(d),
                GeneralName::Rfc822Name(m) => n.mailbox.push(m.as_str().to_owned()),
                GeneralName::DnsName(d) => n.dns.push(d.as_str().to_owned()),
                // No constraint of another form passes `name_constraints`,
                // so names of other forms are unconstrained.
                _ => {}
            }
        }
    }
    Ok(n)
}

/// The text of a directory attribute value of a string type. Teletex is
/// read as Latin-1. `None` for a value of another type.
fn attribute_text(atv: &AttributeTypeAndValue) -> Option<String> {
    let v = atv.value.value();
    match atv.value.tag() {
        der::Tag::Utf8String
        | der::Tag::PrintableString
        | der::Tag::Ia5String
        | der::Tag::VisibleString
        | der::Tag::NumericString => std::str::from_utf8(v).ok().map(str::to_owned),
        der::Tag::TeletexString => Some(v.iter().map(|&b| char::from(b)).collect()),
        der::Tag::BmpString => {
            let units: Vec<u16> = v
                .chunks(2)
                .map(|p| match p {
                    [a, b] => Some(u16::from_be_bytes([*a, *b])),
                    _ => None,
                })
                .collect::<Option<_>>()?;
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// `s` trimmed, with each run of white space folded to one space, in
/// lower case.
fn fold(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Two directory attributes are equal when their types are, and their
/// values are equal strings after [`fold`], or equal DER for another type.
fn attribute_eq(a: &AttributeTypeAndValue, b: &AttributeTypeAndValue) -> bool {
    if a.oid != b.oid {
        return false;
    }
    match (attribute_text(a), attribute_text(b)) {
        (Some(x), Some(y)) => fold(&x) == fold(&y),
        (None, None) => a.value == b.value,
        _ => false,
    }
}

fn rdn_eq(a: &RelativeDistinguishedName, b: &RelativeDistinguishedName) -> bool {
    a.0.len() == b.0.len()
        && a.0.iter().all(|x| b.0.iter().any(|y| attribute_eq(x, y)))
        && b.0.iter().all(|y| a.0.iter().any(|x| attribute_eq(x, y)))
}

/// Whether `name` lies in the directory subtree `base`: `base` is a prefix
/// of `name`, RDN by RDN.
fn in_directory(name: &Name, base: &Name) -> bool {
    base.0.len() <= name.0.len() && base.0.iter().zip(&name.0).all(|(b, n)| rdn_eq(b, n))
}

/// Whether the host name `name` lies in the dNSName subtree `base`: the
/// same name, or one with more labels to the left. A base with a leading
/// dot names the hosts below it only. An empty base names every host.
fn in_dns(name: &str, base: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let base = base.to_ascii_lowercase();
    if base.is_empty() {
        return true;
    }
    if base.starts_with('.') {
        return name.ends_with(&base);
    }
    name == base || name.ends_with(&format!(".{base}"))
}

/// Whether the mailbox `name` lies in the rfc822Name subtree `base`: the
/// same mailbox, any mailbox on the host `base`, or with a leading dot any
/// mailbox on a host below the domain. Hosts compare without case and
/// local parts exactly. `None` for a mailbox with no `@`.
fn in_mailbox(name: &str, base: &str) -> Option<bool> {
    let (local, host) = name.rsplit_once('@')?;
    Some(match base.rsplit_once('@') {
        Some((bl, bh)) => local == bl && host.eq_ignore_ascii_case(bh),
        None if base.starts_with('.') => host
            .to_ascii_lowercase()
            .ends_with(&base.to_ascii_lowercase()),
        None => host.eq_ignore_ascii_case(base),
    })
}

/// Whether `name` lies in the subtree `base`. `None` when `base` is of
/// another form, so it does not constrain `name`.
fn in_subtree(name: &NameRef<'_>, base: &GeneralName) -> Result<Option<bool>, SigvalError> {
    Ok(match (name, base) {
        (NameRef::Directory(n), GeneralName::DirectoryName(b)) => Some(in_directory(n, b)),
        (NameRef::Dns(n), GeneralName::DnsName(b)) => Some(in_dns(n, b.as_str())),
        (NameRef::Mailbox(n), GeneralName::Rfc822Name(b)) => {
            Some(in_mailbox(n, b.as_str()).ok_or(SigvalError::NameConstraints)?)
        }
        _ => None,
    })
}

/// One name of a certificate, by form.
enum NameRef<'a> {
    Directory(&'a Name),
    Mailbox(&'a str),
    Dns(&'a str),
}

/// Checks every name of `names` against the constraints `nc` of one CA:
/// each name must lie in a permitted subtree of its form when the CA
/// permits any of that form, and in no excluded subtree.
fn check_names(nc: &NameConstraints, names: &Names) -> Result<(), SigvalError> {
    let all = names
        .directory
        .iter()
        .map(NameRef::Directory)
        .chain(names.mailbox.iter().map(|m| NameRef::Mailbox(m)))
        .chain(names.dns.iter().map(|d| NameRef::Dns(d)));
    let permitted = nc.permitted_subtrees.as_deref().unwrap_or(&[]);
    let excluded = nc.excluded_subtrees.as_deref().unwrap_or(&[]);
    for name in all {
        let mut of_form = false;
        let mut inside = false;
        for t in permitted {
            if let Some(hit) = in_subtree(&name, &t.base)? {
                of_form = true;
                inside |= hit;
            }
        }
        if of_form && !inside {
            return Err(SigvalError::NameConstraints);
        }
        for t in excluded {
            if in_subtree(&name, &t.base)? == Some(true) {
                return Err(SigvalError::NameConstraints);
            }
        }
    }
    Ok(())
}

/// Enforces the name constraints of every CA on `path` (signer first,
/// anchor last) over every certificate below it. A self-issued
/// intermediate is exempt, as RFC 5280 section 6.1.3 (b) states; the
/// signer never is. Checking each CA on its own is the RFC's intersection
/// of permitted subtrees and union of excluded ones.
fn check_name_constraints(path: &[Certificate]) -> Result<(), SigvalError> {
    for (i, ca) in path.iter().enumerate().skip(1) {
        let Some(nc) = name_constraints(ca)? else {
            continue;
        };
        for (j, below) in path.iter().enumerate().take(i) {
            let self_issued = below.tbs_certificate.issuer == below.tbs_certificate.subject;
            if j > 0 && self_issued {
                continue;
            }
            check_names(&nc, &names_of(below)?)?;
        }
    }
    Ok(())
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
    check_signer(&current)?;
    // The path so far, signer first, for the name constraints (issue 6 M1).
    let mut path = vec![current.clone()];
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
                check_issuer(cert, depth.saturating_sub(1))?;
                path.push(cert.clone());
                check_name_constraints(&path)?;
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
        check_issuer(&issuer, depth.saturating_sub(1))?;
        path.push(issuer.clone());
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
    // TODO(legal): the qualified level comes only from the anchor flag of the
    // trusted list. Which qualified-certificate statements a qualified
    // signature must carry is a legal rule (L14, issue 6).
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

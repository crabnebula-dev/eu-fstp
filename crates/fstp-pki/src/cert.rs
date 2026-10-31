//! Certificate templates, the to-be-signed bytes and assembly (M3 design
//! sections 1.3 and 4.1, ADR-005 "Role certificates", ADR-009).
//!
//! The profile:
//!
//! - X.509 v3, signed with ECDSA P-256 and SHA-256. The subject key is an
//!   uncompressed P-256 key, since every component key is EC secp256r1.
//! - The serial is a big-endian magnitude. Leading zero bytes are dropped,
//!   zero is refused, and the INTEGER holds at most 20 octets (RFC 5280
//!   section 4.1.2.2).
//! - A name is an optional OU RDN, then the CN RDN. Each RDN holds one
//!   attribute, and each value is a `UTF8String` of 1 to 64 characters
//!   (RFC 5280 `ub-common-name` and `ub-organizational-unit-name`). The OU
//!   of a server certificate, when present, is a [`ClusterKindOu`] marker.
//! - Validity is `UTCTime` through 2049 and `GeneralizedTime` from 2050,
//!   in 1950 to 9999. A client certificate is valid for at most 7 days,
//!   counted in valid seconds with both ends included.
//! - A CA has critical basicConstraints `cA TRUE, pathLen 0` and critical
//!   keyUsage `keyCertSign`, and no extKeyUsage or subjectAltName.
//! - An end entity has critical basicConstraints with `cA` false, critical
//!   keyUsage `digitalSignature` and one extKeyUsage purpose. Its
//!   subjectAltName, when present, lists DNS names, then IP addresses.
//! - Every certificate has a non-critical subjectKeyIdentifier. Every
//!   certificate but a self-signed CA has a non-critical
//!   authorityKeyIdentifier with a keyIdentifier (RFC 5280 sections
//!   4.2.1.1 and 4.2.1.2). Both use [`key_identifier`].

use std::net::IpAddr;

use crate::PkiError;
use crate::der::{
    TAG_AKI_KEY_ID, TAG_CONTEXT_0, TAG_CONTEXT_3, TAG_INTEGER, TAG_OCTET_STRING, TAG_SAN_DNS,
    TAG_SAN_IP, TAG_SEQUENCE, TAG_SET, TAG_UTF8_STRING, TRUE, bit_string, sequence, tlv,
};

pub use crate::time::{MAX_TIME, MIN_TIME};

/// The longest validity of a client certificate, in valid seconds: 7 days
/// (design section 1.3, ADR-005 "Role certificates"). No revocation list
/// is used, so the lifetime alone bounds a lost key.
///
/// RFC 5280 section 4.1.2.5 counts both `notBefore` and `notAfter` as
/// valid. A certificate is therefore valid for `not_after - not_before + 1`
/// seconds, and the last accepted `not_after` is `not_before +
/// CLIENT_MAX_LIFETIME - 1`. This is the interim strict reading of design
/// section 17.2, pending Daniel.
pub const CLIENT_MAX_LIFETIME: i64 = 7 * 86_400;

/// The most characters a CN or OU value may hold (RFC 5280
/// `ub-common-name` and `ub-organizational-unit-name`).
pub const MAX_NAME_CHARS: usize = 64;

/// The most content octets of the serial INTEGER (RFC 5280 section
/// 4.1.2.2).
pub const MAX_SERIAL_OCTETS: usize = 20;

/// The length of a key identifier, in bytes: 160 bits (RFC 7093 section 2).
pub const KEY_ID_LEN: usize = 20;

/// The DER SubjectPublicKeyInfo header of an uncompressed P-256 key:
/// `id-ecPublicKey` with the `secp256r1` parameters, then the BIT STRING
/// header and the uncompressed point marker `04` (RFC 5480).
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// Where the subjectPublicKey BIT STRING value starts in a P-256 SPKI:
/// after the header, the BIT STRING tag and length, and the unused-bits
/// octet. The value is the 65-byte uncompressed point.
const P256_POINT_OFFSET: usize = 26;

/// The length of a DER SubjectPublicKeyInfo of an uncompressed P-256 key.
pub const P256_SPKI_LEN: usize = 91;

/// The length of a raw ECDSA P-256 signature `r || s`, in bytes.
pub const RAW_P256_SIGNATURE_LEN: usize = 64;

/// `ecdsa-with-SHA256` with absent parameters (RFC 5758 section 3.2).
const ALG_ECDSA_SHA256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// The X.509 v3 version field: `[0] EXPLICIT INTEGER 2`.
const VERSION_V3: &[u8] = &[TAG_CONTEXT_0, 0x03, TAG_INTEGER, 0x01, 0x02];

/// `id-at-commonName` (2.5.4.3), encoded.
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
/// `id-at-organizationalUnitName` (2.5.4.11), encoded.
const OID_OU: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0b];
/// `id-ce-basicConstraints` (2.5.29.19), encoded.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
/// `id-ce-keyUsage` (2.5.29.15), encoded.
const OID_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
/// `id-ce-extKeyUsage` (2.5.29.37), encoded.
const OID_EXT_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
/// `id-ce-subjectAltName` (2.5.29.17), encoded.
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
/// `id-ce-subjectKeyIdentifier` (2.5.29.14), encoded.
const OID_SUBJECT_KEY_ID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0e];
/// `id-ce-authorityKeyIdentifier` (2.5.29.35), encoded.
const OID_AUTHORITY_KEY_ID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x23];
/// `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1), encoded.
const OID_KP_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2), encoded.
const OID_KP_CLIENT_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// basicConstraints of a CA that signs end-entity certificates only.
const BASIC_CONSTRAINTS_CA: &[u8] = &[TAG_SEQUENCE, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];
/// basicConstraints of an end entity: `cA` takes its default, false.
const BASIC_CONSTRAINTS_END_ENTITY: &[u8] = &[TAG_SEQUENCE, 0x00];
/// keyUsage `keyCertSign` (bit 5) only, as a minimal BIT STRING.
const KEY_USAGE_CA: &[u8] = &[0x03, 0x02, 0x02, 0x04];
/// keyUsage `digitalSignature` (bit 0) only, as a minimal BIT STRING.
const KEY_USAGE_END_ENTITY: &[u8] = &[0x03, 0x02, 0x07, 0x80];

/// The longest DNS name in a subjectAltName, in bytes (RFC 1035).
const MAX_DNS_NAME_LEN: usize = 253;
/// The longest DNS label, in bytes (RFC 1035).
const MAX_DNS_LABEL_LEN: usize = 63;

/// A key identifier: the leftmost 160 bits of the SHA-256 digest of the
/// subjectPublicKey BIT STRING value (RFC 7093 section 2, method 1).
pub type KeyIdentifier = [u8; KEY_ID_LEN];

/// The cluster kind marker a cluster server certificate carries as its
/// subject OU (design sections 1.3, 4.1 and 9.2, I-83). The set is closed,
/// so a misspelt marker such as `Vault` cannot be issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClusterKindOu {
    /// An application cluster, OU `application`.
    Application,
    /// A vault cluster, OU `vault`.
    Vault,
    /// The control-plane cluster, OU `control`.
    Control,
    /// The witness cluster, OU `witness`.
    Witness,
}

impl ClusterKindOu {
    /// Every marker, in the order of design section 4.1.
    pub const ALL: [ClusterKindOu; 4] = [
        ClusterKindOu::Application,
        ClusterKindOu::Vault,
        ClusterKindOu::Control,
        ClusterKindOu::Witness,
    ];

    /// The OU value of this marker, as the cluster kind of design section
    /// 4.1 spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterKindOu::Application => "application",
            ClusterKindOu::Vault => "vault",
            ClusterKindOu::Control => "control",
            ClusterKindOu::Witness => "witness",
        }
    }

    /// The marker whose OU value is exactly `ou`, if any.
    pub fn from_ou(ou: &str) -> Option<ClusterKindOu> {
        ClusterKindOu::ALL.into_iter().find(|k| k.as_str() == ou)
    }
}

/// A subject or issuer name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistinguishedName {
    /// The common name, 1 to 64 characters. For a role certificate it
    /// equals the role (ADR-005 D2).
    pub common_name: String,
    /// The organizational unit, 1 to 64 characters. For a cluster server
    /// certificate it is a [`ClusterKindOu`] marker, such as `vault`
    /// (design sections 1.3 and 9.2, I-83).
    pub organizational_unit: Option<String>,
}

impl DistinguishedName {
    /// A name with a common name only.
    ///
    /// It suits a CA, a client and a server outside a PostgreSQL cluster.
    /// A cluster server certificate must carry its kind in the OU (design
    /// section 1.3, ADR-005), so a cluster CA caller uses
    /// [`DistinguishedName::cluster_server`] instead. The writer cannot
    /// tell a cluster server from another server, so it does not refuse
    /// a server name without an OU.
    pub fn new(common_name: &str) -> DistinguishedName {
        DistinguishedName {
            common_name: common_name.to_owned(),
            organizational_unit: None,
        }
    }

    /// The subject of a cluster server certificate: the cluster kind marker
    /// as OU, then `common_name`. Every cluster CA caller issues its
    /// server certificate with this name (design sections 1.3 and 4.1,
    /// ADR-005, I-83).
    pub fn cluster_server(kind: ClusterKindOu, common_name: &str) -> DistinguishedName {
        DistinguishedName {
            common_name: common_name.to_owned(),
            organizational_unit: Some(kind.as_str().to_owned()),
        }
    }
}

/// The validity period, in UTC seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// The first second the certificate is valid.
    pub not_before: i64,
    /// The last second the certificate is valid.
    pub not_after: i64,
}

/// The signature algorithms the writer supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256. Every CA key is EC secp256r1
    /// (design section 1.3).
    EcdsaP256Sha256,
}

/// What a certificate is for. It fixes the basicConstraints, keyUsage and
/// extKeyUsage extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertKind {
    /// A CA that signs end-entity certificates only: a cluster CA, a cell
    /// CA or the control-plane CA.
    Ca,
    /// A TLS server, such as a PostgreSQL cluster or the witness.
    Server,
    /// A TLS client, such as a database role or `cell-app`. It is valid for
    /// at most [`CLIENT_MAX_LIFETIME`] seconds.
    Client,
}

/// Everything a certificate states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertSpec {
    /// The serial number as a big-endian magnitude, positive. Its INTEGER
    /// holds at most 20 octets.
    pub serial: Vec<u8>,
    /// The issuer.
    pub issuer: DistinguishedName,
    /// The subject.
    pub subject: DistinguishedName,
    /// The validity period.
    pub validity: Validity,
    /// The subject public key info, DER, of an uncompressed P-256 key.
    pub spki_der: Vec<u8>,
    /// The [`key_identifier`] of the issuer's public key. It is written as
    /// the authorityKeyIdentifier, so a verifier picks the right CA when an
    /// old and a new CA share one name during a rollover (ADR-005 "Role
    /// certificates"). It may be `None` only for a self-signed CA: kind
    /// [`CertKind::Ca`] with the issuer equal to the subject (RFC 5280
    /// section 4.2.1.1). A server or client certificate always needs it,
    /// whatever its names. A CA signed by another CA key under the same
    /// name, as during a rollover, must also pass it, since the writer
    /// cannot tell that CA from a self-signed one by its names.
    pub issuer_key_id: Option<KeyIdentifier>,
    /// What the certificate is for.
    pub kind: CertKind,
    /// The `dNSName` entries of the subjectAltName. Lowercase letters,
    /// digits and hyphens in dot-separated labels, with a last label that
    /// is not all digits. Not allowed on a CA.
    pub dns_names: Vec<String>,
    /// The `iPAddress` entries of the subjectAltName, written after the
    /// DNS names. Not allowed on a CA.
    pub ip_addrs: Vec<IpAddr>,
    /// The algorithm the issuer signs with.
    pub algorithm: SignatureAlgorithm,
}

/// The DER `TBSCertificate` bytes, which the caller signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsCertificate {
    der: Vec<u8>,
    algorithm: SignatureAlgorithm,
}

impl TbsCertificate {
    /// The DER bytes to sign.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The algorithm the issuer must sign with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Encodes the to-be-signed part of the certificate `spec` describes.
///
/// # Errors
///
/// Refuses a spec outside the profile of this module, naming the field.
pub fn tbs(spec: &CertSpec) -> Result<TbsCertificate, PkiError> {
    let serial = serial(&spec.serial)?;
    let algorithm = algorithm_identifier(spec.algorithm);
    let issuer = name_der(&spec.issuer)?;
    let validity = validity(spec.kind, spec.validity)?;
    let subject = name_der(&spec.subject)?;
    check_server_ou(spec)?;
    check_spki(&spec.spki_der)?;
    let extensions = extensions(spec)?;
    let der = sequence(&[
        VERSION_V3,
        &serial,
        algorithm,
        &issuer,
        &validity,
        &subject,
        &spec.spki_der,
        &extensions,
    ]);
    Ok(TbsCertificate {
        der,
        algorithm: spec.algorithm,
    })
}

/// Assembles the DER certificate from its to-be-signed part and the
/// issuer's signature over it: `SEQUENCE { tbs, algorithm, BIT STRING }`
/// (RFC 5280 section 4.1.1). The signature is the caller's, from
/// aws-lc-rs or the custody `sign` operation, as an ASN.1 DER ECDSA
/// signature. It is written as given. A signer that returns raw `r || s`
/// converts it first with [`ecdsa_sig_value_from_raw`] (ADR-004 K14).
///
/// # Errors
///
/// [`PkiError::EmptySignature`] when `signature` is empty.
pub fn assemble(tbs: &TbsCertificate, signature: &[u8]) -> Result<Vec<u8>, PkiError> {
    if signature.is_empty() {
        return Err(PkiError::EmptySignature);
    }
    Ok(sequence(&[
        &tbs.der,
        algorithm_identifier(tbs.algorithm),
        &bit_string(signature),
    ]))
}

/// The ASN.1 DER `ECDSA-Sig-Value` (RFC 5480 section 2.2.3 and RFC 5758
/// section 3.2) of a raw P-256 signature `r || s`, each half 32 big-endian
/// bytes. Each INTEGER is minimal and positive: leading zero bytes are
/// dropped, and one zero byte comes back when the high bit is set.
///
/// This only writes. It checks no range of `r` or `s`, since the verifier
/// refuses a bad signature. It serves a custody `sign` that returns raw
/// `r || s` (ADR-004 K14).
pub fn ecdsa_sig_value_from_raw(r_s: &[u8; RAW_P256_SIGNATURE_LEN]) -> Vec<u8> {
    let (r, s) = r_s.split_at(RAW_P256_SIGNATURE_LEN / 2);
    sequence(&[&unsigned_integer(r), &unsigned_integer(s)])
}

/// The minimal DER INTEGER for the unsigned big-endian `magnitude`. Zero
/// is one zero octet.
fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let tail: &[u8] = match magnitude.iter().position(|b| *b != 0) {
        Some(first) => magnitude.get(first..).unwrap_or_default(),
        None => &[0],
    };
    let high_bit = tail.first().is_some_and(|b| b & 0x80 != 0);
    let mut content = Vec::with_capacity(tail.len().saturating_add(1));
    if high_bit {
        content.push(0);
    }
    content.extend_from_slice(tail);
    tlv(TAG_INTEGER, &content)
}

/// Whether `spki_der` is the DER SubjectPublicKeyInfo of an uncompressed
/// P-256 key. This compares against the one fixed header and length, so
/// it reads no DER. Whether the point lies on the curve is for the
/// signature verifier, which runs on proof of possession.
pub fn is_p256_spki(spki_der: &[u8]) -> bool {
    spki_der.len() == P256_SPKI_LEN && spki_der.starts_with(&P256_SPKI_PREFIX)
}

/// The key identifier of the P-256 key in `spki_der`: the leftmost 160
/// bits of the SHA-256 digest of the subjectPublicKey BIT STRING value,
/// without its tag, length and unused-bits octet (RFC 7093 section 2,
/// method 1). The digest comes from `fstp-crypto`.
///
/// A CA certificate carries it as its subjectKeyIdentifier. A certificate
/// that CA issues carries the same value as its authorityKeyIdentifier,
/// passed in [`CertSpec::issuer_key_id`].
///
/// # Errors
///
/// [`PkiError::SpkiNotP256`] when `spki_der` is not the SPKI of an
/// uncompressed P-256 key.
pub fn key_identifier(spki_der: &[u8]) -> Result<KeyIdentifier, PkiError> {
    check_spki(spki_der)?;
    let point = spki_der
        .get(P256_POINT_OFFSET..)
        .ok_or(PkiError::SpkiNotP256)?;
    let digest = fstp_crypto::sha256(point);
    let mut id = [0u8; KEY_ID_LEN];
    for (slot, b) in id.iter_mut().zip(digest.iter()) {
        *slot = *b;
    }
    Ok(id)
}

fn check_spki(spki_der: &[u8]) -> Result<(), PkiError> {
    if is_p256_spki(spki_der) {
        Ok(())
    } else {
        Err(PkiError::SpkiNotP256)
    }
}

/// A server certificate's subject OU, when present, is a cluster kind
/// marker (design section 1.3, I-83).
fn check_server_ou(spec: &CertSpec) -> Result<(), PkiError> {
    match (&spec.kind, &spec.subject.organizational_unit) {
        (CertKind::Server, Some(ou)) if ClusterKindOu::from_ou(ou).is_none() => {
            Err(PkiError::ServerOuNotClusterKind)
        }
        _ => Ok(()),
    }
}

fn algorithm_identifier(algorithm: SignatureAlgorithm) -> &'static [u8] {
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => ALG_ECDSA_SHA256,
    }
}

/// The serial INTEGER for the big-endian magnitude `magnitude`.
fn serial(magnitude: &[u8]) -> Result<Vec<u8>, PkiError> {
    let tail: &[u8] = match magnitude.iter().position(|b| *b != 0) {
        Some(first) => magnitude.get(first..).unwrap_or_default(),
        None => return Err(PkiError::SerialNotPositive),
    };
    let high_bit = tail.first().is_some_and(|b| b & 0x80 != 0);
    let mut content = Vec::with_capacity(tail.len().saturating_add(1));
    if high_bit {
        content.push(0);
    }
    content.extend_from_slice(tail);
    if content.len() > MAX_SERIAL_OCTETS {
        return Err(PkiError::SerialTooLong);
    }
    Ok(tlv(TAG_INTEGER, &content))
}

/// One RDN of one attribute with a `UTF8String` value.
fn rdn(oid: &[u8], value: &str) -> Vec<u8> {
    tlv(
        TAG_SET,
        &sequence(&[oid, &tlv(TAG_UTF8_STRING, value.as_bytes())]),
    )
}

fn name_value_fits(value: &str) -> bool {
    (1..=MAX_NAME_CHARS).contains(&value.chars().count())
}

/// The RDNs of `dn`, without the outer SEQUENCE tag and length: the OU RDN
/// when present, then the CN RDN.
///
/// This is the form rustls-webpki returns from `EndEntityCert::subject`
/// and `EndEntityCert::issuer`. So a start-up check can compare a peer's
/// subject with the expected name byte for byte, with no DER reader (design
/// section 9.2, I-83).
///
/// # Errors
///
/// [`PkiError::CommonNameLength`] or [`PkiError::OrganizationalUnitLength`]
/// for a value outside 1 to 64 characters.
pub fn name_content(dn: &DistinguishedName) -> Result<Vec<u8>, PkiError> {
    if !name_value_fits(&dn.common_name) {
        return Err(PkiError::CommonNameLength);
    }
    let mut rdns = Vec::new();
    if let Some(ou) = &dn.organizational_unit {
        if !name_value_fits(ou) {
            return Err(PkiError::OrganizationalUnitLength);
        }
        rdns.extend(rdn(OID_OU, ou));
    }
    rdns.extend(rdn(OID_CN, &dn.common_name));
    Ok(rdns)
}

/// The encoded OU RDN of the cluster kind `kind`, as the subject of a
/// cluster server certificate holds it first.
///
/// rustls-webpki `EndEntityCert::subject` returns the subject RDNs without
/// the outer SEQUENCE. A start-up check (design section 9.2, ADR-011,
/// I-83) therefore checks that this subject starts with these bytes. It
/// needs neither the server's CN nor a DER reader. A subject with no OU
/// starts with the CN RDN instead, so it fails the check.
pub fn cluster_kind_ou_rdn(kind: ClusterKindOu) -> Vec<u8> {
    rdn(OID_OU, kind.as_str())
}

/// The DER Name for `dn`, as the certificate writes it: a SEQUENCE around
/// [`name_content`].
///
/// # Errors
///
/// As [`name_content`].
pub fn name_der(dn: &DistinguishedName) -> Result<Vec<u8>, PkiError> {
    Ok(tlv(TAG_SEQUENCE, &name_content(dn)?))
}

/// The Validity SEQUENCE, after the order and lifetime checks.
fn validity(kind: CertKind, v: Validity) -> Result<Vec<u8>, PkiError> {
    let not_before = crate::time::time(v.not_before)?;
    let not_after = crate::time::time(v.not_after)?;
    if v.not_before > v.not_after {
        return Err(PkiError::ValidityInverted);
    }
    if kind == CertKind::Client {
        // Both ends lie in MIN_TIME ..= MAX_TIME, so this cannot overflow.
        let span = v
            .not_after
            .checked_sub(v.not_before)
            .ok_or(PkiError::LifetimeTooLong)?;
        // RFC 5280 section 4.1.2.5: both ends are valid, so the
        // certificate is valid for `span + 1` seconds.
        if span >= CLIENT_MAX_LIFETIME {
            return Err(PkiError::LifetimeTooLong);
        }
    }
    Ok(sequence(&[&not_before, &not_after]))
}

/// One Extension. DER omits `critical` when it is false.
fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let value = tlv(TAG_OCTET_STRING, value);
    if critical {
        sequence(&[oid, TRUE, &value])
    } else {
        sequence(&[oid, &value])
    }
}

/// Whether `name` is a DNS host name of lowercase LDH labels (RFC 1035,
/// RFC 5280 section 4.2.1.6). Wildcards and trailing dots are refused. The
/// last label is never all digits (RFC 1123 section 2.1), so an address
/// such as `127.0.0.1` goes only into an `iPAddress` entry.
fn is_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_DNS_NAME_LEN {
        return false;
    }
    let labels_ok = name.split('.').all(|label| {
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= MAX_DNS_LABEL_LEN
            && b.first() != Some(&b'-')
            && b.last() != Some(&b'-')
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    });
    let last_not_numeric = name
        .rsplit('.')
        .next()
        .is_some_and(|last| !last.bytes().all(|c| c.is_ascii_digit()));
    labels_ok && last_not_numeric
}

fn subject_alt_name(spec: &CertSpec) -> Result<Vec<u8>, PkiError> {
    let mut names = Vec::new();
    for dns in &spec.dns_names {
        if !is_dns_name(dns) {
            return Err(PkiError::DnsNameInvalid);
        }
        names.extend(tlv(TAG_SAN_DNS, dns.as_bytes()));
    }
    for ip in &spec.ip_addrs {
        match ip {
            IpAddr::V4(v4) => names.extend(tlv(TAG_SAN_IP, &v4.octets())),
            IpAddr::V6(v6) => names.extend(tlv(TAG_SAN_IP, &v6.octets())),
        }
    }
    Ok(tlv(TAG_SEQUENCE, &names))
}

/// The `[3] EXPLICIT Extensions` field for `spec`, in this order:
/// basicConstraints, keyUsage, extKeyUsage, subjectAltName,
/// subjectKeyIdentifier, authorityKeyIdentifier. An extension that does
/// not apply is left out.
fn extensions(spec: &CertSpec) -> Result<Vec<u8>, PkiError> {
    let has_san = !spec.dns_names.is_empty() || !spec.ip_addrs.is_empty();
    let mut exts = Vec::new();
    match spec.kind {
        CertKind::Ca => {
            if has_san {
                return Err(PkiError::SubjectAltNameOnCa);
            }
            exts.extend(extension(OID_BASIC_CONSTRAINTS, true, BASIC_CONSTRAINTS_CA));
            exts.extend(extension(OID_KEY_USAGE, true, KEY_USAGE_CA));
        }
        CertKind::Server | CertKind::Client => {
            let purpose = if spec.kind == CertKind::Server {
                OID_KP_SERVER_AUTH
            } else {
                OID_KP_CLIENT_AUTH
            };
            exts.extend(extension(
                OID_BASIC_CONSTRAINTS,
                true,
                BASIC_CONSTRAINTS_END_ENTITY,
            ));
            exts.extend(extension(OID_KEY_USAGE, true, KEY_USAGE_END_ENTITY));
            exts.extend(extension(OID_EXT_KEY_USAGE, false, &sequence(&[purpose])));
            if has_san {
                exts.extend(extension(
                    OID_SUBJECT_ALT_NAME,
                    false,
                    &subject_alt_name(spec)?,
                ));
            }
        }
    }
    let ski = key_identifier(&spec.spki_der)?;
    exts.extend(extension(
        OID_SUBJECT_KEY_ID,
        false,
        &tlv(TAG_OCTET_STRING, &ski),
    ));
    match spec.issuer_key_id {
        Some(aki) => exts.extend(extension(
            OID_AUTHORITY_KEY_ID,
            false,
            &tlv(TAG_SEQUENCE, &tlv(TAG_AKI_KEY_ID, &aki)),
        )),
        // RFC 5280 section 4.2.1.1 lets only a self-signed certificate
        // leave the authorityKeyIdentifier out. In this profile only a CA
        // is self-signed, so an end entity whose names match is refused.
        None if spec.kind == CertKind::Ca && spec.issuer == spec.subject => {}
        None => return Err(PkiError::IssuerKeyIdMissing),
    }
    Ok(tlv(TAG_CONTEXT_3, &tlv(TAG_SEQUENCE, &exts)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_follow_the_ldh_rule() {
        for ok in [
            "a",
            "pg-app-1.cluster.test",
            "x1.y2",
            "1a",
            "10.1.2.x3",
            "123.example",
            &"a".repeat(63),
        ] {
            assert!(is_dns_name(ok), "{ok}");
        }
        let long_label = "a".repeat(64);
        let long_name = ["a"; 127].join(".") + ".ab";
        for bad in [
            "",
            ".",
            "a.",
            ".a",
            "a..b",
            "-a",
            "a-",
            "A",
            "*.a",
            "a_b",
            "é",
            "42",
            "pg.1",
            "127.0.0.1",
            "10.1.2.3",
            &long_label,
            &long_name,
        ] {
            assert!(!is_dns_name(bad), "{bad}");
        }
    }

    #[test]
    fn cluster_kind_ou_markers_round_trip() {
        for kind in ClusterKindOu::ALL {
            assert_eq!(ClusterKindOu::from_ou(kind.as_str()), Some(kind));
        }
        for bad in ["Vault", "vault ", "", "app"] {
            assert_eq!(ClusterKindOu::from_ou(bad), None, "{bad}");
        }
    }
}

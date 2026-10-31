//! The certificate profile the tests ask for, the one adapter to the
//! `fstp-pki` API, and the reference writer for that profile.
//!
//! `Profile` states everything design sections 1.3 and 4.1, ADR-005 and
//! ADR-009 say a certificate carries: names with an optional OU (the
//! cluster kind marker of I-83), a usage (CA, server or client), SAN
//! entries and a validity. The W0 stub `CertSpec` cannot state the OU or
//! the SAN, and states the usage only as `ca: bool`. [`to_spec`] is the
//! only place that maps a `Profile` onto `CertSpec`. It returns a [`Gap`]
//! for anything the stub cannot carry, so no test passes by silently
//! dropping a field. When lane W1i extends `CertSpec`, only [`to_spec`]
//! changes.

use std::net::IpAddr;

use fstp_pki::PkiError;
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, tbs,
};

use super::der;
use super::keys::EcKey;
use super::time;

/// A subject or issuer name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dn {
    /// The common name. For a role certificate it equals the role (ADR-005 D2).
    pub(crate) cn: String,
    /// The organizational unit. For a cluster server certificate it is the
    /// cluster kind (design section 1.3, I-83).
    pub(crate) ou: Option<String>,
}

impl Dn {
    /// A name with a common name only.
    pub(crate) fn cn(cn: &str) -> Dn {
        Dn {
            cn: cn.to_owned(),
            ou: None,
        }
    }
}

/// What the certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Usage {
    /// A CA that signs end-entity certificates only (cluster CA, cell CA).
    Ca,
    /// A TLS server, such as a PostgreSQL cluster or the witness.
    Server,
    /// A TLS client, such as a database role or `cell-app`.
    Client,
}

/// Everything a test asks a certificate to state.
#[derive(Clone, Debug)]
pub(crate) struct Profile {
    pub(crate) serial: Vec<u8>,
    pub(crate) issuer: Dn,
    pub(crate) subject: Dn,
    pub(crate) not_before: i64,
    pub(crate) not_after: i64,
    pub(crate) spki_der: Vec<u8>,
    /// Whether the certificate names its issuer key, and with which key
    /// identifier. [`pki_issue`] and [`reference_issue`] replace a `Some`
    /// value with the key identifier of the key that signs, as a caller
    /// would. `None` is for a self-signed certificate only.
    pub(crate) issuer_key_id: Option<[u8; 20]>,
    pub(crate) usage: Usage,
    pub(crate) dns_names: Vec<String>,
    pub(crate) ip_addrs: Vec<IpAddr>,
}

/// A field the W0 stub API cannot carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gap {
    /// `DistinguishedName` has no organizational unit.
    OrganizationalUnit,
    /// `CertSpec` has no subject alternative names.
    SubjectAltName,
}

/// Why a test could not build a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// The `fstp-pki` API cannot state a field of the profile yet.
    Gap(Gap),
    /// `fstp-pki` refused.
    Pki(PkiError),
}

impl From<PkiError> for BuildError {
    fn from(e: PkiError) -> Self {
        BuildError::Pki(e)
    }
}

fn dn_to_pki(d: &Dn) -> DistinguishedName {
    DistinguishedName {
        common_name: d.cn.clone(),
        organizational_unit: d.ou.clone(),
    }
}

/// Maps `p` onto the current `fstp-pki` API.
///
/// The W1i API states every field of a profile, so this never returns a
/// [`Gap`]. The `Result` stays so the callers do not change.
pub(crate) fn to_spec(p: &Profile) -> Result<CertSpec, Gap> {
    Ok(CertSpec {
        serial: p.serial.clone(),
        issuer: dn_to_pki(&p.issuer),
        subject: dn_to_pki(&p.subject),
        validity: Validity {
            not_before: p.not_before,
            not_after: p.not_after,
        },
        spki_der: p.spki_der.clone(),
        issuer_key_id: p.issuer_key_id,
        kind: match p.usage {
            Usage::Ca => CertKind::Ca,
            Usage::Server => CertKind::Server,
            Usage::Client => CertKind::Client,
        },
        dns_names: p.dns_names.clone(),
        ip_addrs: p.ip_addrs.clone(),
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    })
}

/// The to-be-signed bytes `fstp-pki` writes for `p`.
pub(crate) fn pki_tbs(p: &Profile) -> Result<Vec<u8>, BuildError> {
    let spec = to_spec(p).map_err(BuildError::Gap)?;
    Ok(tbs(&spec)?.as_der().to_vec())
}

/// A certificate `fstp-pki` writes for `p`, signed by `issuer_key` through
/// aws-lc-rs, as a caller would.
pub(crate) fn pki_issue(p: &Profile, issuer_key: &EcKey) -> Result<Vec<u8>, BuildError> {
    let spec = to_spec(&signed_by(p, issuer_key)).map_err(BuildError::Gap)?;
    let t = tbs(&spec)?;
    let sig = issuer_key.sign(t.as_der());
    Ok(assemble(&t, &sig)?)
}

/// The issuer key identifier a profile states before it is signed. The
/// issue functions replace it with the signing key's identifier.
pub(crate) const UNSIGNED_ISSUER_KEY_ID: [u8; 20] = [0xa5; 20];

/// `p` as `issuer_key` signs it: a stated issuer key identifier becomes
/// the identifier of `issuer_key`.
pub(crate) fn signed_by(p: &Profile, issuer_key: &EcKey) -> Profile {
    let mut p = p.clone();
    if p.issuer_key_id.is_some() {
        p.issuer_key_id = Some(issuer_key.key_id());
    }
    p
}

/// A profile for a self-signed CA certificate of `key`.
pub(crate) fn ca_profile(cn: &str, key: &EcKey, not_before: i64, not_after: i64) -> Profile {
    Profile {
        serial: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        issuer: Dn::cn(cn),
        subject: Dn::cn(cn),
        not_before,
        not_after,
        spki_der: key.spki_der(),
        issuer_key_id: None,
        usage: Usage::Ca,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
    }
}

/// A profile for a client certificate with CN `cn` for `key`, issued by
/// the CA named `issuer_cn`.
pub(crate) fn client_profile(
    issuer_cn: &str,
    cn: &str,
    key: &EcKey,
    not_before: i64,
    not_after: i64,
) -> Profile {
    Profile {
        serial: vec![0x42, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
        issuer: Dn::cn(issuer_cn),
        subject: Dn::cn(cn),
        not_before,
        not_after,
        spki_der: key.spki_der(),
        issuer_key_id: Some(UNSIGNED_ISSUER_KEY_ID),
        usage: Usage::Client,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
    }
}

/// The name `fstp-pki` must write for `d`, without the outer SEQUENCE tag
/// and length, as rustls-webpki returns it.
pub(crate) fn name_content(d: &Dn) -> Vec<u8> {
    der::name_content(&d.cn, d.ou.as_deref())
}

/// The fields every TBSCertificate of the reference profile starts with,
/// up to and including the SPKI: version, serial, signature algorithm,
/// issuer, validity and subject. `None` when the reference refuses `p`.
pub(crate) fn tbs_prefix(p: &Profile) -> Option<Vec<u8>> {
    let mut out = der::VERSION_V3.to_vec();
    out.extend(der::serial(&p.serial)?);
    out.extend_from_slice(der::ALG_ECDSA_SHA256);
    out.extend(der::name(&p.issuer.cn, p.issuer.ou.as_deref()));
    out.extend(time::validity(p.not_before, p.not_after)?);
    out.extend(der::name(&p.subject.cn, p.subject.ou.as_deref()));
    out.extend_from_slice(&p.spki_der);
    Some(out)
}

/// The extensions of the reference profile for `p`, each encoded.
pub(crate) fn reference_extensions(p: &Profile) -> Vec<Vec<u8>> {
    let mut exts = Vec::new();
    match p.usage {
        Usage::Ca => {
            exts.push(der::extension(
                der::OID_BC,
                true,
                &der::basic_constraints_ca(),
            ));
            exts.push(der::extension(der::OID_KU, true, &der::key_usage_ca()));
        }
        Usage::Server | Usage::Client => {
            exts.push(der::extension(
                der::OID_BC,
                true,
                &der::basic_constraints_leaf(),
            ));
            exts.push(der::extension(der::OID_KU, true, &der::key_usage_leaf()));
            let purpose = if p.usage == Usage::Server {
                der::OID_KP_SERVER
            } else {
                der::OID_KP_CLIENT
            };
            exts.push(der::extension(
                der::OID_EKU,
                false,
                &der::ext_key_usage(purpose),
            ));
        }
    }
    if !p.dns_names.is_empty() || !p.ip_addrs.is_empty() {
        exts.push(der::extension(
            der::OID_SAN,
            false,
            &der::subject_alt_name(&p.dns_names, &p.ip_addrs),
        ));
    }
    exts.push(der::extension(
        der::OID_SKI,
        false,
        &der::subject_key_identifier(&super::keys::key_id_of(&p.spki_der)),
    ));
    if let Some(id) = p.issuer_key_id {
        exts.push(der::extension(
            der::OID_AKI,
            false,
            &der::authority_key_identifier(&id),
        ));
    }
    exts
}

/// The reference TBSCertificate for `p`, or `None` when the reference
/// refuses `p`. Written independently of `fstp-pki`.
pub(crate) fn reference_tbs(p: &Profile) -> Option<Vec<u8>> {
    let mut content = tbs_prefix(p)?;
    content.extend(der::extensions_field(&reference_extensions(p)));
    Some(der::tlv(0x30, &content))
}

/// A reference certificate for `p` signed by `issuer_key`. The harness
/// self-tests use it to show that each oracle accepts a correct
/// certificate, so a red `fstp-pki` test is red because of `fstp-pki`.
pub(crate) fn reference_issue(p: &Profile, issuer_key: &EcKey) -> Option<Vec<u8>> {
    let t = reference_tbs(&signed_by(p, issuer_key))?;
    let sig = issuer_key.sign(&t);
    Some(der::certificate(&t, der::ALG_ECDSA_SHA256, &sig))
}

/// Whether `haystack` holds `needle` as a contiguous byte run.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether `r` is a refusal by real code, not the W0 `NotImplemented`
/// stub. A refusal test asserts this, so it is red while the stub stands.
pub(crate) fn real_refusal<T>(r: &Result<T, BuildError>) -> bool {
    matches!(r, Err(BuildError::Pki(e)) if !matches!(e, PkiError::NotImplemented(_)))
}

/// Like [`real_refusal`], for a plain `fstp-pki` result.
pub(crate) fn real_pki_refusal<T>(r: &Result<T, PkiError>) -> bool {
    matches!(r, Err(e) if !matches!(e, PkiError::NotImplemented(_)))
}

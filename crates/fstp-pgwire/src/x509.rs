//! The X.509 details the client reads from the server certificate. The
//! first is the one channel binding needs: which hash the server
//! certificate's signature algorithm uses.
//!
//! RFC 5929 defines `tls-server-end-point` as a hash of the server's
//! certificate. The hash is the one of the certificate's signature
//! algorithm, except that MD5 and SHA-1 are replaced by SHA-256.
//! fstp-crypto offers only SHA-256, so certificates signed with SHA-384 or
//! SHA-512 cannot be used for channel binding yet.
//!
//! The certificate has already been verified by rustls when this runs. The
//! walker still treats it as untrusted bytes: every length is checked, and
//! only the structure each reader needs is read.
//!
//! [`subject_organizational_units`] reads one more detail, the OUs of the
//! server certificate's subject. The I-83 start checks of the cell and
//! the vault read the cluster kind from it (M3 design section 9.2).

use crate::error::Error;

/// The hash that `tls-server-end-point` uses for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndPointHash {
    /// SHA-256: for `sha256WithRSAEncryption`, `ecdsa-with-SHA256` and, per
    /// RFC 5929, for MD5 and SHA-1 based algorithms.
    Sha256,
    /// A hash that fstp-crypto does not provide, or an algorithm without a
    /// single hash, such as RSASSA-PSS or Ed25519.
    Unsupported(&'static str),
}

/// DER object identifiers, content bytes only.
const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const MD5_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const SHA224_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e];
const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const ECDSA_SHA224: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const ED448: &[u8] = &[0x2b, 0x65, 0x71];

/// Reads one DER TLV at the start of `input`. Returns the tag, the content
/// and the rest. Only definite lengths of up to four length bytes are
/// accepted, and the long form must be minimal.
fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let bad = || Error::auth("server certificate is not valid DER");
    let (&tag, rest) = input.split_first().ok_or_else(bad)?;
    let (&first, mut rest) = rest.split_first().ok_or_else(bad)?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(bad());
        }
        let (bytes, after) = rest.split_at_checked(n).ok_or_else(bad)?;
        rest = after;
        let mut len = 0usize;
        for b in bytes {
            len = len
                .checked_mul(256)
                .and_then(|l| l.checked_add(usize::from(*b)))
                .ok_or_else(bad)?;
        }
        // Minimal encoding: the long form only for 128 and above, and no
        // leading zero byte.
        if len < 0x80 || bytes.first() == Some(&0) {
            return Err(bad());
        }
        len
    };
    let (content, rest) = rest.split_at_checked(len).ok_or_else(bad)?;
    Ok((tag, content, rest))
}

/// Finds the hash that `tls-server-end-point` uses for `cert_der`.
///
/// # Errors
///
/// Returns an [`ErrorKind::Auth`](crate::ErrorKind::Auth) error when the
/// certificate's outer structure is not valid DER.
pub fn end_point_hash(cert_der: &[u8]) -> Result<EndPointHash, Error> {
    let bad = || Error::auth("server certificate is not valid DER");
    let (tag, cert, rest) = tlv(cert_der)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(bad());
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (tbs_tag, _tbs, after_tbs) = tlv(cert)?;
    if tbs_tag != 0x30 {
        return Err(bad());
    }
    let (alg_tag, alg, _after_alg) = tlv(after_tbs)?;
    if alg_tag != 0x30 {
        return Err(bad());
    }
    let (oid_tag, oid, _params) = tlv(alg)?;
    if oid_tag != 0x06 {
        return Err(bad());
    }
    Ok(match oid {
        SHA256_WITH_RSA | ECDSA_SHA256 | SHA1_WITH_RSA | MD5_WITH_RSA | ECDSA_SHA1 => {
            EndPointHash::Sha256
        }
        SHA384_WITH_RSA | ECDSA_SHA384 => EndPointHash::Unsupported("SHA-384"),
        SHA512_WITH_RSA | ECDSA_SHA512 => EndPointHash::Unsupported("SHA-512"),
        SHA224_WITH_RSA | ECDSA_SHA224 => EndPointHash::Unsupported("SHA-224"),
        RSASSA_PSS => EndPointHash::Unsupported("RSASSA-PSS"),
        ED25519 => EndPointHash::Unsupported("Ed25519"),
        ED448 => EndPointHash::Unsupported("Ed448"),
        _ => EndPointHash::Unsupported("an unknown signature algorithm"),
    })
}

/// The `tls-server-end-point` channel binding data for `cert_der`.
///
/// # Errors
///
/// Returns an [`ErrorKind::Auth`](crate::ErrorKind::Auth) error when the
/// certificate is malformed or its signature hash is not available.
pub fn tls_server_end_point(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
    match end_point_hash(cert_der)? {
        EndPointHash::Sha256 => Ok(fstp_crypto::sha256(cert_der).to_vec()),
        EndPointHash::Unsupported(name) => Err(Error::auth(format!(
            "channel binding needs the server certificate's signature hash ({name}), \
             which this client cannot compute; use a certificate signed with SHA-256"
        ))),
    }
}

/// `id-at-organizationalUnitName` (2.5.4.11), content bytes.
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const OBJECT_ID: u8 = 0x06;
const EXPLICIT_0: u8 = 0xa0;

/// Every organizationalUnitName value in the subject of the certificate
/// `cert_der`, in the order the subject lists them (RFC 5280 section
/// 4.1.2.6). Fuzzed (`pg_cert_subject_ou`).
///
/// Each value is the content of its attribute value, without tag and
/// length. The walk reads the whole subject Name. Each relative
/// distinguished name must be a non-empty SET of attributes, and each
/// attribute a SEQUENCE of an OID and exactly one value. A caller that
/// needs one cluster kind from the server certificate refuses a subject
/// with more than one OU, as the I-83 start checks do (M3 design section
/// 9.2).
///
/// # Errors
///
/// Returns an [`ErrorKind::Auth`](crate::ErrorKind::Auth) error when the
/// certificate up to the end of its subject is not valid DER of that
/// structure.
pub fn subject_organizational_units(cert_der: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let bad = || Error::auth("server certificate is not valid DER");
    let expect = |input, want| -> Result<(&[u8], &[u8]), Error> {
        let (tag, content, rest) = tlv(input)?;
        if tag == want {
            Ok((content, rest))
        } else {
            Err(bad())
        }
    };
    let (cert, rest) = expect(cert_der, SEQUENCE)?;
    if !rest.is_empty() {
        return Err(bad());
    }
    let (tbs, _) = expect(cert, SEQUENCE)?;
    let mut rest = tbs;
    // version [0] EXPLICIT, optional (RFC 5280 section 4.1).
    if rest.first() == Some(&EXPLICIT_0) {
        let (_, after) = expect(rest, EXPLICIT_0)?;
        rest = after;
    }
    // serialNumber, signature, issuer and validity come before the subject.
    for want in [INTEGER, SEQUENCE, SEQUENCE, SEQUENCE] {
        let (_, after) = expect(rest, want)?;
        rest = after;
    }
    let (subject, _) = expect(rest, SEQUENCE)?;
    let mut ous = Vec::new();
    let mut rdns = subject;
    while !rdns.is_empty() {
        let (set, after) = expect(rdns, SET)?;
        rdns = after;
        if set.is_empty() {
            return Err(bad());
        }
        let mut attributes = set;
        while !attributes.is_empty() {
            let (attribute, after) = expect(attributes, SEQUENCE)?;
            attributes = after;
            let (oid, value) = expect(attribute, OBJECT_ID)?;
            let (_, content, end) = tlv(value)?;
            if !end.is_empty() {
                return Err(bad());
            }
            if oid == OID_OU {
                ous.push(content);
            }
        }
    }
    Ok(ous)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// An attribute of type `oid` with the UTF8String `value`.
    fn attribute(oid: &[u8], value: &str) -> Vec<u8> {
        let mut body = seq(OBJECT_ID, oid);
        body.extend(seq(0x0c, value.as_bytes()));
        seq(SEQUENCE, &body)
    }

    /// A certificate whose subject has the relative distinguished names
    /// `rdns`, each a list of attributes.
    fn cert_with_subject(rdns: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let mut name = Vec::new();
        for rdn in rdns {
            name.extend(seq(SET, &rdn.concat()));
        }
        cert_with_name(&name)
    }

    /// A certificate whose subject Name has the content `name`.
    fn cert_with_name(name: &[u8]) -> Vec<u8> {
        let mut tbs = seq(EXPLICIT_0, &[0x02, 0x01, 0x02]);
        tbs.extend([0x02, 0x01, 0x01]);
        tbs.extend(seq(SEQUENCE, &seq(OBJECT_ID, ECDSA_SHA256)));
        tbs.extend(seq(SEQUENCE, &[]));
        tbs.extend(seq(SEQUENCE, &[]));
        tbs.extend(seq(SEQUENCE, name));
        tbs.extend(seq(SEQUENCE, &[]));
        let mut body = seq(SEQUENCE, &tbs);
        body.extend(seq(SEQUENCE, &seq(OBJECT_ID, ECDSA_SHA256)));
        body.extend(seq(0x03, &[0x00, 0x01]));
        seq(SEQUENCE, &body)
    }

    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

    /// I-83, design section 9.2: the reader returns every subject OU in
    /// order, in separate and in multi-valued RDNs, and none for a subject
    /// without one.
    #[test]
    fn i83_subject_ous_lists_every_ou_of_the_subject() {
        let one = cert_with_subject(&[
            vec![attribute(OID_OU, "vault")],
            vec![attribute(OID_CN, "127.0.0.1")],
        ]);
        assert_eq!(
            subject_organizational_units(&one).unwrap(),
            vec![b"vault".as_slice()]
        );
        let two = cert_with_subject(&[
            vec![attribute(OID_OU, "vault")],
            vec![attribute(OID_OU, "application")],
            vec![attribute(OID_CN, "127.0.0.1")],
        ]);
        assert_eq!(
            subject_organizational_units(&two).unwrap(),
            vec![b"vault".as_slice(), b"application".as_slice()]
        );
        let multi = cert_with_subject(&[vec![
            attribute(OID_CN, "127.0.0.1"),
            attribute(OID_OU, "vault"),
            attribute(OID_OU, "application"),
        ]]);
        assert_eq!(subject_organizational_units(&multi).unwrap().len(), 2);
        let none = cert_with_subject(&[vec![attribute(OID_CN, "127.0.0.1")]]);
        assert!(subject_organizational_units(&none).unwrap().is_empty());
        let der = first_der(include_bytes!("../../fstp-tls/testdata/server.pem"));
        assert!(subject_organizational_units(&der).unwrap().is_empty());
    }

    /// TH-26: a truncated certificate, trailing bytes, an empty RDN and an
    /// attribute with two values do not read.
    #[test]
    fn th26_subject_ous_rejects_malformed_names() {
        let good = cert_with_subject(&[vec![attribute(OID_OU, "vault")]]);
        for cut in 0..good.len() {
            assert!(
                subject_organizational_units(&good[..cut]).is_err(),
                "cut at {cut}"
            );
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(subject_organizational_units(&trailing).is_err());
        let empty_rdn = cert_with_subject(&[Vec::new()]);
        assert!(subject_organizational_units(&empty_rdn).is_err());
        let mut two_values = seq(OBJECT_ID, OID_OU);
        two_values.extend(seq(0x0c, b"vault"));
        two_values.extend(seq(0x0c, b"application"));
        let doubled = cert_with_subject(&[vec![seq(SEQUENCE, &two_values)]]);
        assert!(subject_organizational_units(&doubled).is_err());
        let not_a_set = cert_with_name(&seq(SEQUENCE, &attribute(OID_OU, "vault")));
        assert!(subject_organizational_units(&not_a_set).is_err());
    }

    fn seq(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if content.len() < 128 {
            v.push(content.len() as u8);
        } else {
            v.push(0x82);
            v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(content);
        v
    }

    fn cert_with_alg(oid: &[u8]) -> Vec<u8> {
        let tbs = seq(0x30, &[0x02, 0x01, 0x01]);
        let alg = seq(0x30, &seq(0x06, oid));
        let sig = seq(0x03, &[0x00, 0x01]);
        let mut body = tbs;
        body.extend(alg);
        body.extend(sig);
        seq(0x30, &body)
    }

    #[test]
    fn recognises_signature_hashes() {
        assert_eq!(
            end_point_hash(&cert_with_alg(ECDSA_SHA256)).unwrap(),
            EndPointHash::Sha256
        );
        assert_eq!(
            end_point_hash(&cert_with_alg(SHA1_WITH_RSA)).unwrap(),
            EndPointHash::Sha256
        );
        assert_eq!(
            end_point_hash(&cert_with_alg(ECDSA_SHA384)).unwrap(),
            EndPointHash::Unsupported("SHA-384")
        );
        assert!(tls_server_end_point(&cert_with_alg(ED25519)).is_err());
    }

    #[test]
    fn th26_rejects_malformed_der() {
        let good = cert_with_alg(ECDSA_SHA256);
        for cut in 0..good.len() {
            assert!(end_point_hash(&good[..cut]).is_err(), "cut at {cut}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(end_point_hash(&trailing).is_err());
        // Non-minimal long-form length.
        assert!(tlv(&[0x30, 0x81, 0x01, 0x00]).is_err());
        assert!(tlv(&[0x30, 0x80]).is_err());
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_err());
    }

    #[test]
    fn test_server_certificate_uses_sha256() {
        let der = first_der(include_bytes!("../../fstp-tls/testdata/server.pem"));
        assert_eq!(end_point_hash(&der).unwrap(), EndPointHash::Sha256);
        assert_eq!(
            tls_server_end_point(&der).unwrap(),
            fstp_crypto::sha256(&der)
        );
    }

    fn first_der(pem: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(pem).unwrap();
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect();
        crate::base64::decode(body.as_bytes()).unwrap()
    }
}

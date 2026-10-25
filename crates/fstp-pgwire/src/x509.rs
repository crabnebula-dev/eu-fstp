//! The one X.509 detail that channel binding needs: which hash the server
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
//! only the outer structure is read.

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

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

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

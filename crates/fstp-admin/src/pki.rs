//! The host CAs and the certificates they issue (ADR-028 "Certificates").
//!
//! Every key pair and signature comes from `fstp_crypto::sig`, and every
//! certificate is written by `fstp_pki`. Nothing here implements a
//! primitive. A CA keeps its PKCS#8 key as a root-only DER file and its
//! certificate as PEM and DER. Each issued certificate gets a sidecar
//! `<file>.expires` with its last valid second, so `renew` and `status`
//! need no certificate parser.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fstp_crypto::sig::EcdsaP256KeyPair;
use fstp_pki::cert::{
    CLIENT_MAX_LIFETIME, CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity,
    assemble, key_identifier, tbs,
};
use fstp_pki::pem::{PemLabel, encode};

use crate::state::write_atomic;

/// How far in the past every certificate starts.
const BACKDATE: i64 = 300;
/// A CA lives ten years.
const CA_LIFETIME: i64 = 10 * 365 * 86_400;
/// A server certificate lives 90 days.
const SERVER_LIFETIME: i64 = 90 * 86_400;
/// A certificate with less than this left is renewed.
pub const RENEW_BEFORE: i64 = 3 * 86_400;

/// Why a certificate operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkiFail {
    /// `fstp-crypto` or `fstp-pki` refused, or the random source failed.
    Crypto,
    /// A file did not read or write.
    Io,
}

impl From<std::io::Error> for PkiFail {
    fn from(_: std::io::Error) -> PkiFail {
        PkiFail::Io
    }
}

/// The current time in UTC seconds.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn serial() -> Result<Vec<u8>, PkiFail> {
    let mut b = fstp_crypto::random_array::<16>().map_err(|_| PkiFail::Crypto)?;
    b[0] = (b[0] & 0x7f) | 0x40;
    Ok(b.to_vec())
}

/// Standard base64 with padding (RFC 4648). Encoding only.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0).wrapping_shl(16) | u32::from(b1).wrapping_shl(8) | u32::from(b2);
        let chars = chunk.len().saturating_add(1);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i < chars {
                let index = usize::try_from(n.wrapping_shr(shift) & 0x3f).unwrap_or(0);
                out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A PKCS#8 private key as PEM.
fn key_pem(der: &[u8]) -> Vec<u8> {
    let body = base64(der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(64));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out.into_bytes()
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A host CA, loaded or created under `<ca_dir>/<name>`.
pub struct Ca {
    name: String,
    key: EcdsaP256KeyPair,
    spki: Vec<u8>,
    /// The CA certificate, PEM.
    pub pem: Vec<u8>,
    /// The CA certificate, DER.
    pub der: Vec<u8>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What an issued certificate is for.
#[derive(Clone, Debug)]
pub struct Leaf<'a> {
    /// The subject CN.
    pub cn: &'a str,
    /// The subject OU, if any.
    pub ou: Option<&'a str>,
    /// Server or client.
    pub kind: CertKind,
    /// DNS names.
    pub dns: &'a [&'a str],
    /// IP addresses.
    pub ips: &'a [IpAddr],
}

/// An issued certificate and key, PEM.
#[derive(Clone)]
pub struct Issued {
    /// The certificate.
    pub cert_pem: Vec<u8>,
    /// The certificate, DER.
    pub cert_der: Vec<u8>,
    /// The key.
    pub key_pem: Vec<u8>,
    /// The last valid second.
    pub not_after: i64,
    /// The SHA-256 of the subject public key info.
    pub spki_sha256: [u8; 32],
}

impl Ca {
    /// Loads the CA `name` from `dir`, or creates it there when it does
    /// not exist.
    ///
    /// # Errors
    ///
    /// [`PkiFail`] for a key or file that does not read or write.
    pub fn open_or_create(dir: &Path, name: &str) -> Result<Ca, PkiFail> {
        let key_path = dir.join(format!("{name}.key.der"));
        let der_path = dir.join(format!("{name}.der"));
        if key_path.is_file() && der_path.is_file() {
            let pkcs8 = std::fs::read(&key_path)?;
            let key = EcdsaP256KeyPair::from_pkcs8(&pkcs8).map_err(|_| PkiFail::Crypto)?;
            let der = std::fs::read(&der_path)?;
            let pem = encode(PemLabel::Certificate, &der)
                .map_err(|_| PkiFail::Crypto)?
                .into_bytes();
            let spki = key.spki_der().map_err(|_| PkiFail::Crypto)?;
            return Ok(Ca {
                name: name.to_owned(),
                key,
                spki,
                pem,
                der,
            });
        }
        let key = EcdsaP256KeyPair::generate().map_err(|_| PkiFail::Crypto)?;
        let spki = key.spki_der().map_err(|_| PkiFail::Crypto)?;
        let now = now();
        let me = DistinguishedName::new(name);
        let spec = CertSpec {
            serial: serial()?,
            issuer: me.clone(),
            subject: me,
            validity: Validity {
                not_before: now.saturating_sub(BACKDATE),
                not_after: now.saturating_add(CA_LIFETIME),
            },
            spki_der: spki.clone(),
            issuer_key_id: None,
            kind: CertKind::Ca,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).map_err(|_| PkiFail::Crypto)?;
        let sig = key.sign(t.as_der()).map_err(|_| PkiFail::Crypto)?;
        let der = assemble(&t, &sig).map_err(|_| PkiFail::Crypto)?;
        let pem = encode(PemLabel::Certificate, &der)
            .map_err(|_| PkiFail::Crypto)?
            .into_bytes();
        let pkcs8 = key.pkcs8_der().map_err(|_| PkiFail::Crypto)?;
        write_atomic(&key_path, &pkcs8, 0o600)?;
        write_atomic(&der_path, &der, 0o644)?;
        write_atomic(&dir.join(format!("{name}.pem")), &pem, 0o644)?;
        Ok(Ca {
            name: name.to_owned(),
            key,
            spki,
            pem,
            der,
        })
    }

    /// The SHA-256 of the CA's subject public key info.
    #[must_use]
    pub fn spki_sha256(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.spki)
    }

    /// Issues a certificate to a fresh key.
    ///
    /// # Errors
    ///
    /// [`PkiFail::Crypto`] when `fstp-pki` refuses the profile.
    pub fn issue(&self, leaf: &Leaf<'_>) -> Result<Issued, PkiFail> {
        self.issue_for(leaf, None)
    }

    /// As [`Self::issue`], for `lifetime` seconds in place of the default
    /// of a server certificate. A client certificate keeps its bound.
    ///
    /// # Errors
    ///
    /// As [`Self::issue`].
    pub fn issue_for(&self, leaf: &Leaf<'_>, lifetime: Option<i64>) -> Result<Issued, PkiFail> {
        let key = EcdsaP256KeyPair::generate().map_err(|_| PkiFail::Crypto)?;
        let now = now();
        let lifetime = match leaf.kind {
            CertKind::Client => CLIENT_MAX_LIFETIME
                .saturating_sub(BACKDATE)
                .saturating_sub(1),
            _ => lifetime.unwrap_or(SERVER_LIFETIME),
        };
        let not_after = now.saturating_add(lifetime);
        let spki = key.spki_der().map_err(|_| PkiFail::Crypto)?;
        let spec = CertSpec {
            serial: serial()?,
            issuer: DistinguishedName::new(&self.name),
            subject: DistinguishedName {
                common_name: leaf.cn.to_owned(),
                organizational_unit: leaf.ou.map(str::to_owned),
            },
            validity: Validity {
                not_before: now.saturating_sub(BACKDATE),
                not_after,
            },
            spki_der: key.spki_der().map_err(|_| PkiFail::Crypto)?,
            issuer_key_id: Some(key_identifier(&self.spki).map_err(|_| PkiFail::Crypto)?),
            kind: leaf.kind,
            dns_names: leaf.dns.iter().map(|s| (*s).to_owned()).collect(),
            ip_addrs: leaf.ips.to_vec(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).map_err(|_| PkiFail::Crypto)?;
        let sig = self.key.sign(t.as_der()).map_err(|_| PkiFail::Crypto)?;
        let der = assemble(&t, &sig).map_err(|_| PkiFail::Crypto)?;
        let cert_pem = encode(PemLabel::Certificate, &der)
            .map_err(|_| PkiFail::Crypto)?
            .into_bytes();
        let pkcs8 = key.pkcs8_der().map_err(|_| PkiFail::Crypto)?;
        Ok(Issued {
            cert_pem,
            cert_der: der,
            key_pem: key_pem(&pkcs8),
            not_after,
            spki_sha256: fstp_crypto::sha256(&spki),
        })
    }
}

/// Writes `issued` as `<dir>/<cert>` and `<dir>/<key>`, with the sidecar
/// `<cert>.expires`.
///
/// # Errors
///
/// [`PkiFail::Io`] when a file does not write.
pub fn write_pair(dir: &Path, cert: &str, key: &str, issued: &Issued) -> Result<(), PkiFail> {
    write_atomic(&dir.join(key), &issued.key_pem, 0o600)?;
    write_atomic(&dir.join(cert), &issued.cert_pem, 0o600)?;
    write_atomic(
        &dir.join(format!("{cert}.expires")),
        issued.not_after.to_string().as_bytes(),
        0o600,
    )?;
    Ok(())
}

/// The last valid second of the certificate at `cert`, from its sidecar.
#[must_use]
pub fn expires(cert: &Path) -> Option<i64> {
    let mut p = cert.as_os_str().to_owned();
    p.push(".expires");
    std::fs::read_to_string(PathBuf::from(p))
        .ok()
        .and_then(|t| t.trim().parse().ok())
}

/// Whether the certificate at `cert` is missing or needs renewal.
#[must_use]
pub fn needs_issue(cert: &Path) -> bool {
    match expires(cert) {
        Some(at) => at.saturating_sub(now()) < RENEW_BEFORE,
        None => true,
    }
}

/// The SHA-256 of a certificate's DER, as 64 lowercase hex digits.
#[must_use]
pub fn cert_pin(der: &[u8]) -> String {
    hex(&fstp_crypto::sha256(der))
}

/// Random lowercase hex of `n` bytes.
///
/// # Errors
///
/// [`PkiFail::Crypto`] when the random source fails.
pub fn random_hex(n: usize) -> Result<String, PkiFail> {
    let mut b = vec![0u8; n];
    fstp_crypto::random_bytes(&mut b).map_err(|_| PkiFail::Crypto)?;
    Ok(hex(&b))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-028 "Certificates": a CA reloads with the same key, and a client
    /// certificate stays within `CLIENT_MAX_LIFETIME` (ADR-005 D2).
    #[test]
    fn adr028_ca_reloads_and_client_lifetime_is_bounded() {
        let dir = std::env::temp_dir().join(format!("fstp-admin-pki-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = Ca::open_or_create(&dir, "test-ca").unwrap();
        let b = Ca::open_or_create(&dir, "test-ca").unwrap();
        assert_eq!(a.spki_sha256(), b.spki_sha256());
        let leaf = b
            .issue(&Leaf {
                cn: "c_00_writer",
                ou: None,
                kind: CertKind::Client,
                dns: &[],
                ips: &[],
            })
            .unwrap();
        assert!(leaf.not_after.saturating_sub(now()) < CLIENT_MAX_LIFETIME);
        assert!(leaf.key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }
}

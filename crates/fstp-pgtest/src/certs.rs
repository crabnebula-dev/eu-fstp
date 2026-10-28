//! Test cluster CAs and client certificates minted at runtime (M3 design
//! sections 1.3, 2.2 and 4.1).
//!
//! Each named server ([`crate::PgServer::shared_named`]) trusts only its
//! own cluster CA. The CA signs the server certificate, with the cluster
//! kind in the subject OU, and client certificates whose CN equals a role
//! name, with a 7-day lifetime. The certificates are written by `fstp-pki`
//! and signed with an ECDSA secp256r1 key from `fstp-crypto`.
//!
//! # Profile
//!
//! | Certificate | Subject | Extensions | Lifetime |
//! | --- | --- | --- | --- |
//! | Cluster CA | CN = the CA name | CA, path length 0, keyCertSign | 30 days |
//! | Server | CN = `127.0.0.1`, OU = the cluster kind | end entity, serverAuth, SAN `127.0.0.1` and `localhost` | 7 days |
//! | Role | CN = the role | end entity, clientAuth | 7 days |
//!
//! Every certificate starts five minutes in the past, so a small clock
//! difference between the test and the server does not matter.
//!
//! # Seams
//!
//! One part of this module waits for a parallel lane. It refuses with
//! [`CertError::NotImplemented`] and names what it waits for:
//!
//! - [`signer`]: key generation, PKCS#8 export and ECDSA P-256 signing.
//!   They wait for the `fstp_crypto::sig` module of lane W1h. Key pairs
//!   come from there, never from code written here (`.claude/CLAUDE.md`).
//!
//! [`to_spec`] maps the profile onto `fstp_pki::cert::CertSpec`, with the
//! issuer's key identifier as the authorityKeyIdentifier. Only [`signer`]
//! changes when lane W1h lands. The
//! certificate PEM comes from `fstp_pki::pem`. The key PEM is written
//! here, since `fstp_pki::pem::PemLabel` names certificates only.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_pki::pem::{PemLabel, encode};

/// Why a certificate operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertError {
    /// The operation is a stub. It names the operation.
    NotImplemented(&'static str),
    /// A name outside the grammar the harness accepts.
    InvalidName(String),
    /// `fstp-pki` refused. The text is its error display.
    Pki(String),
    /// The system clock or random source failed.
    Environment(String),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            CertError::InvalidName(name) => write!(f, "invalid certificate name {name:?}"),
            CertError::Pki(e) => write!(f, "fstp-pki refused: {e}"),
            CertError::Environment(e) => write!(f, "certificate environment: {e}"),
        }
    }
}

impl std::error::Error for CertError {}

impl From<fstp_pki::PkiError> for CertError {
    fn from(e: fstp_pki::PkiError) -> Self {
        match e {
            fstp_pki::PkiError::NotImplemented(op) => CertError::NotImplemented(op),
            #[allow(unreachable_patterns, reason = "fstp-pki gains variants in lane W1i")]
            other => CertError::Pki(other.to_string()),
        }
    }
}

/// A certificate and its private key, both PEM.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCert {
    /// The certificate (PEM).
    pub cert_pem: Vec<u8>,
    /// The private key (PEM, PKCS#8).
    pub key_pem: Vec<u8>,
}

impl fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCert")
            .field("cert_pem", &String::from_utf8_lossy(&self.cert_pem))
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// How far in the past every certificate starts.
const BACKDATE: i64 = 300;
/// The lifetime of a cluster CA certificate.
const CA_LIFETIME: i64 = 2_592_000;
/// The lifetime of server and role certificates (design section 1.3).
pub const LEAF_LIFETIME_SECS: i64 = 604_800;

/// What a certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// A CA that signs end-entity certificates of its own cluster only.
    Ca,
    /// A PostgreSQL server.
    Server,
    /// A database role.
    Client,
}

/// A subject or issuer name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    /// The common name.
    pub cn: String,
    /// The organizational unit: the cluster kind of a server certificate.
    pub ou: Option<String>,
}

/// Everything one certificate of the harness profile states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The serial number, positive, 16 bytes.
    pub serial: Vec<u8>,
    /// The issuer.
    pub issuer: Name,
    /// The subject.
    pub subject: Name,
    /// The first valid second, UTC seconds since the Unix epoch.
    pub not_before: i64,
    /// The last valid second.
    pub not_after: i64,
    /// The subject public key info, DER.
    pub spki_der: Vec<u8>,
    /// The usage.
    pub usage: Usage,
    /// subjectAltName DNS names.
    pub dns_names: Vec<String>,
    /// subjectAltName IP addresses.
    pub ip_addrs: Vec<IpAddr>,
}

/// Maps a harness profile onto the `fstp-pki` certificate template.
/// `issuer_spki_der` is the issuer's subject public key info. Its key
/// identifier becomes the authorityKeyIdentifier, which `fstp-pki`
/// requires on every certificate a CA key signs.
///
/// # Errors
///
/// Refuses a name or a subjectAltName that `fstp-pki` refuses.
pub fn to_spec(p: &Profile, issuer_spki_der: &[u8]) -> Result<CertSpec, CertError> {
    let name = |n: &Name| DistinguishedName {
        common_name: n.cn.clone(),
        organizational_unit: n.ou.clone(),
    };
    Ok(CertSpec {
        serial: p.serial.clone(),
        issuer: name(&p.issuer),
        subject: name(&p.subject),
        validity: Validity {
            not_before: p.not_before,
            not_after: p.not_after,
        },
        spki_der: p.spki_der.clone(),
        issuer_key_id: Some(key_identifier(issuer_spki_der)?),
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

/// The ECDSA secp256r1 key pairs behind the certificates.
///
/// Every key pair comes from `fstp-crypto`. Until its `sig` module exists
/// (lane W1h), [`signer::KeyPair::generate`] refuses, and so does every
/// operation that needs a key.
pub mod signer {
    use super::CertError;

    /// The refusal while the `fstp-crypto` signing module is missing.
    const WAITS: &str = "fstp_crypto::sig ECDSA P-256 key pairs (lane W1h)";

    /// An ECDSA secp256r1 key pair. Its private half never leaves the
    /// test process, except as the PKCS#8 file a server or psql reads.
    pub struct KeyPair {
        _private: (),
    }

    impl KeyPair {
        /// A fresh key pair.
        ///
        /// # Errors
        ///
        /// Refuses until lane W1h lands `fstp_crypto::sig`.
        pub fn generate() -> Result<KeyPair, CertError> {
            Err(CertError::NotImplemented(WAITS))
        }

        /// The subject public key info, DER.
        ///
        /// # Errors
        ///
        /// Refuses until lane W1h lands `fstp_crypto::sig`.
        pub fn spki_der(&self) -> Result<Vec<u8>, CertError> {
            Err(CertError::NotImplemented(WAITS))
        }

        /// The private key as PKCS#8 DER.
        ///
        /// # Errors
        ///
        /// Refuses until lane W1h lands `fstp_crypto::sig`.
        pub fn pkcs8_der(&self) -> Result<Vec<u8>, CertError> {
            Err(CertError::NotImplemented(WAITS))
        }

        /// An ECDSA P-256 SHA-256 signature over `message`, DER.
        ///
        /// # Errors
        ///
        /// Refuses until lane W1h lands `fstp_crypto::sig`.
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CertError> {
            let _ = message;
            Err(CertError::NotImplemented(WAITS))
        }
    }
}

use signer::KeyPair;

/// A test cluster CA: an ECDSA secp256r1 key pair and its self-signed CA
/// certificate. The key never leaves the test process.
pub struct ClusterCa {
    name: String,
    cert_pem: Vec<u8>,
    key: KeyPair,
}

impl fmt::Debug for ClusterCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterCa")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ClusterCa {
    /// Generates a new CA whose subject CN is `name`. Names are 1 to 64
    /// printable ASCII characters.
    ///
    /// # Errors
    ///
    /// Refuses a name outside that grammar. Refuses while `fstp-crypto`
    /// has no signing module or `fstp-pki` refuses.
    pub fn generate(name: &str) -> Result<ClusterCa, CertError> {
        if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(CertError::InvalidName(name.to_owned()));
        }
        let key = KeyPair::generate()?;
        let now = now()?;
        let me = Name {
            cn: name.to_owned(),
            ou: None,
        };
        let profile = Profile {
            serial: serial()?,
            issuer: me.clone(),
            subject: me,
            not_before: now.saturating_sub(BACKDATE),
            not_after: now.saturating_add(CA_LIFETIME),
            spki_der: key.spki_der()?,
            usage: Usage::Ca,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
        };
        let der = build(&profile, &key)?;
        Ok(ClusterCa {
            name: name.to_owned(),
            cert_pem: cert_pem(&der)?,
            key,
        })
    }

    /// The CA's name, its subject CN.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The CA certificate (PEM). A server started with this CA trusts only
    /// client certificates it signed.
    #[must_use]
    pub fn cert_pem(&self) -> &[u8] {
        &self.cert_pem
    }

    /// Issues a server certificate for `127.0.0.1` and `localhost`, with
    /// `ou` as the subject OU (the cluster kind, design section 1.3). OUs
    /// are 1 to 32 lowercase ASCII letters.
    ///
    /// # Errors
    ///
    /// Refuses an OU outside that grammar. Refuses while `fstp-crypto` has
    /// no signing module or `fstp-pki` refuses.
    pub fn issue_server(&self, ou: &str) -> Result<IssuedCert, CertError> {
        if ou.is_empty() || ou.len() > 32 || !ou.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(CertError::InvalidName(ou.to_owned()));
        }
        self.issue(
            Name {
                cn: "127.0.0.1".to_owned(),
                ou: Some(ou.to_owned()),
            },
            Usage::Server,
            vec!["localhost".to_owned()],
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
    }

    /// Issues a client certificate whose CN is `role`, with a fresh key
    /// pair and a 7-day lifetime (design section 1.3). Role names follow
    /// `^[a-z_][a-z0-9_]{0,62}$`.
    ///
    /// # Errors
    ///
    /// Refuses a role outside that grammar. Refuses while `fstp-crypto`
    /// has no signing module or `fstp-pki` refuses.
    pub fn issue_role(&self, role: &str) -> Result<IssuedCert, CertError> {
        if !is_identifier(role) {
            return Err(CertError::InvalidName(role.to_owned()));
        }
        self.issue(
            Name {
                cn: role.to_owned(),
                ou: None,
            },
            Usage::Client,
            Vec::new(),
            Vec::new(),
        )
    }

    fn issue(
        &self,
        subject: Name,
        usage: Usage,
        dns_names: Vec<String>,
        ip_addrs: Vec<IpAddr>,
    ) -> Result<IssuedCert, CertError> {
        let key = KeyPair::generate()?;
        let not_before = now()?.saturating_sub(BACKDATE);
        let profile = Profile {
            serial: serial()?,
            issuer: Name {
                cn: self.name.clone(),
                ou: None,
            },
            subject,
            not_before,
            // RFC 5280: both ends are valid, so the last second is
            // LEAF_LIFETIME_SECS - 1 after the first (fstp_pki::CLIENT_MAX_LIFETIME).
            not_after: not_before.saturating_add(LEAF_LIFETIME_SECS - 1),
            spki_der: key.spki_der()?,
            usage,
            dns_names,
            ip_addrs,
        };
        let der = build(&profile, &self.key)?;
        Ok(IssuedCert {
            cert_pem: cert_pem(&der)?,
            key_pem: pem_block("PRIVATE KEY", &key.pkcs8_der()?),
        })
    }
}

/// Whether `name` follows `^[a-z_][a-z0-9_]{0,62}$`, the harness grammar
/// for role and database names. Such a name needs no quoting in SQL or
/// `pg_hba.conf`, and stays under PostgreSQL's 63-byte limit.
#[must_use]
pub fn is_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= 63
        && (first.is_ascii_lowercase() || *first == b'_')
        && rest
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Builds and signs the certificate `p` describes. `issuer` signs it.
fn build(p: &Profile, issuer: &KeyPair) -> Result<Vec<u8>, CertError> {
    let spec = to_spec(p, &issuer.spki_der()?)?;
    let t = tbs(&spec)?;
    let signature = issuer.sign(t.as_der())?;
    Ok(assemble(&t, &signature)?)
}

fn cert_pem(der: &[u8]) -> Result<Vec<u8>, CertError> {
    Ok(encode(PemLabel::Certificate, der)?.into_bytes())
}

/// The current time in UTC seconds.
fn now() -> Result<i64, CertError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CertError::Environment(format!("clock before 1970: {e}")))?
        .as_secs();
    i64::try_from(secs).map_err(|_| CertError::Environment("clock out of range".to_owned()))
}

/// A positive 16-byte serial from the operating system's random source.
fn serial() -> Result<Vec<u8>, CertError> {
    let mut bytes = crate::server::random_bytes(16)
        .map_err(|e| CertError::Environment(format!("random serial: {e}")))?;
    if let Some(first) = bytes.first_mut() {
        // Positive, and no leading zero byte in DER.
        *first = (*first & 0x7f) | 0x40;
    }
    Ok(bytes)
}

/// One PEM block with `label`, lines of 64 characters, final newline.
fn pem_block(label: &str, der: &[u8]) -> Vec<u8> {
    let body = base64(der);
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in body.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}

/// Standard base64 with padding. Encoding only.
fn base64(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0).wrapping_shl(16) | u32::from(b1).wrapping_shl(8) | u32::from(b2);
        let chars = chunk.len().saturating_add(1);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i < chars {
                let index = usize::try_from(n.wrapping_shr(shift) & 0x3f).unwrap_or(0);
                out.push(ALPHABET.get(index).copied().unwrap_or(b'A'));
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, want) in [
            (&b""[..], &b""[..]),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ] {
            assert_eq!(base64(input), want.to_vec());
        }
    }

    #[test]
    fn pem_block_wraps_at_64_characters() {
        let pem = pem_block("PRIVATE KEY", &[0u8; 60]);
        let text = String::from_utf8(pem).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN PRIVATE KEY-----"));
        assert_eq!(lines.get(1).map(|l| l.len()), Some(64));
        assert_eq!(lines.get(2).map(|l| l.len()), Some(16));
        assert_eq!(lines.last(), Some(&"-----END PRIVATE KEY-----"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn identifier_grammar() {
        for ok in ["a", "_a", "c_0123_writer", &"x".repeat(63)] {
            assert!(is_identifier(ok), "{ok}");
        }
        for bad in ["", "A", "1a", "a-b", "a b", "a\"b", &"x".repeat(64)] {
            assert!(!is_identifier(bad), "{bad}");
        }
    }

    #[test]
    fn ca_name_grammar_is_checked_first() {
        // A CA cannot be generated while the seams stand, so the grammar is
        // checked through the error a bad name gives before any key work.
        assert!(matches!(
            ClusterCa::generate(""),
            Err(CertError::InvalidName(_))
        ));
        assert!(matches!(
            ClusterCa::generate("bad\nname"),
            Err(CertError::InvalidName(_))
        ));
    }
}

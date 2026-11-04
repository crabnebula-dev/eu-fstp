//! Shared helpers for the `fstp-cp-proto` integration tests (lane W2h,
//! test author): base64, generated values of each closed grammar, the DER
//! reference for proof-of-possession signatures, and the refusal check.
//!
//! Every generator builds a value from its specification text, never from
//! the production codec. ADR-011 gives the SCRAM verifier form. The
//! fstp-pki module docs give the proof-of-possession signature form. ADR-010
//! gives the composite signature layout.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fmt::Debug;

use fstp_cp_proto::ProtoError;
use fstp_prop::Gen;

/// The standard base64 alphabet of RFC 4648 section 4.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, the one spelling of each byte string.
pub fn b64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let digits = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, d) in digits.iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(B64[*d as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64, ignoring nothing. Test vectors only.
pub fn unb64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|x| *x == c).unwrap_or_else(|| {
            panic!("not base64: {c:#x}");
        });
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Ok when `r` is a refusal by a real check. A `NotImplemented` error is a
/// stub, not a refusal, so it fails here.
pub fn refused<T: Debug>(what: &str, r: Result<T, ProtoError>) -> Result<(), String> {
    #[allow(
        unreachable_patterns,
        reason = "lane W2h adds the refusal variants of ProtoError"
    )]
    match r {
        Ok(v) => Err(format!("{what} was accepted as {v:?}")),
        Err(ProtoError::NotImplemented(op)) => Err(format!("{op} is NotImplemented ({what})")),
        Err(_) => Ok(()),
    }
}

/// The value of `r`, or why it is not accepted.
pub fn accepted<T>(what: &str, r: Result<T, ProtoError>) -> Result<T, String> {
    r.map_err(|e| format!("{what} was refused: {e:?}"))
}

/// Whether `e` is the W0 stub error.
pub fn is_stub(e: &ProtoError) -> bool {
    matches!(e, ProtoError::NotImplemented(_))
}

// ---------------------------------------------------------------------------
// SCRAM verifiers (ADR-011 "DDL identifier grammar").

/// The parts of a SCRAM-SHA-256 verifier in the form ADR-011 gives:
/// `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, with base64
/// fields. StoredKey and ServerKey are SHA-256 outputs, so 32 bytes each.
#[derive(Clone, Debug)]
pub struct Verifier {
    /// The iteration count, as decimal text.
    pub iterations: String,
    /// The salt field.
    pub salt: String,
    /// The StoredKey field.
    pub stored_key: String,
    /// The ServerKey field.
    pub server_key: String,
}

impl Verifier {
    /// The verifier text.
    pub fn text(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations, self.salt, self.stored_key, self.server_key
        )
    }
}

/// A well-formed verifier: 4096 to 1 000 000 iterations, a 16-byte salt
/// as PostgreSQL draws it, and two 32-byte keys.
pub fn verifier(g: &mut Gen) -> Verifier {
    let iterations = g.u32_in(4096..=1_000_000);
    let salt = g.bytes(16..=16);
    let stored = g.bytes(32..=32);
    let server = g.bytes(32..=32);
    Verifier {
        iterations: iterations.to_string(),
        salt: b64(&salt),
        stored_key: b64(&stored),
        server_key: b64(&server),
    }
}

// ---------------------------------------------------------------------------
// Proof-of-possession signatures: ASN.1 DER ECDSA P-256 (fstp-pki `pop`).

/// The order `n` of the P-256 group, big-endian (SEC 2 section 2.4.2).
pub const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// What the reference says of a candidate signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerClass {
    /// A DER `ECDSA-Sig-Value` with `r` and `s` in 1 to n - 1.
    Valid,
    /// Not DER, or not two positive INTEGERs of at most 32 magnitude bytes.
    Invalid,
    /// DER with a zero or an `r` or `s` of at least n. The grammar may
    /// refuse it or leave it to the verifier, so no test pins it.
    Unpinned,
}

/// One DER INTEGER at the start of `b`: its magnitude and the rest.
fn der_integer(b: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = usize::from(len);
    if tag != 0x02 || !(1..=33).contains(&len) || rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    if content[0] & 0x80 != 0 {
        return None;
    }
    if content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
        return None;
    }
    let magnitude = if content[0] == 0 && content.len() > 1 {
        &content[1..]
    } else {
        content
    };
    if magnitude.len() > 32 {
        return None;
    }
    Some((magnitude.to_vec(), rest))
}

/// Whether the big-endian `m` is zero or at least n.
fn out_of_range(m: &[u8]) -> bool {
    let mut padded = [0u8; 32];
    padded[32 - m.len()..].copy_from_slice(m);
    padded.iter().all(|b| *b == 0) || padded >= P256_N
}

/// The DER reference for a proof-of-possession signature: `SEQUENCE {
/// INTEGER r, INTEGER s }`, short-form lengths only, each INTEGER minimal
/// and positive, nothing after it. Its length is therefore 8 to 72 bytes,
/// the bounds fstp-pki checks.
pub fn der_class(b: &[u8]) -> DerClass {
    let Some((&tag, rest)) = b.split_first() else {
        return DerClass::Invalid;
    };
    let Some((&len, body)) = rest.split_first() else {
        return DerClass::Invalid;
    };
    if tag != 0x30 || len >= 0x80 || usize::from(len) != body.len() {
        return DerClass::Invalid;
    }
    let Some((r, rest)) = der_integer(body) else {
        return DerClass::Invalid;
    };
    let Some((s, rest)) = der_integer(rest) else {
        return DerClass::Invalid;
    };
    if !rest.is_empty() {
        return DerClass::Invalid;
    }
    if out_of_range(&r) || out_of_range(&s) {
        DerClass::Unpinned
    } else {
        DerClass::Valid
    }
}

/// A raw `r || s` pair in 1 to n - 1, with leading zero bytes as often as
/// the generator picks them, so every INTEGER length occurs.
pub fn raw_signature(g: &mut Gen) -> [u8; 64] {
    let mut out = [0u8; 64];
    for half in out.chunks_mut(32) {
        let zeros = g.usize_in(0..=31);
        for (i, b) in half.iter_mut().enumerate() {
            *b = if i < zeros { 0 } else { g.u8() };
        }
        // Below n: n starts with 0xff, so a first byte of at most 0xfe is
        // enough. Not zero: the last byte is at least one.
        half[0] = half[0].min(0xfe);
        if half.iter().all(|b| *b == 0) {
            half[31] = 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Certificates from the fstp-pki writer.

/// What [`certificate_with`] builds.
#[derive(Clone, Debug)]
pub struct CertParams {
    /// A self-signed CA when true, otherwise a client certificate that a
    /// fresh CA signs.
    pub ca: bool,
    /// The CA's common name.
    pub ca_name: String,
    /// The client's common name.
    pub leaf_name: String,
    /// The serial magnitude, positive, at most 19 bytes.
    pub serial: Vec<u8>,
    /// The first second of validity.
    pub not_before: i64,
}

/// A certificate the in-house writer builds from `p`, DER, signed with
/// ECDSA P-256 by a fresh key.
pub fn certificate_with(p: &CertParams) -> Vec<u8> {
    use fstp_crypto::sig::EcdsaP256KeyPair;
    use fstp_pki::cert::{self, key_identifier};
    use fstp_pki::{CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity};

    let ca_key = EcdsaP256KeyPair::generate().unwrap();
    let ca_spki = ca_key.spki_der().unwrap();
    let ca_name = DistinguishedName::new(&p.ca_name);
    let spec = if p.ca {
        CertSpec {
            serial: p.serial.clone(),
            issuer: ca_name.clone(),
            subject: ca_name,
            validity: Validity {
                not_before: p.not_before,
                not_after: p.not_before + 365 * 86_400,
            },
            spki_der: ca_spki,
            issuer_key_id: None,
            kind: CertKind::Ca,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        }
    } else {
        let leaf = EcdsaP256KeyPair::generate().unwrap();
        CertSpec {
            serial: p.serial.clone(),
            issuer: ca_name,
            subject: DistinguishedName::new(&p.leaf_name),
            validity: Validity {
                not_before: p.not_before,
                not_after: p.not_before + 86_400,
            },
            spki_der: leaf.spki_der().unwrap(),
            issuer_key_id: Some(key_identifier(&ca_spki).unwrap()),
            kind: CertKind::Client,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        }
    };
    let tbs = cert::tbs(&spec).unwrap();
    let sig = ca_key.sign(tbs.as_der()).unwrap();
    cert::assemble(&tbs, &sig).unwrap()
}

/// A generated certificate: a self-signed CA or a client certificate,
/// with generated names, serial and validity.
pub fn certificate(g: &mut Gen) -> Vec<u8> {
    let name = |g: &mut Gen| -> String {
        let len = g.usize_in(1..=24);
        (0..len)
            .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz0123456789_")))
            .collect()
    };
    let mut serial = g.bytes(1..=19);
    serial[0] = serial[0].clamp(1, 0x7f);
    let p = CertParams {
        ca: g.bool(),
        ca_name: name(g),
        leaf_name: name(g),
        serial,
        not_before: g.i64_in(1_600_000_000..=1_900_000_000),
    };
    certificate_with(&p)
}

// ---------------------------------------------------------------------------
// The draft 19 composite test vector (ADR-010 "Composite encoding").

/// The bytes of field `name` of the Appendix E vector that lane W1h copied
/// into `crates/fstp-crypto/tests/data`.
pub fn composite_vector_field(name: &str) -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fstp-crypto/tests/data/composite_mldsa65_ed25519_draft19.json"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let key = format!("\"{name}\": \"");
    let start = text.find(&key).unwrap() + key.len();
    let len = text[start..].find('"').unwrap();
    unb64(&text[start..start + len])
}

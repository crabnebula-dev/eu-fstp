//! DKIM signatures (RFC 6376, RFC 8463), M6 design section 5.3.
//!
//! - Canonicalisation is relaxed/relaxed, written here.
//! - `rsa-sha256` and `ed25519-sha256` signatures come from aws-lc-rs
//!   through `fstp-crypto` (ADR-001, "DKIM"). Nothing here is a primitive.
//! - Signing is behind a flag: [`crate::compose`] signs only with the
//!   signers in [`crate::MailConfig::dkim`], and the default is none.
//! - The per-tenant key is held in cell custody (ADR-004). This module
//!   takes a loaded key; the custody wiring belongs to lane L6-EGR.
//! - [`verify`] checks a signature this module wrote. Tests, the demo
//!   sink and the `dkim_verify` fuzz target use it.

use fstp_crypto::sig::{
    Ed25519SigningKey, RsaPkcs1Sha256KeyPair, ed25519_verify, rsa_pkcs1_sha256_verify_spki,
};

use crate::MailError;
use crate::encode::{base64_decode, base64_encode};
use crate::mime::{HeaderField, parse_headers};

/// The header fields every signature covers, when present.
pub const SIGNED_HEADERS: [&str; 10] = [
    "from",
    "to",
    "subject",
    "date",
    "message-id",
    "mime-version",
    "content-type",
    "auto-submitted",
    "x-fstp-event",
    "x-fstp-template",
];

/// The most DKIM-Signature fields [`verify`] looks at.
const MAX_SIGNATURES: usize = 8;

/// A tenant's DKIM private key.
pub enum DkimKey {
    /// `rsa-sha256`, for receivers that need it (ADR-001).
    Rsa(RsaPkcs1Sha256KeyPair),
    /// `ed25519-sha256` (RFC 8463).
    Ed25519(Ed25519SigningKey),
}

impl DkimKey {
    const fn algorithm(&self) -> &'static str {
        match self {
            DkimKey::Rsa(_) => "rsa-sha256",
            DkimKey::Ed25519(_) => "ed25519-sha256",
        }
    }
}

/// A DKIM public key, as the DNS record holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkimPublicKey {
    /// An RSA key as a DER SubjectPublicKeyInfo.
    Rsa(Vec<u8>),
    /// An Ed25519 key, 32 bytes.
    Ed25519([u8; 32]),
}

/// A signing domain, a selector and a key.
pub struct DkimSigner {
    domain: String,
    selector: String,
    key: DkimKey,
}

fn dns_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl DkimSigner {
    /// A signer for `domain` (the `d=` tag) and `selector` (`s=`).
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidDkimName`] unless both are DNS names.
    pub fn new(domain: &str, selector: &str, key: DkimKey) -> Result<DkimSigner, MailError> {
        if !dns_name_ok(domain) || !dns_name_ok(selector) {
            return Err(MailError::InvalidDkimName);
        }
        Ok(DkimSigner {
            domain: domain.to_ascii_lowercase(),
            selector: selector.to_ascii_lowercase(),
            key,
        })
    }

    /// The key.
    pub fn key(&self) -> &DkimKey {
        &self.key
    }

    /// The public key.
    ///
    /// # Errors
    ///
    /// [`MailError::Crypto`] when the key cannot be encoded.
    pub fn public_key(&self) -> Result<DkimPublicKey, MailError> {
        Ok(match &self.key {
            DkimKey::Rsa(k) => DkimPublicKey::Rsa(k.spki_der().map_err(|_| MailError::Crypto)?),
            DkimKey::Ed25519(k) => DkimPublicKey::Ed25519(k.public_key()),
        })
    }

    /// The DNS name of the key record, `selector._domainkey.domain`.
    pub fn record_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }

    /// The TXT record the tenant publishes at [`DkimSigner::record_name`].
    ///
    /// # Errors
    ///
    /// [`MailError::Crypto`] when the key cannot be encoded.
    pub fn dns_txt(&self) -> Result<String, MailError> {
        Ok(match self.public_key()? {
            DkimPublicKey::Rsa(spki) => format!("v=DKIM1; k=rsa; p={}", base64_encode(&spki)),
            DkimPublicKey::Ed25519(pk) => format!("v=DKIM1; k=ed25519; p={}", base64_encode(&pk)),
        })
    }
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Relaxed header canonicalisation (RFC 6376 section 3.4.2): the name in
/// lower case, the value unfolded, runs of white space as one space, and
/// no white space at either end of the value or before the colon. No CRLF
/// is appended.
pub fn canon_header_relaxed(name: &str, raw_value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = name
        .trim_end_matches([' ', '\t'])
        .to_ascii_lowercase()
        .into_bytes();
    out.push(b':');
    let mut pending_space = false;
    let mut started = false;
    for &b in raw_value {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        if is_wsp(b) {
            pending_space = started;
            continue;
        }
        if pending_space {
            out.push(b' ');
            pending_space = false;
        }
        out.push(b);
        started = true;
    }
    out
}

/// Relaxed body canonicalisation (RFC 6376 section 3.4.4): white space at
/// line ends removed, other runs as one space, empty lines at the end
/// removed, and a non-empty body ended with CRLF.
pub fn canon_body_relaxed(body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(rest.get(..i).unwrap_or_default());
        rest = rest.get(i.saturating_add(2)..).unwrap_or_default();
    }
    if !rest.is_empty() {
        lines.push(rest);
    }
    let mut canon: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|l| {
            let mut out = Vec::with_capacity(l.len());
            let mut pending = false;
            for &b in l {
                if is_wsp(b) {
                    pending = true;
                } else {
                    if pending {
                        out.push(b' ');
                        pending = false;
                    }
                    out.push(b);
                }
            }
            out
        })
        .collect();
    while canon.last().is_some_and(Vec::is_empty) {
        canon.pop();
    }
    let mut out = Vec::with_capacity(body.len());
    for l in canon {
        out.extend_from_slice(&l);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// The header hash input for the names in `h`, each field chosen from
/// the bottom up (RFC 6376 section 5.4.2), each followed by CRLF.
fn header_input(fields: &[HeaderField], h: &[String]) -> Vec<u8> {
    let mut used: Vec<(String, usize)> = Vec::new();
    let mut out = Vec::new();
    for name in h {
        let n = used
            .iter_mut()
            .find(|(k, _)| k == name)
            .map(|(_, c)| {
                *c = c.saturating_add(1);
                *c
            })
            .unwrap_or_else(|| {
                used.push((name.clone(), 1));
                1
            });
        if let Some(f) = fields
            .iter()
            .rev()
            .filter(|f| f.name.eq_ignore_ascii_case(name))
            .nth(n.saturating_sub(1))
        {
            out.extend_from_slice(&canon_header_relaxed(&f.name, &f.raw_value));
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

fn split_message(raw: &[u8]) -> Result<(Vec<HeaderField>, &[u8]), MailError> {
    let (fields, off) = parse_headers(raw)?;
    Ok((fields, raw.get(off..).unwrap_or_default()))
}

/// Signs `raw` with `signer` and returns it with a `DKIM-Signature` field
/// in front. RSA PKCS#1 v1.5 and Ed25519 are deterministic, so equal input
/// gives equal output (I-26).
///
/// # Errors
///
/// [`MailError::Malformed`] when `raw` has no well-formed header, and
/// [`MailError::Crypto`] when signing fails.
pub fn sign(raw: &[u8], signer: &DkimSigner) -> Result<Vec<u8>, MailError> {
    let (fields, body) = split_message(raw)?;
    let bh = base64_encode(&fstp_crypto::sha256(&canon_body_relaxed(body)));
    let h: Vec<String> = SIGNED_HEADERS
        .iter()
        .filter(|n| fields.iter().any(|f| f.name.eq_ignore_ascii_case(n)))
        .map(|n| (*n).to_owned())
        .collect();
    let value = format!(
        " v=1; a={}; c=relaxed/relaxed; d={}; s={};\r\n\th={};\r\n\tbh={bh};\r\n\tb=",
        signer.key.algorithm(),
        signer.domain,
        signer.selector,
        h.join(":"),
    );
    let mut input = header_input(&fields, &h);
    input.extend_from_slice(&canon_header_relaxed("DKIM-Signature", value.as_bytes()));
    let sig = match &signer.key {
        DkimKey::Rsa(k) => k.sign(&input).map_err(|_| MailError::Crypto)?,
        DkimKey::Ed25519(k) => k
            .sign(&fstp_crypto::sha256(&input))
            .map_err(|_| MailError::Crypto)?
            .to_vec(),
    };
    let b64 = base64_encode(&sig);
    let folded: Vec<String> = b64
        .as_bytes()
        .chunks(72)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let mut out = format!("DKIM-Signature:{value}{}\r\n", folded.join("\r\n\t")).into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

/// The tags of a signature value. A repeated tag is refused.
fn tags(value: &[u8]) -> Result<Vec<(String, String)>, MailError> {
    let text = std::str::from_utf8(value).map_err(|_| MailError::Malformed("dkim tags"))?;
    let mut out: Vec<(String, String)> = Vec::new();
    for seg in text.split(';') {
        if seg.trim().is_empty() {
            continue;
        }
        let (k, v) = seg
            .split_once('=')
            .ok_or(MailError::Malformed("dkim tag"))?;
        let k = k.trim().to_owned();
        if out.iter().any(|(x, _)| *x == k) {
            return Err(MailError::Malformed("dkim tag repeated"));
        }
        out.push((k, v.chars().filter(|c| !c.is_whitespace()).collect()));
    }
    Ok(out)
}

/// `raw_value` with the value of its `b=` tag removed, white space
/// included (RFC 6376 section 3.7).
fn strip_b(raw_value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_value.len());
    for (i, seg) in raw_value.split(|b| *b == b';').enumerate() {
        if i > 0 {
            out.push(b';');
        }
        let name_is_b = seg.split(|b| *b == b'=').next().is_some_and(|n| {
            let n: Vec<u8> = n
                .iter()
                .copied()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                .collect();
            n == b"b"
        });
        match seg.iter().position(|b| *b == b'=') {
            Some(eq) if name_is_b => out.extend_from_slice(seg.get(..=eq).unwrap_or_default()),
            _ => out.extend_from_slice(seg),
        }
    }
    out
}

fn check_one(
    fields: &[HeaderField],
    body: &[u8],
    sig_field: &HeaderField,
    t: &[(String, String)],
    key: &DkimPublicKey,
) -> Result<(), MailError> {
    let tag = |n: &str| t.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let want_alg = match key {
        DkimPublicKey::Rsa(_) => "rsa-sha256",
        DkimPublicKey::Ed25519(_) => "ed25519-sha256",
    };
    if tag("v") != Some("1") || tag("c") != Some("relaxed/relaxed") || tag("a") != Some(want_alg) {
        return Err(MailError::DkimUnsupported);
    }
    let h: Vec<String> = tag("h")
        .ok_or(MailError::DkimUnsupported)?
        .split(':')
        .map(str::to_ascii_lowercase)
        .collect();
    if !h.iter().any(|n| n == "from") {
        return Err(MailError::DkimUnsupported);
    }
    let bh = base64_decode(tag("bh").ok_or(MailError::DkimUnsupported)?.as_bytes())?;
    if bh != fstp_crypto::sha256(&canon_body_relaxed(body)) {
        return Err(MailError::DkimBodyHash);
    }
    let sig = base64_decode(tag("b").ok_or(MailError::DkimUnsupported)?.as_bytes())?;
    let mut input = header_input(fields, &h);
    input.extend_from_slice(&canon_header_relaxed(
        &sig_field.name,
        &strip_b(&sig_field.raw_value),
    ));
    let ok = match key {
        DkimPublicKey::Rsa(spki) => rsa_pkcs1_sha256_verify_spki(spki, &input, &sig),
        DkimPublicKey::Ed25519(pk) => ed25519_verify(pk, &fstp_crypto::sha256(&input), &sig),
    };
    ok.map_err(|_| MailError::DkimSignature)
}

/// Verifies the signature of `domain` and `selector` on `raw` under `key`.
/// It accepts only what [`sign`] writes: version 1, relaxed/relaxed, the
/// algorithm of `key`, and `From` among the signed fields.
///
/// # Errors
///
/// [`MailError::DkimNoSignature`] when no signature names `domain` and
/// `selector`. Otherwise the error of the last matching signature:
/// [`MailError::DkimUnsupported`], [`MailError::DkimBodyHash`],
/// [`MailError::DkimSignature`] or [`MailError::Malformed`].
pub fn verify(
    raw: &[u8],
    domain: &str,
    selector: &str,
    key: &DkimPublicKey,
) -> Result<(), MailError> {
    let (fields, body) = split_message(raw)?;
    let mut last = MailError::DkimNoSignature;
    for f in fields
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case("DKIM-Signature"))
        .take(MAX_SIGNATURES)
    {
        let t = tags(&f.raw_value)?;
        let d = t.iter().find(|(k, _)| k == "d").map(|(_, v)| v.as_str());
        let s = t.iter().find(|(k, _)| k == "s").map(|(_, v)| v.as_str());
        let named = d.is_some_and(|d| d.eq_ignore_ascii_case(domain))
            && s.is_some_and(|s| s.eq_ignore_ascii_case(selector));
        if !named {
            continue;
        }
        match check_one(&fields, body, f, &t, key) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

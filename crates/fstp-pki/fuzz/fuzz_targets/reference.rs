//! The reference writer of `cert_build_roundtrip`. It restates the rules of
//! `crates/fstp-pki/tests/common` for `CertSpec`, and writes only.
//!
//! The one value it takes from `fstp-pki` is the key identifier, since the
//! fuzz crate has no hash. `tests/cert_extensions.rs` checks that value
//! against an aws-lc-rs SHA-256.

use std::net::IpAddr;

use fstp_pki::cert::{CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, key_identifier};

/// 1950-01-01T00:00:00Z.
pub const MIN_TIME: i64 = -631_152_000;
/// 9999-12-31T23:59:59Z.
pub const MAX_TIME: i64 = 253_402_300_799;
/// The number of encodable instants.
pub const SPAN: i64 = MAX_TIME - MIN_TIME + 1;
/// 2050-01-01T00:00:00Z.
const GENERALIZED_FROM: i64 = 2_524_608_000;
/// The largest `not_after - not_before` of a client certificate: valid for
/// 7 days with both ends counted (RFC 5280 section 4.1.2.5).
pub const CLIENT_MAX_SPAN: i64 = 7 * 86_400 - 1;

/// The cluster kind markers a server OU may hold (design section 4.1).
pub const CLUSTER_KINDS: [&str; 4] = ["application", "vault", "control", "witness"];

/// The SPKI of the P-256 base point, a fixed synthetic public key.
pub const P256_G_SPKI: [u8; 91] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1,
    0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
    0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe,
    0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
    0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

const ALG_ECDSA_SHA256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_OU: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0b];
const OID_BC: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const OID_KU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_SKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0e];
const OID_AKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x23];
const OID_KP_SERVER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_KP_CLIENT: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let mut out = vec![0x80 | (be.len() - first) as u8];
    out.extend_from_slice(&be[first..]);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn value_fits(v: &str) -> bool {
    (1..=64).contains(&v.chars().count())
}

fn rdn(oid: &[u8], value: &str) -> Vec<u8> {
    tlv(0x31, &seq(&[oid, &tlv(0x0c, value.as_bytes())]))
}

fn name(dn: &DistinguishedName) -> Option<Vec<u8>> {
    if !value_fits(&dn.common_name) {
        return None;
    }
    let mut rdns = Vec::new();
    if let Some(ou) = &dn.organizational_unit {
        if !value_fits(ou) {
            return None;
        }
        rdns.extend(rdn(OID_OU, ou));
    }
    rdns.extend(rdn(OID_CN, &dn.common_name));
    Some(tlv(0x30, &rdns))
}

fn serial(magnitude: &[u8]) -> Option<Vec<u8>> {
    let first = magnitude.iter().position(|b| *b != 0)?;
    let tail = &magnitude[first..];
    let mut out = Vec::new();
    if tail[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(tail);
    (out.len() <= 20).then(|| tlv(0x02, &out))
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn time(t: i64) -> Option<Vec<u8>> {
    if !(MIN_TIME..=MAX_TIME).contains(&t) {
        return None;
    }
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    let (hh, mm, ss) = (s / 3600, (s / 60) % 60, s % 60);
    Some(if t < GENERALIZED_FROM {
        let text = format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100);
        tlv(0x17, text.as_bytes())
    } else {
        let text = format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z");
        tlv(0x18, text.as_bytes())
    })
}

/// A lowercase LDH host name whose last label is not all digits (RFC 1035,
/// RFC 1123 section 2.1, RFC 5280 section 4.2.1.6).
fn dns_name_ok(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let each = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    });
    let last = labels.last().copied().unwrap_or("");
    each && !last.bytes().all(|c| c.is_ascii_digit())
}

/// The reference encoding of every TBS field up to the SPKI, or `None`
/// when the reference refuses one of those fields.
pub fn tbs_prefix(spec: &CertSpec) -> Option<Vec<u8>> {
    let v = &spec.validity;
    if v.not_before > v.not_after {
        return None;
    }
    let alg = match spec.algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => ALG_ECDSA_SHA256,
    };
    let mut out = vec![0xa0, 0x03, 0x02, 0x01, 0x02];
    out.extend(serial(&spec.serial)?);
    out.extend_from_slice(alg);
    out.extend(name(&spec.issuer)?);
    out.extend(seq(&[&time(v.not_before)?, &time(v.not_after)?]));
    out.extend(name(&spec.subject)?);
    out.extend_from_slice(&spec.spki_der);
    Some(out)
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let value = tlv(0x04, value);
    if critical {
        seq(&[oid, &[0x01, 0x01, 0xff], &value])
    } else {
        seq(&[oid, &value])
    }
}

/// The reference `[3]` extensions field, or `None` when the reference
/// refuses the spec for a reason outside the prefix.
fn extensions(spec: &CertSpec) -> Option<Vec<u8>> {
    let has_san = !spec.dns_names.is_empty() || !spec.ip_addrs.is_empty();
    let mut exts = Vec::new();
    match spec.kind {
        CertKind::Ca => {
            if has_san {
                return None;
            }
            exts.extend(extension(
                OID_BC,
                true,
                &seq(&[&[0x01, 0x01, 0xff], &[0x02, 0x01, 0x00]]),
            ));
            exts.extend(extension(OID_KU, true, &[0x03, 0x02, 0x02, 0x04]));
        }
        CertKind::Server | CertKind::Client => {
            let purpose = if spec.kind == CertKind::Server {
                OID_KP_SERVER
            } else {
                OID_KP_CLIENT
            };
            exts.extend(extension(OID_BC, true, &seq(&[])));
            exts.extend(extension(OID_KU, true, &[0x03, 0x02, 0x07, 0x80]));
            exts.extend(extension(OID_EKU, false, &seq(&[purpose])));
            if has_san {
                let mut names = Vec::new();
                for d in &spec.dns_names {
                    if !dns_name_ok(d) {
                        return None;
                    }
                    names.extend(tlv(0x82, d.as_bytes()));
                }
                for ip in &spec.ip_addrs {
                    match ip {
                        IpAddr::V4(v4) => names.extend(tlv(0x87, &v4.octets())),
                        IpAddr::V6(v6) => names.extend(tlv(0x87, &v6.octets())),
                    }
                }
                exts.extend(extension(OID_SAN, false, &tlv(0x30, &names)));
            }
        }
    }
    let ski = key_identifier(&spec.spki_der).ok()?;
    exts.extend(extension(OID_SKI, false, &tlv(0x04, &ski)));
    match spec.issuer_key_id {
        Some(aki) => exts.extend(extension(OID_AKI, false, &tlv(0x30, &tlv(0x80, &aki)))),
        // RFC 5280 section 4.2.1.1: only a self-signed certificate omits
        // it, and only a CA is self-signed in this profile.
        None if spec.kind == CertKind::Ca && spec.issuer == spec.subject => {}
        None => return None,
    }
    Some(tlv(0xa3, &tlv(0x30, &exts)))
}

/// The reference TBSCertificate for `spec`, or `None` when the reference
/// refuses it. This predicts every refusal of `fstp_pki::cert::tbs`.
pub fn tbs(spec: &CertSpec) -> Option<Vec<u8>> {
    let mut content = tbs_prefix(spec)?;
    let v = &spec.validity;
    if spec.kind == CertKind::Client && v.not_after - v.not_before > CLIENT_MAX_SPAN {
        return None;
    }
    let server_ou = match (&spec.kind, &spec.subject.organizational_unit) {
        (CertKind::Server, Some(ou)) => CLUSTER_KINDS.contains(&ou.as_str()),
        _ => true,
    };
    if !server_ou {
        return None;
    }
    let p256 = spec.spki_der.len() == 91 && spec.spki_der[..27] == P256_G_SPKI[..27];
    if !p256 {
        return None;
    }
    content.extend(extensions(spec)?);
    Some(tlv(0x30, &content))
}

/// The Certificate SEQUENCE for `tbs` and an ECDSA SHA-256 `signature`.
pub fn certificate(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(signature);
    tlv(0x30, &[tbs, ALG_ECDSA_SHA256, &tlv(0x03, &bits)].concat())
}

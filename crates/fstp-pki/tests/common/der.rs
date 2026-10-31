//! An independent DER writer for the reference certificate profile.
//!
//! It writes only. Nothing here reads DER, so the tests hold no in-house
//! parser. Each function restates one ASN.1 rule of RFC 5280 or X.690, so a
//! test can say which bytes a correct writer must produce.

/// The DER length octets for a content of `n` bytes (X.690 8.1.3).
pub(crate) fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let tail = &be[first..];
    let mut out = vec![0x80 | tail.len() as u8];
    out.extend_from_slice(tail);
    out
}

/// One TLV with a single-byte tag.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len(content.len()));
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of already encoded parts.
pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A SET of one already encoded part.
pub(crate) fn set_of_one(part: &[u8]) -> Vec<u8> {
    tlv(0x31, part)
}

/// A BIT STRING with no unused bits.
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(0x03, &content)
}

/// An OCTET STRING.
pub(crate) fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// A UTF8String.
pub(crate) fn utf8_string(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

/// `id-at-commonName` (2.5.4.3), encoded.
pub(crate) const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
/// `id-at-organizationalUnitName` (2.5.4.11), encoded.
pub(crate) const OID_OU: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0b];
/// `id-ce-basicConstraints` (2.5.29.19), encoded.
pub(crate) const OID_BC: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
/// `id-ce-keyUsage` (2.5.29.15), encoded.
pub(crate) const OID_KU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
/// `id-ce-extKeyUsage` (2.5.29.37), encoded.
pub(crate) const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
/// `id-ce-subjectAltName` (2.5.29.17), encoded.
pub(crate) const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
/// `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1), encoded.
pub(crate) const OID_KP_SERVER: &[u8] =
    &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2), encoded.
pub(crate) const OID_KP_CLIENT: &[u8] =
    &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// `ecdsa-with-SHA256` with absent parameters (RFC 5758 section 3.2).
pub(crate) const ALG_ECDSA_SHA256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
/// `id-Ed25519` with absent parameters (RFC 8410 section 3).
pub(crate) const ALG_ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// The X.509 v3 version field: `[0] EXPLICIT INTEGER 2`.
pub(crate) const VERSION_V3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

/// A Name in the reference profile: an optional OU RDN, then the CN RDN.
/// Each RDN holds one attribute, and each value is a UTF8String.
pub(crate) fn name(common_name: &str, organizational_unit: Option<&str>) -> Vec<u8> {
    tlv(0x30, &name_content(common_name, organizational_unit))
}

/// The content of [`name`], without the outer SEQUENCE tag and length, as
/// rustls-webpki returns a subject or issuer.
pub(crate) fn name_content(common_name: &str, organizational_unit: Option<&str>) -> Vec<u8> {
    let mut rdns = Vec::new();
    if let Some(ou) = organizational_unit {
        rdns.extend(set_of_one(&seq(&[OID_OU, &utf8_string(ou)])));
    }
    rdns.extend(set_of_one(&seq(&[OID_CN, &utf8_string(common_name)])));
    rdns
}

/// The content octets of the serial INTEGER for the big-endian magnitude
/// `magnitude`, or `None` when the serial is refused.
///
/// Leading zero bytes are dropped. Zero is refused, since RFC 5280 section
/// 4.1.2.2 requires a positive integer. A high first bit gets one zero byte.
/// More than 20 content octets are refused (RFC 5280 section 4.1.2.2).
pub(crate) fn serial_content(magnitude: &[u8]) -> Option<Vec<u8>> {
    let first = magnitude.iter().position(|b| *b != 0)?;
    let tail = &magnitude[first..];
    let mut out = Vec::with_capacity(tail.len() + 1);
    if tail[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(tail);
    (out.len() <= 20).then_some(out)
}

/// The serial INTEGER TLV, or `None` when the serial is refused.
pub(crate) fn serial(magnitude: &[u8]) -> Option<Vec<u8>> {
    serial_content(magnitude).map(|c| tlv(0x02, &c))
}

/// One Extension: `SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }`. DER omits `critical` when it is false.
pub(crate) fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[oid, &[0x01, 0x01, 0xff], &octet_string(value)])
    } else {
        seq(&[oid, &octet_string(value)])
    }
}

/// basicConstraints of a CA that signs only end-entity certificates:
/// `cA TRUE, pathLenConstraint 0`.
pub(crate) fn basic_constraints_ca() -> Vec<u8> {
    seq(&[&[0x01, 0x01, 0xff], &[0x02, 0x01, 0x00]])
}

/// basicConstraints of an end entity: `cA` takes its default, false, so
/// the SEQUENCE is empty.
pub(crate) fn basic_constraints_leaf() -> Vec<u8> {
    seq(&[])
}

/// keyUsage `keyCertSign` (bit 5) only, as a minimal DER BIT STRING.
pub(crate) fn key_usage_ca() -> Vec<u8> {
    vec![0x03, 0x02, 0x02, 0x04]
}

/// keyUsage `digitalSignature` (bit 0) only, as a minimal DER BIT STRING.
pub(crate) fn key_usage_leaf() -> Vec<u8> {
    vec![0x03, 0x02, 0x07, 0x80]
}

/// extKeyUsage with the one purpose `purpose`.
pub(crate) fn ext_key_usage(purpose: &[u8]) -> Vec<u8> {
    seq(&[purpose])
}

/// subjectAltName with `dNSName` entries, then `iPAddress` entries.
pub(crate) fn subject_alt_name(dns: &[String], ips: &[std::net::IpAddr]) -> Vec<u8> {
    let mut names = Vec::new();
    for d in dns {
        names.extend(tlv(0x82, d.as_bytes()));
    }
    for ip in ips {
        match ip {
            std::net::IpAddr::V4(v4) => names.extend(tlv(0x87, &v4.octets())),
            std::net::IpAddr::V6(v6) => names.extend(tlv(0x87, &v6.octets())),
        }
    }
    tlv(0x30, &names)
}

/// The `[3] EXPLICIT Extensions` field of a TBSCertificate.
pub(crate) fn extensions_field(extensions: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa3, &tlv(0x30, &extensions.concat()))
}

/// The Certificate SEQUENCE that wraps `tbs` with `algorithm` and the
/// signature `signature` (RFC 5280 section 4.1.1).
pub(crate) fn certificate(tbs: &[u8], algorithm: &[u8], signature: &[u8]) -> Vec<u8> {
    seq(&[tbs, algorithm, &bit_string(signature)])
}

/// `id-ce-subjectKeyIdentifier` (2.5.29.14), encoded.
pub(crate) const OID_SKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0e];
/// `id-ce-authorityKeyIdentifier` (2.5.29.35), encoded.
pub(crate) const OID_AKI: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x23];

/// The subjectKeyIdentifier value: `KeyIdentifier ::= OCTET STRING`
/// (RFC 5280 section 4.2.1.2).
pub(crate) fn subject_key_identifier(key_id: &[u8]) -> Vec<u8> {
    octet_string(key_id)
}

/// The authorityKeyIdentifier value with a keyIdentifier only:
/// `SEQUENCE { [0] IMPLICIT KeyIdentifier }` (RFC 5280 section 4.2.1.1).
pub(crate) fn authority_key_identifier(key_id: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x80, key_id))
}

/// The minimal positive DER INTEGER for the unsigned big-endian
/// `magnitude`. Zero is one zero octet (X.690 8.3).
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|b| *b != 0);
    let tail: &[u8] = match first {
        Some(i) => &magnitude[i..],
        None => &[0],
    };
    let mut content = Vec::with_capacity(tail.len() + 1);
    if tail[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(tail);
    tlv(0x02, &content)
}

/// The `ECDSA-Sig-Value` for the raw halves `r` and `s` (RFC 5480 section
/// 2.2.3): `SEQUENCE { INTEGER r, INTEGER s }`.
pub(crate) fn ecdsa_sig_value(r: &[u8], s: &[u8]) -> Vec<u8> {
    seq(&[&unsigned_integer(r), &unsigned_integer(s)])
}

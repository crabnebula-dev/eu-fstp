//! A write-only DER encoder (X.690) for the certificate profile.
//!
//! Nothing here reads DER. Each function writes one TLV with the
//! definite-length form, which DER requires.

/// `BOOLEAN`.
pub(crate) const TAG_BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub(crate) const TAG_INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
/// `UTF8String`.
pub(crate) const TAG_UTF8_STRING: u8 = 0x0c;
/// `UTCTime`.
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
/// `SEQUENCE` and `SEQUENCE OF`, constructed.
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
/// `SET` and `SET OF`, constructed.
pub(crate) const TAG_SET: u8 = 0x31;
/// `[0]` constructed, the explicit tag of the certificate version.
pub(crate) const TAG_CONTEXT_0: u8 = 0xa0;
/// `[3]` constructed, the explicit tag of the extensions field.
pub(crate) const TAG_CONTEXT_3: u8 = 0xa3;
/// `[2]` primitive, the implicit tag of `dNSName` (RFC 5280 GeneralName).
pub(crate) const TAG_SAN_DNS: u8 = 0x82;
/// `[7]` primitive, the implicit tag of `iPAddress` (RFC 5280 GeneralName).
pub(crate) const TAG_SAN_IP: u8 = 0x87;
/// `[0]` primitive, the implicit tag of `keyIdentifier` in the
/// authorityKeyIdentifier extension (RFC 5280 section 4.2.1.1).
pub(crate) const TAG_AKI_KEY_ID: u8 = 0x80;

/// Appends the DER length octets for a content of `n` bytes (X.690
/// 8.1.3): the short form below 128, otherwise the minimal long form.
fn push_len(out: &mut Vec<u8>, n: usize) {
    match u8::try_from(n) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let be = n.to_be_bytes();
            let tail: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
            // `tail` holds at most `size_of::<usize>()` bytes, so the count
            // never saturates and always fits the 7 bits of the long form.
            let count = tail.iter().fold(0u8, |c, _| c.saturating_add(1));
            out.push(0x80 | count);
            out.extend_from_slice(&tail);
        }
    }
}

/// One TLV with the single-byte tag `tag` around `content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(10));
    out.push(tag);
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A `SEQUENCE` of already encoded parts, in order.
pub(crate) fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

/// A `BIT STRING` with no unused bits.
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len().saturating_add(1));
    content.push(0);
    content.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &content)
}

/// The DER encoding of `TRUE` (X.690 11.1: all bits set).
pub(crate) const TRUE: &[u8] = &[TAG_BOOLEAN, 0x01, 0xff];

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "test code")]

    use super::*;

    #[test]
    fn length_forms_are_minimal() {
        assert_eq!(tlv(0x04, &[0; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[0; 0xff])[..3], [0x04, 0x81, 0xff]);
        assert_eq!(tlv(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
        assert_eq!(
            tlv(0x04, &[0; 0x1_0000])[..5],
            [0x04, 0x83, 0x01, 0x00, 0x00]
        );
    }
}

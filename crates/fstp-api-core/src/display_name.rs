//! Unique display names within the organisation (SA-11 amendment, Daniel
//! 2026-11-15 night; ADR-004, ADR-007, I-20).
//!
//! A display name is stored sealed, so a text store checks uniqueness on
//! a keyed fingerprint of the normalised name, never on the name itself.
//!
//! - [`normalised`] is the comparison form. Daniel chose the simpler
//!   comparison: surrounding white space trimmed, inner white space
//!   collapsed to one space, then `to_lowercase`. No Unicode NFC and no
//!   full case folding is applied, since no workspace code does either.
//!   Two names that differ only in how an accent is encoded, such as
//!   U+00E9 against `e` with U+0301, may therefore both be accepted.
//! - [`fingerprint_key`] derives the fingerprint key from the tenant
//!   cell's App chain `Lookup` key through HKDF-SHA256 with the fixed
//!   label [`FINGERPRINT_KEY_LABEL`], as the delivery body digest key is
//!   derived (ADR-004 "Chains"). Each cell holds one tenant, so the key is
//!   per tenant, and no fingerprint links two tenants (I-20).
//! - [`fingerprint`] is HMAC-SHA256 of the normalised name under that key,
//!   through `fstp-crypto`.
//! - A refused name answers under [`TAKEN_RULE`]. The refusal never names
//!   the account that holds the name (R-CF-03 style).

/// The fixed HKDF label of the display name fingerprint key (SA-11,
/// ADR-004 "Chains").
pub const FINGERPRINT_KEY_LABEL: &[u8] = b"fstp display name fingerprint v1";

/// The rule a name that another account of the tenant holds is refused
/// under (SA-11 amendment). The web shows "This name is already used in
/// your organisation".
pub const TAKEN_RULE: &str = "SA-11-unique";

/// The length of a fingerprint, in bytes.
pub const FINGERPRINT_LEN: usize = fstp_crypto::HMAC_SHA256_LEN;

/// The comparison form of `name` (SA-11 amendment, "Simpler comparison"):
/// white space trimmed, each inner run of white space one U+0020, then
/// `to_lowercase`. White space is Unicode `White_Space`. No NFC is
/// applied.
pub fn normalised(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for word in name.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.to_lowercase()
}

/// The fingerprint key of the tenant cell whose App chain `Lookup` key is
/// `lookup`: `fstp_crypto::kdf::hkdf_sha256` with an empty salt and
/// [`FINGERPRINT_KEY_LABEL`]. A new `Lookup` key gives a new fingerprint
/// key, so a store recomputes its fingerprints when `Lookup` is replaced.
/// The key bytes are never logged.
pub fn fingerprint_key(lookup: &[u8; 32]) -> Result<[u8; 32], fstp_crypto::CryptoError> {
    let mut out = [0u8; 32];
    fstp_crypto::kdf::hkdf_sha256(&[], lookup, FINGERPRINT_KEY_LABEL, &mut out)?;
    Ok(out)
}

/// The fingerprint of `name` under `key`: HMAC-SHA256 of
/// [`normalised`]`(name)`.
pub fn fingerprint(key: &[u8; 32], name: &str) -> [u8; FINGERPRINT_LEN] {
    fstp_crypto::hmac_sha256(key, normalised(name).as_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// SA-11 amendment: trimmed, inner white space collapsed to one
    /// space, then lower case. "Anna Berg" and "anna  berg" are the same.
    #[test]
    fn sa11_unique_normalisation_trims_collapses_and_lowercases() {
        for (raw, want) in [
            ("Anna Berg", "anna berg"),
            ("anna  berg", "anna berg"),
            ("  ANNA\u{a0}\u{2003}Berg \t", "anna berg"),
            ("Anna\u{3000}Berg", "anna berg"),
            ("ÉLODIE Ørsted", "élodie ørsted"),
            ("ΣΊΣΥΦΟΣ", "σίσυφος"),
            ("", ""),
            (" \u{2009} ", ""),
        ] {
            assert_eq!(normalised(raw), want, "{raw:?}");
        }
        assert_eq!(normalised("Anna Berg"), normalised("anna  berg"));
    }

    /// SA-11 amendment: the comparison form is its own fixed point.
    #[test]
    fn sa11_unique_normalisation_is_idempotent() {
        for raw in [
            "Anna Berg",
            "  a  B  c ",
            "İstanbul",
            "STRASSE straße",
            "x\u{2028}y",
        ] {
            let once = normalised(raw);
            assert_eq!(normalised(&once), once, "{raw:?}");
        }
    }

    /// SA-11 amendment, "Simpler comparison": no NFC is applied, so two
    /// encodings of the same accented name stay apart and may both be
    /// accepted. This records the known limit Daniel accepted.
    #[test]
    fn sa11_unique_names_differing_only_in_accent_encoding_stay_apart() {
        let composed = "Jos\u{e9} Synthetic";
        let decomposed = "Jose\u{301} Synthetic";
        assert_ne!(normalised(composed), normalised(decomposed));
        let key = fingerprint_key(&[7; 32]).unwrap();
        assert_ne!(fingerprint(&key, composed), fingerprint(&key, decomposed));
        // No full case folding either: "ß" is not "ss".
        assert_ne!(normalised("Straße"), normalised("STRASSE"));
    }

    /// SA-11 amendment, I-20: the fingerprint is keyed. Equal names give
    /// equal fingerprints under one tenant's key, and different ones under
    /// another tenant's key. The key comes from `Lookup` through HKDF.
    #[test]
    fn sa11_unique_i20_fingerprint_is_keyed_per_tenant() {
        let a = fingerprint_key(&[1; 32]).unwrap();
        let b = fingerprint_key(&[2; 32]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [1; 32], "the key is derived, not the Lookup key");
        assert_eq!(
            fingerprint(&a, "Anna Berg"),
            fingerprint(&a, " anna   BERG ")
        );
        assert_ne!(fingerprint(&a, "Anna Berg"), fingerprint(&b, "Anna Berg"));
        assert_ne!(fingerprint(&a, "Anna Berg"), fingerprint(&a, "Anna Bergh"));
        let plain = fstp_crypto::hmac_sha256(&[1; 32], b"anna berg");
        assert_ne!(fingerprint(&a, "Anna Berg"), plain);
    }
}

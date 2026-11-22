//! Unique display names within the organisation (SA-11 amendment, Daniel
//! 2026-11-15 night; ADR-004, ADR-007, ADR-029, I-20).
//!
//! A display name is stored sealed, so a text store checks uniqueness on
//! a keyed fingerprint of the normalised name, never on the name itself.
//!
//! - [`normalised`] is the comparison form: `fstp_unorm::name_key`, the
//!   compatibility caseless key of ADR-029 (`NFKC_CF`, default ignorables
//!   removed), with white space trimmed and each inner run collapsed to
//!   one space. Lane L26 chose it in place of the "Simpler comparison" of
//!   2026-11-15, which trimmed, collapsed and lower-cased only, because no
//!   workspace code did NFC or case folding then (ADR-004, section
//!   "Written by lane L26", lead reading of 2026-11-22). Two encodings of one
//!   accented name, case variants such as "Straße" and "STRASSE", and a
//!   name with a zero width joiner inside are each one name.
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

/// The comparison form of `name` (SA-11 amendment, ADR-029, lane L26):
/// `fstp_unorm::name_key`. A name whose form is empty, such as one made
/// only of default ignorables, names nobody, and the API core refuses it.
pub fn normalised(name: &str) -> String {
    fstp_unorm::name_key(name)
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

    /// SA-11 amendment, ADR-029: trimmed, inner white space collapsed to
    /// one space, then case folded. "Anna Berg" and "anna  berg" are the
    /// same.
    #[test]
    fn sa11_unique_normalisation_trims_collapses_and_folds() {
        for (raw, want) in [
            ("Anna Berg", "anna berg"),
            ("anna  berg", "anna berg"),
            ("  ANNA\u{a0}\u{2003}Berg \t", "anna berg"),
            ("Anna\u{3000}Berg", "anna berg"),
            ("ÉLODIE Ørsted", "élodie ørsted"),
            // Full case folding folds the final sigma too.
            ("ΣΊΣΥΦΟΣ", "σίσυφοσ"),
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
            "Ａｎｎａ ﬁne",
        ] {
            let once = normalised(raw);
            assert_eq!(normalised(&once), once, "{raw:?}");
        }
    }

    /// SA-11 amendment, ADR-029, lane L26: canonical equivalents, full
    /// case folding, compatibility forms and default ignorables give one
    /// name, so look-alike names cannot both be taken.
    #[test]
    fn sa11_unique_adr029_variants_of_one_name_are_one_name() {
        let key = fingerprint_key(&[7; 32]).unwrap();
        for (a, b) in [
            ("Jos\u{e9} Synthetic", "Jose\u{301} Synthetic"),
            ("Straße", "STRASSE"),
            ("Anna Berg", "An\u{200d}na Berg"),
            ("Anna Berg", "Anna\u{ad} Berg"),
            ("Anna Berg", "Ａｎｎａ Ｂｅｒｇ"),
            ("Synthetic fine", "Synthetic ﬁne"),
        ] {
            assert_eq!(normalised(a), normalised(b), "{a:?} {b:?}");
            assert_eq!(fingerprint(&key, a), fingerprint(&key, b), "{a:?} {b:?}");
        }
        assert_ne!(normalised("Anna Berg"), normalised("Anna Bergh"));
    }

    /// SA-11 amendment, ADR-029: a name of default ignorables only has an
    /// empty comparison form, which the API core refuses.
    #[test]
    fn sa11_unique_name_of_ignorables_only_is_empty() {
        for raw in ["\u{200d}", "\u{ad}\u{200b}", "\u{feff} \u{200c}"] {
            assert_eq!(normalised(raw), "", "{raw:?}");
        }
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

//! R-RP-01, P-53 (M9 design sections 1.3 D3 and 2.5): a programme pins
//! one funder profile version through P-53, and only shipped profiles
//! resolve.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_report::profile::{ProfileError, WordingStatus, for_p53, for_p53_with, shipped};

/// R-RP-01, P-53: the P-53 value the creator compiles for the Horizon
/// Europe profile resolves to the shipped Horizon Europe report profile,
/// version 1, and its digest is the SHA-256 of the shipped file.
#[test]
fn r_rp_01_p53_pins_the_shipped_profile_version() {
    let p53 = fstp_programme::FunderProfile::horizon_europe()
        .policy_ref()
        .unwrap();
    let p = for_p53(p53.0.as_str()).unwrap();
    assert_eq!((p.id(), p.version()), ("horizon-europe", 1));
    assert_eq!(
        p.digest().bytes(),
        fstp_crypto::sha256(fstp_report::profile::HORIZON_EUROPE_V1)
    );
    assert!(p.pin().matches_p53(p53.0.as_str()));
    assert_eq!(p, shipped("horizon-europe", 1).unwrap());
}

/// R-RP-01, D3: a P-53 value that names another version, another
/// profile, or no profile at all resolves to no shipped profile.
/// Tenant-owned versions resolve through `for_p53_with` only.
#[test]
fn r_rp_01_unshipped_p53_resolves_to_nothing() {
    for bad in [
        r#"{"profile":"horizon-europe","version":2}"#,
        r#"{"profile":"synthetic-funder","version":3}"#,
        r#""synthetic funder profile""#,
        "",
    ] {
        assert_eq!(for_p53(bad), Err(ProfileError::NotShipped), "{bad}");
    }
}

/// I-69, L-08: the Horizon Europe profile names its funder visibility
/// elements with wording that stays `TODO(legal)` until Daniel supplies
/// the approved text.
#[test]
fn i69_he_visibility_wording_is_pending_legal() {
    let p = shipped("horizon-europe", 1).unwrap();
    assert!(!p.visibility_elements().is_empty());
    for e in p.visibility_elements() {
        assert_eq!(e.status(), WordingStatus::PendingLegal, "{}", e.key());
        assert!(e.wording().starts_with("horizon-europe/visibility/"));
    }
}

/// R-RP-01 (Daniel, 2026-11-15 late): a programme pins a shipped or a
/// tenant-owned profile. A shipped version wins over the tenant fold; a
/// tenant version resolves from its text, which must parse and carry the
/// id and version P-53 names.
#[test]
fn r_rp_01_p53_pins_a_tenant_profile_version() {
    let he = std::str::from_utf8(fstp_report::profile::HORIZON_EUROPE_V1).unwrap();
    let copy = he
        .replacen("\"id\": \"horizon-europe\"", "\"id\": \"tenant-he\"", 1)
        .replacen("\"version\": 1,", "\"version\": 2,", 1)
        .replace("\"horizon-europe/", "\"tenant-he/");
    let p53 = r#"{"profile":"tenant-he","version":2}"#;
    let p = for_p53_with(p53, |id, v| {
        (id == "tenant-he" && v == 2).then_some(copy.as_str())
    })
    .unwrap();
    assert_eq!((p.id(), p.version()), ("tenant-he", 2));
    assert!(p.pin().matches_p53(p53));
    // No tenant version: nothing resolves.
    assert_eq!(
        for_p53_with(p53, |_, _| None),
        Err(ProfileError::NotShipped)
    );
    // A tenant text whose id or version differs from P-53 is refused.
    assert_eq!(
        for_p53_with(r#"{"profile":"tenant-he","version":3}"#, |_, _| Some(
            copy.as_str()
        )),
        Err(ProfileError::NotShipped)
    );
    // A shipped version never reads the tenant fold.
    let shipped_p53 = r#"{"profile":"horizon-europe","version":1}"#;
    let p = for_p53_with(shipped_p53, |_, _| Some("not a profile")).unwrap();
    assert_eq!(p.id(), "horizon-europe");
}

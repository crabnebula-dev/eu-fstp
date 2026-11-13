//! R-RP-01, P-53 (M9 design sections 1.3 D3 and 2.5): a programme pins
//! one funder profile version through P-53, and only shipped profiles
//! resolve.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_report::profile::{ProfileError, WordingStatus, for_p53, shipped};

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
/// profile, or no profile at all resolves to nothing. Tenant-authored
/// profiles do not exist in M9.
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

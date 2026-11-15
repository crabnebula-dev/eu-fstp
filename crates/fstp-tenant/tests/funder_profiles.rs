//! Tests of tenant copies of funder profiles and the `FunderProfileSaved`
//! record (Daniel, 2026-11-15 late: "The platform ships versioned
//! profiles. A tenant may copy one into a tenant-owned profile and edit
//! it. A programme pins one, as today."; R-RP-01, R-LG-03, I-85).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest};
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    CellKind, TenantAnswers, TenantCommand, TenantCtx, TenantKind, TenantProfile, TenantRecord,
    TenantRefusal, TenantState, decode_record, encode_record,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);
const DIGEST: ContentDigest = ContentDigest::from_bytes([0x3c; 32]);

fn ctx(actor: AccountId) -> TenantCtx {
    TenantCtx {
        actor,
        via: Via::Web,
        at: T0,
    }
}

fn version(id: &str, v: u16, source: Option<(&str, u16)>) -> TenantProfile {
    TenantProfile {
        id: id.to_owned(),
        version: v,
        text: format!("{{\"id\":\"{id}\",\"version\":{v}}}"),
        digest: DIGEST,
        source: source.map(|(p, n)| (p.to_owned(), n)),
    }
}

fn save(p: TenantProfile) -> TenantCommand {
    TenantCommand::SaveFunderProfile { profile: p }
}

/// R-RP-01: a copy is version 1 with its source, each edit the next
/// version with none, and the state keeps every version.
#[test]
fn r_rp_01_copy_then_edit_records_each_version() {
    let admin = AccountId::from_raw(1);
    let mut s = TenantState::genesis(admin, CellKind::Saas);
    for p in [
        version("tenant-he", 1, Some(("horizon-europe", 1))),
        version("tenant-he", 2, None),
        version("tenant-he", 3, None),
    ] {
        let records =
            fstp_tenant::decide(&s, &ctx(admin), &save(p.clone()), &TenantAnswers::new()).unwrap();
        assert_eq!(
            records,
            vec![TenantRecord::FunderProfileSaved {
                profile: p.clone(),
                by: admin
            }]
        );
        for r in &records {
            assert_eq!(decode_record(&encode_record(r).unwrap()).unwrap(), *r);
        }
        s.apply_all(&records).unwrap();
    }
    assert_eq!(
        s.latest_funder_profile("tenant-he").map(|p| p.version),
        Some(3)
    );
    assert_eq!(
        s.funder_profile("tenant-he", 1)
            .and_then(|p| p.source.clone()),
        Some(("horizon-europe".to_owned(), 1))
    );
    assert_eq!(s.funder_profiles().count(), 3);
}

/// R-RP-01: a tenant id never names a shipped profile, versions never
/// skip or repeat, and an edit names no source.
#[test]
fn r_rp_01_malformed_versions_are_refused() {
    let admin = AccountId::from_raw(1);
    let mut s = TenantState::genesis(admin, CellKind::Saas);
    let first = version("tenant-he", 1, Some(("horizon-europe", 1)));
    let records =
        fstp_tenant::decide(&s, &ctx(admin), &save(first), &TenantAnswers::new()).unwrap();
    s.apply_all(&records).unwrap();
    let mut markup = version("tenant-he", 2, None);
    markup.text = "<script>".to_owned();
    for bad in [
        version("horizon-europe", 1, Some(("horizon-europe", 1))),
        version("tenant-HE", 1, Some(("horizon-europe", 1))),
        version("tenant-he", 1, Some(("horizon-europe", 1))),
        version("tenant-he", 3, None),
        version("tenant-he", 2, Some(("horizon-europe", 1))),
        markup,
    ] {
        assert_eq!(
            fstp_tenant::decide(&s, &ctx(admin), &save(bad.clone()), &TenantAnswers::new()),
            Err(TenantRefusal::FunderProfileInvalid),
            "{bad:?}"
        );
    }
}

/// R-LG-03, I-85: saving a profile version is high-risk and web only, and
/// only a tenant admin may.
#[test]
fn r_lg_03_saving_a_profile_is_high_risk_and_admin_only() {
    assert!(TenantKind::SaveFunderProfile.high_risk());
    assert!(TenantKind::SaveFunderProfile.web_only());
    assert!(TenantKind::SaveFunderProfile.admin_only());
    let admin = AccountId::from_raw(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let other = AccountId::from_raw(2);
    assert!(
        fstp_tenant::decide(
            &s,
            &ctx(other),
            &save(version("tenant-he", 1, Some(("horizon-europe", 1)))),
            &TenantAnswers::new()
        )
        .is_err()
    );
}

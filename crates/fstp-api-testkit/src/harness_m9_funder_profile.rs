//! M9 finish: `programme.funder_profile.view` through the API (R-RP-01,
//! R-AC-01, I-44, I-86; M9 design section 2.2).
//!
//! The SuperSAFE policy pins Horizon Europe version 1 through P-53. The
//! programme manager, the auditor and the tenant-wide Financial signatory
//! read the pinned profile: its id, version, file digest, the five output
//! kinds and the visibility element keys. The reply equals the shipped
//! profile. An applicant, a reviewer and the manager of another programme
//! are refused (R-AC-01).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

const GET: ApiMethod = ApiMethod::Get;

fn world() -> Built {
    build(WorldKey {
        state: StateProfile::Proposal(StateTag::Granted),
        policy: Policy::SUPERSAFE,
        variant: Variant::Main,
    })
    .unwrap_or_else(|e| panic!("world: {e}"))
}

fn seeder(w: Built) -> Seeder {
    Seeder {
        ports: w.ports,
        core: w.core,
        now: w.now,
        command: 900_000,
        cookies: BTreeMap::new(),
        next_id: 90_000_000,
        admins: w.admins.iter().copied().collect(),
    }
}

/// R-RP-01, R-AC-01, I-86: the report readers read the pinned profile,
/// which is the shipped Horizon Europe v1, and nobody else does.
#[test]
fn r_rp_01_funder_profile_view_shows_the_pinned_profile_to_report_readers() {
    let w = world();
    let p = w.targets.programme.expect("P").raw().to_string();
    let mut seed = seeder(w);
    let path = format!("/programmes/{p}/funder-profile");
    // The shipped file, read here with no help from `fstp-report`.
    let file: &[u8] = include_bytes!("../../fstp-report/profiles/horizon-europe/profile.v1.json");
    let digest: String = fstp_crypto::sha256(file)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let parsed = fstp_json::parse(file).expect("the profile is I-JSON");
    let list = |k: &str, inner: &str| -> Vec<String> {
        parsed
            .as_object()
            .and_then(|o| o.get(k))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| str_member(x, inner)).collect())
            .unwrap_or_default()
    };
    let kinds = list("outputs", "kind");
    let keys = list("visibility_elements", "key");
    assert_eq!(kinds.len(), 5, "HE v1 defines the five outputs");
    for who in [PM, AUDITOR, ORG_SIGNATORY] {
        let v = seed
            .api(who, GET, &path, &Value::Null)
            .unwrap_or_else(|e| panic!("{who:?}: {e}"));
        let text = v.to_compact();
        assert!(
            !text.contains('@') && !text.contains("account"),
            "I-86: {text}"
        );
        assert_eq!(str_member(&v, "programme"), Some(p.clone()), "{text}");
        let profile = v
            .as_object()
            .and_then(|o| o.get("profile"))
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(
            str_member(&profile, "id").as_deref(),
            Some("horizon-europe"),
            "{text}"
        );
        assert_eq!(
            str_member(&profile, "version").as_deref(),
            Some("1"),
            "{text}"
        );
        assert_eq!(
            str_member(&profile, "digest"),
            Some(digest.clone()),
            "{text}"
        );
        let strings = |k: &str| -> Vec<String> {
            profile
                .as_object()
                .and_then(|o| o.get(k))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(strings("outputs"), kinds, "{text}");
        assert_eq!(strings("visibility_elements"), keys, "{text}");
    }
    for who in [LEAD, REVIEWER, PM_OTHER] {
        let e = seed
            .api(who, GET, &path, &Value::Null)
            .expect_err("refused");
        assert!(e.contains("R-AC-01"), "{who:?}: {e}");
    }
}

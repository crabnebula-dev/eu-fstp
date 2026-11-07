//! Tests of `tenant.branding.set` and the `BrandingSet` record (M9 design
//! sections 2.1 and 2.2, lane B1; I-68, I-70, R-LG-03, I-85).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_brand::{BrandTokens, Rgb, failing_pairs};
use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest};
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_tenant::{
    CellKind, TenantAnswers, TenantCommand, TenantCtx, TenantKind, TenantRecord, TenantRefusal,
    TenantState, decode_command, decode_record, encode_command, encode_record,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);
const DIGEST: ContentDigest = ContentDigest::from_bytes([0x5a; 32]);

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn ctx(actor: AccountId, via: Via) -> TenantCtx {
    TenantCtx { actor, via, at: T0 }
}

fn rgb(g: &mut Gen) -> Rgb {
    Rgb {
        r: g.u8(),
        g: g.u8(),
        b: g.u8(),
    }
}

/// Random tokens: the platform family with some colours replaced.
fn tokens(g: &mut Gen) -> BrandTokens {
    let mut t = BrandTokens::platform("Harbour Fund").expect("name");
    for p in [&mut t.light, &mut t.dark] {
        if g.bool() {
            p.brand = rgb(g);
        }
        if g.bool() {
            p.brand_hover = rgb(g);
        }
        if g.bool() {
            p.brand_text = rgb(g);
        }
        if g.bool() {
            p.on_brand = rgb(g);
        }
        if g.bool() {
            p.focus = rgb(g);
        }
    }
    t
}

fn set(tokens: BrandTokens) -> TenantCommand {
    TenantCommand::SetBranding {
        tokens,
        digest: DIGEST,
    }
}

/// I-70: `tenant.branding.set` is accepted exactly when every pair passes
/// in both modes. A refusal lists exactly the failing pairs. An accepted
/// set folds, and the state shows it.
#[test]
fn i70_branding_set_accepted_iff_all_pairs_pass() {
    check("i70_branding_set_accepted_iff_all_pairs_pass", |g| {
        let admin = acct(1);
        let mut s = TenantState::genesis(admin, CellKind::Saas);
        let t = tokens(g);
        let failing = failing_pairs(&t);
        let out = fstp_tenant::decide(
            &s,
            &ctx(admin, Via::Web),
            &set(t.clone()),
            &TenantAnswers::new(),
        );
        match out {
            Ok(records) => {
                prop_assert!(failing.is_empty());
                prop_assert_eq!(
                    &records,
                    &vec![TenantRecord::BrandingSet {
                        tokens: t.clone(),
                        digest: DIGEST,
                        by: admin,
                    }]
                );
                s.apply_all(&records).map_err(|e| format!("{e:?}"))?;
                prop_assert_eq!(s.branding(), Some((&t, DIGEST)));
            }
            Err(r) => {
                prop_assert_eq!(r, TenantRefusal::BrandingContrast(failing));
                prop_assert!(!failing.is_empty());
            }
        }
        Ok(())
    });
}

/// I-70: a ledger whose `BrandingSet` holds a failing pair refuses to fold.
#[test]
fn i70_failing_branding_record_does_not_fold() {
    let admin = acct(1);
    let mut t = BrandTokens::platform("Yellow").expect("name");
    t.light.brand = Rgb::hex(0xFF_EB_3B);
    let rec = TenantRecord::BrandingSet {
        tokens: t,
        digest: DIGEST,
        by: admin,
    };
    let mut s = TenantState::genesis(admin, CellKind::Saas);
    assert!(s.apply_all(&[rec]).is_err());
    assert_eq!(s.branding(), None);
}

/// R-LG-03, I-78, I-85: setting branding is high-risk, so it needs a
/// fresh step-up and is web only. Through MCP it is refused. The check
/// is no command and saves nothing.
#[test]
fn r_lg_03_branding_set_is_high_risk_with_step_up() {
    let k = TenantKind::SetBranding;
    assert!(TenantKind::ALL.contains(&k));
    assert!(k.high_risk());
    assert!(k.web_only());
    assert!(k.admin_only());
    let admin = acct(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let t = BrandTokens::platform("Harbour").expect("name");
    let r = fstp_tenant::decide(
        &s,
        &ctx(admin, Via::Mcp),
        &set(t.clone()),
        &TenantAnswers::new(),
    );
    assert_eq!(r, Err(TenantRefusal::HighRiskViaMcp));
    // Q31: only a tenant admin sets branding.
    let r = fstp_tenant::decide(&s, &ctx(acct(2), Via::Web), &set(t), &TenantAnswers::new());
    assert_eq!(r, Err(TenantRefusal::NotTenantAdmin));
}

/// I-68: the command and the record round-trip through the canonical
/// codec, and the stored record holds only typed tokens.
#[test]
fn i68_branding_codec_round_trip() {
    check("i68_branding_codec_round_trip", |g| {
        let t = tokens(g);
        let cmd = set(t.clone());
        let bytes = encode_command(&cmd).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(decode_command(&bytes).map_err(|e| format!("{e:?}"))?, cmd);
        let rec = TenantRecord::BrandingSet {
            tokens: t,
            digest: DIGEST,
            by: acct(7),
        };
        let bytes = encode_record(&rec).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(decode_record(&bytes).map_err(|e| format!("{e:?}"))?, rec);
        Ok(())
    });
}

/// I-68: a record whose tokens break the token grammar is refused.
#[test]
fn i68_branding_record_with_markup_is_refused() {
    let rec = TenantRecord::BrandingSet {
        tokens: BrandTokens::platform("Harbour").expect("name"),
        digest: DIGEST,
        by: acct(7),
    };
    let text = String::from_utf8(encode_record(&rec).expect("encode")).expect("utf8");
    let bad = text.replace("Harbour", "<b>Harbour</b>");
    assert!(decode_record(bad.as_bytes()).is_err());
    let bad = text.replace("#1e40af", "url(x)");
    assert!(decode_record(bad.as_bytes()).is_err());
}

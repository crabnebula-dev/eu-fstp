//! Tests of the logo slots and the theme choice in the tenant ledger
//! (ADR-030; I-68, R-WL-03, I-85).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_brand::ThemeMode;
use fstp_brand::image::LogoFormat;
use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_tenant::{
    CellKind, LogoOwner, LogoRef, LogoSlot, TenantAnswers, TenantCommand, TenantCtx, TenantKind,
    TenantRecord, TenantRefusal, TenantState, Theme, decode_command, decode_record, encode_command,
    encode_record,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn ctx(actor: AccountId, via: Via) -> TenantCtx {
    TenantCtx { actor, via, at: T0 }
}

fn slot(g: &mut Gen) -> LogoSlot {
    LogoSlot {
        owner: if g.bool() {
            LogoOwner::Tenant
        } else {
            LogoOwner::Programme(ProgrammeId::from_raw(u128::from(g.u32())))
        },
        mode: *g.pick(&[ThemeMode::Light, ThemeMode::Dark]),
    }
}

fn logo(g: &mut Gen) -> LogoRef {
    LogoRef {
        digest: ContentDigest::from_bytes([g.u8(); 32]),
        format: *g.pick(&LogoFormat::ALL),
        width: g.u32_in(16..=2048),
        height: g.u32_in(16..=2048),
        pdf: g.bool(),
    }
}

fn light_tenant() -> LogoSlot {
    LogoSlot {
        owner: LogoOwner::Tenant,
        mode: ThemeMode::Light,
    }
}

/// R-WL-03, I-68: a tenant admin sets and clears a logo slot. The state
/// shows the latest logo of each slot and nothing for a cleared one.
#[test]
fn r_wl_03_logo_slot_set_and_cleared() {
    check("r_wl_03_logo_slot_set_and_cleared", |g| {
        let admin = acct(1);
        let mut s = TenantState::genesis(admin, CellKind::Saas);
        let sl = slot(g);
        let l = logo(g);
        let set = TenantCommand::SetLogo {
            slot: sl,
            logo: Some(l),
        };
        let r = fstp_tenant::decide(&s, &ctx(admin, Via::Web), &set, &TenantAnswers::new())
            .map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(
            &r,
            &vec![TenantRecord::LogoSet {
                slot: sl,
                logo: Some(l),
                by: admin
            }]
        );
        s.apply_all(&r).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(s.logo(sl), Some(&l));
        let clear = TenantCommand::SetLogo {
            slot: sl,
            logo: None,
        };
        let r = fstp_tenant::decide(&s, &ctx(admin, Via::Web), &clear, &TenantAnswers::new())
            .map_err(|e| format!("{e:?}"))?;
        s.apply_all(&r).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(s.logo(sl), None);
        Ok(())
    });
}

/// I-68: a logo outside the size bounds is refused, and a record that
/// holds one does not fold.
#[test]
fn i68_logo_outside_bounds_is_refused() {
    let admin = acct(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let big = LogoRef {
        digest: ContentDigest::from_bytes([1; 32]),
        format: LogoFormat::Png,
        width: 4096,
        height: 100,
        pdf: true,
    };
    let cmd = TenantCommand::SetLogo {
        slot: light_tenant(),
        logo: Some(big),
    };
    assert_eq!(
        fstp_tenant::decide(&s, &ctx(admin, Via::Web), &cmd, &TenantAnswers::new()),
        Err(TenantRefusal::LogoInvalid)
    );
    let mut s = s;
    let rec = TenantRecord::LogoSet {
        slot: light_tenant(),
        logo: Some(big),
        by: admin,
    };
    assert!(s.apply_all(&[rec]).is_err());
    assert_eq!(s.logo(light_tenant()), None);
}

/// R-LG-03, I-85: setting a logo is high-risk and web only, and only a
/// tenant admin sets one.
#[test]
fn r_lg_03_set_logo_is_high_risk_and_admin_only() {
    let k = TenantKind::SetLogo;
    assert!(TenantKind::ALL.contains(&k));
    assert!(k.high_risk() && k.web_only() && k.admin_only());
    let admin = acct(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let cmd = TenantCommand::SetLogo {
        slot: light_tenant(),
        logo: None,
    };
    assert_eq!(
        fstp_tenant::decide(&s, &ctx(admin, Via::Mcp), &cmd, &TenantAnswers::new()),
        Err(TenantRefusal::HighRiskViaMcp)
    );
    assert_eq!(
        fstp_tenant::decide(&s, &ctx(acct(2), Via::Web), &cmd, &TenantAnswers::new()),
        Err(TenantRefusal::NotTenantAdmin)
    );
}

/// ADR-030 section 1: any account sets its own theme, which the state
/// keeps per account. System is the default.
#[test]
fn adr030_any_account_sets_its_own_theme() {
    let admin = acct(1);
    let person = acct(42);
    let mut s = TenantState::genesis(admin, CellKind::Saas);
    assert_eq!(s.theme(person), Theme::System);
    let k = TenantKind::SetTheme;
    assert!(TenantKind::ALL.contains(&k));
    assert!(!k.high_risk() && !k.admin_only());
    for theme in [Theme::Dark, Theme::Light, Theme::System] {
        let r = fstp_tenant::decide(
            &s,
            &ctx(person, Via::Web),
            &TenantCommand::SetTheme { theme },
            &TenantAnswers::new(),
        )
        .expect("accepted");
        assert_eq!(r, vec![TenantRecord::ThemeSet { theme, by: person }]);
        s.apply_all(&r).expect("folds");
        assert_eq!(s.theme(person), theme);
        assert_eq!(s.theme(admin), Theme::System);
    }
}

/// I-68: the logo and theme commands and records round-trip through the
/// canonical codec.
#[test]
fn i68_logo_and_theme_codec_round_trip() {
    check("i68_logo_and_theme_codec_round_trip", |g| {
        let sl = slot(g);
        let l = if g.bool() { Some(logo(g)) } else { None };
        let theme = *g.pick(&Theme::ALL);
        let cmds = [
            TenantCommand::SetLogo { slot: sl, logo: l },
            TenantCommand::SetTheme { theme },
        ];
        for c in cmds {
            let b = encode_command(&c).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(decode_command(&b).map_err(|e| format!("{e:?}"))?, c);
        }
        let recs = [
            TenantRecord::LogoSet {
                slot: sl,
                logo: l,
                by: acct(7),
            },
            TenantRecord::ThemeSet { theme, by: acct(8) },
        ];
        for r in recs {
            let b = encode_record(&r).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(decode_record(&b).map_err(|e| format!("{e:?}"))?, r);
        }
        Ok(())
    });
}

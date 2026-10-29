//! Tenant settings, one operation per parameter, and the tenant defaults
//! (P-20, P-69 to P-74, P-78, R-PG-01; M4 design sections 3.1, 3.5 and
//! 13, lane W2d).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;

use fstp_domain::Via;
use fstp_domain::rules::{CATALOGUE, Level, ParamId};
use fstp_prop::{Gen, check, check_machine, prop_assert, prop_assert_eq};

use common::gens::{self, Focus, test_env, walk};
use common::machine::TenantMachine;
use common::prod::{self, Sut};
use common::reference::{DEFAULTS_ONLY, SETTABLE, setting_valid};
use common::setup;
use common::vocab::{
    INVALID_SPDX, LoginMethod, Op, P71_DEFAULT_US, P72_ABSOLUTE_DEFAULT_US, P72_IDLE_DEFAULT_US,
    RecordView, Setting, Step, StepInput, VALID_SPDX, Verdict, acct, spec_default_settings,
};

/// P-20, P-69, P-70, P-71, P-72, P-74: random setting changes of every
/// settable parameter, valid and not, through both channels, with every
/// other tenant operation. Each accepted change appends exactly one
/// `SettingChanged { param, by }` record. The settings projection follows
/// the reference and survives a fold of the records alone.
#[test]
fn p20_p69_to_p72_p74_settings_follow_the_reference_and_replay() {
    check_machine(
        "p20_p69_to_p72_p74_settings_follow_the_reference_and_replay",
        &TenantMachine {
            env: test_env(),
            focus: Focus::Settings,
            max: 32,
        },
    );
}

/// P-20, P-69 to P-72, P-74 are settable in the cell, and nothing else.
/// P-73 changes through the control plane (ADR-005), and P-78 arrives with
/// M5. Each settable parameter is tenant level in `CATALOGUE`.
#[test]
fn p20_p69_to_p72_p74_settable_p73_p78_not() {
    let want: BTreeSet<ParamId> = SETTABLE.into_iter().collect();
    assert_eq!(prod::settable_params(), Ok(want.clone()));
    for p in &want {
        let spec = CATALOGUE.iter().find(|s| s.id == *p);
        assert_eq!(spec.map(|s| s.level), Some(Level::Tenant), "{p:?}");
    }
    assert!(!want.contains(&ParamId::P73));
    assert!(!want.contains(&ParamId::P78));
}

/// P-69, P-70, P-71, P-72, P-74: the genesis settings are the Default
/// column of `policy-parameters.md`. P-71 and P-72 are "(proposed)" there,
/// as M3 builds them (Q37). P-20 has no default and stays unset.
#[test]
fn p69_to_p72_p74_genesis_settings_are_the_spec_defaults() {
    let env = test_env();
    let seen = Sut::genesis(&env)
        .and_then(|s| s.observe())
        .map(|o| o.settings);
    assert_eq!(seen, Ok(spec_default_settings()));
}

/// Runs one setting change by the first admin on a fresh genesis and
/// returns its outcome with the settings that follow.
fn set_once(
    setting: &Setting,
) -> Result<(Verdict, Vec<RecordView>, common::vocab::Settings), String> {
    let mut sut = setup(&test_env(), &[])?;
    let o = sut
        .run(&Op::SetSetting {
            actor: acct(1),
            via: Via::Web,
            setting: setting.clone(),
        })
        .map_err(|e| e.to_string())?;
    let seen = sut.observe().map_err(|e| e.to_string())?.settings;
    Ok((o.verdict, o.records, seen))
}

/// Checks one setting change against the reference's value rule.
fn check_setting(g: &mut Gen, s: Setting) -> Result<(), String> {
    g.note("setting", &s);
    let want = setting_valid(&s);
    let (verdict, records, seen) = set_once(&s)?;
    prop_assert_eq!(verdict == Verdict::Accepted, want);
    if want {
        prop_assert_eq!(
            records,
            vec![RecordView::SettingChanged {
                param: s.param(),
                by: acct(1),
            }]
        );
    } else {
        prop_assert!(records.is_empty());
        prop_assert_eq!(seen, spec_default_settings());
    }
    Ok(())
}

/// P-70: "Passkeys always". A login method set without passkeys is
/// refused. Any set with passkeys is accepted and shown as set.
#[test]
fn p70_passkeys_cannot_be_disabled() {
    check("p70_passkeys_cannot_be_disabled", |g| {
        let methods = gens::login_methods(g);
        check_setting(g, Setting::P70(methods.clone()))?;
        if methods.contains(&LoginMethod::Passkey) {
            let (_, _, seen) = set_once(&Setting::P70(methods.clone()))?;
            prop_assert_eq!(seen.p70, methods);
        }
        Ok(())
    });
}

/// P-71: "may only shorten". A value is accepted only when positive and no
/// longer than the 5 minute default, as `fstp_auth::stepup::validate_p71`
/// reads it.
#[test]
fn p71_step_up_freshness_may_only_shorten() {
    check("p71_step_up_freshness_may_only_shorten", |g| {
        let us = gens::micros_around(g, P71_DEFAULT_US);
        check_setting(g, Setting::P71 { us })?;
        if us > 0 && us <= P71_DEFAULT_US {
            let (_, _, seen) = set_once(&Setting::P71 { us })?;
            prop_assert_eq!(seen.p71_us, us);
        }
        Ok(())
    });
}

/// P-72 (interim, pending Daniel, Q37): each lifetime is positive and no
/// longer than its default, the strict reading M3 built in
/// `fstp_cell_core::tenant`.
#[test]
fn p72_session_lifetimes_may_only_shorten() {
    check("p72_session_lifetimes_may_only_shorten", |g| {
        let idle_us = gens::micros_around(g, P72_IDLE_DEFAULT_US);
        let absolute_us = gens::micros_around(g, P72_ABSOLUTE_DEFAULT_US);
        check_setting(
            g,
            Setting::P72 {
                idle_us,
                absolute_us,
            },
        )
    });
}

/// P-69: the default licence of published templates is an SPDX
/// identifier. Free text, markup and line breaks are refused.
#[test]
fn p69_licence_is_an_spdx_identifier() {
    check("p69_licence_is_an_spdx_identifier", |g| {
        let id = if g.bool() {
            g.pick(&VALID_SPDX).to_string()
        } else {
            g.pick(&INVALID_SPDX).to_string()
        };
        check_setting(g, Setting::P69(id))
    });
}

/// P-20, R-EX-03, P-74: each value of the payment mode and of the MCP setting is
/// accepted, recorded once and shown as set.
#[test]
fn p20_p74_values_are_recorded_and_shown() {
    check("p20_p74_values_are_recorded_and_shown", |g| {
        let s = if g.bool() {
            Setting::P20(*g.pick(&[
                common::vocab::PaymentMode::RecordOnly,
                common::vocab::PaymentMode::Execution,
            ]))
        } else {
            Setting::P74(gens::mcp_setting(g))
        };
        check_setting(g, s.clone())?;
        let (_, _, seen) = set_once(&s)?;
        match s {
            Setting::P20(m) => prop_assert_eq!(seen.p20, Some(m)),
            Setting::P74(m) => prop_assert_eq!(seen.p74, m),
            _ => {}
        }
        Ok(())
    });
}

/// R-PG-01, R-ID-01, R-LA-04, design 3.1 and 3.5 (Q36 A, interim
/// pending Daniel): the
/// Identity step records defaults for P-18 and P-45, and the Inference
/// step a default for P-21. A default is shown only while its step's
/// latest save validated. Defaults never become parameters: no setting
/// names P-18, P-21 or P-45, and saving defaults changes no setting.
#[test]
fn r_pg_01_tenant_defaults_prefill_but_never_set_parameters() {
    check(
        "r_pg_01_tenant_defaults_prefill_but_never_set_parameters",
        |g| {
            let env = test_env();
            let mut sut = setup(&env, &walk(acct(1), &Step::ALL[..4]))?;
            let identity = gens::step_input(g, Step::Identity);
            let inference = gens::step_input(g, Step::Inference);
            g.note("identity", &identity);
            g.note("inference", &inference);
            let mut model = common::reference::Reference::new(&env);
            for op in walk(acct(1), &Step::ALL[..4]) {
                model.apply(&op);
            }
            for (step, input) in [(Step::Identity, identity), (Step::Inference, inference)] {
                let op = Op::SaveStep {
                    actor: acct(1),
                    step,
                    input,
                };
                let o = sut.run(&op).map_err(|e| e.to_string())?;
                prop_assert_eq!(o.verdict, model.verdict(&op));
                model.apply(&op);
            }
            let seen = sut.observe().map_err(|e| e.to_string())?;
            prop_assert_eq!(&seen.defaults, &model.observed().defaults);
            prop_assert_eq!(seen.settings, spec_default_settings());
            let settable = prod::settable_params().map_err(|e| e.to_string())?;
            prop_assert!(DEFAULTS_ONLY.iter().all(|p| !settable.contains(p)));
            Ok(())
        },
    );
}

/// R-PG-01: a validated Identity save with a fixed input shows exactly
/// those values as the P-18 and P-45 defaults.
#[test]
fn r_pg_01_validated_identity_values_are_the_defaults() {
    let env = test_env();
    let mut ops = walk(acct(1), &Step::ALL[..4]);
    let p18: BTreeSet<_> = [
        common::vocab::VerifyMethod::EudiWallet,
        common::vocab::VerifyMethod::DocumentUpload,
    ]
    .into_iter()
    .collect();
    ops.push(Op::SaveStep {
        actor: acct(1),
        step: Step::Identity,
        input: StepInput::Identity {
            p18: p18.clone(),
            p45: common::vocab::RpMode::CrabNebulaIntermediary,
        },
    });
    let seen = setup(&env, &ops).and_then(|s| s.observe().map_err(|e| e.to_string()));
    let defaults = seen.map(|o| (o.defaults.p18, o.defaults.p45));
    assert_eq!(
        defaults,
        Ok((
            Some(p18),
            Some(common::vocab::RpMode::CrabNebulaIntermediary)
        ))
    );
}

/// The vocabulary's P-72 defaults: 30 minutes idle, 12 hours absolute.
/// A self-check of the reference constants against the spec text.
#[test]
fn p71_p72_reference_defaults_match_policy_parameters() {
    assert_eq!(P71_DEFAULT_US, 300_000_000);
    assert_eq!(P72_IDLE_DEFAULT_US, 1_800_000_000);
    assert_eq!(P72_ABSOLUTE_DEFAULT_US, 43_200_000_000);
}

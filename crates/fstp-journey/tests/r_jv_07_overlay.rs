//! R-JV-07, I-97, `SPEC/12-journey-ui.md` section 5.5: the programme
//! overlay is computed from the frozen policy version, never edited by
//! hand. Each output follows its source in the section 5.5 table, the
//! computation is deterministic, and nothing outside the table changes
//! it. The overlay never carries the text of a policy value (I-97): an
//! opaque parameter shows by its id only.
//!
//! The policy versions come from the domain testkit's SuperSAFE-shaped
//! `base_version`, with the overlay's sources and other parameters drawn.
//! This is the fuzz-free determinism check of the lane scope.
//!
//! Lane j2 test author. The source test is red until the implementer
//! reads the policy. The determinism, "outside the table" and I-97 tests
//! are green, since the stub answers fixed values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::id::PolicyVersionId;
use fstp_domain::policy::{McpBindingActions, PolicyVersion, ReadAccess, ReviewerAnonymity};
use fstp_domain::rules::ParamId;
use fstp_domain::time::Days;
use fstp_domain_testkit::r#gen::policy::{P1, base_version, opaque};
use fstp_domain_testkit::reference::projection::{CANARY, holds_canary};
use fstp_journey::overlay::{IrcConcern, OverlayInputs, WORDING_PARAMS, compute};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// The frozen programme parameters among the wording parameters.
const FROZEN_WORDING: [ParamId; 4] = [ParamId::P08, ParamId::P60, ParamId::P65, ParamId::P66];

/// The live programme parameters among the wording parameters.
const LIVE_WORDING: [ParamId; 2] = [ParamId::P50, ParamId::P51];

/// A policy version with the overlay's sources drawn: P-07, P-11, P-77
/// and which wording parameters are set.
fn version(g: &mut Gen) -> Result<PolicyVersion, String> {
    let id = PolicyVersionId::from_raw(u128::from(g.u32_in(1..=1_000)));
    let mut v = base_version(id, P1, None)?;
    v.frozen.p07 = Days::new(g.u16_in(1..=120));
    v.frozen.p11 = *g.pick(&[ReviewerAnonymity::Anonymous, ReviewerAnonymity::Named]);
    v.frozen.p77 = *g.pick(&[McpBindingActions::DraftOnly, McpBindingActions::Allowed]);
    for p in FROZEN_WORDING {
        if g.bool() {
            v.frozen.opaque.remove(&p);
        }
    }
    for p in LIVE_WORDING {
        if g.bool() {
            v.live.opaque.remove(&p);
        }
    }
    Ok(v)
}

/// Overlay inputs with drawn facts.
fn inputs(g: &mut Gen) -> OverlayInputs {
    let mut tenant_params = BTreeSet::new();
    if g.bool() {
        tenant_params.insert(ParamId::P20);
    }
    OverlayInputs {
        later_call_published: g.bool(),
        tenant_params,
    }
}

/// The wording parameters the reference expects to be set.
fn wording(v: &PolicyVersion, i: &OverlayInputs) -> BTreeSet<ParamId> {
    WORDING_PARAMS
        .into_iter()
        .filter(|p| {
            v.frozen.opaque.contains_key(p)
                || v.live.opaque.contains_key(p)
                || i.tenant_params.contains(p)
        })
        .collect()
}

/// R-JV-07, section 5.5: each overlay output equals its source: the
/// version id, P-07, P-11, P-77, NOTE 7 and the set wording parameters.
#[test]
fn r_jv_07_overlay_fields_follow_their_section_5_5_sources() {
    fstp_prop::check(
        "r_jv_07_overlay_fields_follow_their_section_5_5_sources",
        |g: &mut Gen| {
            let v = version(g)?;
            let i = inputs(g);
            let o = compute(&v, &i);
            prop_assert_eq!(o.policy, v.id, "R-JV-07: the policy version");
            prop_assert_eq!(o.stage2_window, v.frozen.p07, "R-JV-07: P-07");
            prop_assert_eq!(o.anonymity, v.frozen.p11, "R-JV-07: P-11");
            prop_assert_eq!(o.agent_actions, v.frozen.p77, "R-JV-07: P-77");
            let concern = if i.later_call_published {
                IrcConcern::Deferred
            } else {
                IrcConcern::Declined
            };
            prop_assert_eq!(o.irc_concern, concern, "R-JV-07: NOTE 7");
            prop_assert_eq!(o.wording, wording(&v, &i), "R-JV-07: wording parameters");
            Ok(())
        },
    );
}

/// R-JV-07, section 6 "deterministic for identical inputs": equal inputs
/// give equal overlays, also through a clone of the version.
#[test]
fn r_jv_07_overlay_is_deterministic() {
    fstp_prop::check("r_jv_07_overlay_is_deterministic", |g: &mut Gen| {
        let v = version(g)?;
        let i = inputs(g);
        let a = compute(&v, &i);
        let b = compute(&v.clone(), &i.clone());
        prop_assert_eq!(&a, &b, "R-JV-07: two computations differ");
        prop_assert_eq!(compute(&v, &i), a, "R-JV-07: a third computation differs");
        Ok(())
    });
}

/// R-JV-07: a parameter outside section 5.5 never changes the overlay.
/// P-03, P-10, P-39 and the live P-05 change here, as does the opaque
/// text of every wording parameter, whose id alone the overlay carries.
#[test]
fn r_jv_07_overlay_ignores_parameters_outside_section_5_5() {
    fstp_prop::check(
        "r_jv_07_overlay_ignores_parameters_outside_section_5_5",
        |g: &mut Gen| {
            let v = version(g)?;
            let i = inputs(g);
            let mut w = v.clone();
            w.frozen.p03 = core::num::NonZeroU8::new(g.u8_in(1..=9)).ok_or("a P-03 value")?;
            w.frozen.p39 = core::num::NonZeroU8::new(g.u8_in(1..=9)).ok_or("a P-39 value")?;
            w.frozen.p10 = *g.pick(&[
                ReadAccess::AssignedReviewersOnly,
                ReadAccess::AllCommitteeMembers,
                ReadAccess::OperatorStaffOnly,
            ]);
            w.live.p05 = fstp_domain_testkit::r#gen::policy::eur(g.i64_in(0..=90_000_000))?;
            for p in WORDING_PARAMS {
                if let Some(value) = w.frozen.opaque.get_mut(&p) {
                    *value = opaque(&format!("other wording {}", g.u16()))?;
                }
                if let Some(value) = w.live.opaque.get_mut(&p) {
                    *value = opaque(&format!("other wording {}", g.u16()))?;
                }
            }
            prop_assert_eq!(compute(&w, &i), compute(&v, &i), "R-JV-07");
            Ok(())
        },
    );
}

/// I-97: with the canary as the text of every opaque parameter, the
/// overlay holds no part of it.
#[test]
fn i97_overlay_carries_no_policy_text() {
    fstp_prop::check("i97_overlay_carries_no_policy_text", |g: &mut Gen| {
        let mut v = version(g)?;
        let canary = opaque(CANARY)?;
        for value in v.frozen.opaque.values_mut() {
            *value = canary.clone();
        }
        for value in v.live.opaque.values_mut() {
            *value = canary.clone();
        }
        let o = compute(&v, &inputs(g));
        prop_assert!(
            !holds_canary(format!("{o:?}").as_bytes()),
            "I-97: the overlay holds the canary: {o:?}"
        );
        Ok(())
    });
}

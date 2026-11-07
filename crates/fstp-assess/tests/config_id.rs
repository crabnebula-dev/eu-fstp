//! I-11, R-LA-05: the `config_id` derivation (M7 design section 2,
//! reading 2). It is deterministic, and it changes when any pinned input
//! changes: provider, model, each decoding parameter, the prompt set, the
//! rubric and the call's P-01.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16};

use fstp_assess::{ConfigInput, Provider, RUBRIC_V1, Rubric, config_id};
use fstp_domain::id::{CriterionId, LlmConfigId};
use fstp_domain::scoring::{Criteria, Criterion};
use fstp_infer::{Decoding, ElementTag, ModelName};
use fstp_prop::{check, prop_assert_eq};

fn criteria(ids: &[(u128, u16)], scale: u8) -> Criteria {
    Criteria::new(
        NonZeroU8::new(scale).unwrap(),
        ids.iter()
            .map(|&(id, w)| Criterion {
                id: CriterionId::from_raw(id),
                weight: NonZeroU16::new(w).unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

const DECODING: Decoding = Decoding {
    max_tokens: 2048,
    temperature_milli: 0,
    seed: 1,
};

static RUBRIC_ALT: Rubric = Rubric::new("v1-alt", &[ElementTag::Problem, ElementTag::Approach]);

fn id(input: &ConfigInput<'_>) -> LlmConfigId {
    config_id(input).unwrap()
}

/// I-11: the same inputs give the same id, in every run and every order of
/// construction.
#[test]
fn i11_config_id_is_deterministic() {
    check("i11_config_id_is_deterministic", |g| {
        let model = ModelName::new(&format!("m-{}", g.u16())).unwrap();
        let p01 = criteria(
            &[(u128::from(g.u64()) | 1, g.u16_in(1..=1000))],
            g.u8_in(1..=100),
        );
        let dec = Decoding {
            max_tokens: g.u32(),
            temperature_milli: g.u16_in(0..=2000),
            seed: g.u32(),
        };
        let a = ConfigInput::pinned(Provider::ChatCompletions, &model, dec, &RUBRIC_V1, &p01);
        let (model2, p01b) = (model.clone(), p01.clone());
        let b = ConfigInput::pinned(Provider::ChatCompletions, &model2, dec, &RUBRIC_V1, &p01b);
        prop_assert_eq!(id(&a), id(&b));
        Ok(())
    });
}

/// I-11: each pinned input changes the id: provider, model, every
/// decoding parameter, the prompt set, the rubric, and the P-01 ids,
/// weights, scale and order.
#[test]
fn i11_config_id_changes_with_each_pinned_input() {
    let m = ModelName::new("model-a").unwrap();
    let m2 = ModelName::new("model-b").unwrap();
    let p01 = criteria(&[(0x11, 3), (0x22, 2)], 10);
    let base = ConfigInput::pinned(Provider::ChatCompletions, &m, DECODING, &RUBRIC_V1, &p01);

    let p01_ids = criteria(&[(0x11, 3), (0x23, 2)], 10);
    let p01_weights = criteria(&[(0x11, 3), (0x22, 1)], 10);
    let p01_scale = criteria(&[(0x11, 3), (0x22, 2)], 9);
    let p01_order = criteria(&[(0x22, 2), (0x11, 3)], 10);

    let mut variants = vec![base.clone()];
    variants.push(ConfigInput {
        provider: Provider::Synthetic,
        ..base.clone()
    });
    variants.push(ConfigInput {
        model: &m2,
        ..base.clone()
    });
    variants.push(ConfigInput {
        decoding: Decoding {
            max_tokens: 2049,
            ..DECODING
        },
        ..base.clone()
    });
    variants.push(ConfigInput {
        decoding: Decoding {
            temperature_milli: 1,
            ..DECODING
        },
        ..base.clone()
    });
    variants.push(ConfigInput {
        decoding: Decoding {
            seed: 2,
            ..DECODING
        },
        ..base.clone()
    });
    let mut prompts = base.prompt_set;
    prompts[0] ^= 1;
    variants.push(ConfigInput {
        prompt_set: prompts,
        ..base.clone()
    });
    variants.push(ConfigInput {
        rubric: &RUBRIC_ALT,
        ..base.clone()
    });
    variants.push(ConfigInput {
        criteria: &p01_ids,
        ..base.clone()
    });
    variants.push(ConfigInput {
        criteria: &p01_weights,
        ..base.clone()
    });
    variants.push(ConfigInput {
        criteria: &p01_scale,
        ..base.clone()
    });
    variants.push(ConfigInput {
        criteria: &p01_order,
        ..base.clone()
    });

    let ids: BTreeSet<LlmConfigId> = variants.iter().map(id).collect();
    assert_eq!(
        ids.len(),
        variants.len(),
        "every pinned input changes the id"
    );
    // The id is the pinned prompt set's: `pinned` takes the compiled digest.
    assert_eq!(base.prompt_set, fstp_infer::prompt_set_digest());
    assert_eq!(base.rubric.digest(), RUBRIC_V1.digest());
}

/// I-11: a fallback model gets its own id at the same moment (reading 3).
#[test]
fn i11_each_fallback_model_has_its_own_config_id() {
    let p01 = criteria(&[(0x11, 1)], 5);
    let models = ["primary", "fallback-1", "fallback-2"].map(|n| ModelName::new(n).unwrap());
    let ids: BTreeSet<LlmConfigId> = models
        .iter()
        .map(|m| {
            id(&ConfigInput::pinned(
                Provider::ChatCompletions,
                m,
                DECODING,
                &RUBRIC_V1,
                &p01,
            ))
        })
        .collect();
    assert_eq!(ids.len(), 3);
}

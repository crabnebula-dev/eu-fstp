//! The inference configuration record (P-21, NOTE 10, R-LA-04; M4 design
//! sections 3.5 and 13, lane W2d).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use fstp_domain::id::LlmConfigId;
use fstp_prop::{check, check_machine, prop_assert, prop_assert_eq};

use common::gens::{self, Focus, test_env, walk};
use common::machine::TenantMachine;
use common::reference::{Reference, models_valid, sample_inference_default};
use common::setup;
use common::vocab::{Inference, InferenceDefault, Op, RecordView, Step, StepInput, Verdict, acct};

/// P-21, R-LA-04: random inference records, valid and not, with every
/// other tenant operation and the Inference step's P-21 default, follow
/// the reference. The record survives a fold of the records alone.
#[test]
fn p21_inference_record_follows_the_reference_and_replays() {
    check_machine(
        "p21_inference_record_follows_the_reference_and_replays",
        &TenantMachine {
            env: test_env(),
            focus: Focus::Inference,
            max: 48,
        },
    );
}

/// The operations that validate every step up to Inference, with
/// `default` as the P-21 default.
fn through_inference(default: InferenceDefault) -> Vec<Op> {
    let mut ops = walk(acct(1), &Step::ALL[..5]);
    ops.push(Op::SaveStep {
        actor: acct(1),
        step: Step::Inference,
        input: StepInput::Inference(default),
    });
    ops
}

/// P-21, design 3.5: `call.publish` takes `config` and `config_model` from
/// the latest inference record, never from the client. Before any record
/// there is none, so publication fails closed.
#[test]
fn p21_publication_config_comes_from_the_latest_inference_record() {
    check(
        "p21_publication_config_comes_from_the_latest_inference_record",
        |g| {
            let env = test_env();
            let d = sample_inference_default();
            let ops = through_inference(d.clone());
            let mut sut = setup(&env, &ops)?;
            prop_assert_eq!(sut.publication_config().map_err(|e| e.to_string())?, None);
            let mut model = Reference::new(&env);
            for op in &ops {
                model.apply(op);
            }
            let n = g.usize_in(1..=6);
            for _ in 0..n {
                let (primary, fallbacks) = if g.bool() {
                    (d.primary.clone(), d.fallbacks.clone())
                } else {
                    (gens::model(g), gens::fallbacks(g))
                };
                let op = Op::RecordInference {
                    actor: acct(1),
                    config: LlmConfigId::from_raw(gens::small_id(g)),
                    primary,
                    fallbacks,
                };
                g.note("op", &op);
                let o = sut.run(&op).map_err(|e| e.to_string())?;
                prop_assert_eq!(o.verdict, model.verdict(&op));
                model.apply(&op);
                prop_assert_eq!(
                    sut.publication_config().map_err(|e| e.to_string())?,
                    model.publication_config()
                );
            }
            Ok(())
        },
    );
}

/// P-21 NOTE 10 (interim strict reading, pending Daniel): the record names
/// a primary model and an ordered list of fallbacks. Every name is
/// non-empty, the fallbacks are distinct, and none equals the primary. An
/// accepted record keeps the fallback order and appends one
/// `InferenceConfigRecorded` entry. The models come from the Inference
/// step, which validates under the same rule.
#[test]
fn p21_note10_fallbacks_are_ordered_distinct_and_exclude_the_primary() {
    check(
        "p21_note10_fallbacks_are_ordered_distinct_and_exclude_the_primary",
        |g| {
            let primary = gens::model(g);
            let fallbacks = gens::fallbacks(g);
            let config = LlmConfigId::from_raw(1);
            let default = InferenceDefault {
                provider: "synthetic-provider".to_string(),
                primary: primary.clone(),
                fallbacks: fallbacks.clone(),
            };
            let op = Op::RecordInference {
                actor: acct(1),
                config,
                primary: primary.clone(),
                fallbacks: fallbacks.clone(),
            };
            g.note("op", &op);
            let mut sut = setup(&test_env(), &walk(acct(1), &Step::ALL[..5]))?;
            let save = Op::SaveStep {
                actor: acct(1),
                step: Step::Inference,
                input: StepInput::Inference(default),
            };
            prop_assert_eq!(
                sut.run(&save).map_err(|e| e.to_string())?.verdict,
                Verdict::Accepted
            );
            let o = sut.run(&op).map_err(|e| e.to_string())?;
            let want = models_valid(&primary, &fallbacks);
            prop_assert_eq!(o.verdict == Verdict::Accepted, want);
            let seen = sut.observe().map_err(|e| e.to_string())?;
            if want {
                prop_assert!(o.records.contains(&RecordView::InferenceConfigRecorded {
                    config,
                    by: acct(1),
                }));
                prop_assert_eq!(
                    seen.inference,
                    Some(Inference {
                        config,
                        primary,
                        fallbacks,
                    })
                );
            } else {
                prop_assert!(o.records.is_empty());
                prop_assert_eq!(seen.inference, None);
            }
            Ok(())
        },
    );
}

/// P-21: a configuration id is recorded once. A second record under the
/// same id is refused and the first stays in force.
#[test]
fn p21_configuration_id_is_recorded_once() {
    let d = sample_inference_default();
    let record = Op::RecordInference {
        actor: acct(1),
        config: LlmConfigId::from_raw(3),
        primary: d.primary.clone(),
        fallbacks: d.fallbacks.clone(),
    };
    let run = || -> Result<(Verdict, Option<(LlmConfigId, String)>), String> {
        let mut sut = setup(&test_env(), &through_inference(d.clone()))?;
        let first = sut.run(&record).map_err(|e| e.to_string())?.verdict;
        if first != Verdict::Accepted {
            return Err("the first record was refused".to_string());
        }
        let v = sut.run(&record).map_err(|e| e.to_string())?.verdict;
        Ok((v, sut.publication_config().map_err(|e| e.to_string())?))
    };
    assert_eq!(
        run(),
        Ok((
            Verdict::Refused,
            Some((LlmConfigId::from_raw(3), "model-a".to_string()))
        ))
    );
}

/// P-21, design 3.5 ("The Inference step also records an
/// `InferenceConfigRecorded` entry", interim pending Daniel): the record
/// needs the validated Inference step and carries its models. Before the
/// step validates, and with other models, it is refused. So the model
/// `call.publish` takes is the P-21 default that prefills new drafts.
#[test]
fn p21_inference_record_carries_the_validated_step_models() {
    let d = sample_inference_default();
    let record = |config: u128, primary: &str, fallbacks: &[&str]| Op::RecordInference {
        actor: acct(1),
        config: LlmConfigId::from_raw(config),
        primary: primary.to_string(),
        fallbacks: fallbacks.iter().map(|f| f.to_string()).collect(),
    };
    let run = || -> Result<Vec<Verdict>, String> {
        let mut sut = setup(&test_env(), &walk(acct(1), &Step::ALL[..5]))?;
        let mut out = vec![
            sut.run(&record(1, "model-a", &["model-b"]))
                .map_err(|e| e.to_string())?
                .verdict,
        ];
        let save = Op::SaveStep {
            actor: acct(1),
            step: Step::Inference,
            input: StepInput::Inference(d.clone()),
        };
        out.push(sut.run(&save).map_err(|e| e.to_string())?.verdict);
        for op in [
            record(2, "model-c", &["model-b"]),
            record(3, "model-a", &[]),
            record(4, "model-a", &["model-b"]),
        ] {
            out.push(sut.run(&op).map_err(|e| e.to_string())?.verdict);
        }
        Ok(out)
    };
    use Verdict::{Accepted, Refused};
    assert_eq!(
        run(),
        Ok(vec![Refused, Accepted, Refused, Refused, Accepted])
    );
}

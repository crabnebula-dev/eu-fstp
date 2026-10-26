//! I-11 and P-21 NOTE 10: replacement of a call's findings through the
//! reference driver (`SPEC/02-domain/policy-parameters.md` NOTE 10,
//! `SPEC/04-llm-assessment/assessment.md`).
//!
//! The setup from genesis publishes call 1 with configuration 1 and call
//! 2 with configuration 2, under a frozen P-21 whose primary is model A.
//! A replacement takes the next model on the frozen fallback list. It
//! regenerates every finding of the call in one atomic step, so the
//! call's findings never mix configurations. A replacement names a
//! configuration the call never held, the published pin included, on
//! every regeneration. A refused replacement appends nothing and changes
//! nothing. Finding commands never touch the core (I-10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{CallId, LlmConfigId, ProposalId};
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::findings::{ASSESSOR, INJECTION_PHRASES, MODEL_C, finding, model};
use fstp_domain_testkit::r#gen::policy::{MODEL_A, MODEL_B};
use fstp_domain_testkit::r#gen::review::{PR1, PR2};
use fstp_domain_testkit::r#gen::roster::{T0, call};
use fstp_domain_testkit::mc::findings_model::{
    exec_finding, finding_record, pin_scenario, pin_scenario_with_fallbacks, store_of,
};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::ExecError;
use fstp_findings::{Finding, FindingCommand, FindingId, FindingKind, FindingRecord, FindingStore};

fn cfg(n: u128) -> LlmConfigId {
    LlmConfigId::from_raw(n)
}

fn f(id: u128, c: CallId, p: ProposalId, config: u128) -> Finding {
    finding(
        id,
        c,
        p,
        cfg(config),
        FindingKind::Quality,
        INJECTION_PHRASES[6],
    )
}

fn start() -> Scenario {
    pin_scenario()
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"))
        .0
}

fn run(s: &mut Scenario, cmd: FindingCommand) -> Result<fstp_ledger::Seq, ExecError> {
    exec_finding(s, cmd, ASSESSOR, T0).unwrap_or_else(|e| panic!("{e}"))
}

fn record(s: &mut Scenario, x: Finding) -> Result<fstp_ledger::Seq, ExecError> {
    run(s, FindingCommand::Record(x))
}

fn regenerate(
    s: &mut Scenario,
    c: CallId,
    config: u128,
    m: &str,
    findings: Vec<Finding>,
) -> Result<fstp_ledger::Seq, ExecError> {
    run(
        s,
        FindingCommand::Regenerate {
            call: c,
            config: cfg(config),
            config_model: model(m),
            findings,
        },
    )
}

fn store(s: &Scenario) -> FindingStore {
    store_of(&s.state().findings)
        .unwrap_or_else(|e| panic!("{e}"))
        .clone()
}

fn ids(s: &Scenario, c: CallId) -> Vec<u128> {
    store(s).findings_of(c).iter().map(|x| x.id.raw()).collect()
}

fn ledger_len(s: &Scenario) -> usize {
    s.entries().unwrap().len()
}

fn refused(r: Result<fstp_ledger::Seq, ExecError>, what: &str) -> fstp_domain::refusal::Refusal {
    match r {
        Err(ExecError::Refused(r)) => r,
        other => panic!("{what}: expected a refusal, got {other:?}"),
    }
}

/// I-11, P-21 NOTE 10: a replacement regenerates every finding of the call
/// in one step under the replacement configuration. The earlier findings
/// leave the call, their ids stay taken, other calls and the core are
/// untouched.
#[test]
fn i11_p21_replacement_regenerates_every_finding_of_the_call_at_once() {
    let mut s = start();
    record(&mut s, f(1, call(1), PR1, 1)).unwrap();
    record(&mut s, f(2, call(1), PR1, 1)).unwrap();
    record(&mut s, f(3, call(2), PR2, 2)).unwrap();
    let core = s.state().core.clone();
    let before = ledger_len(&s);

    regenerate(&mut s, call(1), 5, MODEL_B, vec![f(4, call(1), PR1, 5)]).unwrap();

    let entries = s.entries().unwrap();
    let batch: Vec<&FindingRecord> = entries[before..]
        .iter()
        .map(|e| finding_record(&e.record).unwrap_or_else(|| panic!("I-10: core record {e:?}")))
        .collect();
    assert!(
        matches!(
            batch.as_slice(),
            [FindingRecord::Regenerated { call: c, fallback: 0, config, findings, .. }]
                if *c == call(1) && *config == cfg(5) && findings.len() == 1
        ),
        "P-21 NOTE 10: one atomic regeneration at fallback 0, got {batch:?}"
    );
    let st = store(&s);
    assert_eq!(ids(&s, call(1)), vec![4]);
    assert_eq!(st.config_of(call(1)), Some(cfg(5)));
    assert_eq!(st.fallback_of(call(1)), Some(0));
    assert!(st.finding(FindingId::from_raw(1)).is_none());
    assert!(st.is_taken(FindingId::from_raw(1)) && st.is_taken(FindingId::from_raw(2)));
    assert_eq!(ids(&s, call(2)), vec![3]);
    assert_eq!(st.config_of(call(2)), Some(cfg(2)));
    assert_eq!(
        s.state().core,
        core,
        "I-10: a regeneration changed the core"
    );
}

/// I-11: a call stores only its pinned configuration, and after a
/// replacement only the replacement configuration. The old pin and the
/// retired ids are refused.
#[test]
fn i11_after_replacement_only_the_replacement_config_is_stored() {
    let mut s = start();
    let r = refused(
        record(&mut s, f(8, call(1), PR1, 2)),
        "call 2's pin in call 1",
    );
    assert_eq!(r.rule, RuleRef::I11, "I-11: the refusal names I-11: {r}");
    record(&mut s, f(1, call(1), PR1, 1)).unwrap();
    regenerate(&mut s, call(1), 5, MODEL_B, Vec::new()).unwrap();
    assert!(ids(&s, call(1)).is_empty());
    assert_eq!(store(&s).config_of(call(1)), Some(cfg(5)));

    let r = refused(
        record(&mut s, f(6, call(1), PR1, 1)),
        "the old pin after a replacement",
    );
    assert_eq!(r.rule, RuleRef::I11, "I-11: the refusal names I-11: {r}");
    refused(
        record(&mut s, f(1, call(1), PR1, 5)),
        "a retired finding id",
    );
    record(&mut s, f(7, call(1), PR1, 5)).unwrap();
    assert_eq!(ids(&s, call(1)), vec![7]);
}

/// I-11, P-21 NOTE 10: a replacement under the published pin, under the
/// primary or an unlisted model, of an unpublished call, or with a set
/// that mixes configurations, calls or taken ids is refused, appends
/// nothing and changes nothing.
#[test]
fn i11_replacement_refuses_the_pin_wrong_models_and_mixed_sets() {
    let mut s = start();
    record(&mut s, f(1, call(1), PR1, 1)).unwrap();
    let len = ledger_len(&s);
    let st = store(&s);
    let state = s.state().clone();
    let cases: Vec<(&str, CallId, u128, &str, Vec<Finding>)> = vec![
        (
            "the published pin",
            call(1),
            1,
            MODEL_B,
            vec![f(10, call(1), PR1, 1)],
        ),
        (
            "the primary model",
            call(1),
            5,
            MODEL_A,
            vec![f(11, call(1), PR1, 5)],
        ),
        (
            "an unlisted model",
            call(1),
            5,
            MODEL_C,
            vec![f(12, call(1), PR1, 5)],
        ),
        (
            "a mixed set",
            call(1),
            5,
            MODEL_B,
            vec![f(13, call(1), PR1, 5), f(14, call(1), PR1, 6)],
        ),
        (
            "another call's finding",
            call(1),
            5,
            MODEL_B,
            vec![f(15, call(2), PR2, 5)],
        ),
        (
            "a taken id",
            call(1),
            5,
            MODEL_B,
            vec![f(1, call(1), PR1, 5)],
        ),
        (
            "a repeated id",
            call(1),
            5,
            MODEL_B,
            vec![f(16, call(1), PR1, 5), f(16, call(1), PR1, 5)],
        ),
        ("an unpublished call", call(3), 5, MODEL_B, Vec::new()),
        ("an unknown call", call(9), 5, MODEL_B, Vec::new()),
    ];
    for (what, c, config, m, set) in cases {
        refused(regenerate(&mut s, c, config, m, set), what);
        assert_eq!(
            ledger_len(&s),
            len,
            "{what}: a refused replacement appended"
        );
        assert_eq!(
            store(&s),
            st,
            "{what}: a refused replacement changed the store"
        );
        assert_eq!(
            *s.state(),
            state,
            "{what}: a refused replacement changed the state"
        );
    }
}

/// P-21 NOTE 10: each replacement takes the next model on the frozen
/// list, so a list of one fallback allows one replacement per call.
#[test]
fn i11_p21_fallback_list_runs_out_after_its_last_model() {
    let mut s = start();
    record(&mut s, f(1, call(1), PR1, 1)).unwrap();
    regenerate(&mut s, call(1), 5, MODEL_B, vec![f(2, call(1), PR1, 5)]).unwrap();
    let len = ledger_len(&s);
    for (what, config, m) in [
        ("the same fallback again", 7, MODEL_B),
        ("the primary", 7, MODEL_A),
        ("an unlisted model", 7, MODEL_C),
    ] {
        refused(regenerate(&mut s, call(1), config, m, Vec::new()), what);
        assert_eq!(ledger_len(&s), len, "{what}: appended");
    }
    assert_eq!(ids(&s, call(1)), vec![2]);
    assert_eq!(store(&s).config_of(call(1)), Some(cfg(5)));
}

/// I-11, P-21 NOTE 10: a call without findings is regenerated too, and
/// every regeneration refuses the published pin and every configuration
/// the call held, not only the first one.
#[test]
fn i11_every_replacement_refuses_the_pin_and_held_configs() {
    let (mut s, _) = pin_scenario_with_fallbacks(vec![model(MODEL_B), model(MODEL_C)])
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"));
    refused(
        regenerate(&mut s, call(2), 2, MODEL_B, Vec::new()),
        "the published pin of a call without findings",
    );
    regenerate(&mut s, call(2), 8, MODEL_B, Vec::new()).unwrap();
    assert_eq!(store(&s).config_of(call(2)), Some(cfg(8)));
    refused(record(&mut s, f(1, call(2), PR2, 2)), "the old pin");
    record(&mut s, f(2, call(2), PR2, 8)).unwrap();
    for (what, config) in [("the published pin", 2), ("the held replacement", 8)] {
        refused(
            regenerate(&mut s, call(2), config, MODEL_C, Vec::new()),
            what,
        );
    }
    regenerate(&mut s, call(2), 9, MODEL_C, vec![f(3, call(2), PR2, 9)]).unwrap();
    assert_eq!(ids(&s, call(2)), vec![3]);
    assert_eq!(store(&s).fallback_of(call(2)), Some(1));
}

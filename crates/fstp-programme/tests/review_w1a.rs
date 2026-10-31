//! Review reproducers for lane m4w1a (R-PG-01, R-PG-04, I-51, I-52).
//!
//! Each test fails against the code under review and passes once the
//! defect it names is fixed.

use std::collections::BTreeSet;

use fstp_domain::id::{CallId, ClassId, PolicyVersionId, ProgrammeId};
use fstp_domain::policy::{ExclusionClasses, LiveSnapshot, PolicyVersion};
use fstp_domain::rules::ParamId;
use fstp_money::{Amount, Currency, NonNegAmount};
use fstp_programme::{
    CallFacts, CompileIds, FIELDS, FieldId, FieldKind, FunderProfile, ImpactEffect,
    PublishedLimits, compile, impact_on, supersafe_fixture,
};

fn eur(minor: i64) -> Result<NonNegAmount, String> {
    match Amount::from_minor(minor, Currency::Eur).map(NonNegAmount::new) {
        Ok(Ok(a)) => Ok(a),
        _ => Err(format!("bad test amount {minor}")),
    }
}

/// The compiled SuperSAFE policy: P-05 400000.00, P-58 400000.00, P-13 {1, 2}.
fn supersafe() -> Result<PolicyVersion, String> {
    let spec = supersafe_fixture().map_err(|e| e.to_string())?.spec;
    let ids = CompileIds::new(ProgrammeId::from_raw(1), PolicyVersionId::from_raw(2), None);
    compile(&spec, &FunderProfile::horizon_europe(), ids)
        .map(|c| c.policy)
        .map_err(|e| e.to_string())
}

fn one(facts: &CallFacts, field: FieldId, next: &PolicyVersion) -> Result<ImpactEffect, String> {
    let out = impact_on(std::slice::from_ref(facts), &BTreeSet::from([field]), next);
    match out.as_slice() {
        [i] => Ok(i.effect.clone()),
        other => Err(format!("expected one impact, got {other:?}")),
    }
}

/// The value of a helper result, or a test failure with its message.
macro_rules! ok {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        }
    };
}

/// R-PG-04, I-51, NOTE 7 (Q37 C, D12): a published call keeps its
/// publication values plus every later tightening. P-05 was 400000.00 at
/// publication and was tightened to 300000.00 by a corrigendum. Raising the
/// live value to 350000.00 must not loosen the published call, or the
/// Guide read with its corrigenda no longer equals the enforced limit.
#[test]
fn review_r_pg_04_p05_loosening_after_tightening_reaches_no_published_call() {
    let v = ok!(supersafe());
    let facts = CallFacts {
        call: CallId::from_raw(10),
        published: Some(PublishedLimits {
            snapshot: LiveSnapshot {
                p05: ok!(eur(40_000_000)),
                p13: v.live.p13.clone(),
            },
            p05: ok!(eur(30_000_000)),
            p13: v.live.p13.0.clone(),
        }),
    };
    let mut next = v.clone();
    next.live.p05 = ok!(eur(35_000_000));
    assert_eq!(
        ok!(one(&facts, FieldId::P05, &next)),
        ImpactEffect::NextCallOnly,
        "a loosening after a corrigendum is reported as reaching the published call"
    );
}

/// R-PG-04, I-51, NOTE 7 (Q37 C, D12): P-13 class 9 was added after
/// publication by a corrigendum. Removing it again from the live value must
/// not loosen the published call.
#[test]
fn review_r_pg_04_p13_removal_after_tightening_reaches_no_published_call() {
    let v = ok!(supersafe());
    let mut enforced = v.live.p13.0.clone();
    enforced.insert(ClassId::from_raw(9));
    let facts = CallFacts {
        call: CallId::from_raw(10),
        published: Some(PublishedLimits {
            snapshot: LiveSnapshot {
                p05: v.live.p05,
                p13: v.live.p13.clone(),
            },
            p05: v.live.p05,
            p13: enforced,
        }),
    };
    let mut next = v.clone();
    next.live.p13 = ExclusionClasses(v.live.p13.0.clone());
    assert_eq!(
        ok!(one(&facts, FieldId::P13, &next)),
        ImpactEffect::NextCallOnly,
        "a P-13 removal after a corrigendum is reported as reaching the published call"
    );
}

/// R-PG-01, I-52: M4 design section 3.1 gives steps 1, 3, 6 and 10 fields
/// beyond their parameters: the action number (step 1), the persons
/// supported and minors (step 3), the amount criteria (step 6), and the
/// message templates and FAQ (step 10). The Guide binds `{{action.number}}`,
/// `{{eligibility.persons}}`, `{{annexe.amount_criteria}}` and
/// `{{programme.faq}}` to them. Each of these steps needs an artefact field.
#[test]
fn review_r_pg_01_creator_steps_hold_their_artefact_fields() {
    let missing: Vec<u8> = [1_u8, 3, 6, 10]
        .into_iter()
        .filter(|n| {
            !FIELDS
                .iter()
                .any(|f| f.step.number() == *n && f.kind == FieldKind::Artefact)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "creator steps with no artefact field for what they capture: {missing:?}"
    );
}

/// R-PG-01, R-CT-01: P-29 is "Contract instrument and template version",
/// and `contracts.md` freezes the template version at call publication.
/// The compiled SuperSAFE P-29 holds only the instrument, so no template
/// version freezes.
#[test]
fn review_r_pg_01_p29_freezes_a_template_version() {
    let v = ok!(supersafe());
    let p29 = match v.frozen.opaque.get(&ParamId::P29) {
        Some(o) => o.as_str().to_owned(),
        None => panic!("P-29 is not in the frozen policy"),
    };
    assert!(
        p29.contains("template"),
        "P-29 freezes no template version: {p29}"
    );
}

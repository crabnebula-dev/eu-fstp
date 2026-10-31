//! Self-tests of the W1a test author's readings against the spec (R-PG-01).
//!
//! These tests name no `fstp-programme` item. They check that the
//! references in `tests/support/readings.rs` still match `SPEC/` and
//! `CATALOGUE`, so the tests that use them check the crate against the
//! spec and not against a stale reading.

mod support;

use std::collections::BTreeSet;

use fstp_domain::policy::{TYPED_FROZEN, TYPED_LIVE, is_frozen_opaque, is_live_opaque};
use fstp_domain::rules::{CATALOGUE, Level, ParamId};

use support::readings::{
    DESIGN_PLACEMENT, DESIGN_SYNTHETIC, Reading, UNLISTED_IN_CREATOR_TABLE, placement, readings,
    synthetic,
};
use support::spec::{creator_steps, onboarding_params, param_rows};

fn programme_level() -> BTreeSet<ParamId> {
    CATALOGUE
        .iter()
        .filter(|s| s.level == Level::Programme)
        .map(|s| s.id)
        .collect()
}

/// R-PG-01, Q36: `UNLISTED_IN_CREATOR_TABLE` is exactly the set of
/// programme-level parameters that no "Bounded by" cell of the creator
/// table names. It holds every parameter M4 design section 3.1 lists as
/// unlisted, and the onboarding parameters that are programme level.
#[test]
fn r_pg_01_unlisted_in_creator_table_matches_spec() {
    let steps = match creator_steps() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let named: BTreeSet<ParamId> = steps
        .iter()
        .flat_map(|s| s.bounds.params.iter().copied())
        .collect();
    let unlisted: BTreeSet<ParamId> = UNLISTED_IN_CREATOR_TABLE.iter().copied().collect();
    assert_eq!(
        unlisted.len(),
        UNLISTED_IN_CREATOR_TABLE.len(),
        "UNLISTED_IN_CREATOR_TABLE repeats a parameter"
    );
    let want: BTreeSet<ParamId> = programme_level().difference(&named).copied().collect();
    assert_eq!(
        unlisted, want,
        "UNLISTED_IN_CREATOR_TABLE differs from the spec"
    );
    for p in &named {
        assert_eq!(
            p.spec().map(|s| s.level),
            Some(Level::Programme),
            "the creator table names {p:?}, which is not programme level"
        );
    }

    use ParamId::*;
    for p in [P06, P12, P19, P22, P39, P42, P43, P46, P47, P48, P49] {
        assert!(
            unlisted.contains(&p),
            "{p:?} is unlisted in M4 design 3.1 but not here"
        );
    }
    let onboarding = match onboarding_params() {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    let onboarding: BTreeSet<ParamId> = onboarding.into_iter().map(|(_, p)| p).collect();
    assert_eq!(
        onboarding,
        [P18, P20, P21, P45].into_iter().collect::<BTreeSet<_>>(),
        "the onboarding table names other parameters than this reading expects"
    );
    for p in [P18, P21, P45] {
        assert!(
            unlisted.contains(&p),
            "{p:?} is programme level and named only in onboarding"
        );
    }
}

/// R-PG-01, Q36: `DESIGN_PLACEMENT` places every programme-level parameter
/// in exactly one of the creator steps 1 to 10. It agrees with the creator
/// table for every parameter the table names, and places no tenant-level
/// or fixed parameter.
#[test]
fn r_pg_01_design_placement_agrees_with_creator_table() {
    let steps = match creator_steps() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let numbers: Vec<u8> = steps.iter().map(|s| s.number).collect();
    assert_eq!(
        numbers,
        (1..=11).collect::<Vec<u8>>(),
        "the creator table no longer has steps 1 to 11"
    );

    let mut placed = Vec::new();
    for (step, ps) in DESIGN_PLACEMENT {
        assert!(
            (1..=10).contains(step),
            "placement in step {step}, outside 1 to 10"
        );
        placed.extend(ps.iter().copied());
    }
    let unique: BTreeSet<ParamId> = placed.iter().copied().collect();
    assert_eq!(unique.len(), placed.len(), "a parameter is placed twice");
    assert_eq!(
        unique,
        programme_level(),
        "the placement does not cover exactly the programme-level parameters"
    );

    for s in &steps {
        for p in &s.bounds.params {
            assert_eq!(
                placement(*p),
                Some(s.number),
                "the creator table names {p:?} in step {}",
                s.number
            );
        }
    }
}

/// R-PG-01: the SuperSAFE readings cover every row of both parameter
/// tables once, each made from the cell the spec holds today. Each kind of
/// reading fits the parameter's place in `PolicyVersion`, and every
/// opaque JSON text holds no fractional number, since amounts travel as
/// ADR-006 strings.
#[test]
fn r_pg_01_supersafe_readings_match_the_spec_column() {
    let rows = match param_rows() {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let ours = readings();
    let spec_ids: Vec<ParamId> = rows.iter().map(|r| r.id).collect();
    let our_ids: Vec<ParamId> = ours.iter().map(|r| r.id).collect();
    assert_eq!(
        our_ids, spec_ids,
        "readings and spec rows differ in ids or order"
    );
    assert_eq!(
        our_ids,
        ParamId::ALL.to_vec(),
        "readings not in catalogue order"
    );

    for (row, reading) in rows.iter().zip(&ours) {
        let p = row.id;
        assert_eq!(
            reading.cell, row.supersafe,
            "{p:?}: the spec cell changed, so revisit its reading"
        );
        let level = p.spec().map(|s| s.level);
        let typed = TYPED_FROZEN.contains(&p) || TYPED_LIVE.contains(&p);
        let opaque = is_frozen_opaque(p) || is_live_opaque(p);
        match reading.reading {
            Reading::NotProgramme => {
                assert_ne!(level, Some(Level::Programme), "{p:?} is programme level")
            }
            Reading::Typed(_) => assert!(typed, "{p:?} has no typed field in PolicyVersion"),
            Reading::Opaque(text) => {
                assert!(opaque, "{p:?} is not an opaque parameter");
                let v = match fstp_json::parse_str(text) {
                    Ok(v) => v,
                    Err(e) => panic!("{p:?}: reading {text:?} is not JSON: {e:?}"),
                };
                assert!(
                    no_fraction(&v),
                    "{p:?}: reading {text:?} holds a fractional number"
                );
            }
            Reading::Synthetic(gap) => {
                assert_eq!(
                    level,
                    Some(Level::Programme),
                    "{p:?} is not programme level"
                );
                assert!(!gap.is_empty(), "{p:?}: a synthetic reading names its gap");
            }
            Reading::PartlySynthetic(text, gap) => {
                assert!(opaque, "{p:?} is not an opaque parameter");
                assert_eq!(
                    level,
                    Some(Level::Programme),
                    "{p:?} is not programme level"
                );
                assert!(!gap.is_empty(), "{p:?}: a synthetic reading names its gap");
                let v = match fstp_json::parse_str(text) {
                    Ok(v) => v,
                    Err(e) => panic!("{p:?}: reading {text:?} is not JSON: {e:?}"),
                };
                assert!(
                    no_fraction(&v),
                    "{p:?}: reading {text:?} holds a fractional number"
                );
            }
        }
    }

    let synth = synthetic();
    for p in DESIGN_SYNTHETIC {
        assert!(synth.contains(p), "M4 design 3.1 lists {p:?} as synthetic");
    }
}

/// Whether no number in `v` has a fraction or an exponent.
fn no_fraction(v: &fstp_json::Value) -> bool {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            fstp_json::Value::Number(n) => {
                if !n.is_integer() || n.as_str().contains(['.', 'e', 'E']) {
                    return false;
                }
            }
            fstp_json::Value::Array(a) => stack.extend(a.iter()),
            fstp_json::Value::Object(o) => stack.extend(o.values()),
            _ => {}
        }
    }
    true
}

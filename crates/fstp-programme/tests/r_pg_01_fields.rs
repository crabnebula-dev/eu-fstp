//! The `FIELDS` table against the creator table, `CATALOGUE` and the
//! interim placement of M4 design section 3.1 (R-PG-01, I-50, I-73, Q36).
//!
//! The creator table of `SPEC/02-domain/programme-creator.md` is read at
//! test time. Parameters it names nowhere follow `DESIGN_PLACEMENT`, which
//! is interim, pending Daniel (Q36).

mod support;
mod target_api;

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{CATALOGUE, Level, ParamId};
use fstp_programme::{FIELDS, FieldId, FieldKind};

use support::readings::{UNLISTED_IN_CREATOR_TABLE, placement};
use support::spec::creator_steps;

/// The steps of the fields that set `p`.
fn steps_setting(p: ParamId) -> Vec<u8> {
    FIELDS
        .iter()
        .filter(|f| f.params.contains(&p))
        .map(|f| f.step.number())
        .collect()
}

/// R-PG-01: every parameter a "Bounded by" cell of the creator table names
/// is set by a field of that step. Every other programme-level parameter
/// with a field is in `UNLISTED_IN_CREATOR_TABLE`, which equals the
/// programme-level parameters the table leaves out, and sits in its
/// interim step (Q36). No field sits in step 11, the review step.
#[test]
fn r_pg_01_creator_table_maps_to_fields() {
    let steps = match creator_steps() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let mut named = BTreeSet::new();
    for s in &steps {
        for p in &s.bounds.params {
            named.insert(*p);
            let found = steps_setting(*p);
            assert!(
                !found.is_empty(),
                "step {} ({}) names {p:?}, but no field sets it",
                s.number,
                s.name
            );
            assert!(
                found.iter().all(|n| *n == s.number),
                "step {} names {p:?}, but its fields sit in steps {found:?}",
                s.number
            );
        }
    }

    let unlisted: BTreeSet<ParamId> = UNLISTED_IN_CREATOR_TABLE.iter().copied().collect();
    let programme: BTreeSet<ParamId> = CATALOGUE
        .iter()
        .filter(|s| s.level == Level::Programme)
        .map(|s| s.id)
        .collect();
    let left_out: BTreeSet<ParamId> = programme.difference(&named).copied().collect();
    assert_eq!(
        unlisted, left_out,
        "UNLISTED_IN_CREATOR_TABLE differs from the spec"
    );

    for f in FIELDS {
        let n = f.step.number();
        assert!(
            (1..=10).contains(&n),
            "field {:?} sits in step {n}, outside the steps 1 to 10",
            f.id
        );
        for p in f.params {
            if named.contains(p) {
                continue;
            }
            assert!(
                unlisted.contains(p),
                "field {:?} sets {p:?}, which the creator table does not name \
                 and which is not in UNLISTED_IN_CREATOR_TABLE",
                f.id
            );
            assert_eq!(
                Some(n),
                placement(*p),
                "field {:?} places {p:?} in step {n}; the interim placement differs (Q36)",
                f.id
            );
        }
    }
}

/// R-PG-01: every programme-level parameter of `CATALOGUE` is set by
/// exactly one field, of kind `Policy`. No field sets a tenant-level or
/// fixed parameter: those come from `fstp-tenant` or are not configurable.
#[test]
fn r_pg_01_every_programme_parameter_has_one_field() {
    for spec in CATALOGUE {
        let p = spec.id;
        let setting: Vec<FieldId> = FIELDS
            .iter()
            .filter(|f| f.params.contains(&p))
            .map(|f| f.id)
            .collect();
        match spec.level {
            Level::Programme => {
                assert_eq!(
                    setting.len(),
                    1,
                    "{p:?} is set by the fields {setting:?}, not by exactly one"
                );
                for f in FIELDS.iter().filter(|f| f.params.contains(&p)) {
                    assert_eq!(
                        f.kind,
                        FieldKind::Policy,
                        "field {:?} sets {p:?} but is not a policy field",
                        f.id
                    );
                }
            }
            Level::Tenant | Level::Fixed => assert!(
                setting.is_empty(),
                "{p:?} is {:?}, but the fields {setting:?} set it",
                spec.level
            ),
        }
    }
}

/// R-PG-01: the `FIELDS` table is well formed. It holds each `FieldId`
/// once and every `FieldId` has its row. A field is a policy field exactly
/// when it sets parameters, and it names each parameter once.
#[test]
fn r_pg_01_fields_table_is_well_formed() {
    let ids: Vec<FieldId> = target_api::field_ids();
    let unique: BTreeSet<FieldId> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "a FieldId has two rows");
    let all: BTreeSet<FieldId> = FieldId::ALL.iter().copied().collect();
    assert_eq!(all.len(), FieldId::ALL.len(), "FieldId::ALL repeats an id");
    assert_eq!(unique, all, "FIELDS and FieldId::ALL differ");

    for f in FIELDS {
        let params: BTreeSet<ParamId> = f.params.iter().copied().collect();
        assert_eq!(
            params.len(),
            f.params.len(),
            "field {:?} names a parameter twice",
            f.id
        );
        assert_eq!(
            f.kind == FieldKind::Policy,
            !f.params.is_empty(),
            "field {:?} is {:?} with parameters {:?}",
            f.id,
            f.kind,
            f.params
        );
    }

    let mut per_step: BTreeMap<u8, usize> = BTreeMap::new();
    for f in FIELDS {
        let e = per_step.entry(f.step.number()).or_insert(0);
        *e = e.saturating_add(1);
    }
    for n in 1..=10_u8 {
        assert!(
            per_step.get(&n).copied().unwrap_or(0) > 0,
            "creator step {n} has no field"
        );
    }
}

/// I-73, R-PG-01: people are never part of a programme spec. Creator
/// step 9 holds only the cooling-off policy P-12. Invitations and grants
/// are creator records, never fields.
#[test]
fn i73_r_pg_01_people_step_holds_policy_only() {
    let step9: Vec<_> = FIELDS.iter().filter(|f| f.step.number() == 9).collect();
    assert!(!step9.is_empty(), "step 9 has no P-12 field");
    for f in &step9 {
        assert_eq!(
            f.kind,
            FieldKind::Policy,
            "step 9 field {:?} is not policy",
            f.id
        );
        assert_eq!(
            f.params,
            &[ParamId::P12][..],
            "step 9 field {:?} sets {:?}, not P-12 alone",
            f.id,
            f.params
        );
    }
}

/// I-50, R-PG-01 AC: the per-recipient cap P-05 has a field of its own,
/// bounded by I-50 against the funder ceiling P-58.
#[test]
fn i50_r_pg_01_cap_field_is_bound_by_i50() {
    let cap: Vec<_> = FIELDS
        .iter()
        .filter(|f| f.params.contains(&ParamId::P05))
        .collect();
    assert_eq!(cap.len(), 1, "P-05 is set by {} fields", cap.len());
    for f in cap {
        assert_eq!(f.params, &[ParamId::P05][..], "the P-05 field sets more");
        assert!(
            f.bound_by.contains(&RuleRef::I50),
            "the P-05 field {:?} is not bound by I-50: {:?}",
            f.id,
            f.bound_by
        );
    }
}

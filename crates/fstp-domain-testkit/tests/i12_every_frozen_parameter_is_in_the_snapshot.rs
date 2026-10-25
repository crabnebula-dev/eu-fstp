//! I-12, pure: every frozen parameter is part of the frozen snapshot (design 6.2).
//!
//! "Policy parameters marked frozen are immutable for a call once it is
//! published" (I-12). The snapshot is `FrozenValues`. A frozen parameter
//! is either one of its typed fields or a key of its opaque map, so every
//! frozen parameter freezes, interpreted or not (design 2.4 and 9.1 item 5).
//!
//! The frozen and live sets come from the Frozen column of
//! `SPEC/02-domain/policy-parameters.md`, parsed at test time by the
//! reference. The typed fields come from exhaustive destructuring, so a
//! field added to or removed from the structs fails to compile here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_domain::policy::{
    CATALOGUE, Freeze, FrozenValues, InferenceBinding, Level, LiveSnapshot, LiveValues,
};
use fstp_domain_testkit::r#gen::policy::{FROZEN_OPAQUE, LIVE_OPAQUE, base_version};
use fstp_domain_testkit::reference::policy::{
    TYPED_FROZEN, TYPED_LIVE, allowed_live_opaque, expected_frozen_opaque, spec_frozen, spec_live,
};

/// The P-ids of the typed `FrozenValues` fields. The destructuring has no
/// `..`, so every field is named here, each with the parameter it holds.
fn typed_frozen_fields(v: &FrozenValues) -> BTreeSet<&'static str> {
    let FrozenValues {
        p01: _,
        p02: _,
        p03: _,
        p04: _,
        p07: _,
        p09: _,
        p10: _,
        p11: _,
        p14: _,
        p15: _,
        p16: _,
        p17: _,
        p21: _,
        p24: _,
        p26: _,
        p39: _,
        p53: _,
        p77: _,
        opaque: _,
    } = v;
    [
        "P-01", "P-02", "P-03", "P-04", "P-07", "P-09", "P-10", "P-11", "P-14", "P-15", "P-16",
        "P-17", "P-21", "P-24", "P-26", "P-39", "P-53", "P-77",
    ]
    .into_iter()
    .collect()
}

/// The P-ids of the typed `LiveValues` fields, destructured without `..`.
fn typed_live_fields(v: &LiveValues) -> BTreeSet<&'static str> {
    let LiveValues {
        p05: _,
        p12: _,
        p13: _,
        p38: _,
        p56: _,
        p58: _,
        opaque: _,
    } = v;
    ["P-05", "P-12", "P-13", "P-38", "P-56", "P-58"]
        .into_iter()
        .collect()
}

fn base() -> fstp_domain::policy::PolicyVersion {
    base_version(PolicyVersionId::from_raw(1), ProgrammeId::from_raw(1), None).expect("base")
}

/// I-12: every frozen programme parameter of the spec is a typed field of
/// `FrozenValues` or one of the opaque keys, and nothing else is frozen.
/// The fixture policy holds exactly those opaque keys.
#[test]
fn i12_every_frozen_parameter_is_in_the_snapshot() {
    let frozen = spec_frozen().expect("spec");
    let v = base();
    let typed = typed_frozen_fields(&v.frozen);
    assert_eq!(
        typed,
        TYPED_FROZEN.into_iter().collect(),
        "the reference list of typed frozen fields follows the struct"
    );
    let typed_not_frozen: Vec<_> = typed.iter().filter(|p| !frozen.contains(**p)).collect();
    assert!(
        typed_not_frozen.is_empty(),
        "I-12: typed frozen fields hold parameters the spec does not freeze: {typed_not_frozen:?}"
    );
    let opaque = expected_frozen_opaque().expect("spec");
    let union: BTreeSet<String> = typed
        .iter()
        .map(|p| (*p).to_owned())
        .chain(opaque.iter().cloned())
        .collect();
    assert_eq!(
        union, frozen,
        "I-12: typed fields and opaque keys together are exactly the frozen parameters"
    );
    let fixture: BTreeSet<String> = v
        .frozen
        .opaque
        .keys()
        .map(|k| k.spec_id().to_owned())
        .collect();
    assert_eq!(
        fixture, opaque,
        "the fixture freezes every untyped frozen parameter"
    );
    let listed: BTreeSet<String> = FROZEN_OPAQUE
        .iter()
        .map(|k| k.spec_id().to_owned())
        .collect();
    assert_eq!(listed, opaque);
}

/// I-12: the catalogue marks as frozen at programme level exactly the
/// parameters the spec's Frozen column marks "Yes".
#[test]
fn i12_catalogue_freezes_exactly_the_spec_frozen_parameters() {
    let frozen = spec_frozen().expect("spec");
    let catalogue: BTreeSet<String> = CATALOGUE
        .iter()
        .filter(|s| s.freeze == Freeze::Frozen && s.level == Level::Programme)
        .map(|s| s.id.spec_id().to_owned())
        .collect();
    assert_eq!(catalogue, frozen);
}

/// I-12 with R-PC-02 NOTE 1: no live parameter is frozen. The typed live
/// fields are live programme parameters, and the fixture's live opaque keys
/// are exactly the untyped live programme parameters.
#[test]
fn i12_no_live_parameter_is_frozen() {
    let live = spec_live().expect("spec");
    let v = base();
    let typed = typed_live_fields(&v.live);
    assert_eq!(typed, TYPED_LIVE.into_iter().collect());
    for p in &typed {
        assert!(
            live.contains(*p),
            "{p} is a typed live field but the spec freezes it"
        );
    }
    let fixture: BTreeSet<String> = v
        .live
        .opaque
        .keys()
        .map(|k| k.spec_id().to_owned())
        .collect();
    assert_eq!(fixture, allowed_live_opaque().expect("spec"));
    let listed: BTreeSet<String> = LIVE_OPAQUE.iter().map(|k| k.spec_id().to_owned()).collect();
    assert_eq!(listed, fixture);
    let frozen = spec_frozen().expect("spec");
    assert!(fixture.is_disjoint(&frozen));
}

/// I-12 with NOTE 7: the publication snapshot holds P-05 and P-13, which
/// stay live; NOTE 10: the frozen P-21 holds a primary model and an
/// ordered fallback list. Both are destructured without `..`.
#[test]
fn i12_snapshot_and_p21_hold_what_notes_7_and_10_name() {
    let live = spec_live().expect("spec");
    let frozen = spec_frozen().expect("spec");
    assert!(live.contains("P-05") && live.contains("P-13"));
    assert!(frozen.contains("P-21"));
    let v = base();
    let snapshot = LiveSnapshot {
        p05: v.live.p05,
        p13: v.live.p13.clone(),
    };
    let LiveSnapshot { p05: _, p13: _ } = &snapshot;
    let InferenceBinding {
        provider: _,
        primary,
        fallbacks,
    } = &v.frozen.p21;
    assert!(
        !fallbacks.contains(primary),
        "the fixture's fallbacks are other models than the primary"
    );
}

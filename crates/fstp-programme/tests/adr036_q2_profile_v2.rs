//! ADR-036 section 8 (Daniel, 2026-11-23, "everything v2"): the programme
//! compiler pins horizon-europe profile v2 for new programmes, still reads
//! a v1 spec, and moves it to v2 when it compiles (P-53, R-PG-01).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::num::NonZeroU16;

use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_programme::{CompileError, CompileIds, Field, FunderProfile, compile};

fn ids() -> CompileIds {
    CompileIds::new(ProgrammeId::from_raw(1), PolicyVersionId::from_raw(1), None)
}

fn v(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap()
}

/// The compiled P-53 text of `spec` under `profile`.
fn p53_of(spec: &fstp_programme::ProgrammeSpec, profile: &FunderProfile) -> String {
    compile(spec, profile, ids())
        .unwrap()
        .policy
        .frozen
        .p53
        .0
        .as_str()
        .to_owned()
}

/// ADR-036 section 8: a new programme pins v2. The blank spec and the
/// compiled policy name version 2.
#[test]
fn adr036_q2_new_programmes_pin_v2() {
    let he = FunderProfile::horizon_europe();
    assert_eq!(he.reference().version, v(2));
    assert_eq!(he.reference().profile.as_str(), "horizon-europe");
    let p53 = p53_of(&he.blank(), &he);
    assert!(p53.contains(r#""version":2"#), "{p53}");
    assert_eq!(FunderProfile::horizon_europe_v1().reference().version, v(1));
}

/// ADR-036 section 8: a spec that still pins v1 compiles under the current
/// profile, and the compiled policy pins v2. That is the recorded move: the
/// core `EditPolicy` of the next policy version holds it.
#[test]
fn adr036_q2_v1_spec_compiles_to_v2() {
    let he = FunderProfile::horizon_europe();
    let mut spec = he.blank();
    spec.funder.p53_funder_profile = Field::Set(FunderProfile::horizon_europe_v1().reference());
    let p53 = p53_of(&spec, &he);
    assert!(p53.contains(r#""version":2"#), "{p53}");
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let p53 = p53_of(&fixture.spec, &he);
    assert!(
        p53.contains(r#""version":2"#),
        "the SuperSAFE fixture: {p53}"
    );
}

/// ADR-036 section 8: a P-53 reference of v1 or v2 names the current
/// profile, v2. Any other version names none, and a spec pinning a newer
/// version than the compiling profile is refused.
#[test]
fn adr036_q2_policy_refs_of_v1_and_v2_name_the_current_profile() {
    let current = FunderProfile::horizon_europe();
    for p in [FunderProfile::horizon_europe_v1(), current] {
        let r = p.policy_ref().unwrap();
        assert_eq!(FunderProfile::for_policy_ref(&r), Some(current));
    }
    let mut other = current.reference();
    other.version = v(3);
    let mut spec = current.blank();
    spec.funder.p53_funder_profile = Field::Set(other);
    assert_eq!(
        compile(&spec, &current, ids()),
        Err(CompileError::ProfileMismatch)
    );
    let mut spec = current.blank();
    spec.funder.p53_funder_profile = Field::Set(current.reference());
    assert_eq!(
        compile(&spec, &FunderProfile::horizon_europe_v1(), ids()),
        Err(CompileError::ProfileMismatch),
        "v1 does not compile a v2 spec"
    );
}

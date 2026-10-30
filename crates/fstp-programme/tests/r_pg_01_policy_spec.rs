//! The policy part of a spec, which the creator edits a draft policy
//! with (R-PG-01, I-51; M4 design sections 3.1 and 3.2).

mod support;
mod target_api;

use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_json::Value;
use fstp_programme::{FIELDS, FieldKind, FunderProfile, policy_spec};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use target_api::{
    compile, compile_with, decompile_unset, fixture_spec_value, gen_spec, gen_unset, ids,
    strings_in,
};

/// R-PG-01, I-51: `compile` of `policy_spec` of a compiled policy, with
/// the same ids, gives that policy back, gaps included. So a creator save
/// that compiles the head policy with the saved values changes no other
/// parameter.
#[test]
fn r_pg_01_i51_policy_spec_compiles_back_to_its_policy() {
    let base = match fixture_spec_value() {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let strings = strings_in(&base);
    check("r_pg_01_i51_policy_spec_compiles_back_to_its_policy", |g| {
        let Some(s) = gen_spec(g, &base, &strings) else {
            g.reject()
        };
        let Ok(c) = compile(&s) else { g.reject() };
        let unset = gen_unset(g);
        g.note("unset", &unset);
        let Ok(c) = compile(&decompile_unset(&c, &unset)) else {
            g.reject()
        };
        let spec = policy_spec(&c.policy);
        let artefact_set = FIELDS
            .iter()
            .any(|f| f.kind == FieldKind::Artefact && spec.get(f.id).is_set());
        prop_assert!(!artefact_set, "policy_spec sets an artefact field");
        let back = compile_with(&spec, ids())?;
        prop_assert_eq!(back.policy, c.policy);
        Ok(())
    });
}

/// R-PG-01 (P-53): the Horizon Europe profile names the P-53 value its
/// compiled policies hold, and no other value names a profile.
#[test]
fn r_pg_01_profile_names_its_policy_reference() {
    let he = FunderProfile::horizon_europe();
    let compiled = match compile(&he.blank()) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let p53 = compiled.policy.frozen.p53;
    assert_eq!(he.policy_ref(), Some(p53.clone()));
    assert_eq!(FunderProfile::for_policy_ref(&p53), Some(he));
    let other = match OpaqueValue::from_value(&Value::String("horizon-europe".to_owned())) {
        Ok(o) => FunderProfileRef(o),
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(FunderProfile::for_policy_ref(&other), None);
}

//! The SuperSAFE fixture against the SuperSAFE column of
//! `SPEC/02-domain/policy-parameters.md` (R-PG-01, I-50, I-12).
//!
//! The column is read at test time. Each row has a reading in
//! `tests/support/readings.rs`, made from the spec cell it names. The
//! opaque encodings there are interim, pending Daniel.

mod support;
mod target_api;

use std::collections::BTreeSet;

use fstp_domain::policy::{PolicyVersion, is_frozen_opaque, is_live_opaque, validate};
use fstp_domain::rules::{CATALOGUE, ParamId};
use fstp_json::Value;
use fstp_money::Currency;

use support::readings::{Reading, readings, same_json, synthetic};
use support::spec::param_rows;

/// The opaque value of `p` in the map its freeze flag selects.
fn opaque_of(v: &PolicyVersion, p: ParamId) -> Option<&str> {
    if is_frozen_opaque(p) {
        v.frozen.opaque.get(&p).map(|o| o.as_str())
    } else if is_live_opaque(p) {
        v.live.opaque.get(&p).map(|o| o.as_str())
    } else {
        None
    }
}

/// Whether the policy holds some value for the synthetic parameter `p`.
fn synthetic_present(v: &PolicyVersion, p: ParamId) -> Result<(), String> {
    let ok = match p {
        ParamId::P21 => !v.frozen.p21.primary.0.is_empty(),
        ParamId::P26 => !v.frozen.p26.0.is_empty(),
        ParamId::P56 => v.live.p56.is_some(),
        ParamId::P58 => v.live.p58.is_some(),
        _ => opaque_of(v, p).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{p:?} has no placeholder value in the policy"))
    }
}

/// R-PG-01: the SuperSAFE fixture compiles to the SuperSAFE column. Every
/// concrete cell matches its typed field or its opaque value. Every
/// synthetic parameter holds a placeholder, and no tenant-level or fixed
/// parameter is set. The currency is EUR, as P-04 and P-05 state.
#[test]
fn r_pg_01_supersafe_fixture_matches_policy_defaults() {
    let rows = match param_rows() {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let compiled = match target_api::fixture_compiled() {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let v = &compiled.policy;
    assert_eq!(v.currency, Currency::Eur, "the SuperSAFE currency is EUR");

    let ours = readings();
    let mut faults = Vec::new();
    for row in &rows {
        let Some(r) = ours.iter().find(|r| r.id == row.id) else {
            faults.push(format!("{:?}: no reading", row.id));
            continue;
        };
        if r.cell != row.supersafe {
            faults.push(format!("{:?}: the spec cell changed", row.id));
            continue;
        }
        let p = row.id;
        let result = match r.reading {
            Reading::Typed(check) => check(v),
            Reading::Opaque(want) => match opaque_of(v, p) {
                Some(have) => same_json(have, want),
                None => Err("no opaque value".to_owned()),
            },
            Reading::Synthetic(_) => synthetic_present(v, p),
            Reading::PartlySynthetic(want, _) => match opaque_of(v, p) {
                Some(have) => same_json(have, want),
                None => Err("no opaque value".to_owned()),
            },
            Reading::NotProgramme => {
                if v.frozen.opaque.contains_key(&p) || v.live.opaque.contains_key(&p) {
                    Err("set, but it is not a programme parameter".to_owned())
                } else {
                    Ok(())
                }
            }
        };
        if let Err(e) = result {
            faults.push(format!("{p:?} ({:?}): {e}", row.supersafe));
        }
    }
    assert!(
        faults.is_empty(),
        "the fixture differs from the SuperSAFE column:\n{}",
        faults.join("\n")
    );
}

/// R-PG-01: the fixture file is canonical RFC 8785 text, optionally ended
/// by one line feed. It holds exactly the members `"provenance"` and
/// `"spec"`, and `encode_spec` writes the decoded spec back byte for byte.
#[test]
fn r_pg_01_supersafe_fixture_is_canonical() {
    let text = match target_api::fixture_text() {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let body = text.strip_suffix('\n').unwrap_or(&text);
    let parsed = match fstp_json::parse_str(body) {
        Ok(v) => v,
        Err(e) => panic!("the fixture is not JSON: {e:?}"),
    };
    let canonical = match fstp_json::to_canonical(&parsed) {
        Ok(c) => c,
        Err(e) => panic!("the fixture has no canonical form: {e:?}"),
    };
    assert_eq!(body, canonical, "the fixture is not in canonical form");

    let members: Vec<&str> = match parsed.as_object() {
        Some(o) => o.keys().collect(),
        None => panic!("the fixture is not a JSON object"),
    };
    assert_eq!(members, ["provenance", "spec"], "the fixture's members");

    let spec_text = match target_api::fixture_spec_text() {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let spec = match target_api::decode(spec_text.as_bytes()) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(
        target_api::encode(&spec),
        spec_text,
        "encode_spec does not write the fixture's spec back"
    );
}

/// R-PG-01, I-50: the SuperSAFE fixture sets every field, compiles for the
/// given ids, and its policy passes the M2 `validate`, which refuses
/// P-05 above P-58 (I-50). So the synthetic P-58 is at least 400000.00.
#[test]
fn r_pg_01_i50_supersafe_fixture_compiles_with_every_field_set() {
    let compiled = match target_api::fixture_compiled() {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    assert!(
        compiled.unset.is_empty(),
        "the fixture leaves fields unset: {:?}",
        compiled.unset
    );
    let v = &compiled.policy;
    assert_eq!(v.id, target_api::VERSION, "the policy version id");
    assert_eq!(v.programme, target_api::PROGRAMME, "the programme id");
    assert_eq!(v.parent, None, "a first version has no parent");
    if let Err(r) = validate(v) {
        panic!("the compiled SuperSAFE policy fails validation: {r:?}");
    }
}

/// R-PG-01, I-12: `compile` sets every programme-level parameter and
/// nothing else. The opaque maps hold exactly the programme-level
/// parameters without a typed field, by freeze flag.
#[test]
fn r_pg_01_compile_sets_every_programme_parameter_and_nothing_else() {
    let compiled = match target_api::fixture_compiled() {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let v = &compiled.policy;
    let frozen: BTreeSet<ParamId> = v.frozen.opaque.keys().copied().collect();
    let live: BTreeSet<ParamId> = v.live.opaque.keys().copied().collect();
    let want_frozen: BTreeSet<ParamId> = CATALOGUE
        .iter()
        .map(|s| s.id)
        .filter(|p| is_frozen_opaque(*p))
        .collect();
    let want_live: BTreeSet<ParamId> = CATALOGUE
        .iter()
        .map(|s| s.id)
        .filter(|p| is_live_opaque(*p))
        .collect();
    assert_eq!(frozen, want_frozen, "frozen opaque parameters");
    assert_eq!(live, want_live, "live opaque parameters");
}

/// R-PG-01: the synthetic placeholders are listed in the fixture's
/// provenance block, each with `"synthetic": true`, and exactly those.
/// Parameters are listed by their id. Every other key names an artefact
/// field by its `"<step>.<member>"` path, since artefact text the spec
/// does not give is synthetic too. The flag never reaches the policy: no
/// opaque value holds a member named `synthetic`.
#[test]
fn r_pg_01_supersafe_synthetic_placeholders_listed_in_provenance_only() {
    let fixture = match target_api::fixture() {
        Ok(f) => f,
        Err(e) => panic!("{e}"),
    };
    let Some(prov) = fixture.get("provenance").and_then(Value::as_object) else {
        panic!("the fixture has no provenance object");
    };
    let (params, others): (BTreeSet<String>, BTreeSet<String>) = prov
        .keys()
        .map(str::to_owned)
        .partition(|k| ParamId::ALL.iter().any(|p| p.spec_id() == k));
    let want: BTreeSet<String> = synthetic()
        .into_iter()
        .map(|p| p.spec_id().to_owned())
        .collect();
    assert_eq!(params, want, "the provenance block lists other parameters");
    let artefacts = target_api::artefact_keys();
    let stray: Vec<&String> = others.iter().filter(|k| !artefacts.contains(*k)).collect();
    assert!(
        stray.is_empty(),
        "provenance keys that name no artefact field: {stray:?}"
    );
    for (k, entry) in prov.iter() {
        assert_eq!(
            entry.get("synthetic").and_then(Value::as_bool),
            Some(true),
            "provenance entry {k} is not marked synthetic"
        );
    }

    let compiled = match target_api::fixture_compiled() {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let v = &compiled.policy;
    let texts = v
        .frozen
        .opaque
        .iter()
        .chain(v.live.opaque.iter())
        .map(|(p, o)| (*p, o.as_str().to_owned()))
        .chain([
            (ParamId::P14, v.frozen.p14.0.as_str().to_owned()),
            (ParamId::P16, v.frozen.p16.0.as_str().to_owned()),
            (ParamId::P17, v.frozen.p17.0.as_str().to_owned()),
            (ParamId::P21, v.frozen.p21.provider.as_str().to_owned()),
            (ParamId::P53, v.frozen.p53.0.as_str().to_owned()),
        ]);
    for (p, text) in texts {
        let parsed = match fstp_json::parse_str(&text) {
            Ok(x) => x,
            Err(e) => panic!("{p:?} holds no JSON: {e:?}"),
        };
        let flagged = target_api::paths(&parsed).into_iter().any(
            |(path, _)| matches!(path.last(), Some(target_api::Seg::Key(k)) if k == "synthetic"),
        );
        assert!(!flagged, "{p:?} carries a synthetic flag inside the policy");
    }
}

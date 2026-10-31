//! Round trips and strict decoding of programme specs (R-PG-01, R-PG-02,
//! ADR-006).
//!
//! Generated specs start from the SuperSAFE fixture's spec and take up to
//! three leaf edits: a flipped boolean, another integer, another ADR-006
//! amount, another string, or an array with an element removed or
//! repeated. Edits that `decode_spec` or `compile` rejects are discarded,
//! and the harness fails a run that discards too many cases. Gaps come
//! from `decompile` with a generated set of unset fields.

mod support;
mod target_api;

use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_domain::rules::ParamId;
use fstp_json::{Object, Value};
use fstp_programme::{CompileIds, FIELDS};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use target_api::{
    Seg, at_mut, compact, compile, compile_with, decode, decompile, decompile_unset, encode,
    fixture_spec_text, fixture_spec_value, gen_spec, gen_unset, is_amount_text, number, paths,
    strings_in,
};

/// The value of a helper result, or a test failure with its message.
macro_rules! ok {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        }
    };
}

/// R-PG-01, R-PG-02: `decompile` after `compile` is the identity on every
/// spec `compile` accepts, so a clone or a template start reproduces the
/// spec exactly (M4 design section 3.1, round trip).
#[test]
fn r_pg_01_compile_then_decompile_is_identity() {
    let base = ok!(fixture_spec_value());
    let strings = strings_in(&base);
    check("r_pg_01_compile_then_decompile_is_identity", |g| {
        let Some(s) = gen_spec(g, &base, &strings) else {
            g.reject()
        };
        let Ok(c) = compile(&s) else { g.reject() };
        prop_assert_eq!(decompile(&c), s);
        Ok(())
    });
}

/// R-PG-01: a gap survives the round trip. A spec with any set of unset
/// fields compiles, `Compiled::unset` names exactly those fields, and
/// `decompile` gives the spec back. The gaps are what the `FieldUnset`
/// check of the validation report reads.
#[test]
fn r_pg_01_unset_fields_survive_compile_and_decompile() {
    let base = ok!(fixture_spec_value());
    let strings = strings_in(&base);
    check("r_pg_01_unset_fields_survive_compile_and_decompile", |g| {
        let Some(s) = gen_spec(g, &base, &strings) else {
            g.reject()
        };
        let Ok(c) = compile(&s) else { g.reject() };
        let mut unset = gen_unset(g);
        unset.extend(c.unset.iter().copied());
        g.note("unset", &unset);
        let gapped = decompile_unset(&c, &unset);
        let c2 = compile(&gapped);
        prop_assert!(c2.is_ok(), "a spec with gaps does not compile: {:?}", c2);
        let Ok(c2) = c2 else { g.reject() };
        prop_assert_eq!(c2.unset, unset);
        prop_assert_eq!(decompile(&c2), gapped);
        Ok(())
    });
}

/// R-PG-01: `encode_spec` writes canonical RFC 8785 text, and
/// `decode_spec` reads it back to the same spec, with or without gaps.
#[test]
fn r_pg_01_spec_encoding_round_trips() {
    let base = ok!(fixture_spec_value());
    let strings = strings_in(&base);
    check("r_pg_01_spec_encoding_round_trips", |g| {
        let Some(s) = gen_spec(g, &base, &strings) else {
            g.reject()
        };
        let s = match (g.bool(), compile(&s)) {
            (true, Ok(c)) => {
                let mut unset = gen_unset(g);
                unset.extend(c.unset.iter().copied());
                decompile_unset(&c, &unset)
            }
            _ => s,
        };
        let text = encode(&s);
        let canonical = fstp_json::parse_str(&text)
            .map_err(|e| format!("encode_spec wrote no JSON: {e:?}"))
            .and_then(|v| fstp_json::to_canonical(&v).map_err(|e| format!("{e:?}")))?;
        prop_assert_eq!(&canonical, &text);
        prop_assert_eq!(decode(text.as_bytes()), Ok(s));
        Ok(())
    });
}

/// R-PG-01: `compile` is a pure function of the spec, the profile and the
/// shell-supplied ids (M4 design section 3.1, determinism). The ids reach
/// the policy version and never the spec.
#[test]
fn r_pg_01_compile_is_deterministic() {
    let base = ok!(fixture_spec_value());
    let strings = strings_in(&base);
    let other_programme = ProgrammeId::from_raw(0x0b0b_0000_0001);
    let other_version = PolicyVersionId::from_raw(0x0b0b_0000_0002);
    check("r_pg_01_compile_is_deterministic", |g| {
        let Some(s) = gen_spec(g, &base, &strings) else {
            g.reject()
        };
        let a = compile(&s);
        prop_assert_eq!(&a, &compile(&s));
        let other = CompileIds::new(other_programme, other_version, Some(target_api::VERSION));
        let b = compile_with(&s, other);
        prop_assert_eq!(a.is_ok(), b.is_ok());
        if let (Ok(a), Ok(b)) = (a, b) {
            prop_assert_eq!(b.policy.id, other_version);
            prop_assert_eq!(b.policy.programme, other_programme);
            prop_assert_eq!(b.policy.parent, Some(target_api::VERSION));
            prop_assert_eq!(&b.unset, &a.unset);
            prop_assert_eq!(decompile(&b), decompile(&a));
        }
        Ok(())
    });
}

/// R-PG-01: the SuperSAFE fixture round-trips exactly, through
/// `compile` and `decompile` and through `encode_spec`.
#[test]
fn r_pg_01_supersafe_fixture_round_trips() {
    let text = match fixture_spec_text() {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let spec = match decode(text.as_bytes()) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let compiled = match compile(&spec) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let back = decompile(&compiled);
    assert_eq!(back, spec, "decompile does not give the fixture back");
    assert_eq!(encode(&back), text, "the fixture changed on the way back");
}

/// ADR-006: amounts in a spec travel only as decimal strings. Each string
/// of the fixture's spec spelled as an amount, at least P-04 and P-05,
/// is rejected when it is written as a JSON number with the same digits.
#[test]
fn adr006_spec_amounts_only_as_strings() {
    let base = ok!(fixture_spec_value());
    if let Err(e) = decode(&compact(&base)) {
        panic!("the fixture's spec does not decode: {e}");
    }
    let amounts: Vec<(Vec<Seg>, String)> = paths(&base)
        .into_iter()
        .filter_map(|(p, v)| match v {
            Value::String(s) if is_amount_text(&s) => Some((p, s)),
            _ => None,
        })
        .collect();
    assert!(
        amounts.len() >= 3,
        "the fixture's spec holds {} amount strings, fewer than P-04 and P-05 need",
        amounts.len()
    );
    for (path, text) in amounts {
        let mut v = base.clone();
        let n = match number(&text) {
            Ok(n) => n,
            Err(e) => panic!("{e}"),
        };
        match at_mut(&mut v, &path) {
            Some(slot) => *slot = n,
            None => panic!("lost the path {path:?}"),
        }
        assert!(
            decode(&compact(&v)).is_err(),
            "the amount {text} at {path:?} was accepted as a JSON number"
        );
    }
}

/// R-PG-01: `decode_spec` rejects an unknown member at the top level and
/// in every step object.
#[test]
fn r_pg_01_spec_decode_rejects_unknown_members() {
    let base = ok!(fixture_spec_value());
    let Some(top) = base.as_object() else {
        panic!("the fixture's spec is not an object");
    };
    let mut targets: Vec<Vec<Seg>> = vec![Vec::new()];
    for (k, v) in top.iter() {
        if v.as_object().is_some() {
            targets.push(vec![Seg::Key(k.to_owned())]);
        }
    }
    assert!(
        targets.len() >= 11,
        "the spec has {} step objects, fewer than the ten creator steps",
        targets.len().saturating_sub(1)
    );
    for path in targets {
        let mut v = base.clone();
        match at_mut(&mut v, &path).and_then(Value::as_object_mut) {
            Some(o) => {
                o.insert("zz_unknown_member", Value::Null);
            }
            None => panic!("lost the path {path:?}"),
        }
        assert!(
            decode(&compact(&v)).is_err(),
            "an unknown member at {path:?} was accepted"
        );
    }
}

/// R-PG-01: `decode_spec` rejects a spec without any one of its top-level
/// members. A missing step is never read as a default.
#[test]
fn r_pg_01_spec_decode_rejects_missing_members() {
    let base = ok!(fixture_spec_value());
    let Some(top) = base.as_object() else {
        panic!("the fixture's spec is not an object");
    };
    let keys: Vec<String> = top.keys().map(str::to_owned).collect();
    for k in keys {
        let mut v = base.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove(&k);
        }
        assert!(
            decode(&compact(&v)).is_err(),
            "a spec without {k:?} was accepted"
        );
    }
}

/// R-PG-01: a spec names its schema `"fstp.programme/1"` (M4 design
/// section 3.1), and `decode_spec` rejects any other schema.
#[test]
fn r_pg_01_spec_decode_rejects_other_schema() {
    let base = ok!(fixture_spec_value());
    assert_eq!(
        base.get("schema").and_then(Value::as_str),
        Some("fstp.programme/1"),
        "the fixture's spec schema"
    );
    for other in [
        "fstp.programme/2",
        "fstp.programme/",
        "",
        "FSTP.PROGRAMME/1",
    ] {
        let mut v = base.clone();
        if let Some(o) = v.as_object_mut() {
            o.insert("schema", Value::String(other.to_owned()));
        }
        assert!(
            decode(&compact(&v)).is_err(),
            "the schema {other:?} was accepted"
        );
    }
    let mut v = base.clone();
    if let Some(o) = v.as_object_mut() {
        o.insert("schema", Value::Object(Object::new()));
    }
    assert!(
        decode(&compact(&v)).is_err(),
        "an object schema was accepted"
    );
}

/// ADR-006, I-50: the P-05 field decodes only an ADR-006 EUR string. It
/// writes an accepted value back unchanged, and refuses numbers, other
/// scales, signs, padding and leading zeros.
#[test]
fn adr006_field_amounts_only_as_strings() {
    let Some(field) = FIELDS.iter().find(|f| f.params == [ParamId::P05]) else {
        panic!("no field sets P-05 alone");
    };
    match fstp_programme::decode_field_value(field.id, b"\"400000.00\"") {
        Ok(v) => {
            assert_eq!(v.field(), field.id, "the decoded value names another field");
            assert_eq!(
                fstp_programme::encode_field_value(&v),
                "\"400000.00\"",
                "the P-05 value changed on the way back"
            );
        }
        Err(e) => panic!("the P-05 field refused \"400000.00\": {e:?}"),
    }
    let bad: [&[u8]; 9] = [
        b"400000.00",
        b"400000",
        b"\"400000.0\"",
        b"\"400000\"",
        b"\"-1.00\"",
        b"\"+1.00\"",
        b"\"0400000.00\"",
        b"\" 400000.00\"",
        b"\"400,000.00\"",
    ];
    for input in bad {
        assert!(
            fstp_programme::decode_field_value(field.id, input).is_err(),
            "the P-05 field accepted {:?}",
            String::from_utf8_lossy(input)
        );
    }
}

//! The field codec of creator commands and records (R-PG-01, M4 design
//! sections 3.1, 3.2 and 9).
//!
//! A field travels as its `FieldId::key`, and a value as a string holding
//! its canonical RFC 8785 text from `fstp_programme::encode_field_value`.
//! A decoder accepts only text that re-encodes byte for byte. These tests
//! cover every field of `FieldId::ALL`, with the SuperSAFE fixture's value
//! for each. The fuzz seeds of `creator_command_decode` and
//! `creator_record_decode` are checked here too, so a seed never goes
//! stale.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;

use fstp_creator::{
    CheckId, CheckSubject, CreatorCommand, CreatorRecord, DraftRevision, FieldEdit,
    ImportProposalId, ImportResolution, Provenance, TemplateId, ValueDigest, WarningKey,
    decode_command, decode_record, encode_command, encode_record,
};
use fstp_domain::id::{AccountId, ContentDigest, PolicyVersionId, ProgrammeId};
use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_json::{Object, Value};
use fstp_ledger::Seq;
use fstp_programme::{Field, FieldId, FieldValue, encode_field_value, supersafe_fixture};
use fstp_prop::{check, prop_assert_eq};

const P: ProgrammeId = ProgrammeId::from_raw(7);
const M1: AccountId = AccountId::from_raw(0xB1);

fn base() -> DraftRevision {
    DraftRevision::new(3, Seq::from_raw(41))
}

fn profile() -> FunderProfileRef {
    FunderProfileRef(OpaqueValue::from_value(&Value::String("horizon-europe".to_owned())).unwrap())
}

/// The SuperSAFE fixture's value of every field, in `FieldId::ALL` order.
/// The fixture sets every field.
fn values() -> Vec<FieldValue> {
    let spec = supersafe_fixture().unwrap().spec;
    FieldId::ALL
        .iter()
        .map(|f| match spec.get(*f) {
            Field::Set(v) => v,
            Field::Unset => panic!("the fixture leaves {} unset", f.key()),
        })
        .collect()
}

fn digest_of(n: u8) -> ValueDigest {
    ValueDigest::new(ContentDigest::from_bytes([n; 32]))
}

fn edit(value: FieldValue, n: u8, provenance: Provenance) -> FieldEdit {
    FieldEdit {
        field: value.field(),
        value,
        digest: digest_of(n),
        provenance,
    }
}

fn save(fields: Vec<FieldEdit>) -> CreatorCommand {
    CreatorCommand::SaveFields {
        programme: P,
        base: base(),
        fields,
    }
}

/// The command's canonical text and the command it decodes to.
fn command_round_trip(c: &CreatorCommand) -> (String, CreatorCommand) {
    let text = encode_command(c).unwrap();
    let back = decode_command(text.as_bytes()).unwrap_or_else(|e| panic!("{e}: {text}"));
    (text, back)
}

/// The JSON object of a `SaveFields` text with one edit, and that edit.
fn single_edit_json(value: &FieldValue) -> Value {
    let text = encode_command(&save(vec![edit(value.clone(), 1, Provenance::Manual)])).unwrap();
    fstp_json::parse(text.as_bytes()).unwrap()
}

/// `v` with the first edit's member `name` set to `to`.
fn with_edit_member(v: &Value, name: &'static str, to: Value) -> Vec<u8> {
    let mut root = v.as_object().unwrap().clone();
    let fields = root.get("fields").unwrap().as_array().unwrap().clone();
    let mut first = fields[0].as_object().unwrap().clone();
    first.insert(name, to);
    let mut items = fields.clone();
    items[0] = Value::Object(first);
    root.insert("fields", Value::Array(items));
    fstp_json::to_compact(&Value::Object(root)).into_bytes()
}

/// R-PG-01: a `SaveFields` edit of every field round-trips. The field
/// travels as its key and the value as its canonical text, so the decoded
/// command is the encoded one.
#[test]
fn r_pg_01_every_field_edit_round_trips_through_the_command_codec() {
    for value in values() {
        let f = value.field();
        let c = save(vec![edit(value.clone(), 9, Provenance::Manual)]);
        let (text, back) = command_round_trip(&c);
        assert_eq!(back, c, "{}", f.key());
        let v = fstp_json::parse(text.as_bytes()).unwrap();
        let first = &v
            .as_object()
            .unwrap()
            .get("fields")
            .unwrap()
            .as_array()
            .unwrap()[0];
        let o = first.as_object().unwrap();
        assert_eq!(
            o.get("field").and_then(Value::as_str),
            Some(f.key().as_str())
        );
        assert_eq!(
            o.get("value").and_then(Value::as_str),
            Some(encode_field_value(&value).as_str()),
            "{}",
            f.key()
        );
    }
}

/// R-PG-01: every field id round-trips wherever a command names one: the
/// narrative acceptance and the field subject of a warning.
#[test]
fn r_pg_01_every_field_id_round_trips_in_commands() {
    for f in FieldId::ALL.iter().copied() {
        let accept = CreatorCommand::AcceptNarrative {
            programme: P,
            base: base(),
            field: f,
        };
        assert_eq!(command_round_trip(&accept).1, accept, "{}", f.key());
        let ack = CreatorCommand::AcknowledgeWarning {
            programme: P,
            revision: base(),
            warning: WarningKey {
                check: CheckId::FieldUnset,
                subject: CheckSubject::Field(f),
            },
        };
        assert_eq!(command_round_trip(&ack).1, ack, "{}", f.key());
    }
}

/// R-PG-01: a `FieldsSaved` record naming every field round-trips, and so
/// does a `NarrativeAccepted` record for each field. The record holds the
/// value's digest, never the value.
#[test]
fn r_pg_01_every_saved_field_round_trips_through_the_record_codec() {
    let provenances = [
        Provenance::Manual,
        Provenance::Default { profile: profile() },
        Provenance::Template {
            template: TemplateId::from_raw(2),
            version: 1,
        },
        Provenance::Clone {
            source: ProgrammeId::from_raw(3),
            version: PolicyVersionId::from_raw(4),
        },
        Provenance::Import {
            proposal: ImportProposalId::from_raw(5),
            resolution: ImportResolution::Edited,
        },
    ];
    let fields: Vec<(FieldId, ValueDigest, Provenance)> = FieldId::ALL
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let n = u8::try_from(i % 256).unwrap();
            (*f, digest_of(n), provenances[i % provenances.len()].clone())
        })
        .collect();
    let r = CreatorRecord::FieldsSaved {
        programme: P,
        revision: base(),
        fields,
        by: M1,
    };
    let text = encode_record(&r).unwrap();
    assert!(
        !text.contains("\"value\""),
        "a record holds no value: {text}"
    );
    assert_eq!(decode_record(text.as_bytes()).unwrap(), r);
    for f in FieldId::ALL.iter().copied() {
        let n = CreatorRecord::NarrativeAccepted {
            programme: P,
            revision: base(),
            field: f,
            by: M1,
        };
        let text = encode_record(&n).unwrap();
        assert_eq!(decode_record(text.as_bytes()).unwrap(), n, "{}", f.key());
    }
}

/// R-PG-01: a value text that is not the canonical text of a value of the
/// field is refused, for every field. That covers padding, a gap, the
/// JSON value itself in place of its text, and a value in another
/// spelling.
#[test]
fn r_pg_01_every_field_refuses_a_non_canonical_value() {
    for value in values() {
        let key = value.field().key();
        let v = single_edit_json(&value);
        let canonical = encode_field_value(&value);
        let inner = fstp_json::parse(canonical.as_bytes()).unwrap();
        let mut refused = vec![
            Value::String(format!(" {canonical}")),
            Value::String(format!("{canonical}\n")),
            Value::String("null".to_owned()),
            Value::String(String::new()),
            Value::Null,
            inner.clone(),
        ];
        // An object or array value with whitespace inside its brackets,
        // which always lies outside any string.
        if let Some(rest) = canonical
            .strip_prefix('{')
            .or_else(|| canonical.strip_prefix('['))
        {
            let open = &canonical[..1];
            refused.push(Value::String(format!("{open} {rest}")));
            let (head, close) = canonical.split_at(canonical.len() - 1);
            refused.push(Value::String(format!("{head} {close}")));
        }
        // A string value with a needless escape of its first character.
        if let Some(rest) = canonical.strip_prefix('"')
            && let Some(c) = rest.chars().next()
            && c.is_ascii_alphanumeric()
        {
            let code = u32::from(c);
            refused.push(Value::String(format!(
                "\"\\u{code:04x}{}",
                &rest[c.len_utf8()..]
            )));
        }
        for bad in refused {
            let bytes = with_edit_member(&v, "value", bad.clone());
            if bad.as_str() == Some(canonical.as_str()) {
                continue;
            }
            assert!(
                decode_command(&bytes).is_err(),
                "{key}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        // The canonical text itself is accepted.
        let good = with_edit_member(&v, "value", Value::String(canonical.clone()));
        assert!(decode_command(&good).is_ok(), "{key}");
    }
}

/// R-PG-01: a value is decoded by the decoder of the edit's own field. A
/// value of one field placed under another field is refused, unless the
/// two fields share a value type, in which case it decodes as a value of
/// the named field.
#[test]
fn r_pg_01_a_value_decodes_only_under_its_own_field() {
    let all = values();
    let mut refused = 0usize;
    for value in &all {
        let v = single_edit_json(value);
        let text = Value::String(encode_field_value(value));
        for other in FieldId::ALL.iter().copied() {
            let mut moved = with_edit_member(&v, "value", text.clone());
            let o = fstp_json::parse(&moved).unwrap();
            moved = with_edit_member(&o, "field", Value::String(other.key()));
            match decode_command(&moved) {
                Ok(CreatorCommand::SaveFields { fields, .. }) => {
                    assert_eq!(fields.len(), 1);
                    assert_eq!(fields[0].field, other);
                    assert_eq!(fields[0].value.field(), other, "{}", other.key());
                }
                Ok(c) => panic!("decoded as another command: {c:?}"),
                Err(_) => {
                    assert_ne!(other, value.field(), "{}", other.key());
                    refused += 1;
                }
            }
        }
    }
    assert!(refused > 0, "no value was refused under a foreign field");
}

/// R-PG-01: only the exact key of a field names it. A step or member name
/// alone, another case, padding or an unknown key is refused.
#[test]
fn r_pg_01_unknown_field_key_refused() {
    let value = values().into_iter().next().unwrap();
    let v = single_edit_json(&value);
    let mut bad: Vec<String> = [
        "",
        ".",
        "funder",
        "funder.",
        ".p53_funder_profile",
        "x.y",
        "funder.x",
        "funder..p53_funder_profile",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    for f in FieldId::ALL.iter().copied() {
        let key = f.key();
        bad.push(f.name().to_owned());
        bad.push(key.to_ascii_uppercase());
        bad.push(format!(" {key}"));
        bad.push(format!("{key} "));
        bad.push(format!("{key}.x"));
        bad.push(key.replacen('.', "/", 1));
    }
    for k in bad {
        assert!(
            FieldId::from_key(&k).is_none_or(|f| f.key() == k),
            "from_key accepts {k:?}"
        );
        if FieldId::from_key(&k).is_some() {
            continue;
        }
        let bytes = with_edit_member(&v, "field", Value::String(k.clone()));
        assert!(decode_command(&bytes).is_err(), "{k:?}");
        let accept = format!(
            r#"{{"base":{{"entry":"41","seq":"3"}},"field":{},"kind":"AcceptNarrative","programme":"7"}}"#,
            fstp_json::to_compact(&Value::String(k.clone()))
        );
        assert!(decode_command(accept.as_bytes()).is_err(), "{k:?}");
    }
}

/// R-PG-01: an edit's digest is 64 lowercase hex digits, and an edit has
/// exactly the members `field`, `value`, `digest` and `provenance`.
#[test]
fn r_pg_01_edit_digest_and_members_are_strict() {
    let value = values().into_iter().next().unwrap();
    let v = single_edit_json(&value);
    for d in [
        "",
        "00",
        &"A".repeat(64),
        &"0".repeat(63),
        &"0".repeat(65),
        &"g".repeat(64),
    ] {
        let bytes = with_edit_member(&v, "digest", Value::String(d.to_owned()));
        assert!(decode_command(&bytes).is_err(), "digest {d:?}");
    }
    let extra = with_edit_member(&v, "extra", Value::Null);
    assert!(decode_command(&extra).is_err(), "an unknown member");
    let mut root = v.as_object().unwrap().clone();
    let fields = root.get("fields").unwrap().as_array().unwrap().clone();
    for name in ["field", "value", "digest", "provenance"] {
        let mut first: Object = Object::new();
        for (k, x) in fields[0].as_object().unwrap().iter() {
            if k != name {
                first.insert(k, x.clone());
            }
        }
        let mut items = fields.clone();
        items[0] = Value::Object(first);
        root.insert("fields", Value::Array(items));
        let bytes = fstp_json::to_compact(&Value::Object(root.clone())).into_bytes();
        assert!(decode_command(&bytes).is_err(), "missing {name}");
    }
}

/// R-PG-01: a generated `SaveFields` command with edits of any fields, in
/// any order, with any digests and provenances, round-trips through its
/// canonical text.
#[test]
fn r_pg_01_generated_save_fields_round_trip() {
    let all = values();
    check("r_pg_01_generated_save_fields_round_trip", |g| {
        let fields = g.vec(0..=6, |g| {
            let value = g.pick(&all).clone();
            let n = g.u8();
            let provenance = match g.u8_in(0..=3) {
                0 => Provenance::Manual,
                1 => Provenance::Template {
                    template: TemplateId::from_raw(u128::from(g.u64())),
                    version: g.u32(),
                },
                2 => Provenance::Clone {
                    source: ProgrammeId::from_raw(u128::from(g.u64())),
                    version: PolicyVersionId::from_raw(u128::from(g.u64())),
                },
                _ => Provenance::Import {
                    proposal: ImportProposalId::from_raw(u128::from(g.u64())),
                    resolution: if g.bool() {
                        ImportResolution::Confirmed
                    } else {
                        ImportResolution::Edited
                    },
                },
            };
            edit(value, n, provenance)
        });
        let c = save(fields);
        let text = encode_command(&c).unwrap();
        let back = decode_command(text.as_bytes());
        prop_assert_eq!(back.ok(), Some(c));
        Ok(())
    });
}

fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("seeds")
        .join(target);
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            let p = e.unwrap().path();
            (p.display().to_string(), std::fs::read(&p).unwrap())
        })
        .collect();
    out.sort();
    out
}

/// R-PG-01, design section 9: every `creator_command_decode` seed is the
/// canonical text of a command that names fields, so the fuzzer starts
/// from inputs that reach the field codec.
#[test]
fn r_pg_01_command_fuzz_seeds_decode_and_are_canonical() {
    let s = seeds("creator_command_decode");
    assert!(!s.is_empty());
    for (name, bytes) in s {
        let c = decode_command(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(encode_command(&c).unwrap().as_bytes(), &bytes[..], "{name}");
    }
}

/// R-PG-01, design section 9: every `creator_record_decode` seed is the
/// canonical text of a record.
#[test]
fn r_pg_01_record_fuzz_seeds_decode_and_are_canonical() {
    let s = seeds("creator_record_decode");
    assert!(!s.is_empty());
    for (name, bytes) in s {
        let r = decode_record(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(encode_record(&r).unwrap().as_bytes(), &bytes[..], "{name}");
    }
}

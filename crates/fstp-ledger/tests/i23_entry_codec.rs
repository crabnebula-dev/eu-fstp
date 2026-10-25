//! I-23 and ADR-007: the entry codec (`docs/handoff/m2-design.md` sections
//! 5.1 and 7).
//!
//! Record bodies are stored as RFC 8785 text, and the stored bytes are the
//! bytes that are hashed. So every entry that decodes must have canonical
//! bytes, those bytes must decode to the same entry, and encoding again must
//! give the same bytes. The decoder accepts one spelling per entry, which
//! keeps the stored bytes a function of the entry.
//!
//! The JSON shape follows the W0 fuzz seed `fuzz/seeds/entry_decode/entry`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{MAX_SAFE, Parts, Rec, entry_json, gen_record, hex, int};
use fstp_json::{FromJson, Object, ToJson, Value, json, parse, to_canonical};
use fstp_ledger::Entry;
use fstp_prop::{check, prop_assert, prop_assert_eq};

fn decode(v: &Value) -> Result<Entry<Rec>, String> {
    Entry::<Rec>::from_json(v).map_err(|e| e.to_string())
}

/// I-23 and ADR-007: decode, encode and decode give the same entry, the
/// encoding has the seed's shape, and the canonical bytes are stable.
///
/// A time beyond 2^53 - 1 microseconds has no RFC 8785 form as a JSON
/// number. Such an entry may be refused, but an entry that decodes must
/// always have canonical bytes.
#[test]
fn i23_entry_round_trip_keeps_canonical_bytes_stable() {
    check("i23_entry_round_trip_keeps_canonical_bytes_stable", |g| {
        let mut command = [0u8; 16];
        for b in command.iter_mut() {
            *b = g.u8();
        }
        let at = if g.weighted(&[4, 1]) == 0 {
            g.i64_in(-MAX_SAFE..=MAX_SAFE)
        } else {
            g.i64()
        };
        let p = Parts {
            seq: g.u64_in(1..=u64::MAX),
            at,
            command,
            schema: g.u16_in(1..=u16::MAX),
            record: gen_record(g),
        };
        g.note("parts", &p);
        let v = entry_json(&p);
        let safe = (-MAX_SAFE..=MAX_SAFE).contains(&at);
        let entry = match decode(&v) {
            Ok(e) => e,
            Err(e) if safe => return Err(format!("a well-formed entry was refused: {e}")),
            Err(_) => return Ok(()),
        };

        let encoded = entry.to_json();
        if safe {
            prop_assert_eq!(&encoded, &v, "the encoding differs from the seed shape");
        }
        let again = decode(&encoded)?;
        prop_assert_eq!(&again, &entry, "decode, encode, decode changed the entry");

        let canonical = to_canonical(&encoded)
            .map_err(|e| format!("a decoded entry has no canonical bytes: {e}"))?;
        let reparsed = parse(canonical.as_bytes()).map_err(|e| e.to_string())?;
        let third = decode(&reparsed)?;
        prop_assert_eq!(
            &third,
            &entry,
            "the canonical bytes decode to another entry"
        );
        prop_assert_eq!(
            to_canonical(&third.to_json()).ok(),
            Some(canonical),
            "canonical bytes are not stable"
        );
        Ok(())
    });
}

/// The W0 fuzz seed, an entry in the stored shape.
const SEED: &[u8] = include_bytes!("../fuzz/seeds/entry_decode/entry");

fn base() -> Value {
    parse(SEED).expect("the seed is JSON")
}

fn with(member: &str, value: Value) -> Value {
    let mut v = base();
    let o = v.as_object_mut().expect("the seed is an object");
    o.insert(member, value);
    v
}

fn without(member: &str) -> Value {
    let mut v = base();
    let o = v.as_object_mut().expect("the seed is an object");
    o.remove(member);
    v
}

fn lexeme(text: &str) -> Value {
    parse(text.as_bytes()).expect("a JSON number")
}

/// I-23 and ADR-007: the seed and every record value decode, and the
/// canonical bytes of the encoding equal those of the input. Unknown or
/// missing members and other spellings of the envelope are refused.
#[test]
fn i23_adr007_entry_decode_accepts_one_spelling() {
    // Accepted: the seed, and records of every JSON type.
    let mut accepted = vec![("seed", base())];
    for (name, record) in [
        ("record null", Value::Null),
        ("record array", json!([1, "a", [true]])),
        ("record string", json!("x")),
        ("record number", lexeme("1.5")),
        ("record nested", json!({"b": {"c": [1, 2]}, "a": null})),
    ] {
        accepted.push((name, with("record", record)));
    }
    accepted.push(("seq max", with("seq", json!("18446744073709551615"))));
    accepted.push(("schema max", with("schema", int(u16::MAX))));
    accepted.push(("at negative", with("at", int(-1))));
    accepted.push((
        "command ff",
        with("command", Value::String(hex(&[0xff; 16]))),
    ));
    for (name, v) in &accepted {
        let entry = decode(v).unwrap_or_else(|e| panic!("{name}: refused: {e}"));
        let encoded = entry.to_json();
        assert_eq!(
            to_canonical(&encoded).ok(),
            to_canonical(v).ok(),
            "{name}: the encoding changed the canonical bytes"
        );
        assert!(
            to_canonical(v).is_ok(),
            "{name}: test input has no canonical form"
        );
    }

    // Refused: every other spelling of the envelope.
    let mut refused: Vec<(&str, Value)> = vec![
        ("not an object", json!([1])),
        ("null", Value::Null),
        ("unknown member", with("extra", int(1))),
        ("seq number", with("seq", int(1))),
        ("seq zero", with("seq", json!("0"))),
        ("seq leading zero", with("seq", json!("01"))),
        ("seq plus", with("seq", json!("+1"))),
        ("seq space", with("seq", json!(" 1"))),
        ("seq fraction", with("seq", json!("1.0"))),
        ("seq empty", with("seq", json!(""))),
        ("seq negative", with("seq", json!("-1"))),
        ("seq hex", with("seq", json!("0x1"))),
        ("seq overflow", with("seq", json!("18446744073709551616"))),
        (
            "command upper",
            with("command", json!("000102030405060708090A0B0C0D0E0F")),
        ),
        (
            "command short",
            with("command", json!("000102030405060708090a0b0c0d0e")),
        ),
        (
            "command long",
            with("command", json!("000102030405060708090a0b0c0d0e0f00")),
        ),
        (
            "command odd",
            with("command", json!("000102030405060708090a0b0c0d0e0")),
        ),
        (
            "command not hex",
            with("command", json!("zz0102030405060708090a0b0c0d0e0f")),
        ),
        ("command number", with("command", int(1))),
        (
            "command array",
            with(
                "command",
                json!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            ),
        ),
        ("schema string", with("schema", json!("1"))),
        ("schema negative", with("schema", int(-1))),
        ("schema overflow", with("schema", int(65_536))),
        ("schema fraction", with("schema", lexeme("1.0"))),
        ("schema null", with("schema", Value::Null)),
        ("at string", with("at", json!("1767225600000000"))),
        ("at fraction", with("at", lexeme("1.5"))),
        ("at exponent", with("at", lexeme("1e3"))),
        ("at overflow", with("at", lexeme("9223372036854775808"))),
        ("at bool", with("at", Value::Bool(true))),
    ];
    for member in ["seq", "at", "command", "schema", "record"] {
        refused.push(("missing member", without(member)));
    }
    for (name, v) in &refused {
        assert!(decode(v).is_err(), "{name}: decoded {v}");
    }
}

/// I-23 and ADR-007: an entry whose canonical text holds the members in any
/// order decodes to the same entry, because RFC 8785 sorts members.
#[test]
fn i23_entry_decode_ignores_member_order() {
    check("i23_entry_decode_ignores_member_order", |g| {
        let p = Parts {
            seq: g.u64_in(1..=1_000),
            at: g.i64_in(0..=MAX_SAFE),
            command: [7; 16],
            schema: 1,
            record: gen_record(g),
        };
        let v = entry_json(&p);
        let mut members: Vec<(String, Value)> = v
            .as_object()
            .expect("an object")
            .iter()
            .map(|(k, v)| (k.to_owned(), v.clone()))
            .collect();
        g.shuffle(&mut members);
        let shuffled = Value::Object(Object::from_members(members).expect("unique names"));
        let a = decode(&v)?;
        let b = decode(&shuffled)?;
        prop_assert_eq!(&a, &b);
        prop_assert!(to_canonical(&a.to_json()).is_ok());
        Ok(())
    });
}

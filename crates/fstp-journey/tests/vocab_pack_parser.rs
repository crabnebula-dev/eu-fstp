//! ADR-015, R-WL-05: the vocabulary pack parser reads the shipped packs, round-trips every pack it accepts, and refuses malformed packs.
//!
//! A pack is one I-JSON object read by the in-house `fstp-json` codec
//! (`SPEC/12-journey-ui.md` section 13, "vocabulary pack parser"). The
//! fuzz target `vocab_parse` checks the same promises on arbitrary bytes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_journey::vocab::{
    FIXED, LABEL_KEYS, MAX_LABEL_BYTES, Pack, PackKind, VOYAGE_V1, VocabErrorKind as K, parse,
    plain_v1, voyage_v1,
};
use fstp_json::{Object, Value};
use fstp_prop::Gen;

fn shipped(bytes: &[u8]) -> Value {
    fstp_json::parse(bytes).expect("the shipped pack is I-JSON")
}

fn top(v: &mut Value) -> &mut Object {
    match v {
        Value::Object(o) => o,
        _ => panic!("not an object"),
    }
}

fn labels(v: &mut Value) -> &mut Object {
    match top(v).get_mut("labels") {
        Some(Value::Object(o)) => o,
        _ => panic!("no labels object"),
    }
}

fn refused(v: &Value, want: K, what: &str) {
    match parse(v.to_compact().as_bytes()) {
        Ok(_) => panic!("ADR-015: {what}: the parser accepted it"),
        Err(e) => assert_eq!(e.kind(), want, "ADR-015: {what}: {e}"),
    }
}

/// ADR-015, O-55: both shipped packs parse, with their kinds. The plain
/// pack names every label key, and the Voyage pack only label keys.
#[test]
fn adr015_vocab_shipped_packs_parse() {
    let plain = plain_v1().unwrap();
    let voyage = voyage_v1().unwrap();
    assert_eq!(plain.kind(), PackKind::Plain);
    assert_eq!(voyage.kind(), PackKind::Voyage);
    for key in LABEL_KEYS {
        assert!(plain.get(key).is_some(), "O-55: plain lacks {key}");
    }
    assert!(voyage.labels().count() > 0);
    for (key, _) in voyage.labels() {
        assert!(LABEL_KEYS.contains(&key), "I-72: {key}");
    }
}

/// ADR-015: encoding an accepted pack and parsing it again gives the same
/// pack, for the shipped packs and for generated ones.
#[test]
fn adr015_vocab_round_trip() {
    for p in [plain_v1().unwrap(), voyage_v1().unwrap()] {
        let again = parse(p.encode().as_bytes()).unwrap();
        assert_eq!(again, p, "ADR-015: shipped round trip");
    }
    fstp_prop::check("adr015_vocab_round_trip", |g: &mut Gen| {
        let kind = if g.bool() {
            PackKind::Plain
        } else {
            PackKind::Voyage
        };
        let mut labels = BTreeMap::new();
        for key in LABEL_KEYS {
            if kind == PackKind::Voyage && g.bool() {
                continue;
            }
            let text = match FIXED.iter().find(|f| f.key == *key) {
                Some(f) if kind == PackKind::Plain => f.plain.to_owned(),
                Some(f) => f.voyage.to_owned(),
                None => text(g),
            };
            labels.insert((*key).to_owned(), text);
        }
        let pack = Pack::new(kind, labels).map_err(|e| format!("generated pack refused: {e}"))?;
        let again =
            parse(pack.encode().as_bytes()).map_err(|e| format!("encoded pack refused: {e}"))?;
        fstp_prop::prop_assert_eq!(again, pack, "ADR-015: round trip");
        Ok(())
    });
}

/// A label text the parser accepts: 1 to 40 characters with no control
/// character, brace or angle bracket, and no space at either end.
fn text(g: &mut Gen) -> String {
    const CHARS: &[char] = &[
        'a', 'B', 'z', '0', ' ', '-', ',', '.', ':', '/', '(', ')', '\'', 'é', 'ß', 'ł', '’', 'Ω',
    ];
    let len = g.usize_in(1..=40);
    let mut s: String = (0..len).map(|_| *g.pick(CHARS)).collect();
    s = s.trim().to_owned();
    if s.is_empty() { "x".to_owned() } else { s }
}

/// ADR-015: the parser refuses text that is not one I-JSON object,
/// including a repeated label key.
#[test]
fn adr015_vocab_refuses_non_json() {
    for bytes in [
        &b""[..],
        b"[]",
        b"{",
        b"{\"vocab_pack_version\":1,\"pack\":\"voyage\",\"labels\":{\"vocab.team\":\"Crew\",\"vocab.team\":\"Crew\"}}",
    ] {
        let e = parse(bytes).unwrap_err();
        assert!(matches!(e.kind(), K::Json | K::WrongType), "{e}");
    }
}

/// ADR-015: an unknown or missing member, a version other than 1, a pack
/// name outside `plain` and `voyage`, and a value of the wrong type are
/// each refused with their own kind.
#[test]
fn adr015_vocab_refuses_malformed_shapes() {
    let mut v = shipped(VOYAGE_V1);
    top(&mut v).insert("colour", Value::from("blue"));
    refused(&v, K::UnknownMember, "an unknown member");

    for member in ["vocab_pack_version", "pack", "labels"] {
        let mut v = shipped(VOYAGE_V1);
        top(&mut v).remove(member);
        refused(&v, K::MissingMember, member);
    }

    let mut v = shipped(VOYAGE_V1);
    top(&mut v).insert("vocab_pack_version", Value::from(2u64));
    refused(&v, K::UnsupportedVersion, "version 2");

    let mut v = shipped(VOYAGE_V1);
    top(&mut v).insert("vocab_pack_version", Value::from("1"));
    refused(&v, K::WrongType, "a version string");

    let mut v = shipped(VOYAGE_V1);
    top(&mut v).insert("pack", Value::from("pirate"));
    refused(&v, K::InvalidValue, "an unknown pack");

    let mut v = shipped(VOYAGE_V1);
    top(&mut v).insert("labels", Value::from("Crew"));
    refused(&v, K::WrongType, "labels as a string");

    let mut v = shipped(VOYAGE_V1);
    labels(&mut v).insert("vocab.team", Value::from(true));
    refused(&v, K::WrongType, "a label that is no string");
}

/// ADR-015, I-68: a label text is plain text of 1 to `MAX_LABEL_BYTES`
/// bytes. Empty text, a space at either end, a control character, a
/// placeholder brace and markup brackets are refused.
#[test]
fn adr015_vocab_refuses_bad_label_text() {
    let long = "a".repeat(MAX_LABEL_BYTES + 1);
    for bad in [
        "",
        " Crew",
        "Crew ",
        "Cr\new",
        "Cr\u{7}ew",
        "Crew {count}",
        "Crew }",
        "<b>Crew</b>",
        long.as_str(),
    ] {
        let mut v = shipped(VOYAGE_V1);
        labels(&mut v).insert("vocab.team", Value::from(bad));
        refused(&v, K::InvalidText, &format!("label text {bad:?}"));
    }
    let mut v = shipped(VOYAGE_V1);
    labels(&mut v).insert("vocab.team", Value::from("a".repeat(MAX_LABEL_BYTES)));
    assert!(
        parse(v.to_compact().as_bytes()).is_ok(),
        "the longest label"
    );
}

/// ADR-015, O-55: the plain pack is the platform default, so it must name
/// every label key. A Voyage pack may leave one out.
#[test]
fn adr015_vocab_plain_pack_is_complete() {
    let mut v = shipped(fstp_journey::vocab::PLAIN_V1);
    labels(&mut v).remove("vocab.team");
    refused(&v, K::MissingLabel, "a plain pack without vocab.team");

    let mut v = shipped(VOYAGE_V1);
    labels(&mut v).remove("vocab.team");
    assert!(
        parse(v.to_compact().as_bytes()).is_ok(),
        "a partial Voyage pack"
    );
}

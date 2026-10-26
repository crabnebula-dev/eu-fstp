//! Fuzz target for the engine envelope decoder (TH-26, H-05).
//!
//! The input is parsed as JSON and decoded as a ledger entry. The record is
//! then split by the envelope layer into its side, `core` or `finding`, and
//! the inner record's JSON value. The target checks:
//!
//! - nothing panics, and a refusal formats without panicking;
//! - joining the parts again gives the stored record value exactly;
//! - the entry's canonical text decodes to an entry with the same envelope
//!   fields and side, and encoding that entry again gives the same bytes;
//! - an entry whose record decodes under its schema version with
//!   `fstp_engine::record_from_json_at` also splits, on the side its record
//!   is on, and at the current version the plain decode agrees;
//! - for such an entry, decode, encode and decode give the same entry,
//!   encoding is deterministic, its canonical bytes decode to the same
//!   entry, and they are stable under a second round trip.

#![no_main]

use fstp_engine::{
    EnvelopeKind, Record, envelope_from_json, envelope_to_json, record_from_json_at,
};
use fstp_json::{FromJson, FromJsonError, ToJson, Value, parse};
use fstp_ledger::Entry;
use libfuzzer_sys::fuzz_target;

/// The side `record` is stored on.
fn side(record: &Record) -> EnvelopeKind {
    match record {
        Record::Core(_) => EnvelopeKind::Core,
        Record::Finding(_) => EnvelopeKind::Finding,
    }
}

/// Decodes `v` as a stored entry, with the record decoded under the
/// entry's own schema version. At the current version it must agree with
/// the plain `FromJson` decode.
fn decode(v: &Value) -> Result<Entry<Record>, FromJsonError> {
    let entry = Entry::<Value>::from_json(v)?
        .try_map_record(|schema, record| record_from_json_at(schema, &record))?;
    if entry.schema == fstp_domain::codec::CURRENT_SCHEMA {
        assert_eq!(
            Entry::<Record>::from_json(v).as_ref(),
            Ok(&entry),
            "the schema decode and the current decode disagree"
        );
    }
    Ok(entry)
}

/// The full round trip of a decoded entry through its JSON value and its
/// RFC 8785 bytes.
fn typed_round_trip(entry: &Entry<Record>) {
    let encoded = entry.to_json();
    assert!(
        encoded.identical(&entry.to_json()),
        "encoding an entry is not deterministic"
    );
    let again = decode(&encoded).expect("an encoded entry decodes");
    assert_eq!(&again, entry, "decode, encode, decode changed the entry");

    let text = entry
        .canonical_text()
        .expect("a decoded entry has canonical bytes");
    let reparsed = parse(text.as_bytes()).expect("canonical bytes parse");
    let third = decode(&reparsed).expect("canonical bytes decode");
    assert_eq!(&third, entry, "canonical bytes decode to another entry");
    assert_eq!(
        third.canonical_text().expect("the entry encodes again"),
        text,
        "canonical bytes of the record are not stable"
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };

    match decode(&v) {
        Ok(entry) => {
            let raw = Entry::<Value>::from_json(&v).expect("a typed entry is also a raw entry");
            let (kind, _) =
                envelope_from_json(&raw.record).expect("a decoded record has an envelope");
            assert_eq!(
                kind,
                side(&entry.record),
                "the record decoded on the other side"
            );
            typed_round_trip(&entry);
        }
        Err(e) => {
            let _ = format!("{e}");
        }
    }

    let Ok(raw) = Entry::<Value>::from_json(&v) else {
        return;
    };
    let Ok(parts) = raw
        .clone()
        .try_map_record(|_, r| envelope_from_json(&r).map(|(kind, inner)| (kind, inner.clone())))
    else {
        return;
    };
    let rebuilt = parts.map_record(|(kind, inner)| envelope_to_json(kind, inner));
    assert!(
        rebuilt.record.identical(&raw.record),
        "joining the envelope parts changed the record"
    );
    assert_eq!(rebuilt, raw, "joining the envelope parts changed the entry");

    let Ok(text) = rebuilt.canonical_text() else {
        return;
    };
    let reparsed = parse(text.as_bytes()).expect("canonical text parses");
    let again = Entry::<Value>::from_json(&reparsed).expect("canonical text decodes");
    // RFC 8785 sorts members and rewrites numbers inside the inner value,
    // so the envelope fields and the side are compared, then the bytes.
    assert_eq!(
        (again.seq, again.at, again.command, again.schema),
        (rebuilt.seq, rebuilt.at, rebuilt.command, rebuilt.schema),
        "the canonical round trip changed the entry envelope"
    );
    let (kind_again, _) = envelope_from_json(&again.record).expect("the envelope still splits");
    let (kind, _) = envelope_from_json(&rebuilt.record).expect("the envelope splits");
    assert_eq!(
        kind_again, kind,
        "the canonical round trip changed the side"
    );
    assert_eq!(
        again.canonical_text().expect("the entry encodes again"),
        text,
        "canonical bytes are not stable"
    );
});

//! Fuzz target for the engine envelope decoder (TH-26, H-05).
//!
//! The input is parsed as JSON and decoded as a ledger entry. The record is
//! then split by the envelope layer into its side, `core` or `finding`, and
//! the inner record's JSON value. The target checks:
//!
//! - nothing panics;
//! - joining the parts again gives the stored record value exactly;
//! - the entry's canonical text decodes to an entry with the same envelope
//!   fields and side, and encoding that entry again gives the same bytes.
//!
//! The inner record codecs land with lanes L-CODEC (core) and L-FIND-A
//! (findings). Until then the inner value stays JSON. When they land, the
//! target decodes it as `fstp_engine::Record` and checks the full round
//! trip: decode, encode and decode give the same record, and its canonical
//! bytes are stable.

#![no_main]

use fstp_engine::{envelope_from_json, envelope_to_json};
use fstp_json::{FromJson, Value, parse};
use fstp_ledger::Entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
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

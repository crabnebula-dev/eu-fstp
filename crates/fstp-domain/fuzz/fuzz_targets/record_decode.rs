//! Fuzz target for the `fstp-domain` record decoder (TH-26, H-05, I-23,
//! ADR-007).
//!
//! The input is the JSON form of one core ledger record. It is decoded at
//! every version in `codec::PUBLISHED_SCHEMAS` through the schema-aware
//! entry point `codec::record_from_json_at` (design section 7).
//!
//! - At `CURRENT_SCHEMA`, the shared oracle in `common` checks that decoding
//!   never panics, rejects unknown members at every object, round-trips with
//!   stable canonical bytes and accepts one spelling per record. The result
//!   agrees with plain `Record::from_json`, and an accepted record formats
//!   without panicking.
//! - At any older published version, decoding never panics, and an
//!   accepted record encodes and decodes at `CURRENT_SCHEMA` to itself.
//! - An unpublished version, such as 0, `CURRENT_SCHEMA + 1` or `u16::MAX`,
//!   is always refused.

#![no_main]

mod common;

use fstp_domain::codec::{CURRENT_SCHEMA, PUBLISHED_SCHEMAS, record_from_json_at};
use fstp_domain::record::Record;
use fstp_json::{FromJson, ToJson, parse};
use libfuzzer_sys::fuzz_target;

use common::{Codec, Outcome, oracle};

fuzz_target!(|data: &[u8]| {
    let current = Codec::<Record> {
        enc: |r| Ok(r.to_json()),
        dec: |v| Ok(record_from_json_at(CURRENT_SCHEMA, v)),
    };
    if let Outcome::Accepted(r) = oracle(&current, data) {
        let _ = format!("{r:?}");
    }

    let Ok(v) = parse(data) else {
        return;
    };
    assert_eq!(
        record_from_json_at(CURRENT_SCHEMA, &v).ok(),
        Record::from_json(&v).ok(),
        "the current schema decodes as FromJson does"
    );
    for schema in PUBLISHED_SCHEMAS {
        if schema == CURRENT_SCHEMA {
            continue;
        }
        if let Ok(r) = record_from_json_at(schema, &v) {
            assert_eq!(
                record_from_json_at(CURRENT_SCHEMA, &r.to_json()).ok(),
                Some(r),
                "an accepted record upcasts to the current schema"
            );
        }
    }
    let unpublished = [0, CURRENT_SCHEMA.saturating_add(1), u16::MAX];
    for schema in unpublished {
        if !PUBLISHED_SCHEMAS.contains(&schema) {
            assert!(
                record_from_json_at(schema, &v).is_err(),
                "an unpublished schema version is refused"
            );
        }
    }
});

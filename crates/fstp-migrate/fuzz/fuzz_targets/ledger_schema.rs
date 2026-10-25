//! TH-26, H-05: ledger schema name validation (P4) on arbitrary input.
//!
//! The input, read as UTF-8 with invalid sequences replaced, is a
//! candidate schema name. `LedgerSchema::new` must agree with a reference
//! model of the rule: `[a-z_][a-z0-9_]*`, at most 63 bytes, not starting
//! with `pg_` and not `information_schema`. An accepted name is kept
//! unchanged. A refusal names a rule that the input breaks, and an
//! invalid byte offset points at the first byte that breaks it.

#![no_main]

use fstp_migrate::{LedgerSchema, LedgerSchemaError, MAX_LEDGER_SCHEMA_LEN};
use libfuzzer_sys::fuzz_target;

fn allowed(offset: usize, b: u8) -> bool {
    b.is_ascii_lowercase() || b == b'_' || (offset > 0 && b.is_ascii_digit())
}

fn reference(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LEDGER_SCHEMA_LEN
        && b.iter().enumerate().all(|(i, &c)| allowed(i, c))
        && !name.starts_with("pg_")
        && name != "information_schema"
}

fuzz_target!(|data: &[u8]| {
    let name = String::from_utf8_lossy(data);
    let name = name.as_ref();
    let got = LedgerSchema::new(name);
    assert_eq!(got.is_ok(), reference(name), "{name:?}");
    match got {
        Ok(schema) => {
            assert_eq!(schema.as_str(), name);
            assert_eq!(schema.to_string(), name);
        }
        Err(LedgerSchemaError::Empty) => assert!(name.is_empty()),
        Err(LedgerSchemaError::TooLong { len }) => {
            assert_eq!(len, name.len());
            assert!(len > MAX_LEDGER_SCHEMA_LEN);
        }
        Err(LedgerSchemaError::InvalidByte { offset }) => {
            let bytes = name.as_bytes();
            assert!(bytes.len() <= MAX_LEDGER_SCHEMA_LEN);
            let first_bad = bytes.iter().enumerate().position(|(i, &c)| !allowed(i, c));
            assert_eq!(first_bad, Some(offset), "{name:?}");
        }
        Err(LedgerSchemaError::Reserved) => {
            assert!(name.starts_with("pg_") || name == "information_schema");
        }
        Err(other) => panic!("unexpected error {other:?}"),
    }
});

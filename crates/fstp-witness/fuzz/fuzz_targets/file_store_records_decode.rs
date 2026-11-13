//! Fuzz target `file_store_records_decode` of `fstp-witness` (TH-26,
//! I-24, ADR-010 "Self-hosted witness"). Lane F-SELF.
//!
//! Checks, for the record content of a local witness's file store:
//!
//! - no panic, and both loaders are deterministic.
//! - a loaded chain has one log record per file record, and its witness
//!   sequence is the record count, so no record is skipped.
//! - the outstanding prepare of a loaded chain is the last record, and
//!   only when that record is a prepare.
//! - a loaded registry names each cell once.

#![no_main]

use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId};
use fstp_witness::file_store::{load_chain_file, load_registry_file};
use fstp_witness::load_file_store;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = match data.split_first() {
        Some((s, rest)) => (*s, rest),
        None => return,
    };
    if selector & 1 == 0 {
        let first = load_registry_file(bytes);
        assert_eq!(first, load_registry_file(bytes), "not deterministic");
        if let Ok(cells) = first {
            for (i, c) in cells.iter().enumerate() {
                assert!(
                    cells.iter().skip(i + 1).all(|d| d.cell != c.cell),
                    "a cell registered twice"
                );
            }
        }
        return;
    }
    let cell = CellId([selector; 16]);
    let chain = if selector & 2 == 0 {
        ChainId::App
    } else {
        ChainId::Vault
    };
    let first = load_chain_file(cell, chain, bytes);
    assert_eq!(
        first,
        load_chain_file(cell, chain, bytes),
        "not deterministic"
    );
    let Ok(loaded) = first else {
        return;
    };
    let records = load_file_store(bytes).expect("a loaded chain is a loaded store");
    assert_eq!(loaded.log.len(), records.len(), "a record was skipped");
    assert_eq!(
        loaded.state.seq,
        u64::try_from(records.len()).unwrap_or(u64::MAX),
        "the witness sequence is not the record count"
    );
    match loaded.log.last() {
        Some(WitnessRecord::Prepare(row)) => assert_eq!(
            loaded.state.outstanding,
            Some((row.anchor.n, row.anchor.link)),
            "the last prepare is not outstanding"
        ),
        _ => assert_eq!(
            loaded.state.outstanding, None,
            "a withdrawn prepare is outstanding"
        ),
    }
});

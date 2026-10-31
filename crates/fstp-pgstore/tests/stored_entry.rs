//! The stored-row decoder `fstp_pgstore::decode_stored_entry` (M3 design
//! sections 4.2 and 15, TH-26, H-05).
//!
//! The decoder must never panic, must accept only rows the schema allows,
//! and must accept one spelling per row. The no-panic and row-check
//! properties hold over the W0 stub too, since it refuses every input.
//! The round-trip properties wait for an encoder
//! (`common::STORED_ENTRY_SEAM`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{RowParts, encode_stored_entry, row_parts, stored_entry};
use fstp_pgstore::decode_stored_entry;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// The shortest sealed body: a 12-byte nonce and a 16-byte tag around an
/// empty ciphertext (design section 4.2).
const MIN_SEALED: usize = 28;

/// The checks every decoded row meets, from the `ledger.entry` columns:
/// `seq >= 1`, `schema >= 1`, and a sealed body of at least
/// [`MIN_SEALED`] bytes.
fn row_checks(p: &RowParts) -> Result<(), String> {
    if p.seq == 0 {
        return Err("TH-26: seq 0 decoded".to_owned());
    }
    if p.schema == 0 {
        return Err("TH-26: schema 0 decoded".to_owned());
    }
    if p.sealed.len() < MIN_SEALED {
        return Err(format!(
            "TH-26: a sealed body of {} bytes decoded",
            p.sealed.len()
        ));
    }
    Ok(())
}

fn parts(g: &mut Gen) -> RowParts {
    let mut command = [0u8; 16];
    command.copy_from_slice(&g.bytes(16..=16));
    RowParts {
        seq: g.u64_in(1..=u64::MAX),
        at: g.i64_in(-fstp_ledger::MAX_AT..=fstp_ledger::MAX_AT),
        command,
        schema: g.u16_in(1..=u16::MAX),
        sealed: g.bytes(MIN_SEALED..=200),
    }
}

/// TH-26, design section 15: arbitrary bytes never make the decoder
/// panic, and every refusal formats.
#[test]
fn th_26_decode_stored_entry_never_panics() {
    fstp_prop::check("th_26_decode_stored_entry_never_panics", |g: &mut Gen| {
        let bytes = g.bytes(0..=300);
        let shown = format!("{:?}", decode_stored_entry(&bytes));
        prop_assert!(!shown.is_empty());
        Ok(())
    });
}

/// TH-26, design section 4.2: whatever the decoder accepts meets the row
/// checks of `ledger.entry`.
#[test]
fn th_26_decoded_stored_entry_meets_the_row_checks() {
    fstp_prop::check(
        "th_26_decoded_stored_entry_meets_the_row_checks",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=300);
            if let Ok(e) = decode_stored_entry(&bytes) {
                row_checks(&row_parts(&e))?;
            }
            Ok(())
        },
    );
}

/// TH-26, design section 15 ("one layout"): every valid row encodes, and
/// the decoder returns it unchanged.
#[test]
fn th_26_stored_entry_round_trips() {
    fstp_prop::check("th_26_stored_entry_round_trips", |g: &mut Gen| {
        let e = stored_entry(&parts(g));
        let bytes = encode_stored_entry(&e)?.ok_or("TH-26: a valid row did not encode")?;
        prop_assert_eq!(decode_stored_entry(&bytes), Ok(e), "TH-26: round trip");
        Ok(())
    });
}

/// TH-26: the decoder accepts one spelling per row. A strict prefix or
/// an extension of a valid row is refused.
#[test]
fn th_26_stored_entry_has_one_spelling() {
    fstp_prop::check("th_26_stored_entry_has_one_spelling", |g: &mut Gen| {
        let e = stored_entry(&parts(g));
        let bytes = encode_stored_entry(&e)?.ok_or("TH-26: a valid row did not encode")?;
        let cut = g.usize_in(0..=bytes.len().saturating_sub(1));
        prop_assert!(
            decode_stored_entry(&bytes[..cut]).is_err(),
            "TH-26: a prefix of {cut} bytes decoded"
        );
        let mut longer = bytes.clone();
        longer.push(g.u8());
        prop_assert!(
            decode_stored_entry(&longer).is_err(),
            "TH-26: a trailing byte decoded"
        );
        Ok(())
    });
}

/// TH-26: the encoding of a row that breaks a row check never decodes.
/// The encoder may refuse such a row itself.
#[test]
fn th_26_stored_entry_refuses_rows_outside_the_schema() {
    fstp_prop::check(
        "th_26_stored_entry_refuses_rows_outside_the_schema",
        |g: &mut Gen| {
            let mut p = parts(g);
            match g.u8_in(0..=2) {
                0 => p.seq = 0,
                1 => p.schema = 0,
                _ => {
                    let keep = g.usize_in(0..=MIN_SEALED - 1);
                    p.sealed.truncate(keep);
                }
            }
            if let Some(bytes) = encode_stored_entry(&stored_entry(&p))? {
                prop_assert!(
                    decode_stored_entry(&bytes).is_err(),
                    "TH-26: a row outside the schema decoded: {p:?}"
                );
            }
            Ok(())
        },
    );
}

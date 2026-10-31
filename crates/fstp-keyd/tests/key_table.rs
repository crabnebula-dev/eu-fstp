//! The file custody key table of `fstp-keyd` (ADR-004 part 2 "File
//! custody", design section 3.3, Q32 A, I-80, I-81).
//!
//! ADR-004 part 2: the per-epoch keys `K(e)` "live in a separate small
//! key table. It is sealed under a key derived from the passphrase with
//! PBKDF2-HMAC-SHA-256 from aws-lc-rs, at least 600 000 iterations, with
//! a random salt in the table header." Destroy overwrites `K(e)` in
//! place.
//!
//! The tests go through two helpers with the shape the ADR implies.
//! Lane W2f filled them with `fstp_keyd::encode_key_table`, and with
//! `decode_custody_file` followed by `CustodyFile::open` under the
//! passphrase. The empty-input test calls the decoder itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use common::{Fail, classify, contains, expect_refused};
use fstp_custody::Chain;
use fstp_keyd::decode_custody_file;

/// The least PBKDF2 iteration count ADR-004 part 2 allows.
const MIN_ITERATIONS: u32 = 600_000;

/// One entry of the key table.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// The chain of the epoch.
    chain: Chain,
    /// The epoch.
    epoch: u64,
    /// `K(e)`, or `None` once destroy has overwritten it.
    key: Option<[u8; 32]>,
}

/// Seals `entries` under `passphrase` with `iterations` PBKDF2 rounds,
/// through `fstp_keyd::encode_key_table`.
fn encode_table(passphrase: &[u8], iterations: u32, entries: &[Entry]) -> Result<Vec<u8>, Fail> {
    let passphrase = fstp_keyd::Passphrase::from_bytes(passphrase).map_err(classify)?;
    let table = fstp_keyd::KeyTable {
        entries: entries
            .iter()
            .map(|e| {
                fstp_keyd::KeyTableEntry::new(
                    e.chain,
                    fstp_custody::Epoch(e.epoch),
                    e.key.map(fstp_keyd::EpochKey::from_bytes),
                )
            })
            .collect(),
    };
    fstp_keyd::encode_key_table(&passphrase, iterations, &table).map_err(classify)
}

/// Opens a key table under `passphrase`, through
/// `fstp_keyd::decode_custody_file` and `CustodyFile::open`. The key
/// bytes of the entries stay inside `fstp-keyd` (I-80), so [`same`]
/// compares them there.
fn decode_table(passphrase: &[u8], bytes: &[u8]) -> Result<Vec<fstp_keyd::KeyTableEntry>, Fail> {
    let passphrase = fstp_keyd::Passphrase::from_bytes(passphrase).map_err(classify)?;
    let table = decode_custody_file(bytes)
        .and_then(|f| f.open(&passphrase))
        .map_err(classify)?;
    Ok(table.entries)
}

/// Whether the opened entries `back` are exactly `want`: the same
/// chains and epochs in order, each live entry with the same `K(e)`
/// bytes, each overwritten entry with none.
fn same(back: &[fstp_keyd::KeyTableEntry], want: &[Entry]) -> bool {
    back.len() == want.len()
        && back.iter().zip(want).all(|(b, w)| {
            b.chain == w.chain
                && b.epoch.0 == w.epoch
                && match w.key {
                    Some(k) => b.holds(&fstp_keyd::EpochKey::from_bytes(k)),
                    None => !b.is_live(),
                }
        })
}

const PASSPHRASE: &[u8] = b"synthetic test passphrase, not a real one";

fn entries() -> Vec<Entry> {
    vec![
        Entry {
            chain: Chain::App,
            epoch: 1,
            key: None,
        },
        Entry {
            chain: Chain::App,
            epoch: 2,
            key: Some([0xa2; 32]),
        },
        Entry {
            chain: Chain::Vault,
            epoch: 1,
            key: Some([0xb1; 32]),
        },
    ]
}

/// Design section 15 (`custody_file_decode`): empty input is no key
/// table.
#[test]
fn adr004_custody_file_decoder_refuses_empty_input() {
    let r = decode_custody_file(&[]).map_err(classify);
    if let Err(e) = expect_refused(r, "empty input") {
        panic!("{e}");
    }
}

/// ADR-004 part 2: a key table opens under its passphrase to the entries
/// it was sealed with, live and overwritten alike.
#[test]
fn adr004_key_table_round_trips_under_its_passphrase() {
    let bytes =
        encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    let back = decode_table(PASSPHRASE, &bytes).unwrap_or_else(|e| panic!("{e}"));
    assert!(same(&back, &entries()), "the key table did not round trip");
}

/// I-80, ADR-004 part 2: the key table opens under no other passphrase.
#[test]
fn adr004_key_table_refuses_a_wrong_passphrase() {
    let bytes =
        encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    let r = decode_table(b"another synthetic passphrase", &bytes);
    if let Err(e) = expect_refused(r, "a wrong passphrase") {
        panic!("{e}");
    }
}

/// ADR-004 part 2: "at least 600 000 iterations". A table sealed with
/// fewer is refused when it is written or when it is read.
#[test]
fn adr004_key_table_refuses_fewer_than_600000_iterations() {
    let written = encode_table(PASSPHRASE, MIN_ITERATIONS - 1, &entries());
    let r = written.and_then(|bytes| decode_table(PASSPHRASE, &bytes));
    if let Err(e) = expect_refused(r, "599 999 iterations") {
        panic!("{e}");
    }
}

/// ADR-004 part 2: "a random salt in the table header". Two tables of the
/// same entries under the same passphrase differ.
#[test]
fn adr004_key_table_draws_a_fresh_salt() {
    let a = encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    let b = encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a, b, "two tables with the same salt");
}

/// I-80, ADR-004 part 2: the table is sealed. No live `K(e)` and no byte
/// of the passphrase appears in its bytes.
#[test]
fn i80_key_table_holds_no_epoch_key_or_passphrase_in_clear() {
    let bytes =
        encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    for e in entries() {
        if let Some(k) = e.key {
            assert!(
                !contains(&bytes, &k),
                "K({}) of {:?} in clear",
                e.epoch,
                e.chain
            );
        }
    }
    assert!(!contains(&bytes, PASSPHRASE), "the passphrase in clear");
}

/// Design section 15 ("limits enforced"): a key table cut short by any
/// number of bytes is refused.
#[test]
fn adr004_key_table_refuses_truncation() {
    let bytes =
        encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    let mut wrong = Vec::new();
    for keep in [0, 1, bytes.len() / 2, bytes.len().saturating_sub(1)] {
        let r = decode_table(PASSPHRASE, &bytes[..keep.min(bytes.len())]);
        if let Err(e) = expect_refused(r, &format!("cut to {keep} bytes")) {
            wrong.push(e);
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

/// The length of the header and passphrase check of a key table, before
/// its first slot, and the length of one slot (ADR-004 part 2, the
/// `fstp_keyd::table` layout).
const PREFIX_LEN: usize = 54;
const SLOT_LEN: usize = 70;

/// ADR-004 part 2 "A crash at any step loses nothing": a key table with
/// one slot damaged, as a torn in-place write leaves it, still opens.
/// Every other entry keeps its `K(e)`, and the damaged one is left out.
#[test]
fn adr004_key_table_damaged_slot_spares_the_others() {
    let bytes =
        encode_table(PASSPHRASE, MIN_ITERATIONS, &entries()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes.len(), PREFIX_LEN + SLOT_LEN * entries().len());
    let mut wrong = Vec::new();
    for slot in 0..entries().len() {
        for at in [0, SLOT_LEN / 2, SLOT_LEN - 1] {
            let mut torn = bytes.clone();
            torn[PREFIX_LEN + slot * SLOT_LEN + at] ^= 0x5a;
            let mut want = entries();
            want.remove(slot);
            match decode_table(PASSPHRASE, &torn) {
                Ok(back) if same(&back, &want) => {}
                Ok(_) => wrong.push(format!("slot {slot} byte {at}: other entries changed")),
                Err(e) => wrong.push(format!("slot {slot} byte {at}: {e}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

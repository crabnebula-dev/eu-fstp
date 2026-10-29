//! Fuzz target `stored_entry_decode` (M3 design section 15).
//!
//! Design checks: decrypt and decode never panic on arbitrary rows.
//!
//! Checks:
//!
//! - No input panics, and every refusal formats.
//! - Every accepted row meets the checks of `ledger.entry` (design section
//!   4.2): a sequence and a schema version from 1, and a sealed body of at
//!   least 28 bytes, a 12-byte nonce and a 16-byte tag around the
//!   ciphertext.
//! - The layout has one spelling: `encode_stored_entry` of an accepted row
//!   gives the input back.
//! - The open step of every ledger read, `open_stored_entry`, never panics
//!   on an accepted row under a fixed key, and never opens a body the key
//!   did not seal.
//! - A body sealed under the fixed key with the row's own AAD opens to its
//!   plaintext through the same path, after an encode and decode round
//!   trip.

#![no_main]

use fstp_crypto::aead;
use fstp_keys::DekId;
use fstp_pgstore::{
    LedgerKey, LedgerKeys, MAX_SEALED_LEN, StoredEntry, decode_stored_entry, encode_stored_entry,
    ledger_aad, open_stored_entry,
};
use libfuzzer_sys::fuzz_target;

/// The shortest sealed body: nonce and tag.
const MIN_SEALED: usize = 28;

/// The cell of every row.
const CELL: [u8; 16] = [0x5C; 16];

/// The fixed test key.
const KEY: [u8; 32] = [0xA7; 32];

/// Keys whose current generation is `key_ix`, under the fixed test key.
fn keys(key_ix: u32) -> Option<LedgerKeys> {
    let key = aead::Key::from_bytes(&KEY).ok()?;
    Some(LedgerKeys::new(LedgerKey::new(key_ix, DekId([1; 16]), key)))
}

fuzz_target!(|data: &[u8]| {
    let e = match decode_stored_entry(data) {
        Ok(e) => e,
        Err(err) => {
            let shown = format!("{err:?} {err}");
            assert!(!shown.is_empty());
            return;
        }
    };
    assert!(e.seq >= 1, "a decoded row has seq 0");
    assert!(e.schema >= 1, "a decoded row has schema 0");
    assert!(e.sealed.len() >= MIN_SEALED, "a decoded body is too short");
    assert_eq!(
        encode_stored_entry(&e).as_deref(),
        Ok(data),
        "a decoded row has a second spelling"
    );
    let Some(k) = keys(e.key_ix) else {
        return;
    };
    // Arbitrary bytes never open: the key sealed nothing yet.
    if let Ok(plain) = open_stored_entry(&k, &CELL, &e) {
        panic!("an unsealed body opened to {} bytes", plain.len());
    }
    // A body the key seals under the row's AAD opens through the read
    // path, after the layout round trip.
    let plain = &e.sealed;
    if plain.len() > MAX_SEALED_LEN - MIN_SEALED {
        return;
    }
    let Ok(key) = aead::Key::from_bytes(&KEY) else {
        return;
    };
    let aad = ledger_aad(&CELL, e.seq, e.at, &e.command, e.schema);
    let Ok(sealed) = aead::seal(&key, &aad, plain) else {
        return;
    };
    let mut body = sealed.nonce.to_vec();
    body.extend_from_slice(&sealed.body);
    let row = StoredEntry {
        sealed: body,
        ..e.clone()
    };
    let Ok(bytes) = encode_stored_entry(&row) else {
        panic!("a sealed row did not encode");
    };
    let Ok(back) = decode_stored_entry(&bytes) else {
        panic!("a sealed row did not decode");
    };
    match open_stored_entry(&k, &CELL, &back) {
        Ok(opened) => assert_eq!(opened.as_slice(), plain.as_slice(), "a body opened wrong"),
        Err(err) => panic!("a sealed body did not open: {err}"),
    }
    let moved = StoredEntry {
        seq: back.seq.wrapping_add(1).max(1),
        ..back
    };
    if moved.seq != e.seq {
        assert!(
            open_stored_entry(&k, &CELL, &moved).is_err(),
            "a body moved to another sequence opened"
        );
    }
});

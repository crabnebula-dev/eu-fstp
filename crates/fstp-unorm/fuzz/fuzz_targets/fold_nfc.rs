//! Fuzz target for the in-house normaliser (ADR-029, TH-26).
//!
//! Checks, for any UTF-8 input:
//! - no form panics;
//! - NFC and NFD are idempotent and agree on canonical equivalence;
//! - `fold_nfc` is idempotent, in NFC, and equal for NFC and NFD of the
//!   input;
//! - case folding is idempotent;
//! - every result keeps the `MAX_EXPANSION` bound.

#![no_main]

use fstp_unorm::{MAX_EXPANSION, casefold, fold_nfc, nfc, nfd};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let (c, d, k, f) = (nfc(s), nfd(s), fold_nfc(s), casefold(s));
    assert_eq!(nfc(&c), c, "NFC is not idempotent");
    assert_eq!(nfd(&d), d, "NFD is not idempotent");
    assert_eq!(nfc(&d), c, "NFC(NFD(s)) differs from NFC(s)");
    assert_eq!(nfd(&c), d, "NFD(NFC(s)) differs from NFD(s)");
    assert_eq!(fold_nfc(&k), k, "fold_nfc is not idempotent");
    assert_eq!(nfc(&k), k, "fold_nfc is not in NFC");
    assert_eq!(fold_nfc(&c), k, "fold_nfc differs on NFC(s)");
    assert_eq!(fold_nfc(&d), k, "fold_nfc differs on NFD(s)");
    assert_eq!(casefold(&f), f, "case folding is not idempotent");
    for out in [&c, &d, &k, &f] {
        assert!(
            out.len() <= MAX_EXPANSION * s.len(),
            "expansion bound broken"
        );
    }
});

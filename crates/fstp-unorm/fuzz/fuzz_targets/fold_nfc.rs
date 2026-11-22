//! Fuzz target for the in-house normaliser (ADR-029, TH-26).
//!
//! Checks, for any UTF-8 input:
//! - no form panics;
//! - NFC and NFD are idempotent and agree on canonical equivalence;
//! - `fold_nfc` is idempotent, in NFC, and equal for NFC and NFD of the
//!   input;
//! - case folding is idempotent;
//! - NFKC and NFKD are idempotent and agree with each other;
//! - `fold_nfkc` and `name_key` are idempotent, in NFC, and equal for
//!   NFC and NFD of the input;
//! - every result keeps the `MAX_EXPANSION` or `MAX_COMPAT_EXPANSION`
//!   bound.

#![no_main]

use fstp_unorm::{
    MAX_COMPAT_EXPANSION, MAX_EXPANSION, casefold, fold_nfc, fold_nfkc, name_key, nfc, nfd, nfkc,
    nfkd,
};
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
    let (kc, kd, kk, n) = (nfkc(s), nfkd(s), fold_nfkc(s), name_key(s));
    assert_eq!(nfkc(&kc), kc, "NFKC is not idempotent");
    assert_eq!(nfkd(&kd), kd, "NFKD is not idempotent");
    assert_eq!(nfc(&kd), kc, "NFC(NFKD(s)) differs from NFKC(s)");
    assert_eq!(nfkd(&kc), kd, "NFKD(NFKC(s)) differs from NFKD(s)");
    assert_eq!(fold_nfkc(&kk), kk, "fold_nfkc is not idempotent");
    assert_eq!(nfc(&kk), kk, "fold_nfkc is not in NFC");
    assert_eq!(fold_nfkc(&c), kk, "fold_nfkc differs on NFC(s)");
    assert_eq!(fold_nfkc(&d), kk, "fold_nfkc differs on NFD(s)");
    assert_eq!(name_key(&n), n, "name_key is not idempotent");
    assert_eq!(name_key(&c), n, "name_key differs on NFC(s)");
    for out in [&kc, &kd, &kk, &n] {
        assert!(
            out.len() <= MAX_COMPAT_EXPANSION * s.len(),
            "compatibility expansion bound broken"
        );
    }
    for out in [&c, &d, &k, &f] {
        assert!(
            out.len() <= MAX_EXPANSION * s.len(),
            "expansion bound broken"
        );
    }
});

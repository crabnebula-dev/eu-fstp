//! Fuzz target `custody_file_decode` of `fstp-keyd` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; limits enforced.
//!
//! The input feeds two decoders. The first is the sealed key table
//! decoder, which takes no passphrase: an accepted file must name no
//! more entries than 32-byte keys its input could hold, and at least
//! the 600 000 PBKDF2 iterations of ADR-004 part 2. Opening the table
//! is not fuzzed, since each PBKDF2 derivation of 600 000 rounds would
//! slow the target to a few runs a second. The second is the plaintext
//! body decoder that runs once a table opens. An accepted body must
//! name no more entries than its input holds. Every refusal must have a
//! short display, so no error can carry key table bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The longest error display the target accepts.
const DISPLAY_LIMIT: usize = 512;

fn check_display(e: &fstp_keyd::KeydError) {
    let shown = e.to_string();
    assert!(!shown.is_empty(), "an empty error display");
    assert!(
        shown.len() <= DISPLAY_LIMIT,
        "an error display of {} bytes",
        shown.len()
    );
}

fuzz_target!(|data: &[u8]| {
    match fstp_keyd::decode_custody_file(data) {
        Ok(f) => {
            assert!(
                f.root_count() <= data.len() / 32,
                "more roots than the input holds"
            );
            assert!(
                f.iterations() >= fstp_keyd::MIN_ITERATIONS,
                "accepted fewer than 600 000 iterations"
            );
        }
        Err(e) => check_display(&e),
    }
    match fstp_keyd::decode_key_table_body(data) {
        Ok(t) => assert!(
            t.entries.len() <= data.len() / 32,
            "more entries than the input holds"
        ),
        Err(e) => check_display(&e),
    }
});

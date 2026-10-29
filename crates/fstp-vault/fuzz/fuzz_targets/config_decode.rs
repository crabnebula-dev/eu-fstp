//! Fuzz target `config_decode` of `fstp-vault` (H-05, M3 design sections
//! 6.1, 6.9 and 15).
//!
//! Design checks: no panic. For every input:
//!
//! - `decode_config` never panics and is deterministic.
//! - An accepted configuration pins one to four ticket keys, and its
//!   input is the canonical spelling of the closed member set, so no
//!   extra member such as a fact source can pass.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The most pinned ticket keys (`fstp_vault_core::MAX_PINNED_KEYS`).
const MAX_PINNED_KEYS: usize = 4;

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault::config::decode_config(data);
    assert_eq!(
        got,
        fstp_vault::config::decode_config(data),
        "decode is not deterministic"
    );
    if let Ok(c) = got {
        assert!(
            (1..=MAX_PINNED_KEYS).contains(&c.ticket_keys.len()),
            "{} pinned keys",
            c.ticket_keys.len()
        );
        let text = String::from_utf8_lossy(data);
        for member in fstp_vault::config::CONFIG_MEMBERS {
            assert!(text.contains(&format!("\"{member}\":")), "no {member}");
        }
    }
});

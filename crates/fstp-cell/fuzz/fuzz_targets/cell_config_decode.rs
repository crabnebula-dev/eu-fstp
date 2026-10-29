//! Fuzz target `cell_config_decode` of `fstp-cell` (TH-26, H-05, I-16,
//! I-19, I-38, B12, M3 design sections 1.2, 10.3 and 15).
//!
//! `fstp_cell::config::decode` reads the configuration file of a cell.
//!
//! - No input panics, and every refusal formats.
//! - Decoding is a function of the input: the same bytes give the same
//!   answer twice.
//! - An input longer than `MAX_CONFIG_LEN` is refused.
//! - An accepted configuration keeps the mode rules: a self-hosted cell
//!   never runs as a P-45 intermediary (I-38), and a SaaS cell holds no
//!   licence (B12).
//! - An accepted configuration stays refused once an unknown member is
//!   added, so a typo never falls back to a default.
//! - An accepted configuration stays refused once one of its members is
//!   given twice, so no two readers can read it differently.
//!
//! The seeds under `fuzz/seeds/cell_config_decode` are accepted
//! configurations, so the last three checks run from the first input.

#![no_main]

use fstp_cell::config::{self, Mode, RelyingParty};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = config::decode(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    let again = config::decode(data);
    assert_eq!(
        first, again,
        "the decoder answered the same bytes twice differently"
    );
    if data.len() > config::MAX_CONFIG_LEN {
        assert!(first.is_err(), "a configuration over the limit decoded");
    }
    let Ok(cfg) = first else {
        return;
    };
    assert!(
        !(cfg.mode == Mode::SelfHosted && cfg.relying_party == RelyingParty::Intermediary),
        "I-38: a self-hosted configuration in intermediary mode decoded"
    );
    assert!(
        !(cfg.mode == Mode::Saas && cfg.licence.is_some()),
        "B12: a SaaS configuration with a licence decoded"
    );
    let Some(rest) = data.strip_prefix(b"{") else {
        return;
    };
    let mut unknown = b"{\"x_unknown\":0,".to_vec();
    unknown.extend_from_slice(rest);
    assert!(
        config::decode(&unknown).is_err(),
        "a configuration with an unknown member decoded"
    );
    let mut twice = b"{\"version\":\"0.0.1\",".to_vec();
    twice.extend_from_slice(rest);
    assert!(
        config::decode(&twice).is_err(),
        "a configuration with a member given twice decoded"
    );
});

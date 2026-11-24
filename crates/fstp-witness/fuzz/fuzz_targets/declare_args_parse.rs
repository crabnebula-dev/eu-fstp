//! Fuzz target `declare_args_parse` of `fstp-witness` (TH-26, ADR-012
//! record of lane m10/declared-restore): the arguments of the root-only
//! `declare-restore` console command.
//!
//! Checks:
//!
//! - no panic, and parsing is deterministic.
//! - accepted arguments print back to the same text, so each has one
//!   spelling: lowercase hex of fixed length, `app` or `vault`, and a
//!   decimal row with no leading zero.

#![no_main]

use fstp_audit::ChainId;
use fstp_witness::declare::parse_args;
use libfuzzer_sys::fuzz_target;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let args: Vec<&str> = text.split(' ').collect();
    let first = parse_args(&args);
    assert_eq!(first, parse_args(&args), "not deterministic");
    let Ok(a) = first else {
        return;
    };
    let chain = match a.chain {
        ChainId::App => "app",
        ChainId::Vault => "vault",
    };
    let back = format!(
        "{} {chain} {} {} {}",
        hex(&a.cell.0),
        a.head.0,
        hex(&a.head.1.0),
        hex(&a.job)
    );
    assert_eq!(back, text, "not one spelling");
});

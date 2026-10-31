//! Fuzz target `install_config_decode` of `fstp-control` (TH-26, H-05,
//! R-NF-01, ADR-011, M3 design sections 9.5 and 15).
//!
//! Design checks: no panic.
//!
//! On every input the decoder returns without a panic, its result formats,
//! and a second decode gives the same result. An accepted configuration
//! names a host in lowercase LDH form, and `id.<host>` is one too, since
//! the install routes both through the local edge (design section 9.5
//! step 7).

#![no_main]

use fstp_control::install::decode_install_config;
use libfuzzer_sys::fuzz_target;

/// A lowercase LDH host name: 1 to 253 bytes, labels of 1 to 63 letters,
/// digits and hyphens, no hyphen at a label's edge, and a last label that
/// is not all digits.
fn is_ldh_host(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    name.split('.').all(label_ok)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

fuzz_target!(|data: &[u8]| {
    let first = decode_install_config(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_install_config(data), first);
    if let Ok(cfg) = first {
        assert!(is_ldh_host(&cfg.host), "host {:?}", cfg.host);
        assert!(is_ldh_host(&format!("id.{}", cfg.host)), "{:?}", cfg.host);
    }
});

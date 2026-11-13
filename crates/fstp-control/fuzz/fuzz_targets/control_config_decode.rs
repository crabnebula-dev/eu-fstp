//! Fuzz target `control_config_decode` of `fstp-control` (TH-26, H-05,
//! I-16, I-20, M3 design sections 2.3, 9.1 and 15).
//!
//! Design checks: no panic.
//!
//! On every input the decoder returns without a panic, its result formats,
//! and a second decode gives the same result. An accepted configuration
//! has distinct cluster ids, distinct staff credential ids, an absolute
//! credentials path and a relying party host that `fstp-webauthn` takes.

#![no_main]

use std::collections::BTreeSet;

use fstp_control::config::{decode_control_config, is_config_path};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_control_config(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_control_config(data), first);
    if let Ok(cfg) = first {
        let ids: BTreeSet<[u8; 16]> = cfg.clusters.iter().map(|c| c.id.0).collect();
        assert_eq!(ids.len(), cfg.clusters.len());
        let creds: BTreeSet<&[u8]> = cfg
            .staff
            .iter()
            .map(|s| s.credential_id.as_slice())
            .collect();
        assert_eq!(creds.len(), cfg.staff.len());
        assert!(is_config_path(&cfg.credentials_dir));
        assert!(fstp_webauthn_host_ok(&cfg.operator_host));
        assert_ne!(cfg.cell_listen.port(), 0);
    }
});

/// The relying party rule, restated: at least three lowercase LDH labels.
fn fstp_webauthn_host_ok(host: &str) -> bool {
    host.split('.').count() >= 3
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

//! Fuzz target `pgagent_config_decode` of `fstp-control` (TH-26, H-05,
//! ADR-011, M3 design sections 2.3 and 15).
//!
//! Design checks: no panic.
//!
//! On every input the decoder returns without a panic, its result formats,
//! and a second decode gives the same result. An accepted configuration
//! never names a control cluster, which has no agent, and its paths are
//! absolute with no `.` or `..` segment.

#![no_main]

use fstp_control::config::{decode_pgagent_config, is_config_path};
use fstp_control::placement::ClusterKind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_pgagent_config(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_pgagent_config(data), first);
    if let Ok(cfg) = first {
        assert_ne!(cfg.cluster_kind, ClusterKind::Control);
        assert!(is_config_path(&cfg.credentials_dir));
        assert!(is_config_path(&cfg.hba_file));
        assert_ne!(cfg.postgres_port, 0);
        assert_ne!(cfg.listen.port(), 0);
    }
});

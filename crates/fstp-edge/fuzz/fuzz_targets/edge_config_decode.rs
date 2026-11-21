//! Fuzz target `edge_config_decode` of `fstp-edge` (TH-26, H-05, ADR-009
//! "Pilot edge configuration", R-NF-02). Lane L9 `prod/edgerun`.
//!
//! Design checks: no panic; limits enforced; deterministic.
//!
//! `decode_config` runs on every input. A decoded configuration names
//! absolute paths and holds limits within their ranges, with `per_client`
//! at most `connections`.

#![no_main]

use std::time::Duration;

use fstp_edge::config::{MAX_CONFIG_LEN, decode_config};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_config(data);
    assert_eq!(first, decode_config(data), "not deterministic");
    if let Ok(c) = first {
        assert!(data.len() <= MAX_CONFIG_LEN);
        assert!(c.credentials_dir.is_absolute());
        assert!(c.routes.is_absolute());
        let l = c.limits;
        assert!((1..=65_536).contains(&l.connections));
        assert!((1..=l.connections).contains(&l.per_client));
        for d in [l.hello, l.open] {
            assert!((Duration::from_secs(1)..=Duration::from_secs(60)).contains(&d));
        }
        assert!((Duration::from_secs(60)..=Duration::from_secs(86_400)).contains(&l.lifetime));
    }
});

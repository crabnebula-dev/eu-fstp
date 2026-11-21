//! Fuzz target `edge_config_decode` of `fstp-edge` (TH-26, H-05, ADR-009
//! "Pilot edge configuration" and "Pilot route feed", R-NF-02). Lane L9
//! `prod/edgerun`, lane L15 `prod/route-feed`.
//!
//! Design checks: no panic; limits enforced; deterministic.
//!
//! `decode_config` runs on every input. A decoded configuration names an
//! absolute credentials path, holds limits within their ranges, with
//! `per_client` at most `connections`, and a feed poll interval of 1 to
//! 60 seconds. `decode_feed_keys` runs on every input too: it gives one
//! or two distinct composite public keys, and the file re-encodes byte
//! for byte.

#![no_main]

use std::time::Duration;

use fstp_edge::config::{
    FEED_KEY_LEN, MAX_CONFIG_LEN, MAX_FEED_KEYS, decode_config, decode_feed_keys,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_config(data);
    assert_eq!(first, decode_config(data), "not deterministic");
    if let Ok(c) = first {
        assert!(data.len() <= MAX_CONFIG_LEN);
        assert!(c.credentials_dir.is_absolute());
        let l = c.limits;
        assert!((1..=65_536).contains(&l.connections));
        assert!((1..=l.connections).contains(&l.per_client));
        for d in [l.hello, l.open] {
            assert!((Duration::from_secs(1)..=Duration::from_secs(60)).contains(&d));
        }
        assert!((Duration::from_secs(60)..=Duration::from_secs(86_400)).contains(&l.lifetime));
        assert!(
            (Duration::from_secs(1)..=Duration::from_secs(60)).contains(&c.feed.poll),
            "poll interval out of range"
        );
    }
    let keys = decode_feed_keys(data);
    assert_eq!(keys, decode_feed_keys(data), "not deterministic");
    if let Ok(keys) = keys {
        assert!((1..=MAX_FEED_KEYS).contains(&keys.len()));
        assert!(keys.len() < 2 || keys[0] != keys[1], "a key twice");
        let mut again = String::new();
        for k in &keys {
            assert_eq!(k.len(), FEED_KEY_LEN);
            for b in k {
                again.push_str(&format!("{b:02x}"));
            }
            again.push('\n');
        }
        assert_eq!(again.as_bytes(), data, "the keys file has two spellings");
    }
});

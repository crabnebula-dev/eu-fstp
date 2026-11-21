//! Fuzz target `route_feed_decode` of `fstp-control` (TH-26, H-05, I-19,
//! R-NF-02, ADR-009 "Pilot route feed"). Lane L15 `prod/route-feed`.
//!
//! Design checks: no panic; limits enforced; deterministic; one spelling.
//!
//! Every decoder of the pilot route feed runs on every input: the
//! configuration, the feed key file, the operator request and reply, and
//! the audit log. An accepted configuration lists 1 to 16 distinct edges
//! and absolute paths. An accepted key file, request, reply or audit log
//! re-encodes to its input byte for byte, and an audit log's versions
//! rise.

#![no_main]

use fstp_control::config::{MAX_FEED_EDGES, decode_feed_config, is_config_path};
use fstp_control::route_change::{decode_audit_log, encode_audit_record};
use fstp_control::route_feed::{
    decode_feed_key_file, decode_operator_reply, decode_operator_request, encode_feed_key_file,
    encode_operator_message, encode_operator_reply,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = decode_feed_config(data);
    assert_eq!(cfg, decode_feed_config(data), "not deterministic");
    if let Ok(c) = cfg {
        assert!((1..=MAX_FEED_EDGES).contains(&c.edges.len()));
        for (i, e) in c.edges.iter().enumerate() {
            assert!(!c.edges[..i].contains(e), "an edge twice");
        }
        for p in [
            &c.credentials_dir,
            &c.keyd_socket,
            &c.operator_socket,
            &c.state_dir,
        ] {
            assert!(is_config_path(p));
        }
        assert_ne!(c.feed_listen.port(), 0);
    }
    if let Ok(f) = decode_feed_key_file(data) {
        assert_eq!(encode_feed_key_file(&f).as_deref(), Ok(data), "key file");
    }
    if let Ok((user, r)) = decode_operator_request(data) {
        assert_eq!(
            encode_operator_message(&user, &r).as_deref(),
            Ok(data),
            "request"
        );
    }
    if let Ok(r) = decode_operator_reply(data) {
        assert_eq!(&encode_operator_reply(&r)[..], data, "reply");
    }
    if let Ok((records, head)) = decode_audit_log(data) {
        let mut again = Vec::new();
        let mut h = [0u8; 32];
        for (i, r) in records.iter().enumerate() {
            assert!(i == 0 || records[i - 1].version < r.version, "versions");
            let (bytes, next) = encode_audit_record(&h, r).expect("a record encodes");
            again.extend_from_slice(&bytes);
            h = next;
        }
        assert_eq!(h, head, "chain head");
        assert_eq!(again, data, "audit log");
    }
});

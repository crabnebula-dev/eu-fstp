//! Fuzz target `route_feed_decode` of `fstp-control` (TH-26, H-05, I-19,
//! R-NF-02, ADR-009 "Pilot route feed"). Lane L15 `prod/route-feed`.
//!
//! Design checks: no panic; limits enforced; deterministic; one spelling.
//!
//! The route feed configuration decoder, the feed key file decoder, the
//! operator request decoder and the operator reply decoder run on every
//! input. An accepted configuration lists 1 to 16 distinct edges and
//! absolute paths. An accepted key file, request or reply re-encodes to
//! its input byte for byte.

#![no_main]

use fstp_control::config::{MAX_FEED_EDGES, decode_feed_config, is_config_path};
use fstp_control::route_feed::{
    decode_feed_key_file, decode_operator_reply, decode_operator_request, encode_feed_key_file,
    encode_operator_reply, encode_operator_request,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = decode_feed_config(data);
    assert_eq!(
        format!("{cfg:?}"),
        format!("{:?}", decode_feed_config(data))
    );
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
    if let Ok(r) = decode_operator_request(data) {
        assert_eq!(encode_operator_request(&r).as_deref(), Ok(data), "request");
    }
    if let Ok(r) = decode_operator_reply(data) {
        assert_eq!(&encode_operator_reply(&r)[..], data, "reply");
    }
});

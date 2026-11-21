//! Fuzz target `route_table_decode` of `fstp-edge` (TH-26, H-05, design
//! section 3.7 step 3, ADR-004 "Decided by Daniel, 2026-11-15 (late)",
//! ADR-009 "Pilot route feed"). Lane m3/erase-prod, lane L15.
//!
//! Design checks: no panic; limits enforced; one spelling.
//!
//! The signed route table decoder, the one-route decoder and the poll
//! decoder run on every input. A decoded table holds at most `MAX_ROUTES`
//! routes in strictly rising host order, and its body re-encodes byte for
//! byte, so the signed bytes have one spelling. A decoded route and a
//! decoded poll re-encode to their input.

#![no_main]

use fstp_edge::{
    MAX_ROUTES, decode_poll, decode_route, decode_signed_route_table, encode_poll, encode_route,
    encode_route_table_body, encode_signed_route_table,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_signed_route_table(data);
    assert_eq!(first, decode_signed_route_table(data), "not deterministic");
    if let Ok(t) = first {
        assert!(t.routes.len() <= MAX_ROUTES);
        assert!(
            t.routes
                .windows(2)
                .all(|w| w[0].route.host < w[1].route.host)
        );
        assert_eq!(
            encode_route_table_body(t.version, &t.routes).as_deref(),
            Ok(t.body.as_slice()),
            "the body does not re-encode"
        );
        assert_eq!(
            encode_signed_route_table(&t.body, &t.signature).as_deref(),
            Ok(data),
            "the signed table does not re-encode"
        );
    }
    if let Ok(r) = decode_route(data) {
        let mut again = Vec::new();
        encode_route(&mut again, &r).expect("a decoded route encodes");
        assert_eq!(again, data, "the route does not re-encode");
    }
    if let Ok(v) = decode_poll(data) {
        assert_eq!(&encode_poll(v)[..], data);
    }
});

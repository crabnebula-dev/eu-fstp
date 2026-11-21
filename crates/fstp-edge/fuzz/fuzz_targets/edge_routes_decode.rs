//! Fuzz target `edge_routes_decode` of `fstp-edge` (TH-26, H-05, I-19,
//! ADR-009 "Pilot edge configuration", R-NF-02). Lane L9 `prod/edgerun`.
//!
//! Design checks: no panic; limits enforced; deterministic; I-19.
//!
//! `decode_routes` runs on every input. A decoded file holds at most
//! `MAX_PILOT_ROUTES` cells, two routes each. Every route's endpoint has
//! exactly one pin, no two endpoints share a pin or an address, and a
//! host routes to one cell only.

#![no_main]

use fstp_edge::config::{MAX_PILOT_ROUTES, decode_routes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_routes(data);
    assert_eq!(first, decode_routes(data), "not deterministic");
    if let Ok(r) = first {
        assert!(r.table.len() <= 2 * MAX_PILOT_ROUTES);
        assert_eq!(r.table.len() % 2, 0);
        assert_eq!(r.pins.len(), r.table.len());
        let mut pins = Vec::new();
        let mut addrs = Vec::new();
        for (host, (ep, _)) in r.table.iter() {
            let pin = r.pins.pin_of(ep).expect("every endpoint has a pin");
            assert!(!pins.contains(&pin), "a pin serves two endpoints");
            pins.push(pin);
            assert!(!addrs.contains(&ep.address), "an address serves two routes");
            addrs.push(ep.address);
            assert_eq!(r.table.route(host).map(|(e, _)| e.cell), Some(ep.cell));
        }
    }
});

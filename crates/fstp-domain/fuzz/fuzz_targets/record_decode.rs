//! Fuzz target for the `fstp-domain` record decoder (TH-26, H-05).
//!
//! W0 stub: the record codec does not exist yet, so the target exercises the
//! closest existing stage, the JSON parser and canonical writer that the
//! codec will sit on. Lane L-CODEC replaces the body when it lands the
//! codec. The final target decodes core ledger records, for every schema version. It rejects unknown members and checks the round trip.

#![no_main]

use fstp_domain as _;
use fstp_json::{parse, to_canonical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    let _ = to_canonical(&v);
});

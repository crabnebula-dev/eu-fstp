//! Fuzz target `vault_request_decode` of `fstp-vault-proto` (TH-26, H-05,
//! M3 design sections 6.2 and 15).
//!
//! Design checks: no panic; round trip; exact amount strings; one-bit
//! answers carry no account set. For every input:
//!
//! - `decode_request` never panics and is deterministic.
//! - An accepted request re-encodes through the reference encoding of
//!   `tests/common/wire.rs` to the input byte for byte. So it has one
//!   spelling, and every amount in its query arguments is the exact
//!   ADR-006 string it arrived as.
//! - Every query of an accepted `ask` has a kind of `QueryKind::ALL`.
//!
//! Against the W0 stub every input is refused, so only the first check
//! has teeth until lane W2d lands the decoder.

#![no_main]

#[path = "../../tests/common/wire.rs"]
mod wire;

use fstp_vault_proto::VaultRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault_proto::decode_request(data);
    assert_eq!(
        got,
        fstp_vault_proto::decode_request(data),
        "decode is not deterministic"
    );
    if let Ok(r) = got {
        assert_eq!(
            wire::request(&r),
            data,
            "an accepted request has another spelling"
        );
        if let VaultRequest::Ask { queries, .. } = &r {
            assert!(queries.iter().all(|q| q.kind < wire::kind::COUNT));
        }
    }
});

//! Fuzz target `vault_response_decode` of `fstp-vault-proto` (TH-26, H-05,
//! M3 design sections 6.2 and 15, NOTE 5).
//!
//! Design checks: no panic; round trip; exact amount strings; one-bit
//! answers carry no account set. For every input:
//!
//! - `decode_response` never panics and is deterministic.
//! - An accepted response re-encodes through the reference encoding of
//!   `tests/common/wire.rs` to the input byte for byte.
//! - Every accepted answer keeps the one-bit rule: an account set appears
//!   in ascending order, and its bit says whether it is non-empty.
//!
//! Against the W0 stub every input is refused, so only the first check
//! has teeth until lane W2d lands the decoder.

#![no_main]

#[path = "../../tests/common/wire.rs"]
mod wire;

use fstp_vault_proto::VaultResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault_proto::decode_response(data);
    assert_eq!(
        got,
        fstp_vault_proto::decode_response(data),
        "decode is not deterministic"
    );
    if let Ok(r) = got {
        assert_eq!(
            wire::response(&r),
            data,
            "an accepted response has another spelling"
        );
        if let VaultResponse::Answers(answers) = &r {
            assert!(answers.iter().all(wire::answer_is_lawful));
        }
    }
});

//! Every reply of the vault's internal API decodes at the cell (NOTE 2,
//! NOTE 5, design section 6.2).
//!
//! The cell reads each reply with the shared `decode_response` and pairs
//! answers with queries through `answers_for`. A reply it cannot read
//! fails the cell closed, so the vault must never emit one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

#[path = "../../fstp-vault-proto/tests/common/mod.rs"]
mod proto;

use fstp_prop::{Gen, prop_assert};
use fstp_vault::Vault;
use fstp_vault_proto::{VaultRequest, VaultResponse, answers_for, decode_response, encode_request};

const CELL: [u8; 16] = [0xCE; 16];
const NOW: i64 = 10_001_000_000;

/// The next request: a generated one, or the acknowledgement of the
/// provisional epoch, so writes become effective and later asks see them.
fn next(g: &mut Gen, v: &Vault) -> VaultRequest {
    match (g.u8_in(0..=2), v.state().provisional()) {
        (0, Some(p)) => VaultRequest::Ack {
            epoch: p.epoch(),
            ledger_seq: p.epoch(),
            link: [7; 32],
        },
        _ => proto::gen_request(g),
    }
}

/// NOTE 2, NOTE 5: over any sequence of internal requests, every reply
/// `internal_bytes` emits decodes with `decode_response`, and every
/// answer set pairs with its queries through `answers_for`.
#[test]
fn note5_every_internal_reply_decodes_at_the_cell() {
    fstp_prop::check(
        "note5_every_internal_reply_decodes_at_the_cell",
        |g: &mut Gen| {
            let mut v = Vault::new(CELL, &[[0x11; 32]]).unwrap();
            for _ in 0..g.usize_in(1..=24) {
                let req = next(g, &v);
                let Ok(bytes) = encode_request(&req) else {
                    continue;
                };
                let reply = v.internal_bytes(&bytes, NOW);
                let decoded = decode_response(&reply);
                prop_assert!(decoded.is_ok(), "{req:?} gave an unreadable reply");
                if let (VaultRequest::Ask { queries, .. }, Ok(r @ VaultResponse::Answers(_))) =
                    (&req, &decoded)
                {
                    prop_assert!(answers_for(queries, r).is_ok(), "{req:?} gave {r:?}");
                }
            }
            Ok(())
        },
    );
}

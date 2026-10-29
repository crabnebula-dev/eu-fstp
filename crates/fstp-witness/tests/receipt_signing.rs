//! ADR-010 "Composite encoding", lane W2g hard limit (interim): no
//! production code in `fstp-witness` signs a receipt before Daniel
//! accepts the composite encoding table. Receipt signing must refuse with
//! a typed refusal that names that acceptance.
//!
//! This is an interim test. It turns red once the table is accepted, and
//! is then replaced by the R-CR-03 receipt signing test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::ACCEPTANCE;
use common::api::{self, Chain, Receipt};
use fstp_witness::WitnessError;

/// ADR-010, lane W2g hard limit: receipt signing refuses, naming "ADR-010
/// composite encoding acceptance (Daniel)". It never signs with Ed25519
/// alone or with the aws-lc-rs oracle.
#[test]
fn adr010_receipt_signing_refuses_until_the_composite_encoding_is_accepted() {
    let receipt = Receipt {
        n: 2,
        link: [0x5C; 32],
        witness_seq: 9,
        witness_link: [0xA5; 32],
        received_at: 1_700_000_000_000_005,
    };
    let r = api::sign_receipt_with_a_fresh_key([0x11; 16], Chain::App, &receipt);
    let named = match &r {
        Err(WitnessError::NotImplemented(op)) => op.contains(ACCEPTANCE),
        #[allow(
            unreachable_patterns,
            reason = "the W0 stub has one variant; W2g may add a refusal"
        )]
        Err(e) => format!("{e:?}").contains(ACCEPTANCE),
        Ok(_) => false,
    };
    assert!(
        named,
        "receipt signing must refuse naming {ACCEPTANCE:?}, got {r:?}"
    );
}

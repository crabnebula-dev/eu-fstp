//! `fstp_vault_proto::decode_ticket` (I-17, ADR-009 "Tickets", design
//! sections 6.5 and 15).
//!
//! A signed ticket is the canonical claims body followed by the 64-byte
//! Ed25519 signature over it. This crate holds no key, so it cannot check
//! the signature. ADR-009 says the signature is checked before any other
//! field is used. So `decode_ticket` only frames the bytes. It reads no
//! claim, and the vault parses the claims after the signature verifies.
//!
//! Reading, in the lane report: the decoder accepts any body of at least
//! one byte before the signature. ADR-009 sets a body limit per ticket
//! kind but no ticket limit, and the kind is a claim, so no length bound
//! is tested here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::wire::{RTicket, SIGNATURE_LEN};
use common::{is_stub, shown};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_proto::{Ticket, decode_ticket};

fn ticket() -> RTicket {
    RTicket {
        kind: "release".to_owned(),
        cell: [0xCE; 16],
        account: 501,
        proposal: Some(1),
        scope: "identity".to_owned(),
        issued_at: 10_000_000_000,
        expires_at: 10_000_000_000 + 300_000_000,
        nonce: [7; 16],
    }
}

/// I-17, ADR-009: a framed ticket decodes to exactly its bytes.
#[test]
fn i17_ticket_decode_keeps_the_signed_bytes() {
    let bytes = ticket().framed(&[0x5A; SIGNATURE_LEN]);
    assert_eq!(
        decode_ticket(&bytes),
        Ok(Ticket {
            bytes: bytes.clone()
        })
    );
}

/// I-17, ADR-009 "The ticket signature is checked before any other field
/// is used": the decoder parses no claim, so a body that is not a claims
/// object still frames. The vault refuses it once the signature fails.
#[test]
fn i17_ticket_decode_reads_no_claim_before_the_signature() {
    fstp_prop::check(
        "i17_ticket_decode_reads_no_claim_before_the_signature",
        |g: &mut Gen| {
            let body = g.bytes(1..=300);
            let sig = g.bytes(SIGNATURE_LEN..=SIGNATURE_LEN);
            let bytes = [body.as_slice(), sig.as_slice()].concat();
            prop_assert_eq!(
                decode_ticket(&bytes),
                Ok(Ticket {
                    bytes: bytes.clone()
                })
            );
            Ok(())
        },
    );
}

/// I-17: input with no room for a body and a signature is refused, with
/// a typed error, while a full ticket frames.
#[test]
fn i17_ticket_decode_refuses_input_without_body_and_signature() {
    let full = ticket().framed(&[0x5A; SIGNATURE_LEN]);
    assert!(decode_ticket(&full).is_ok(), "the full twin");
    for len in 0..=SIGNATURE_LEN {
        let got = decode_ticket(&full[full.len() - len..]);
        assert!(
            matches!(&got, Err(e) if !is_stub(e)),
            "{len} bytes: {}",
            shown(&got)
        );
    }
}

/// TH-26: arbitrary bytes never panic, and an accepted input is kept
/// whole and has room for a body and a signature.
#[test]
fn th_26_ticket_decode_is_total() {
    fstp_prop::check("th_26_ticket_decode_is_total", |g: &mut Gen| {
        let bytes = g.bytes(0..=200);
        match decode_ticket(&bytes) {
            Ok(t) => {
                prop_assert_eq!(&t.bytes, &bytes);
                prop_assert!(bytes.len() > SIGNATURE_LEN);
            }
            Err(e) => prop_assert!(
                !is_stub(&e) || bytes.len() <= SIGNATURE_LEN,
                "the W0 stub refused {} bytes",
                bytes.len()
            ),
        }
        Ok(())
    });
}

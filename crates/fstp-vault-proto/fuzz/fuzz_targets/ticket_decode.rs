//! Fuzz target `ticket_decode` of `fstp-vault-proto` (TH-26, H-05, I-17,
//! M3 design sections 6.5 and 15, ADR-009 "Tickets").
//!
//! Design checks: no panic; round trip. For every input:
//!
//! - `decode_ticket` never panics and is deterministic.
//! - An accepted ticket keeps the input whole, so the vault checks the
//!   signature over exactly the bytes the cell signed. It has room for a
//!   body and the 64-byte signature.
//! - `TicketClaims::parse` never panics, on the whole input and on the
//!   body of a framed ticket. Accepted claims write back to exactly the
//!   bytes they were parsed from, so a claim set has one spelling.

#![no_main]

use fstp_vault_proto::TicketClaims;
use libfuzzer_sys::fuzz_target;

/// The length of the Ed25519 signature that ends a signed ticket.
const SIGNATURE_LEN: usize = 64;

/// Parses `body` as ticket claims and checks the canonical round trip.
fn claims(body: &[u8]) {
    let got = TicketClaims::parse(body);
    assert_eq!(got, TicketClaims::parse(body), "parse is not deterministic");
    if let Ok(c) = got {
        let again = c
            .canonical()
            .expect("accepted claims have a canonical form");
        assert_eq!(again, body, "the claims do not round-trip");
        assert_eq!(
            TicketClaims::parse(&again),
            Ok(c),
            "the round trip changed the claims"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let got = fstp_vault_proto::decode_ticket(data);
    assert_eq!(
        got,
        fstp_vault_proto::decode_ticket(data),
        "decode is not deterministic"
    );
    claims(data);
    if let Ok(t) = got {
        assert_eq!(t.bytes, data, "the ticket bytes changed");
        assert!(data.len() > SIGNATURE_LEN, "no room for body and signature");
        claims(t.body());
    }
});

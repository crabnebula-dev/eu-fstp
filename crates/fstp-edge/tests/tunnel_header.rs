//! Tests of the tunnel header codec (M3 design sections 1.3, 9.4 and 15,
//! ADR-009 "Edge and tunnel", I-19, TH-26).
//!
//! The header is the first frame of the edge-to-cell tunnel. It has a
//! fixed length, round-trips, and has exactly one spelling: every
//! accepted input re-encodes byte for byte, and every other length is
//! refused. `fstp-cell` and `fstp-vault` call the same decoder.
//!
//! `HostName` has no public constructor in the W0 stub, so each header's
//! host comes from the ClientHello parser. These tests stay red until both
//! the parser and the codec land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/common.rs"]
mod common;
#[path = "support/hello.rs"]
mod hello;

use fstp_edge::{TUNNEL_HEADER_LEN, TunnelHeader, decode_tunnel_header};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

use common::{encode, host_via_parser, is_stub};

/// A random header: a host from the parser and any client address.
fn gen_header(g: &mut Gen) -> Result<TunnelHeader, String> {
    let host = host_via_parser(g)?;
    let mut client = [0u8; 16];
    for b in &mut client {
        *b = g.u8();
    }
    let port = g.u16();
    Ok(TunnelHeader { host, client, port })
}

/// I-19, TH-26 (design section 15, `tunnel_header_decode`): every header
/// round-trips through the encoder and the decoder.
#[test]
fn i19_tunnel_header_round_trips() {
    check("i19_tunnel_header_round_trips", |g| {
        let h = gen_header(g)?;
        let bytes = encode(&h)?;
        let back = decode_tunnel_header(&bytes);
        prop_assert_eq!(back, Ok(h));
        Ok(())
    });
}

/// I-19, TH-26 (design section 15): the header has one spelling. Changing
/// any one byte of an encoding either is refused or decodes to another
/// header, and that header re-encodes to exactly the changed bytes.
#[test]
fn i19_tunnel_header_has_one_spelling() {
    check("i19_tunnel_header_has_one_spelling", |g| {
        let h = gen_header(g)?;
        let mut bytes = encode(&h)?;
        let at = g.usize_in(0..=TUNNEL_HEADER_LEN - 1);
        let delta = g.u8_in(1..=255);
        bytes[at] ^= delta;
        match decode_tunnel_header(&bytes) {
            Ok(other) => {
                prop_assert!(other != h, "byte {} changed but the header did not", at);
                let again = encode(&other)?;
                prop_assert_eq!(again, bytes, "byte {} has a second spelling", at);
            }
            Err(e) => prop_assert!(!is_stub(&e), "stub refusal {:?}", e),
        }
        Ok(())
    });
}

/// I-19, TH-26 (design section 15): any input the decoder accepts
/// re-encodes byte for byte. Inputs are encodings with up to eight random
/// byte changes; the unchanged ones must decode, so the property is never
/// vacuous.
#[test]
fn i19_tunnel_header_accepted_input_reencodes_byte_for_byte() {
    check(
        "i19_tunnel_header_accepted_input_reencodes_byte_for_byte",
        |g| {
            let h = gen_header(g)?;
            let mut bytes = encode(&h)?;
            let changes = g.usize_in(0..=8);
            for _ in 0..changes {
                let at = g.usize_in(0..=TUNNEL_HEADER_LEN - 1);
                bytes[at] = g.u8();
            }
            let verdict = decode_tunnel_header(&bytes);
            if changes == 0 {
                prop_assert_eq!(verdict.as_ref(), Ok(&h), "an encoding did not decode");
            }
            match verdict {
                Ok(d) => prop_assert_eq!(encode(&d)?, bytes),
                Err(e) => prop_assert!(!is_stub(&e), "stub refusal {:?}", e),
            }
            Ok(())
        },
    );
}

/// I-19, TH-26 (design section 1.3: a fixed-length header): an encoding
/// cut short, or followed by any further bytes, is refused. The decoder
/// takes exactly `TUNNEL_HEADER_LEN` bytes, so tunnel bytes after the
/// header are never read as part of it.
#[test]
fn i19_tunnel_header_refuses_any_other_length() {
    check("i19_tunnel_header_refuses_any_other_length", |g| {
        let h = gen_header(g)?;
        let full = encode(&h)?;
        let bytes = if g.bool() {
            full[..g.usize_in(0..=TUNNEL_HEADER_LEN - 1)].to_vec()
        } else {
            let mut longer = full.to_vec();
            longer.extend_from_slice(&g.bytes(1..=TUNNEL_HEADER_LEN));
            longer
        };
        let verdict = decode_tunnel_header(&bytes);
        prop_assert!(
            matches!(&verdict, Err(e) if !is_stub(e)),
            "{} bytes: {:?}",
            bytes.len(),
            verdict
        );
        Ok(())
    });
}

//! Fuzz target `tunnel_header_decode` of `fstp-edge` (TH-26, H-05, I-19,
//! M3 design section 15).
//!
//! Design checks: no panic; the tunnel header round-trips and has one
//! spelling.
//!
//! - Decode side: the whole input goes to the decoder. An accepted input
//!   is exactly `TUNNEL_HEADER_LEN` bytes and re-encodes byte for byte,
//!   and its re-encoding decodes to the same header.
//! - Encode side: the input also names a host and a client address. The
//!   host goes through a ClientHello to the parser, since `HostName` has
//!   no public constructor. When the parser names it, the header built
//!   from it round-trips.
//!
//! While the codec and the parser are W0 stubs, they refuse with
//! `NotImplemented`, and the target checks only that no input panics.
//! It tells that refusal apart by its `Debug` form. The design gives an
//! infallible encoder, and the stub returns a `Result`, so the target
//! reads the encoder's output through a trait that both forms implement.

#![no_main]

#[path = "../../tests/support/hello.rs"]
mod hello;

use std::fmt::Debug;

use fstp_edge::{
    SniOutcome, TUNNEL_HEADER_LEN, TunnelHeader, decode_tunnel_header, encode_tunnel_header,
    parse_client_hello_sni,
};
use libfuzzer_sys::fuzz_target;

fn is_stub<E: Debug>(e: &E) -> bool {
    format!("{e:?}").starts_with("NotImplemented")
}

/// The encoder's output as bytes, or `None` for the stub's refusal.
trait Encoded {
    fn into_bytes(self) -> Option<[u8; TUNNEL_HEADER_LEN]>;
}

impl Encoded for [u8; TUNNEL_HEADER_LEN] {
    fn into_bytes(self) -> Option<[u8; TUNNEL_HEADER_LEN]> {
        Some(self)
    }
}

impl<E: Debug> Encoded for Result<[u8; TUNNEL_HEADER_LEN], E> {
    fn into_bytes(self) -> Option<[u8; TUNNEL_HEADER_LEN]> {
        match self {
            Ok(b) => Some(b),
            Err(e) if is_stub(&e) => None,
            Err(e) => panic!("the infallible encoder refused: {e:?}"),
        }
    }
}

fn encode(h: &TunnelHeader) -> Option<[u8; TUNNEL_HEADER_LEN]> {
    encode_tunnel_header(h).into_bytes()
}

/// Bytes a host name is drawn from. The parser decides validity.
const HOST_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-.";

/// A header built from the input, if the parser names its host.
fn header_from(data: &[u8]) -> Option<TunnelHeader> {
    let (&n, rest) = data.split_first()?;
    let n = usize::from(n).min(rest.len());
    let (name, rest) = rest.split_at(n);
    let host: Vec<u8> = name
        .iter()
        .map(|b| HOST_BYTES[usize::from(*b) % HOST_BYTES.len()])
        .collect();
    let record = hello::Hello::tls13(Some(&host)).record();
    let Ok(SniOutcome::Host(host)) = parse_client_hello_sni(&record) else {
        return None;
    };
    let mut client = [0u8; 16];
    for (c, b) in client.iter_mut().zip(rest) {
        *c = *b;
    }
    let port = rest
        .get(16..18)
        .map_or(0, |p| u16::from_be_bytes([p[0], p[1]]));
    Some(TunnelHeader { host, client, port })
}

fuzz_target!(|data: &[u8]| {
    match decode_tunnel_header(data) {
        Ok(h) => {
            assert_eq!(
                data.len(),
                TUNNEL_HEADER_LEN,
                "accepted a header of another length"
            );
            if let Some(again) = encode(&h) {
                assert_eq!(&again[..], data, "an accepted header has a second spelling");
                assert_eq!(
                    decode_tunnel_header(&again),
                    Ok(h),
                    "re-encoding changed it"
                );
            }
        }
        Err(e) => {
            let shown = format!("{e:?}");
            assert!(!shown.is_empty());
        }
    }
    if let Some(h) = header_from(data)
        && let Some(bytes) = encode(&h)
    {
        assert_eq!(
            decode_tunnel_header(&bytes),
            Ok(h),
            "a header did not round-trip"
        );
    }
});

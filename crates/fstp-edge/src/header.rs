//! The tunnel header codec (M3 design sections 1.3 and 9.4, ADR-009 "Edge
//! and tunnel", I-19, TH-26).
//!
//! The header is the first frame of the edge-to-cell tunnel. The client's
//! TLS stream follows it unchanged. `fstp-cell` and `fstp-vault` call
//! [`decode_tunnel_header`] on the first [`TUNNEL_HEADER_LEN`] bytes of
//! each tunnel.
//!
//! Byte layout, version 1, all integers big endian:
//!
//! | Offset | Length | Field |
//! | --- | --- | --- |
//! | 0 | 1 | Version, [`TUNNEL_HEADER_VERSION`] |
//! | 1 | 1 | Address family: 4 for IPv4, 6 for IPv6 |
//! | 2 | 16 | Client address. An IPv4 address is IPv4-mapped (`::ffff:a.b.c.d`) |
//! | 18 | 2 | Client port |
//! | 20 | 1 | Host length, 1 to 253 |
//! | 21 | 253 | Routed host, lowercase LDH, then zero bytes to the end |
//!
//! The header has one spelling. The address family follows from the
//! address: 4 exactly when the address is IPv4-mapped. The decoder refuses
//! any other length, version or family, an upper case or invalid host and
//! a non-zero padding byte. So every accepted header re-encodes byte for
//! byte.
//!
//! The client address and port serve in-memory rate limits only. They are
//! never stored or logged (ADR-009, design Q19).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::host::{HostName, MAX_HOST_LEN};

/// The version this codec writes and accepts.
pub const TUNNEL_HEADER_VERSION: u8 = 1;

/// The address family byte for IPv4.
pub const FAMILY_IPV4: u8 = 4;

/// The address family byte for IPv6.
pub const FAMILY_IPV6: u8 = 6;

/// The bytes before the host field: version, family, address, port and
/// host length.
const FIXED_LEN: usize = 1 + 1 + 16 + 2 + 1;

/// The length of the tunnel header.
pub const TUNNEL_HEADER_LEN: usize = FIXED_LEN + MAX_HOST_LEN;

/// The first twelve bytes of an IPv4-mapped IPv6 address.
const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// The header the edge sends before the spliced bytes.
///
/// Its `Debug` form names the host and redacts the client address and
/// port, which are never logged (ADR-009, design Q19).
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelHeader {
    /// The routed host, as the ClientHello named it.
    pub host: HostName,
    /// The client address as sixteen bytes. An IPv4 address is
    /// IPv4-mapped. For in-memory rate limits only.
    pub client: [u8; 16],
    /// The client port. For in-memory rate limits only.
    pub port: u16,
}

impl fmt::Debug for TunnelHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHeader")
            .field("host", &self.host)
            .field("client", &"<redacted>")
            .field("port", &"<redacted>")
            .finish()
    }
}

/// Why a tunnel header did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The input is not exactly [`TUNNEL_HEADER_LEN`] bytes.
    Length,
    /// The version is not [`TUNNEL_HEADER_VERSION`].
    Version,
    /// The family byte does not match the address.
    Family,
    /// The host length is zero or longer than [`MAX_HOST_LEN`].
    HostLength,
    /// The host is not a lowercase LDH name.
    Host,
    /// A byte after the host is not zero.
    Padding,
}

impl TunnelHeader {
    /// A header for `host` and the client's socket address.
    pub fn new(host: HostName, peer: SocketAddr) -> TunnelHeader {
        let client = match peer.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        TunnelHeader {
            host,
            client,
            port: peer.port(),
        }
    }

    /// The address family byte of the client address.
    pub fn family(&self) -> u8 {
        family_of(&self.client)
    }

    /// The client address. An IPv4-mapped address comes back as IPv4.
    pub fn client_ip(&self) -> IpAddr {
        let v6 = Ipv6Addr::from(self.client);
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    }
}

/// The family byte of a sixteen-byte address.
fn family_of(client: &[u8; 16]) -> u8 {
    if client.starts_with(&V4_MAPPED_PREFIX) {
        FAMILY_IPV4
    } else {
        FAMILY_IPV6
    }
}

/// Encodes a tunnel header.
pub fn encode_tunnel_header(h: &TunnelHeader) -> [u8; TUNNEL_HEADER_LEN] {
    let host = h.host.as_bytes();
    // A `HostName` holds at most `MAX_HOST_LEN` bytes, so its length fits
    // one byte and the host fits its field.
    let host_len = u8::try_from(host.len()).unwrap_or(0);
    let port = h.port.to_be_bytes();
    let fields = [TUNNEL_HEADER_VERSION, h.family()]
        .into_iter()
        .chain(h.client)
        .chain(port)
        .chain([host_len])
        .chain(host.iter().copied());
    let mut out = [0u8; TUNNEL_HEADER_LEN];
    for (slot, b) in out.iter_mut().zip(fields) {
        *slot = b;
    }
    out
}

/// Decodes a tunnel header. Fuzzed (`tunnel_header_decode`). The cell
/// calls it too.
///
/// The host field repeats the SNI that the cell or vault TLS server sees
/// itself. A caller must refuse a tunnel whose header host differs from
/// that SNI, and must never trust the header host over its own TLS
/// server. Whether the field stays is open for the lead and Daniel
/// (ADR-009 records neither the field nor the layout yet).
///
/// # Errors
///
/// Returns a [`HeaderError`] for any input other than the one spelling of
/// a header.
pub fn decode_tunnel_header(b: &[u8]) -> Result<TunnelHeader, HeaderError> {
    let bytes: &[u8; TUNNEL_HEADER_LEN] = b.try_into().map_err(|_| HeaderError::Length)?;
    let (&[version, family], rest) = bytes.split_first_chunk::<2>().ok_or(HeaderError::Length)?;
    if version != TUNNEL_HEADER_VERSION {
        return Err(HeaderError::Version);
    }
    let (&client, rest) = rest.split_first_chunk::<16>().ok_or(HeaderError::Length)?;
    if family != family_of(&client) {
        return Err(HeaderError::Family);
    }
    let (&port, rest) = rest.split_first_chunk::<2>().ok_or(HeaderError::Length)?;
    let (&host_len, field) = rest.split_first().ok_or(HeaderError::Length)?;
    let host_len = usize::from(host_len);
    if host_len == 0 || host_len > MAX_HOST_LEN {
        return Err(HeaderError::HostLength);
    }
    let (name, padding) = field
        .split_at_checked(host_len)
        .ok_or(HeaderError::HostLength)?;
    let host = HostName::parse_lowercase(name).map_err(|_| HeaderError::Host)?;
    if padding.iter().any(|p| *p != 0) {
        return Err(HeaderError::Padding);
    }
    Ok(TunnelHeader {
        host,
        client,
        port: u16::from_be_bytes(port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-19: the header layout is the one recorded in the module docs, and
    /// an IPv4 client is mapped with family 4.
    #[test]
    fn i19_tunnel_header_layout_is_fixed() -> Result<(), crate::host::HostError> {
        assert_eq!(TUNNEL_HEADER_LEN, 274);
        let host = HostName::parse(b"ab.example")?;
        let peer = SocketAddr::from(([192, 0, 2, 7], 443));
        let h = TunnelHeader::new(host, peer);
        let bytes = encode_tunnel_header(&h);
        assert_eq!(bytes.get(..2), Some(&[1u8, 4][..]));
        assert_eq!(bytes.get(12..18), Some(&[0xff, 0xff, 192, 0, 2, 7][..]));
        assert_eq!(bytes.get(18..21), Some(&[0x01, 0xbb, 10][..]));
        assert_eq!(bytes.get(21..31), Some(&b"ab.example"[..]));
        assert!(bytes.get(31..).is_some_and(|p| p.iter().all(|b| *b == 0)));
        assert_eq!(h.client_ip(), peer.ip());
        assert_eq!(decode_tunnel_header(&bytes), Ok(h));
        Ok(())
    }

    /// I-19, ADR-009 (design Q19 interim): the `Debug` form of a header never
    /// shows the client address or port, so no log line or error message
    /// can carry them.
    #[test]
    fn adr009_tunnel_header_debug_redacts_client_address() -> Result<(), crate::host::HostError> {
        let host = HostName::parse(b"ab.example")?;
        for peer in [
            SocketAddr::from(([198, 51, 100, 23], 50_123)),
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0xbeef, 0x42], 61_234)),
        ] {
            let shown = format!("{:?}", TunnelHeader::new(host.clone(), peer));
            assert!(shown.contains("redacted"), "{shown}");
            // The host has no digit, so any digit is a leaked address or port.
            assert!(!shown.chars().any(|c| c.is_ascii_digit()), "{shown}");
        }
        Ok(())
    }
}

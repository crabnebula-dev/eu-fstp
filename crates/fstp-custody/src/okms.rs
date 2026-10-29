//! The OVHcloud KMS client (ADR-004 part 2 "Backends", Q11).
//!
//! ADR-004 part 2 decides the authentication (Q11: an access certificate
//! over mutual TLS on REST if OKMS accepts it, otherwise KMIP) and says
//! "The `OkmsCustody` lane waits until A or B is confirmed. Record at
//! first use: the OKMS API or KMIP protocol version." Verify item K1 is
//! still open. So this module holds what does not depend on that answer:
//!
//! - [`OkmsCustody::new`] accepts only an `https` endpoint (R-NF-09).
//! - Every custody call refuses with [`CustodyError::AwaitingDecision`].
//!   It names Q11 and K1. No call falls back to a token or to plain TLS,
//!   which ADR-004 refuses (option C).
//! - [`decode_response`] parses a response under tight limits and refuses
//!   every member outside the closed set [`KNOWN_MEMBERS`]. That set is
//!   empty until the OKMS API version is recorded, so no member name is
//!   guessed.

use crate::{
    Aad, Custody, CustodyError, DestroyReceipt, EcdsaSignature, RootLabel, RootRef, SealKey,
    SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};

/// Why every OKMS call refuses for now.
pub const AWAITS: &str =
    "OKMS authentication and API version wait on Q11 and verify item K1 (ADR-004 part 2)";

/// The member names an OKMS response may carry. Empty until the OKMS
/// API version is recorded at first use (ADR-004 part 2, Q11).
pub const KNOWN_MEMBERS: &[&str] = &[];

/// The longest OKMS response the decoder reads.
pub const MAX_RESPONSE_BYTES: usize = 65_536;

/// The deepest nesting an OKMS response may have.
pub const MAX_DEPTH: usize = 8;

/// A custody client for OVHcloud KMS.
#[derive(Debug)]
pub struct OkmsCustody {
    endpoint: String,
}

impl OkmsCustody {
    /// A client for the KMS at `endpoint`: `https://`, a host name of
    /// letters, digits, dots and hyphens, an optional port and an
    /// optional path. No user part, query or fragment.
    ///
    /// # Errors
    ///
    /// Refuses any other endpoint (R-NF-09).
    pub fn new(endpoint: &str) -> Result<OkmsCustody, CustodyError> {
        check_endpoint(endpoint)?;
        Ok(OkmsCustody {
            endpoint: endpoint.to_owned(),
        })
    }

    /// The KMS endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

fn check_endpoint(endpoint: &str) -> Result<(), CustodyError> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or(CustodyError::InvalidConfig(
            "the OKMS endpoint is not https",
        ))?;
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    if !host_ok {
        return Err(CustodyError::InvalidConfig("the OKMS host is malformed"));
    }
    if let Some(p) = port {
        let ok = !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != 0);
        if !ok {
            return Err(CustodyError::InvalidConfig("the OKMS port is malformed"));
        }
    }
    let path_ok = path
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#' && b != b'@' && b != b'\\');
    if !path_ok {
        return Err(CustodyError::InvalidConfig("the OKMS path is malformed"));
    }
    Ok(())
}

impl Custody for OkmsCustody {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl std::future::Future<Output = Result<RootRef, CustodyError>> + Send {
        let _ = label;
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl std::future::Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let _ = (root, key, aad);
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl std::future::Future<Output = Result<SealKey, CustodyError>> + Send {
        let _ = (root, w, aad);
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl std::future::Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let _ = root;
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }

    fn sign(
        &self,
        key: &SignKeyRef,
        digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        let _ = (key, digest);
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }

    fn usage_since(
        &self,
        root: &RootRef,
        cursor: UsageCursor,
    ) -> impl std::future::Future<Output = Result<UsagePage, CustodyError>> + Send {
        let _ = (root, cursor);
        std::future::ready(Err(CustodyError::AwaitingDecision(AWAITS)))
    }
}

/// A decoded KMS response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkmsResponse {
    /// The response body, decoded.
    pub body: fstp_json::Value,
}

/// Decodes a KMS response body. Fuzzed (`okms_response_decode`).
///
/// The body must be one JSON object of at most [`MAX_RESPONSE_BYTES`]
/// and [`MAX_DEPTH`] levels, whose members are all in [`KNOWN_MEMBERS`].
/// Unknown members are refused, and no error display carries input
/// bytes, so key bytes never reach one.
///
/// # Errors
///
/// Returns [`CustodyError::Protocol`] with the rule the input breaks.
pub fn decode_response(bytes: &[u8]) -> Result<OkmsResponse, CustodyError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(CustodyError::Protocol("OKMS response too long"));
    }
    let limits = fstp_json::ParseLimits {
        max_input_bytes: MAX_RESPONSE_BYTES,
        max_depth: MAX_DEPTH,
        max_string_bytes: 16_384,
        max_number_len: 64,
        max_container_len: 256,
        max_nodes: 4096,
        max_memory_bytes: 1 << 20,
    };
    let body = fstp_json::parse_with(bytes, &limits)
        .map_err(|_| CustodyError::Protocol("OKMS response is not JSON within limits"))?;
    let fstp_json::Value::Object(members) = &body else {
        return Err(CustodyError::Protocol("OKMS response is not an object"));
    };
    if members.keys().any(|k| !KNOWN_MEMBERS.contains(&k)) {
        return Err(CustodyError::Protocol(
            "OKMS response has an unknown member",
        ));
    }
    Ok(OkmsResponse { body })
}

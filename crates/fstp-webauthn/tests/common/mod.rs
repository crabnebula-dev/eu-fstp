//! Shared helpers for the `fstp-webauthn` tests (lane W2a, test author).
//!
//! - [`cbor`] is an independent CBOR writer. It writes only, so the tests
//!   hold no second CBOR reader.
//! - [`authn`] is a test authenticator that writes the WebAuthn Level 2
//!   byte formats and signs through `fstp_crypto::sig`. It mirrors the
//!   formats and faults of `fstp_celltest::soft_authn` (design section
//!   14.3). That crate cannot be a dev-dependency here, because layering
//!   rule 1 reads every dependency kind of a pure core, and
//!   `fstp-celltest` reaches tokio.
//! - [`refused`] tells a real refusal from the W0 stub's `NotImplemented`.
//!   A refusal test that accepted `NotImplemented` would pass against the
//!   stub for the wrong reason.

#![allow(dead_code, reason = "each test binary uses a different part")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert on known-good values"
)]

pub(crate) mod authn;
pub(crate) mod b64;
pub(crate) mod cbor;
pub(crate) mod rsa;

use fstp_webauthn::WebAuthnError;

/// `Ok` when `r` is a refusal other than the W0 stub's `NotImplemented`.
/// Otherwise a message that names `what`.
pub(crate) fn refused<T: std::fmt::Debug>(
    what: &str,
    r: &Result<T, WebAuthnError>,
) -> Result<(), String> {
    match r {
        Err(WebAuthnError::NotImplemented(op)) => Err(format!(
            "{what}: refused only because {op} is the W0 stub, not for the input"
        )),
        #[allow(
            unreachable_patterns,
            reason = "the W0 stub has only NotImplemented; W2a adds the refusal reasons"
        )]
        Err(_) => Ok(()),
        Ok(v) => Err(format!("{what}: accepted, but must be refused: {v:?}")),
    }
}

/// Panics unless `r` is a real refusal (see [`refused`]).
#[track_caller]
pub(crate) fn assert_refused<T: std::fmt::Debug>(what: &str, r: &Result<T, WebAuthnError>) {
    if let Err(msg) = refused(what, r) {
        panic!("{msg}");
    }
}

/// Lower-case hex to bytes. Test constants only.
pub(crate) fn hex(s: &str) -> Vec<u8> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not lower-case hex: {c}"),
    };
    assert!(s.len().is_multiple_of(2), "odd hex length");
    s.as_bytes()
        .chunks(2)
        .map(|p| digit(p[0]) << 4 | digit(p[1]))
        .collect()
}

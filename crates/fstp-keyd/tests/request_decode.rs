//! The request decoder of `fstp-keyd` (ADR-004 part 2 "File custody",
//! design sections 3.3 and 15, TH-26).
//!
//! Requests carry a request id, a chain, an epoch and wrapped bytes
//! (ADR-004 part 2 "Reconciliation"). Lane W2f wrote their bytes in
//! `fstp_custody::keyd`, whose `encode_request` the client sends. The
//! decoder under test is the separate one of `fstp-keyd`. The tests draw
//! sample requests of every kind and encode them through
//! [`encode_request`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use common::{Fail, classify, expect_refused};
use fstp_custody::keyd::{RequestId, RootHandle};
use fstp_custody::{CellId, Chain, Epoch};
use fstp_keyd::{KeydRequest, decode_request};
use fstp_prop::{Gen, prop_assert_eq};

fn arr<const N: usize>(g: &mut Gen) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&g.bytes(N..=N));
    out
}

fn root(g: &mut Gen) -> RootHandle {
    RootHandle {
        chain: *g.pick(&Chain::ALL),
        epoch: Epoch(g.u64()),
    }
}

/// A generated request of any operation, with generated fields.
fn sample_request(g: &mut Gen) -> Result<KeydRequest, Fail> {
    let id = RequestId(arr(g));
    Ok(match g.usize_in(0..=5) {
        0 => KeydRequest::CreateRoot {
            id,
            cell: if g.bool() { Some(CellId(arr(g))) } else { None },
            chain: *g.pick(&Chain::ALL),
            epoch: Epoch(g.u64()),
        },
        1 => KeydRequest::Wrap {
            id,
            root: root(g),
            aad: g.bytes(0..=64),
            key: zeroize::Zeroizing::new(arr(g)),
        },
        2 => KeydRequest::Unwrap {
            id,
            root: root(g),
            aad: g.bytes(0..=64),
            wrapped: g.bytes(0..=96),
        },
        3 => KeydRequest::Destroy { id, root: root(g) },
        4 => KeydRequest::Sign {
            id,
            key: g.bytes(0..=64),
            digest: arr(g),
        },
        _ => KeydRequest::UsageSince {
            id,
            root: root(g),
            cursor: g.u64(),
        },
    })
}

/// Encodes `request` in its one spelling, as `KeydCustody` sends it,
/// through `fstp_custody::keyd::encode_request`.
fn encode_request(request: &KeydRequest) -> Result<Vec<u8>, Fail> {
    fstp_custody::keyd::encode_request(request).map_err(classify)
}

/// Design section 15: empty input is no request.
#[test]
fn adr004_keyd_request_decoder_refuses_empty_input() {
    if let Err(e) = expect_refused(decode_request(&[]).map_err(classify), "empty input") {
        panic!("{e}");
    }
}

/// ADR-004 part 2: every request decodes from its encoding to itself.
#[test]
fn adr004_keyd_request_round_trips_through_its_one_spelling() {
    fstp_prop::check(
        "adr004_keyd_request_round_trips_through_its_one_spelling",
        |g: &mut Gen| {
            let request = sample_request(g)?;
            let bytes = encode_request(&request)?;
            prop_assert_eq!(decode_request(&bytes).map_err(classify)?, request);
            Ok(())
        },
    );
}

/// Design section 15: on any input the decoder refuses, or returns a
/// request whose encoding is that input. No second spelling decodes.
#[test]
fn adr004_keyd_request_decoder_accepts_only_its_one_spelling() {
    fstp_prop::check(
        "adr004_keyd_request_decoder_accepts_only_its_one_spelling",
        |g: &mut Gen| {
            let bytes = g.bytes(0..=300);
            match decode_request(&bytes).map_err(classify) {
                Err(Fail::Refused { .. }) => Ok(()),
                Err(Fail::Seam(s)) => Err(s),
                Ok(request) => {
                    prop_assert_eq!(encode_request(&request)?, bytes, "a second spelling");
                    Ok(())
                }
            }
        },
    );
}

/// Design section 15 ("limits enforced"): a request followed by any
/// further byte, or cut short by any number of bytes, is refused.
#[test]
fn adr004_keyd_request_decoder_refuses_trailing_and_missing_bytes() {
    fstp_prop::check(
        "adr004_keyd_request_decoder_refuses_trailing_and_missing_bytes",
        |g: &mut Gen| {
            let mut bytes = encode_request(&sample_request(g)?)?;
            if g.bool() {
                bytes.extend(g.bytes(1..=8));
            } else {
                let keep = g.usize_in(0..=bytes.len() - 1);
                bytes.truncate(keep);
            }
            expect_refused(decode_request(&bytes).map_err(classify), "a spoilt request")?;
            Ok(())
        },
    );
}

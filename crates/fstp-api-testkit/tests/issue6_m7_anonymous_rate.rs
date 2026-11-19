//! Issue 6 M7 (H-01, ADR-024): calls with no account are charged to
//! their peer, and the first rate refusal of a key in a window leaves
//! the one audit entry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::decode_public_page;
use fstp_api_core::port::Outcome;
use fstp_api_core::rate::PER_PEER_ANONYMOUS;
use fstp_api_core::{ApiError, Credential, ErrorCode, PeerKey, RequestHead};
use fstp_api_testkit::fake::FakeCell;
use fstp_rt::future::block_on;

fn peer(s: &str) -> PeerKey {
    PeerKey::from_ip(s.parse().unwrap())
}

/// One anonymous public read from `head`: `true` when the rate limit
/// refused it.
fn limited(c: &FakeCell, head: &RequestHead) -> bool {
    let op = decode_public_page("/p/nowhere/").unwrap();
    matches!(
        block_on(c.core().dispatch(Credential::None, head, op)),
        Err(ApiError::Refused {
            code: ErrorCode::RateLimited,
            ..
        })
    )
}

fn rate_entries(c: &FakeCell) -> usize {
    c.ports
        .audit
        .entries()
        .iter()
        .filter(|e| e.outcome == Outcome::Refused("rate"))
        .count()
}

/// M7, H-01, ADR-024: one peer is refused after the limit, a second peer
/// and the shared key are charged apart, and the refusals of one key in
/// one window leave exactly one audit entry that names no peer.
#[test]
fn issue6_m7_anonymous_calls_are_charged_per_peer() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let a = RequestHead::new().with_peer(peer("192.0.2.1"));
    let b = RequestHead::new().with_peer(peer("192.0.2.2"));
    let shared = RequestHead::new();
    let n = PER_PEER_ANONYMOUS.count;
    // (a) peer A is admitted up to the limit, then refused.
    for i in 0..n {
        assert!(!limited(&c, &a), "call {i} of peer A");
    }
    assert_eq!(rate_entries(&c), 0);
    assert!(limited(&c, &a));
    // (d) the first refusal wrote one entry, later ones none.
    assert_eq!(rate_entries(&c), 1);
    assert!(limited(&c, &a));
    assert!(limited(&c, &a));
    assert_eq!(rate_entries(&c), 1);
    // (b) a second peer is still admitted.
    assert!(!limited(&c, &b));
    // (c) a head with no peer is charged the shared key, apart from A and B.
    for i in 0..n {
        assert!(!limited(&c, &shared), "shared call {i}");
    }
    assert!(limited(&c, &shared));
    assert!(!limited(&c, &b));
    // The shared key's first refusal is a key of its own.
    assert_eq!(rate_entries(&c), 2);
    // (d) no entry names a peer.
    let text = format!("{:?}", c.ports.audit.entries());
    assert!(!text.contains("192.0.2"), "an audit entry names a peer");
}

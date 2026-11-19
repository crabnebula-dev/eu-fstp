//! Rate limits of the public auth routes, of `PutText` and of the public
//! routes (ADR-024, issue 6 M8 and M9, H-21, H-01, TH-21; exit audit item
//! 7, lane m4/pubtext).
//!
//! Sliding windows, as `fstp-api-core/src/rate.rs` keeps them: a refused
//! call counts against no key, and idle keys are swept. The counters live
//! in memory only. A peer key never enters a log line, an audit entry, an
//! error text or a metric label (ADR-009). A request with no peer address
//! is charged to one shared key, so the limit still applies.
//!
//! Values accepted by Daniel on 2026-11-19 (ADR-024): one named constant each.
//! [`PUBLIC_PER_PEER`] is interim, pending Daniel's acceptance.
//!
//! The counters belong to one cell front, so each cell keeps its own keys:
//! a peer that one cell refuses is charged nothing on another cell
//! (`t_iso_public_rate_limit_keys_are_per_cell`).

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};

use fstp_domain::id::AccountId;

/// A count of calls within a sliding window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    /// The most calls the window admits.
    pub count: usize,
    /// The window length, in microseconds.
    pub window_us: i64,
}

const MINUTE_US: i64 = 60_000_000;
const HOUR_US: i64 = 3_600_000_000;

/// Login start and finish, per peer (30 per minute, ADR-024).
pub(crate) const LOGIN_PER_PEER: Limit = Limit {
    count: 30,
    window_us: MINUTE_US,
};

/// Magic-link and recovery requests, per peer (10 per minute).
pub(crate) const MAIL_PER_PEER: Limit = Limit {
    count: 10,
    window_us: MINUTE_US,
};

/// Magic-link and recovery requests, per target address digest (ADR-024:
/// 5 per hour).
pub(crate) const MAIL_PER_TARGET: Limit = Limit {
    count: 5,
    window_us: HOUR_US,
};

/// `PutText`, per account (120 per minute).
pub(crate) const PUT_TEXT_PER_ACCOUNT: Limit = Limit {
    count: 120,
    window_us: MINUTE_US,
};

/// The public routes, per peer: the `/p` pages, the feed, the public tools
/// and any path under `/p/` that no route matches (120 per minute).
/// Interim, pending Daniel's acceptance (ADR-024): the value of "API calls
/// per peer with no account", which the web adapter charges the same
/// requests against (`fstp_api_core::rate::PER_PEER_ANONYMOUS`).
pub(crate) const PUBLIC_PER_PEER: Limit = Limit {
    count: 120,
    window_us: MINUTE_US,
};

/// The limit values of one cell front (ADR-024). The default holds the
/// ADR-024 values above, and the production cell starts with it. A test
/// world whose clients all share the loopback address passes its own
/// values through `crate::process::StartOptions`, and says so there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthLimits {
    /// Login start and finish, per peer.
    pub login_per_peer: Limit,
    /// Magic-link and recovery requests, per peer.
    pub mail_per_peer: Limit,
    /// Magic-link and recovery requests, per target address digest.
    pub mail_per_target: Limit,
    /// `PutText`, per account.
    pub put_text_per_account: Limit,
    /// The public routes, per peer.
    pub public_per_peer: Limit,
}

impl Default for AuthLimits {
    fn default() -> AuthLimits {
        AuthLimits {
            login_per_peer: LOGIN_PER_PEER,
            mail_per_peer: MAIL_PER_PEER,
            mail_per_target: MAIL_PER_TARGET,
            put_text_per_account: PUT_TEXT_PER_ACCOUNT,
            public_per_peer: PUBLIC_PER_PEER,
        }
    }
}

/// Most keys the counters hold. At the bound, after a sweep, a new key is
/// refused, so memory stays bounded under a flood of distinct keys.
const MAX_KEYS: usize = 65_536;

/// The peer key of ADR-024: an IPv4 address whole, an IPv6 address by its
/// /64 prefix. Memory only: its `Debug` prints no address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Peer([u8; 9]);

impl Peer {
    /// The key of the peer address of a request. No address charges the
    /// one shared key.
    pub(crate) fn of(addr: Option<SocketAddr>) -> Peer {
        let mut bytes = [0u8; 9];
        match addr.map(|a| a.ip().to_canonical()) {
            None => {}
            Some(IpAddr::V4(v4)) => {
                bytes[0] = 4;
                for (slot, b) in bytes.iter_mut().skip(1).zip(v4.octets()) {
                    *slot = b;
                }
            }
            Some(IpAddr::V6(v6)) => {
                bytes[0] = 6;
                for (slot, b) in bytes.iter_mut().skip(1).zip(v6.octets().iter().take(8)) {
                    *slot = *b;
                }
            }
        }
        Peer(bytes)
    }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Peer(..)")
    }
}

/// What one window counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Login(Peer),
    Mail(Peer),
    Target([u8; 32]),
    PutText(AccountId),
    Public(Peer),
}

#[derive(Default)]
struct State {
    hits: BTreeMap<Key, VecDeque<i64>>,
    swept: i64,
}

/// The counters of one cell front.
#[derive(Default)]
pub(crate) struct Limits {
    values: AuthLimits,
    state: Mutex<State>,
}

impl Limits {
    /// Counters that enforce `values`.
    pub(crate) fn new(values: AuthLimits) -> Limits {
        Limits {
            values,
            state: Mutex::default(),
        }
    }

    fn charge(&self, key: Key, limit: Limit, now_us: i64) -> bool {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Sweep keys idle for longer than the longest window, once a minute.
        if now_us.saturating_sub(st.swept) >= MINUTE_US || st.hits.len() >= MAX_KEYS {
            st.swept = now_us;
            let oldest = now_us.saturating_sub(HOUR_US);
            st.hits
                .retain(|_, q| q.back().is_some_and(|newest| *newest > oldest));
        }
        if !st.hits.contains_key(&key) && st.hits.len() >= MAX_KEYS {
            return false;
        }
        let q = st.hits.entry(key).or_default();
        let from = now_us.saturating_sub(limit.window_us);
        while q.front().is_some_and(|t| *t <= from) {
            q.pop_front();
        }
        if q.len() >= limit.count {
            // A refused call counts against no key.
            return false;
        }
        q.push_back(now_us);
        true
    }

    /// Charges a login start or finish to `peer`.
    pub(crate) fn login(&self, peer: Peer, now_us: i64) -> bool {
        self.charge(Key::Login(peer), self.values.login_per_peer, now_us)
    }

    /// Charges a magic-link or recovery request to `peer`.
    pub(crate) fn mail_peer(&self, peer: Peer, now_us: i64) -> bool {
        self.charge(Key::Mail(peer), self.values.mail_per_peer, now_us)
    }

    /// Charges a magic-link or recovery request to the digest of its
    /// target address. The charge is the same whether or not the address
    /// holds an account.
    pub(crate) fn mail_target(&self, digest: [u8; 32], now_us: i64) -> bool {
        self.charge(Key::Target(digest), self.values.mail_per_target, now_us)
    }

    /// Charges a request of a public route to `peer`.
    pub(crate) fn public(&self, peer: Peer, now_us: i64) -> bool {
        self.charge(Key::Public(peer), self.values.public_per_peer, now_us)
    }

    /// Charges a `PutText` to `account`.
    pub(crate) fn put_text(&self, account: AccountId, now_us: i64) -> bool {
        self.charge(
            Key::PutText(account),
            self.values.put_text_per_account,
            now_us,
        )
    }
}

/// The digest that keys the per-target limit: SHA-256 of the lowercased
/// address. The address itself is never kept.
pub(crate) fn target_digest(email: &str) -> [u8; 32] {
    fstp_crypto::sha256(email.trim().to_ascii_lowercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue 6 M8, H-21, ADR-024: a window admits its count, refuses the
    /// next call, and admits again once the window has passed. A refused
    /// call extends nothing.
    #[test]
    fn issue6_m8_sliding_window_refuses_then_recovers() {
        let l = Limits::default();
        let p = Peer::of(None);
        for i in 0..MAIL_PER_PEER.count {
            assert!(l.mail_peer(p, i64::try_from(i).unwrap()));
        }
        assert!(!l.mail_peer(p, 1_000));
        assert!(!l.mail_peer(p, 2_000));
        assert!(l.mail_peer(p, MINUTE_US + 100));
    }

    /// Exit audit item 7, ADR-024: the public routes are limited per peer,
    /// another peer is unaffected, and the public budget is apart from the
    /// login budget of the same peer.
    #[test]
    fn adr024_public_routes_are_limited_per_peer() {
        let l = Limits::default();
        let a = Peer::of(Some(SocketAddr::from(([203, 0, 113, 1], 1))));
        let b = Peer::of(Some(SocketAddr::from(([203, 0, 113, 2], 1))));
        for i in 0..PUBLIC_PER_PEER.count {
            assert!(l.public(a, i64::try_from(i).unwrap()), "call {i}");
        }
        assert!(!l.public(a, 1_000));
        assert!(l.public(b, 1_000));
        assert!(l.login(a, 1_000));
        assert!(l.public(a, MINUTE_US + 100));
    }

    /// Issue 6 M8, ADR-024: IPv6 peers count by /64, other peers apart.
    #[test]
    fn issue6_m8_peer_key_counts_ipv6_by_prefix() {
        let a: SocketAddr = "[2001:db8:1:2::1]:1".parse().unwrap();
        let b: SocketAddr = "[2001:db8:1:2:f::9]:2".parse().unwrap();
        let c: SocketAddr = "[2001:db8:1:3::1]:2".parse().unwrap();
        assert_eq!(Peer::of(Some(a)), Peer::of(Some(b)));
        assert_ne!(Peer::of(Some(a)), Peer::of(Some(c)));
        assert_ne!(Peer::of(Some(a)), Peer::of(None));
    }
}

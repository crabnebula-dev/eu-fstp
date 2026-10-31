//! Rate limits (design section 3.7 step 4).
//!
//! Limits apply per session, account, token and client. Dry runs that ask
//! the vault have their own limit per account (H-07), because each answer
//! tells the platform one bit. The counters live in memory only, never
//! persisted or logged (design section 4.1).
//!
//! Interim, pending Daniel: the design names the limits and no values.
//! The values below are this lane's reading. A refused call does not
//! count, so a caller at the limit cannot extend its own window.

use std::collections::{BTreeMap, VecDeque};

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

use crate::port::{AgentClientId, SessionId};

/// A count of calls within a sliding window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limit {
    /// The most calls the window admits.
    pub count: u32,
    /// The window length, in microseconds.
    pub window_micros: i64,
}

/// Dry runs that ask the vault, per account (H-07).
///
/// Interim, pending Daniel: the design names the limit and no value. This
/// reading admits 30 such dry runs per account per minute. The limit is
/// checked before the dry run, so a caller at the limit asks the vault
/// nothing more.
pub const DRY_RUN_VAULT_PER_ACCOUNT: Limit = Limit {
    count: 30,
    window_micros: 60_000_000,
};

/// Calls per account, through any channel (interim: 600 per minute).
pub const PER_ACCOUNT: Limit = Limit {
    count: 600,
    window_micros: 60_000_000,
};

/// Calls per web session (interim: 600 per minute).
pub const PER_SESSION: Limit = Limit {
    count: 600,
    window_micros: 60_000_000,
};

/// Calls per MCP token (interim: 300 per minute).
pub const PER_TOKEN: Limit = Limit {
    count: 300,
    window_micros: 60_000_000,
};

/// Calls per agent client, across its tokens (interim: 600 per minute).
pub const PER_CLIENT: Limit = Limit {
    count: 600,
    window_micros: 60_000_000,
};

/// What one counter counts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Key {
    /// An account's calls.
    Account(AccountId),
    /// A web session's calls.
    Session(SessionId),
    /// An MCP token's calls, by the SHA-256 of the token value.
    Token([u8; 32]),
    /// An agent client's calls.
    Client(AgentClientId),
    /// An account's dry runs that asked the vault (H-07).
    VaultDryRun(AccountId),
}

/// How often the counters are swept, in microseconds (interim: once a
/// second). A sweep drops every key whose newest hit is older than the
/// longest window charged, so the map holds only the keys seen within
/// that window plus one sweep interval.
pub(crate) const SWEEP_INTERVAL_MICROS: i64 = 1_000_000;

/// The sliding-window counters of one cell.
///
/// Memory stays bounded: a key is dropped once its window has passed with
/// no hit, by the check of that key or by the next sweep.
#[derive(Debug, Default)]
pub(crate) struct Rates {
    /// The hit times of each key, oldest first.
    hits: BTreeMap<Key, VecDeque<Timestamp>>,
    /// The longest window any key was charged against.
    longest_window: i64,
    /// The earliest time of the next sweep.
    next_sweep: i64,
}

impl Rates {
    /// Drops the hits of `key` at or before `now - window`, and the key
    /// once it holds none.
    fn trim(&mut self, key: &Key, limit: Limit, now: Timestamp) {
        let floor = now.micros().saturating_sub(limit.window_micros);
        if let Some(q) = self.hits.get_mut(key) {
            while q.front().is_some_and(|t| t.micros() <= floor) {
                q.pop_front();
            }
            if q.is_empty() {
                self.hits.remove(key);
            }
        }
    }

    /// Drops every key whose newest hit has left the longest window, at
    /// most once per sweep interval, so the cost is amortised over the
    /// calls of that interval.
    fn sweep(&mut self, now: Timestamp) {
        if now.micros() < self.next_sweep {
            return;
        }
        let floor = now.micros().saturating_sub(self.longest_window);
        self.hits
            .retain(|_, q| q.back().is_some_and(|t| t.micros() > floor));
        self.next_sweep = now.micros().saturating_add(SWEEP_INTERVAL_MICROS);
    }

    /// Whether `key` is below `limit` at `now`.
    pub(crate) fn admits(&mut self, key: &Key, limit: Limit, now: Timestamp) -> bool {
        self.sweep(now);
        self.trim(key, limit, now);
        let used = self.hits.get(key).map_or(0, VecDeque::len);
        u32::try_from(used).is_ok_and(|n| n < limit.count)
    }

    /// Counts one call of `key` against `limit` at `now`.
    pub(crate) fn hit(&mut self, key: Key, limit: Limit, now: Timestamp) {
        self.sweep(now);
        self.longest_window = self.longest_window.max(limit.window_micros);
        self.hits.entry(key).or_default().push_back(now);
    }

    /// Checks every `(key, limit)` and counts each one only if all admit.
    pub(crate) fn take_all(&mut self, keys: &[(Key, Limit)], now: Timestamp) -> bool {
        if !keys.iter().all(|(k, l)| self.admits(k, *l, now)) {
            return false;
        }
        for (k, l) in keys {
            self.hit(k.clone(), *l, now);
        }
        true
    }

    /// The number of keys held, for the bounded-memory tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.hits.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// H-07: the window admits `count` hits, refuses the next, and admits
    /// again once the first hit is older than the window.
    #[test]
    fn h07_sliding_window_admits_count_then_refuses() {
        let mut r = Rates::default();
        let k = Key::VaultDryRun(AccountId::from_raw(1));
        let l = Limit {
            count: 2,
            window_micros: 10,
        };
        let t = Timestamp::from_micros(100);
        assert!(r.admits(&k, l, t));
        r.hit(k.clone(), l, t);
        r.hit(k.clone(), l, t);
        assert!(!r.admits(&k, l, t));
        assert!(!r.admits(&k, l, Timestamp::from_micros(109)));
        assert!(r.admits(&k, l, Timestamp::from_micros(110)));
    }

    /// Design section 3.7 step 4: a refused call counts against no key.
    #[test]
    fn h07_refused_calls_do_not_count() {
        let mut r = Rates::default();
        let a = Key::Account(AccountId::from_raw(1));
        let s = Key::Session(SessionId::from_raw(1));
        let one = Limit {
            count: 1,
            window_micros: 1_000,
        };
        let t = Timestamp::from_micros(0);
        r.hit(s.clone(), one, t);
        assert!(!r.take_all(&[(a.clone(), one), (s.clone(), one)], t));
        assert!(r.admits(&a, one, t), "the account was not charged");
    }

    /// Design section 3.7 step 4, bounded memory: a sweep drops every key
    /// whose newest hit has left the longest window, and keeps a key hit
    /// within it, whatever its kind.
    #[test]
    fn h07_sweep_drops_idle_keys_of_every_kind() {
        let mut r = Rates::default();
        let l = Limit {
            count: 5,
            window_micros: SWEEP_INTERVAL_MICROS,
        };
        let t0 = Timestamp::from_micros(0);
        for i in 0..100u128 {
            r.hit(Key::Session(SessionId::from_raw(i)), l, t0);
            r.hit(Key::Account(AccountId::from_raw(i)), l, t0);
            r.hit(Key::Client(AgentClientId::from_raw(i)), l, t0);
            r.hit(Key::VaultDryRun(AccountId::from_raw(i)), l, t0);
        }
        let kept = Key::Token([7; 32]);
        let t1 = Timestamp::from_micros(SWEEP_INTERVAL_MICROS / 2);
        r.hit(kept.clone(), l, t1);
        assert_eq!(r.len(), 401);
        let later = Timestamp::from_micros(SWEEP_INTERVAL_MICROS);
        assert!(r.take_all(&[(Key::Account(AccountId::from_raw(1_000)), l)], later));
        assert_eq!(
            r.len(),
            2,
            "only the key hit within the window and the new one"
        );
        assert!(
            !r.admits(&kept, Limit { count: 1, ..l }, later),
            "the kept hit still counts"
        );
    }
}

#[cfg(test)]
mod review_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Review reproducer, design section 3.7 step 4 and the bounded
    /// allocation rule: a counter whose every hit is older than its window
    /// is kept forever unless the same key is seen again. Each bearer
    /// token that resolves to no grant gets its own `Key::Token`, so a
    /// caller sending fresh random tokens to a public tool grows the map
    /// without bound. Idle counters must be dropped once their window has
    /// passed.
    #[test]
    fn review_idle_rate_counters_are_dropped_after_their_window() {
        let mut r = Rates::default();
        let t0 = Timestamp::from_micros(0);
        for i in 0..10_000u32 {
            let key = Key::Token(fstp_crypto::sha256(&i.to_be_bytes()));
            assert!(r.take_all(&[(key, PER_TOKEN)], t0));
        }
        let later = Timestamp::from_micros(PER_TOKEN.window_micros.saturating_add(1));
        let fresh = Key::Token([0xff; 32]);
        assert!(r.take_all(&[(fresh, PER_TOKEN)], later));
        let floor = later.micros().saturating_sub(PER_TOKEN.window_micros);
        let stale = r
            .hits
            .values()
            .filter(|q| q.back().is_none_or(|t| t.micros() <= floor))
            .count();
        assert_eq!(stale, 0, "{stale} idle counters are still held");
    }
}

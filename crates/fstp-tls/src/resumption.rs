//! Session resumption bounded by the age of the full handshake (policy P2,
//! R-NF-09).
//!
//! A session can be resumed for less than [`MAX_RESUMPTION_AGE`] after the
//! full handshake that authenticated it. After that, a full handshake
//! validates every certificate again. This holds for servers with and
//! without client authentication, and for clients.
//!
//! # Why stateful resumption
//!
//! rustls 0.23.46 offers stateless tickets through a ticketer and stateful
//! tickets through a session store. Its aws-lc-rs ticketer rotates keys
//! every 6 hours and accepts a ticket for up to 12 hours. The key generator
//! behind it is private, so a shorter rotation would need an in-house
//! ticket encryption scheme, which this crate avoids on purpose. The
//! rotation also reads the system clock directly. Above all, a key rotation
//! bounds the age of a ticket, not the age of its session, and each resumed
//! session receives fresh tickets.
//!
//! So the server keeps its sessions in the in-house [`ServerSessions`]
//! table, and the client keeps its tickets in the in-house
//! [`ClientSessions`] table. Each entry records the time of the full
//! handshake that authenticated its session, called its origin here. The
//! rustls ticket identifiers come from the provider's secure random source.
//! Nothing in this module encrypts or derives keys.
//!
//! # Carrying the origin through a chain
//!
//! A resumed connection receives new tickets. They must keep the origin of
//! the session that was resumed, not the time they were issued. rustls
//! calls a store without saying which connection it serves. So
//! [`connect`](crate::connect) and [`accept`](crate::accept) give every
//! connection its own copy of the rustls configuration. That copy holds a
//! per-connection handle to the shared table. The handle remembers when the
//! connection started and the oldest origin it consumed. A ticket stored
//! through it gets the earlier of the two as its origin.
//!
//! That origin is never later than the true one. When rustls consumes a
//! ticket and still runs a full handshake, the new tickets get the older
//! origin and expire early. That costs at most one extra full handshake.
//!
//! # Clock
//!
//! Both sides read the time from the rustls configuration's time provider,
//! which also decides certificate validity. A session is resumable while
//! fewer than 3600 whole seconds have passed since its origin. The clock
//! counts whole seconds and the origin is read when the connection starts.
//! So a resumed session is always less than one hour old. A clock that
//! fails, or that reads earlier than an origin, ends resumption.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::NamedGroup;
use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::server::StoresServerSessions;
use rustls::time_provider::TimeProvider;
use rustls_pki_types::ServerName;

const MAX_AGE_SECS: u64 = 60 * 60;

/// How long after a full handshake its session can still be resumed
/// (policy P2): less than one hour. A full handshake validates every
/// certificate again after that.
pub const MAX_RESUMPTION_AGE: Duration = Duration::from_secs(MAX_AGE_SECS);

/// Sessions one server configuration keeps. The oldest goes first.
pub(crate) const SERVER_SESSIONS: usize = 1024;

/// Server names one client configuration keeps tickets for. The name
/// added first goes first.
pub(crate) const CLIENT_SERVERS: usize = 256;

/// Tickets one client configuration keeps per server name. The oldest
/// goes first.
pub(crate) const CLIENT_TICKETS_PER_SERVER: usize = 8;

/// Least time between two sweeps of expired server sessions, in seconds.
const SWEEP_INTERVAL_SECS: u64 = 60;

/// Whether a session with this origin can be resumed at `now`.
fn resumable(origin: u64, now: u64) -> bool {
    now.checked_sub(origin)
        .is_some_and(|age| age < MAX_AGE_SECS)
}

fn now_secs(clock: &dyn TimeProvider) -> Option<u64> {
    clock.current_time().map(|t| t.as_secs())
}

/// The origin a connection gives the tickets it stores: the time it
/// started, or the oldest origin it consumed if that is earlier.
///
/// `u64::MAX` stands for an unknown start, when the clock failed. Nothing
/// is resumable from it.
struct ConnectionOrigin(AtomicU64);

impl ConnectionOrigin {
    fn start(clock: &dyn TimeProvider) -> Self {
        Self(AtomicU64::new(now_secs(clock).unwrap_or(u64::MAX)))
    }

    fn consumed(&self, origin: u64) {
        self.0.fetch_min(origin, Ordering::SeqCst);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ConnectionOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            u64::MAX => f.write_str("unknown"),
            secs => write!(f, "{secs}"),
        }
    }
}

/// One stored server session.
struct ServerEntry<V> {
    value: V,
    origin: u64,
    seq: u64,
}

/// Server sessions by ticket, bounded by a capacity. Beyond it, the entry
/// inserted first is dropped.
struct ServerTable<V> {
    entries: HashMap<Vec<u8>, ServerEntry<V>>,
    /// Keys in insertion order, each with the sequence number of its
    /// insertion. A record whose entry was taken or replaced is stale and
    /// skipped.
    order: VecDeque<(Vec<u8>, u64)>,
    next_seq: u64,
    last_sweep: u64,
    capacity: usize,
}

impl<V> ServerTable<V> {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
            last_sweep: 0,
            capacity,
        }
    }

    fn insert(&mut self, key: Vec<u8>, value: V, origin: u64, now: u64) -> bool {
        self.maybe_sweep(now);
        if self.capacity == 0 {
            return false;
        }
        while self.entries.len() >= self.capacity {
            let Some((old, seq)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&old).is_some_and(|e| e.seq == seq) {
                self.entries.remove(&old);
            }
        }
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        self.order.push_back((key.clone(), seq));
        self.entries.insert(key, ServerEntry { value, origin, seq });
        if self.order.len() > self.capacity.saturating_mul(2).max(16) {
            self.compact();
        }
        true
    }

    /// Removes the entry for `key` and returns it with its origin. The
    /// caller checks whether it is still resumable.
    fn remove(&mut self, key: &[u8]) -> Option<(V, u64)> {
        self.entries.remove(key).map(|e| (e.value, e.origin))
    }

    /// Drops every expired entry, at most once per sweep interval, so that
    /// expired session secrets do not wait for eviction.
    fn maybe_sweep(&mut self, now: u64) {
        if now.abs_diff(self.last_sweep) < SWEEP_INTERVAL_SECS {
            return;
        }
        self.last_sweep = now;
        self.entries.retain(|_, e| resumable(e.origin, now));
        self.compact();
    }

    fn compact(&mut self) {
        let entries = &self.entries;
        self.order
            .retain(|(k, seq)| entries.get(k).is_some_and(|e| e.seq == *seq));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The session table that one server configuration shares between its
/// connections. Connections reach it through a [`ServerSessionHandle`].
pub(crate) struct ServerSessions {
    table: Mutex<ServerTable<Vec<u8>>>,
}

impl ServerSessions {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            table: Mutex::new(ServerTable::new(capacity)),
        }
    }

    /// A handle for one new connection that reads time from `clock`.
    pub(crate) fn handle(self: &Arc<Self>, clock: Arc<dyn TimeProvider>) -> ServerSessionHandle {
        ServerSessionHandle {
            origin: ConnectionOrigin::start(&*clock),
            table: self.clone(),
            clock,
        }
    }

    /// Number of stored sessions, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.table.lock().map(|t| t.len()).unwrap_or(0)
    }
}

impl fmt::Debug for ServerSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSessions").finish_non_exhaustive()
    }
}

/// One connection's view of a [`ServerSessions`] table. rustls uses it as
/// the session store of that connection only.
pub(crate) struct ServerSessionHandle {
    table: Arc<ServerSessions>,
    clock: Arc<dyn TimeProvider>,
    origin: ConnectionOrigin,
}

impl fmt::Debug for ServerSessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSessionHandle")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl StoresServerSessions for ServerSessionHandle {
    /// Stores a session that this connection authenticated, or resumed
    /// from an earlier one. It keeps the origin of that full handshake.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let Some(now) = now_secs(&*self.clock) else {
            return false;
        };
        let origin = self.origin.get();
        if !resumable(origin, now) {
            return false;
        }
        match self.table.table.lock() {
            Ok(mut table) => table.insert(key, value, origin, now),
            Err(_) => false,
        }
    }

    /// Always `None`. Only TLS 1.2 looks sessions up without removing them,
    /// and this crate speaks TLS 1.3 only. No lookup leaves a session in
    /// place to be used twice.
    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Removes the session for `key`. Returns it only while it is
    /// resumable, and lets this connection's new tickets inherit its
    /// origin.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = now_secs(&*self.clock);
        let (value, origin) = self.table.table.lock().ok()?.remove(key)?;
        if !resumable(origin, now?) {
            return None;
        }
        self.origin.consumed(origin);
        Some(value)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

/// Client tickets by server name, bounded in server names and in tickets
/// per name. Each queue holds the oldest ticket first.
struct ClientTable<K, V> {
    servers: HashMap<K, VecDeque<(V, u64)>>,
    /// Server names in the order they were added. It always holds exactly
    /// the keys of `servers`.
    order: VecDeque<K>,
    max_servers: usize,
    per_server: usize,
}

impl<K: Clone + Eq + Hash, V> ClientTable<K, V> {
    fn new(max_servers: usize, per_server: usize) -> Self {
        Self {
            servers: HashMap::new(),
            order: VecDeque::new(),
            max_servers,
            per_server,
        }
    }

    fn insert(&mut self, name: K, value: V, origin: u64) {
        if self.max_servers == 0 || self.per_server == 0 {
            return;
        }
        if !self.servers.contains_key(&name) {
            while self.servers.len() >= self.max_servers {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                self.servers.remove(&old);
            }
            self.order.push_back(name.clone());
        }
        let queue = self.servers.entry(name).or_default();
        while queue.len() >= self.per_server {
            queue.pop_front();
        }
        queue.push_back((value, origin));
    }

    /// Drops the expired tickets for `name`, then removes and returns the
    /// newest one left, with its origin.
    fn take(&mut self, name: &K, now: u64) -> Option<(V, u64)> {
        let queue = self.servers.get_mut(name)?;
        queue.retain(|(_, origin)| resumable(*origin, now));
        queue.pop_back()
    }
}

/// The ticket cache that one client configuration shares between its
/// connections. Connections reach it through a [`ClientSessionHandle`].
pub(crate) struct ClientSessions {
    table: Mutex<ClientTable<ServerName<'static>, Tls13ClientSessionValue>>,
}

impl ClientSessions {
    pub(crate) fn new(max_servers: usize, per_server: usize) -> Self {
        Self {
            table: Mutex::new(ClientTable::new(max_servers, per_server)),
        }
    }

    /// A handle for one new connection that reads time from `clock`.
    pub(crate) fn handle(self: &Arc<Self>, clock: Arc<dyn TimeProvider>) -> ClientSessionHandle {
        ClientSessionHandle {
            origin: ConnectionOrigin::start(&*clock),
            table: self.clone(),
            clock,
        }
    }
}

impl fmt::Debug for ClientSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSessions").finish_non_exhaustive()
    }
}

/// One connection's view of a [`ClientSessions`] cache. rustls uses it as
/// the session store of that connection only.
///
/// Key exchange hints are not kept. They would change the key share the
/// client sends first, and the offered groups stay as configured (ADR-001).
/// TLS 1.2 sessions do not exist here.
pub(crate) struct ClientSessionHandle {
    table: Arc<ClientSessions>,
    clock: Arc<dyn TimeProvider>,
    origin: ConnectionOrigin,
}

impl fmt::Debug for ClientSessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSessionHandle")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl ClientSessionStore for ClientSessionHandle {
    fn set_kx_hint(&self, _server_name: ServerName<'static>, _group: NamedGroup) {}

    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, _server_name: ServerName<'static>, _: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}

    /// Keeps a ticket with the origin of the full handshake behind this
    /// connection, whatever lifetime the server announced.
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        let Some(now) = now_secs(&*self.clock) else {
            return;
        };
        let origin = self.origin.get();
        if !resumable(origin, now) {
            return;
        }
        if let Ok(mut table) = self.table.table.lock() {
            table.insert(server_name, value, origin);
        }
    }

    /// Returns the newest resumable ticket for `server_name`, at most once,
    /// and lets this connection's new tickets inherit its origin.
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let now = now_secs(&*self.clock)?;
        let (value, origin) = self.table.table.lock().ok()?.take(server_name, now)?;
        self.origin.consumed(origin);
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests of the tables and the per-connection origin. The TLS
    //! level tests are in `resumption_tests.rs`.

    #![allow(clippy::arithmetic_side_effects)]

    use std::sync::atomic::AtomicU64;

    use fstp_prop::{Config, check_with, prop_assert_eq};
    use rustls_pki_types::UnixTime;

    use super::*;

    /// A clock that reads `None` when set to `u64::MAX`.
    #[derive(Debug)]
    struct Clock(AtomicU64);

    impl Clock {
        fn at(secs: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(secs)))
        }

        fn set(&self, secs: u64) {
            self.0.store(secs, Ordering::SeqCst);
        }
    }

    impl TimeProvider for Clock {
        fn current_time(&self) -> Option<UnixTime> {
            match self.0.load(Ordering::SeqCst) {
                u64::MAX => None,
                secs => Some(UnixTime::since_unix_epoch(Duration::from_secs(secs))),
            }
        }
    }

    const T0: u64 = 1_800_000_000;

    #[test]
    fn p2_resumable_is_strictly_under_one_hour() {
        assert!(resumable(T0, T0));
        assert!(resumable(T0, T0 + MAX_AGE_SECS - 1));
        assert!(!resumable(T0, T0 + MAX_AGE_SECS));
        // A clock that reads earlier than the origin ends resumption.
        assert!(!resumable(T0, T0 - 1));
        assert!(!resumable(u64::MAX, T0));
        assert_eq!(MAX_RESUMPTION_AGE, Duration::from_secs(3600));
    }

    #[test]
    fn p2_server_take_removes_and_checks_age() {
        let clock = Clock::at(T0);
        let sessions = Arc::new(ServerSessions::new(8));
        let first = sessions.handle(clock.clone());
        assert!(first.put(b"a".to_vec(), b"A".to_vec()));
        assert!(first.put(b"b".to_vec(), b"B".to_vec()));
        assert_eq!(sessions.len(), 2);

        let second = sessions.handle(clock.clone());
        // Single use: a second take of the same ticket finds nothing.
        assert_eq!(second.take(b"a"), Some(b"A".to_vec()));
        assert_eq!(second.take(b"a"), None);
        // `get` never returns a session.
        assert_eq!(second.get(b"b"), None);

        // An expired session is removed and not returned.
        clock.set(T0 + MAX_AGE_SECS);
        let third = sessions.handle(clock.clone());
        assert_eq!(third.take(b"b"), None);
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn p2_server_tickets_from_a_resumed_connection_keep_the_origin() {
        let clock = Clock::at(T0);
        let sessions = Arc::new(ServerSessions::new(8));
        assert!(
            sessions
                .handle(clock.clone())
                .put(b"a".to_vec(), b"A".to_vec())
        );

        clock.set(T0 + MAX_AGE_SECS - 10);
        let resumed = sessions.handle(clock.clone());
        assert_eq!(resumed.take(b"a"), Some(b"A".to_vec()));
        assert_eq!(resumed.origin.get(), T0);
        assert!(resumed.put(b"b".to_vec(), b"B".to_vec()));

        // Ten seconds later the new ticket is as old as the full handshake.
        clock.set(T0 + MAX_AGE_SECS);
        assert_eq!(sessions.handle(clock.clone()).take(b"b"), None);

        // A connection whose origin has passed stores nothing.
        assert!(!resumed.put(b"c".to_vec(), b"C".to_vec()));
    }

    #[test]
    fn p2_expired_take_does_not_lower_the_origin() {
        let clock = Clock::at(T0);
        let sessions = Arc::new(ServerSessions::new(8));
        assert!(
            sessions
                .handle(clock.clone())
                .put(b"a".to_vec(), b"A".to_vec())
        );
        clock.set(T0 + 2 * MAX_AGE_SECS);
        let full = sessions.handle(clock.clone());
        assert_eq!(full.take(b"a"), None);
        assert_eq!(full.origin.get(), T0 + 2 * MAX_AGE_SECS);
        assert!(full.put(b"b".to_vec(), b"B".to_vec()));
    }

    #[test]
    fn p2_a_failed_clock_ends_resumption() {
        let clock = Clock::at(u64::MAX);
        let sessions = Arc::new(ServerSessions::new(8));
        let handle = sessions.handle(clock.clone());
        assert!(!handle.put(b"a".to_vec(), b"A".to_vec()));
        // The clock recovers, but the connection's start stays unknown.
        clock.set(T0);
        assert!(!handle.put(b"a".to_vec(), b"A".to_vec()));
        assert!(
            sessions
                .handle(clock.clone())
                .put(b"a".to_vec(), b"A".to_vec())
        );
        clock.set(u64::MAX);
        // Take still removes the entry, and returns nothing.
        assert_eq!(sessions.handle(clock.clone()).take(b"a"), None);
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn server_table_drops_the_oldest_beyond_capacity() {
        let mut table = ServerTable::new(3);
        for (i, key) in [b"a", b"b", b"c", b"d"].into_iter().enumerate() {
            assert!(table.insert(key.to_vec(), i, T0, T0));
        }
        assert_eq!(table.len(), 3);
        assert_eq!(table.remove(b"a"), None);
        assert_eq!(table.remove(b"b"), Some((1, T0)));
        // A replaced key counts once, and its stale order record is skipped.
        assert!(table.insert(b"c".to_vec(), 9, T0, T0));
        assert!(table.insert(b"e".to_vec(), 5, T0, T0));
        assert_eq!(table.len(), 3);
        assert!(table.insert(b"f".to_vec(), 6, T0, T0));
        assert_eq!(table.remove(b"d"), None);
        assert_eq!(table.remove(b"c"), Some((9, T0)));

        let mut empty: ServerTable<u8> = ServerTable::new(0);
        assert!(!empty.insert(b"a".to_vec(), 1, T0, T0));
    }

    #[test]
    fn server_table_sweeps_expired_entries() {
        let mut table = ServerTable::new(16);
        assert!(table.insert(b"old".to_vec(), 1, T0, T0));
        assert!(table.insert(b"new".to_vec(), 2, T0 + 30, T0 + 30));
        // Within the sweep interval nothing is swept.
        assert!(table.insert(b"x".to_vec(), 3, T0 + 30, T0 + 30));
        assert_eq!(table.len(), 3);
        assert!(table.insert(b"y".to_vec(), 4, T0 + MAX_AGE_SECS, T0 + MAX_AGE_SECS));
        assert_eq!(table.len(), 3, "the entry from T0 is gone");
        assert_eq!(table.remove(b"old"), None);
    }

    #[test]
    fn client_table_bounds_names_and_tickets() {
        let mut table: ClientTable<&str, u32> = ClientTable::new(2, 3);
        for v in 0..5 {
            table.insert("a", v, T0);
        }
        // Three tickets kept, newest first out.
        assert_eq!(table.take(&"a", T0), Some((4, T0)));
        assert_eq!(table.take(&"a", T0), Some((3, T0)));
        assert_eq!(table.take(&"a", T0), Some((2, T0)));
        assert_eq!(table.take(&"a", T0), None);
        table.insert("b", 10, T0);
        table.insert("c", 20, T0);
        // "a" was added first and is evicted, although its queue is empty.
        assert_eq!(table.servers.len(), 2);
        assert_eq!(table.order.len(), 2);
        assert_eq!(table.take(&"b", T0), Some((10, T0)));
        assert_eq!(table.take(&"c", T0), Some((20, T0)));

        let mut none: ClientTable<&str, u32> = ClientTable::new(0, 3);
        none.insert("a", 1, T0);
        assert_eq!(none.take(&"a", T0), None);
    }

    #[test]
    fn client_table_skips_expired_tickets() {
        let mut table: ClientTable<&str, u32> = ClientTable::new(4, 4);
        table.insert("a", 1, T0 + 100);
        table.insert("a", 2, T0);
        // The newest ticket has the older origin and is dropped.
        assert_eq!(table.take(&"a", T0 + MAX_AGE_SECS), Some((1, T0 + 100)));
        assert_eq!(table.take(&"a", T0 + MAX_AGE_SECS), None);
    }

    /// P2 as a property of the server store alone. In a random schedule,
    /// each connection either resumes from a ticket or runs a full
    /// handshake. A ticket resumes exactly when its session is less than an
    /// hour old, counted from the full handshake behind it. So a chain of
    /// resumptions never extends the hour. The capacity is large enough
    /// that nothing is evicted.
    #[test]
    fn p2_chained_resumption_never_outlives_the_full_handshake() {
        let cfg = Config {
            cases: 200,
            ..Config::default()
        };
        check_with(
            "p2_chained_resumption_never_outlives_the_full_handshake",
            cfg,
            |g| {
                let clock = Clock::at(T0);
                let sessions = Arc::new(ServerSessions::new(64));
                // Tickets the client holds: (key, origin of the full handshake).
                let mut held: Vec<(Vec<u8>, u64)> = Vec::new();
                let mut now = T0;
                let mut next_key = 0u32;
                let steps = g.usize_in(1..=24);
                for step in 0..steps {
                    let gap = match g.weighted(&[4, 2, 1]) {
                        0 => g.u64_in(0..=1200),
                        1 => g.u64_in(MAX_AGE_SECS - 5..=MAX_AGE_SECS + 5),
                        _ => g.u64_in(0..=3 * MAX_AGE_SECS),
                    };
                    now = now.saturating_add(gap);
                    clock.set(now);
                    let handle = sessions.handle(clock.clone());
                    // The client offers some ticket it holds, or none.
                    let offered = if held.is_empty() || g.weighted(&[5, 1]) == 1 {
                        None
                    } else {
                        Some(held.remove(g.usize_in(0..=held.len() - 1)))
                    };
                    let mut lineage = now;
                    if let Some((key, origin)) = offered {
                        let resumed = handle.take(&key).is_some();
                        let age = now - origin;
                        g.note("age of the offered session", &age);
                        prop_assert_eq!(resumed, age < MAX_AGE_SECS, "step {}", step);
                        if resumed {
                            lineage = origin;
                        }
                    }
                    prop_assert_eq!(handle.origin.get(), lineage);
                    for _ in 0..g.usize_in(0..=2) {
                        let key = next_key.to_be_bytes().to_vec();
                        next_key += 1;
                        if handle.put(key.clone(), Vec::new()) {
                            held.push((key, lineage));
                        }
                    }
                }
                Ok(())
            },
        );
    }
}

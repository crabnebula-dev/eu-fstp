//! The guards on the second custodian's key volume (ADR-004 record of
//! lane `m10/guard-key`, rows "Where the guard lives" to "Order at the
//! custodian").
//!
//! Each guard generation is a hybrid key pair from
//! [`fstp_crypto::hybrid_kem`]. Its secret half is sealed under a random
//! key `K` of its own in the file `guard-<entry>-<generation>.key`, and `K`
//! sits in a slot of the key table in the sign-key slot form with the
//! class byte [`super::GUARD_CLASS`]. A destroy overwrites `K` in place,
//! fsyncs, unlinks the file, fsyncs the directory and reads back, the five
//! steps of a sign-key destroy.
//!
//! ```text
//! guard file = "FGK1" | version u8 = 1 | class u8 = 0x10 | name 8
//!              | nonce 12 | AES-256-GCM(K, aad = header, secret 2432) | tag 16
//! name       = entry u8 | 0 0 0 | generation u32
//! event file = "FGE1" | version u8 = 1 | state u8 | event 16 | from u32 | to u32
//! log record = tag 0xf2 | time u64 | op u8 | entry u8 | outcome u8
//!              | generation u32 | next u32 | id 16 | check 4
//! ```
//!
//! Every decoder here is fuzzed (`guard_link_decode`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey, SECRET_KEY_LEN};
use fstp_custody::Refusal;
use fstp_custody::keyd::SignKeyReceipt;

use super::copy::{self, HEADER_LEN};
use super::wire::{GuardRequest, GuardResponse, decode_guard_request, decode_guard_response};
use super::{GUARD_CLASS, GuardClient, GuardEntry, GuardFault, Rotated, fresh_id};
use crate::server::Server;
use crate::table::{EpochKey, SignKeyName, Slot};
use crate::{KeydError, Passphrase};

/// The magic of a guard file.
pub const GUARD_FILE_MAGIC: [u8; 4] = *b"FGK1";
/// The version of a guard file.
pub const GUARD_FILE_VERSION: u8 = 1;
/// The length of a guard file header.
pub const GUARD_HEADER_LEN: usize = 14;
/// The length of a guard file.
pub const GUARD_FILE_LEN: usize =
    GUARD_HEADER_LEN + aead::NONCE_LEN + SECRET_KEY_LEN + aead::TAG_LEN;
/// The magic of an event file.
pub const EVENT_MAGIC: [u8; 4] = *b"FGE1";
/// The length of an event file.
pub const EVENT_LEN: usize = 30;
/// The custodian's guard log.
pub const LOG_FILE: &str = "guard.log";
/// The length of one guard log record.
pub const LOG_RECORD_LEN: usize = 40;
/// The tag of a guard log record.
pub const LOG_TAG: u8 = 0xf2;
/// The guard log size above which the custodian refuses: an operation
/// that cannot be logged is not served (ADR-004 "Reconciliation").
pub const MAX_LOG_LEN: u64 = 64 << 20;

const EVENT_PENDING: u8 = 1;
const EVENT_DONE: u8 = 2;
/// The outcome code of a served request in the log.
const OUTCOME_SERVED: u8 = 0;

fn bad(rule: &'static str) -> KeydError {
    KeydError::Malformed(rule)
}

/// The key table name of `entry`'s guard of `generation`.
#[must_use]
pub fn guard_name(entry: GuardEntry, generation: u32) -> SignKeyName {
    let g = generation.to_be_bytes();
    SignKeyName {
        class: GUARD_CLASS,
        name: [entry.code(), 0, 0, 0, g[0], g[1], g[2], g[3]],
    }
}

/// The entry and generation a guard slot names, or `None` for another
/// slot.
#[must_use]
pub fn of_name(name: SignKeyName) -> Option<(GuardEntry, u32)> {
    if name.class != GUARD_CLASS {
        return None;
    }
    let [code, 0, 0, 0, a, b, c, d] = name.name else {
        return None;
    };
    let generation = u32::from_be_bytes([a, b, c, d]);
    (generation > 0)
        .then_some(())
        .and(GuardEntry::from_code(code))
        .map(|e| (e, generation))
}

/// The file name of `entry`'s guard of `generation`.
#[must_use]
pub fn file_name(entry: GuardEntry, generation: u32) -> String {
    format!("guard-{}-{generation}.key", entry.name())
}

fn header(name: SignKeyName) -> [u8; GUARD_HEADER_LEN] {
    let mut out = [0u8; GUARD_HEADER_LEN];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&GUARD_FILE_MAGIC);
    let (codes, n) = rest.split_at_mut(2);
    codes.copy_from_slice(&[GUARD_FILE_VERSION, name.class]);
    n.copy_from_slice(&name.name);
    out
}

/// Decodes the structure of a guard file without opening it, and returns
/// the entry and generation it names. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for another length, magic, version or class,
/// and a name that is not a guard's.
pub fn decode_guard_file(bytes: &[u8]) -> Result<(GuardEntry, u32), KeydError> {
    if bytes.len() != GUARD_FILE_LEN {
        return Err(bad("a guard file has the wrong length"));
    }
    let (head, _) = bytes
        .split_first_chunk::<GUARD_HEADER_LEN>()
        .ok_or(bad("a guard file is cut short"))?;
    let (magic, rest) = head.split_at(4);
    if magic != GUARD_FILE_MAGIC {
        return Err(bad("a guard file has the wrong magic"));
    }
    let (codes, n) = rest.split_at(2);
    if codes != [GUARD_FILE_VERSION, GUARD_CLASS] {
        return Err(bad("a guard file has an unknown version or class"));
    }
    let name = SignKeyName {
        class: GUARD_CLASS,
        name: n.try_into().map_err(|_| bad("a guard file is cut short"))?,
    };
    of_name(name).ok_or(bad("a guard file names no guard"))
}

fn seal_file(
    k: &EpochKey,
    name: SignKeyName,
    secret: &HybridSecretKey,
) -> Result<Vec<u8>, KeydError> {
    let key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let hb = header(name);
    let plain = secret.to_bytes();
    let sealed = aead::seal(&key, &hb, &plain[..]).map_err(KeydError::Crypto)?;
    let mut out = Vec::with_capacity(GUARD_FILE_LEN);
    out.extend_from_slice(&hb);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

fn open_file(k: &EpochKey, name: SignKeyName, bytes: &[u8]) -> Result<HybridSecretKey, KeydError> {
    let named = decode_guard_file(bytes)?;
    if Some(named) != of_name(name) {
        return Err(bad("a guard file names another guard"));
    }
    let rest = bytes
        .get(GUARD_HEADER_LEN..)
        .ok_or(bad("a guard file is cut short"))?;
    let (nonce, body) = rest
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(bad("a guard file is cut short"))?;
    let key = aead::Key::from_bytes(k.expose()).map_err(KeydError::Crypto)?;
    let plain = Zeroizing::new(
        aead::open(&key, nonce, &header(name), body)
            .map_err(|_| bad("a guard file did not open"))?,
    );
    HybridSecretKey::from_bytes(&plain).map_err(KeydError::Crypto)
}

/// One rotation event of an entry, as `guard-<entry>.event` holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardEvent {
    /// The owed event.
    pub event: [u8; 16],
    /// Whether the rotation finished.
    pub done: bool,
    /// The newest live generation when it began, or 0.
    pub from: u32,
    /// The generation it makes.
    pub to: u32,
}

impl GuardEvent {
    /// The event file bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; EVENT_LEN] {
        let mut out = [0u8; EVENT_LEN];
        let state = if self.done { EVENT_DONE } else { EVENT_PENDING };
        let parts: [&[u8]; 6] = [
            &EVENT_MAGIC,
            &[1, state],
            &self.event,
            &self.from.to_be_bytes(),
            &self.to.to_be_bytes(),
            &[],
        ];
        let mut at = 0usize;
        for p in parts {
            let end = at.saturating_add(p.len());
            if let Some(dst) = out.get_mut(at..end) {
                dst.copy_from_slice(p);
            }
            at = end;
        }
        out
    }
}

/// Decodes an event file. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for another length, magic, version or state,
/// and a `to` that is not above `from`.
pub fn decode_event(bytes: &[u8]) -> Result<GuardEvent, KeydError> {
    let b: &[u8; EVENT_LEN] = bytes
        .try_into()
        .map_err(|_| bad("a guard event has the wrong length"))?;
    let (magic, rest) = b.split_at(4);
    if magic != EVENT_MAGIC {
        return Err(bad("a guard event has the wrong magic"));
    }
    let (codes, rest) = rest.split_at(2);
    let done = match codes {
        [1, EVENT_PENDING] => false,
        [1, EVENT_DONE] => true,
        _ => return Err(bad("a guard event has an unknown version or state")),
    };
    let (event, rest) = rest.split_at(16);
    let (from, to) = rest.split_at(4);
    let from = u32::from_be_bytes(from.try_into().map_err(|_| bad("cut short"))?);
    let to = u32::from_be_bytes(to.try_into().map_err(|_| bad("cut short"))?);
    if to <= from {
        return Err(bad("a guard event makes no newer generation"));
    }
    Ok(GuardEvent {
        event: event.try_into().map_err(|_| bad("cut short"))?,
        done,
        from,
        to,
    })
}

/// One record of the custodian's guard log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// When, in Unix seconds.
    pub time: u64,
    /// 1 public, 2 rotate, 3 open, 4 put, 5 fetch, 0 a request that did
    /// not decode.
    pub op: u8,
    /// The entry code the request named, 0 when none.
    pub entry: u8,
    /// 0 served, or the refusal code.
    pub outcome: u8,
    /// The generation answered, destroyed or opened, or 0.
    pub generation: u32,
    /// The generation a rotation made, or 0.
    pub next: u32,
    /// The request id, or for a rotation the owed event.
    pub id: [u8; 16],
}

impl LogRecord {
    /// The record bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; LOG_RECORD_LEN] {
        let mut out = [0u8; LOG_RECORD_LEN];
        let parts: [&[u8]; 8] = [
            &[LOG_TAG],
            &self.time.to_be_bytes(),
            &[self.op, self.entry, self.outcome],
            &self.generation.to_be_bytes(),
            &self.next.to_be_bytes(),
            &self.id,
            &[],
            &[],
        ];
        let mut at = 0usize;
        for p in parts {
            let end = at.saturating_add(p.len());
            if let Some(dst) = out.get_mut(at..end) {
                dst.copy_from_slice(p);
            }
            at = end;
        }
        let check = fstp_crypto::sha256(out.get(..LOG_RECORD_LEN - 4).unwrap_or_default());
        if let (Some(dst), Some(src)) = (out.get_mut(LOG_RECORD_LEN - 4..), check.get(..4)) {
            dst.copy_from_slice(src);
        }
        out
    }
}

/// Decodes a guard log. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for a length that is not whole records, a
/// wrong tag, op or check.
pub fn decode_log(bytes: &[u8]) -> Result<Vec<LogRecord>, KeydError> {
    if !bytes.len().is_multiple_of(LOG_RECORD_LEN) {
        return Err(bad("a guard log is cut short"));
    }
    let mut out = Vec::with_capacity(bytes.len() / LOG_RECORD_LEN);
    for rec in bytes.chunks_exact(LOG_RECORD_LEN) {
        let (body, check) = rec.split_at(LOG_RECORD_LEN - 4);
        if fstp_crypto::sha256(body).get(..4) != Some(check) {
            return Err(bad("a guard log record fails its check"));
        }
        let at = |i: usize| body.get(i).copied().unwrap_or(0);
        if at(0) != LOG_TAG || at(9) > 5 {
            return Err(bad("a guard log record has a wrong tag or op"));
        }
        let arr =
            |from: usize, n: usize| body.get(from..from.saturating_add(n)).unwrap_or_default();
        out.push(LogRecord {
            time: u64::from_be_bytes(arr(1, 8).try_into().map_err(|_| bad("cut short"))?),
            op: at(9),
            entry: at(10),
            outcome: at(11),
            generation: u32::from_be_bytes(arr(12, 4).try_into().map_err(|_| bad("cut short"))?),
            next: u32::from_be_bytes(arr(16, 4).try_into().map_err(|_| bad("cut short"))?),
            id: arr(20, 16).try_into().map_err(|_| bad("cut short"))?,
        });
    }
    Ok(out)
}

fn event_path(volume: &Path, entry: GuardEntry) -> PathBuf {
    volume.join(format!("guard-{}.event", entry.name()))
}

fn read_event(volume: &Path, entry: GuardEntry) -> Result<Option<GuardEvent>, KeydError> {
    match std::fs::read(event_path(volume, entry)) {
        Ok(b) => decode_event(&b).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(KeydError::Io("read a guard event")),
    }
}

fn write_event(volume: &Path, entry: GuardEntry, ev: &GuardEvent) -> Result<(), KeydError> {
    let path = event_path(volume, entry);
    let tmp = path.with_extension("event.new");
    let _ = std::fs::remove_file(&tmp);
    let mut f = crate::volume::private(std::fs::OpenOptions::new().write(true).create_new(true))
        .open(&tmp)
        .map_err(|_| KeydError::Io("create a guard event"))?;
    f.write_all(&ev.encode())
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write a guard event"))?;
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|_| KeydError::Io("move a guard event"))?;
    crate::epoch::sync_dir(volume)
}

fn append_log(volume: &Path, rec: &LogRecord) -> Result<(), KeydError> {
    let path = volume.join(LOG_FILE);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() >= MAX_LOG_LEN) {
        return Err(KeydError::Io("the guard log is full"));
    }
    let mut f = crate::volume::private(std::fs::OpenOptions::new().append(true).create(true))
        .open(&path)
        .map_err(|_| KeydError::Io("open the guard log"))?;
    f.write_all(&rec.encode())
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write the guard log"))
}

/// The live generations of `entry` on a table, and the newest one known
/// at all, live or destroyed.
fn generations(server: &Server, entry: GuardEntry) -> (Vec<u32>, u32) {
    let mut live = Vec::new();
    let mut newest = 0u32;
    for s in &server.table.table.sign_keys {
        if let Some((e, g)) = of_name(s.name)
            && e == entry
        {
            newest = newest.max(g);
            if s.is_live() {
                live.push(g);
            }
        }
    }
    live.sort_unstable();
    (live, newest)
}

impl Server {
    /// Whether this volume holds a guard: then it is a custodian's, and
    /// never copied.
    pub(crate) fn holds_guard(table: &crate::table::KeyTable) -> bool {
        table.sign_keys.iter().any(|s| s.name.class == GUARD_CLASS)
    }

    fn create_guard(&mut self, entry: GuardEntry, generation: u32) -> Result<(), Refusal> {
        let name = guard_name(entry, generation);
        let k = EpochKey::generate().map_err(|_| Refusal::Internal)?;
        let secret = hybrid_kem::generate().map_err(|_| Refusal::Internal)?;
        let sealed = seal_file(&k, name, &secret).map_err(|_| Refusal::Internal)?;
        write_file(&self.volume, &file_name(entry, generation), &sealed)
            .map_err(|_| Refusal::Internal)?;
        self.table
            .insert_sign_key(name, k)
            .map_err(|_| Refusal::Internal)
    }

    fn open_guard(&self, entry: GuardEntry, generation: u32) -> Result<HybridSecretKey, Refusal> {
        let name = guard_name(entry, generation);
        let (live, newest) = generations(self, entry);
        let Some(s) = self.table.table.sign_key(name) else {
            return Err(if generation <= newest {
                Refusal::Destroyed
            } else {
                Refusal::UnknownRoot
            });
        };
        let k = s.key.as_ref().ok_or(Refusal::Destroyed)?;
        if !live.contains(&generation) {
            return Err(Refusal::Destroyed);
        }
        let bytes = std::fs::read(self.volume.join(file_name(entry, generation)))
            .map_err(|_| Refusal::Internal)?;
        open_file(k, name, &bytes).map_err(|_| Refusal::Internal)
    }

    /// Destroys `entry`'s guard of `generation` in the five steps of a
    /// sign-key destroy and returns its receipt.
    fn destroy_guard(&mut self, entry: GuardEntry, generation: u32) -> Result<Vec<u8>, Refusal> {
        let name = guard_name(entry, generation);
        let slot = Slot::Sign(name);
        if self.table.table.sign_key(name).is_some_and(|s| s.is_live()) {
            self.table
                .mark_sign_key_destroyed(name)
                .map_err(|_| Refusal::Internal)?;
        }
        self.table
            .scrub_blocked_slot(slot)
            .map_err(|_| Refusal::Internal)?;
        let path = self.volume.join(file_name(entry, generation));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Refusal::Internal),
        }
        crate::epoch::sync_dir(&self.volume).map_err(|_| Refusal::Internal)?;
        let gone = self
            .table
            .read_back_slot_gone(slot)
            .map_err(|_| Refusal::Internal)?;
        if !gone || path.exists() {
            return Err(Refusal::Internal);
        }
        SignKeyReceipt::full(&name.handle())
            .encode()
            .map_err(|_| Refusal::Internal)
    }

    fn public_of(&mut self, entry: GuardEntry) -> Result<(u32, HybridPublicKey), Refusal> {
        let (live, newest) = generations(self, entry);
        let generation = match live.last() {
            Some(g) => *g,
            None => {
                let g = newest.checked_add(1).ok_or(Refusal::LimitReached)?;
                self.create_guard(entry, g)?;
                g
            }
        };
        let secret = self.open_guard(entry, generation)?;
        let pk = HybridPublicKey::from_bytes(&secret.public().to_bytes())
            .map_err(|_| Refusal::Internal)?;
        Ok((generation, pk))
    }

    fn rotate_for(&mut self, entry: GuardEntry, event: [u8; 16]) -> Result<Rotated, Refusal> {
        let recorded = read_event(&self.volume, entry).map_err(|_| Refusal::Internal)?;
        let ev = match recorded {
            Some(ev) if ev.event == event => ev,
            _ => {
                let (live, newest) = generations(self, entry);
                let from = live.last().copied().unwrap_or(0);
                let to = newest.checked_add(1).ok_or(Refusal::LimitReached)?;
                let ev = GuardEvent {
                    event,
                    done: false,
                    from,
                    to,
                };
                write_event(&self.volume, entry, &ev).map_err(|_| Refusal::Internal)?;
                ev
            }
        };
        if !ev.done {
            let (live, newest) = generations(self, entry);
            if !live.contains(&ev.to) && ev.to > newest {
                self.create_guard(entry, ev.to)?;
            }
            let mut destroyed = Vec::new();
            for g in live.into_iter().filter(|g| *g < ev.to) {
                self.destroy_guard(entry, g)?;
                destroyed.push(g);
            }
            // Every destroyed guard of the entry but the newest leaves
            // the table, as a chain's older destroyed roots do.
            let dead: Vec<u32> = self
                .table
                .table
                .sign_keys
                .iter()
                .filter(|s| !s.is_live())
                .filter_map(|s| of_name(s.name))
                .filter(|(e, _)| *e == entry)
                .map(|(_, g)| g)
                .collect();
            let keep = dead.iter().copied().max().unwrap_or(0);
            let older: Vec<SignKeyName> = dead
                .into_iter()
                .filter(|g| *g != keep)
                .map(|g| guard_name(entry, g))
                .collect();
            self.table.reclaim_sign_keys(&older);
            write_event(&self.volume, entry, &GuardEvent { done: true, ..ev })
                .map_err(|_| Refusal::Internal)?;
        }
        // ADR-004 "The custodian's copy": a held copy sealed to an older
        // generation goes with it. A failed unlink leaves a file sealed to
        // a destroyed guard, which no key opens, and is tried again later.
        let _ = self.drop_held_below(entry, ev.to);
        let secret = self.open_guard(entry, ev.to)?;
        let receipt = if ev.from == 0 {
            Vec::new()
        } else {
            SignKeyReceipt::full(&guard_name(entry, ev.from).handle())
                .encode()
                .map_err(|_| Refusal::Internal)?
        };
        Ok(Rotated {
            destroyed: ev.from,
            generation: ev.to,
            public: secret.public().to_bytes(),
            receipt,
        })
    }

    /// The path of `entry`'s held copy.
    fn held_path(&self, entry: GuardEntry) -> PathBuf {
        self.volume.join(format!("held-{}.fgc", entry.name()))
    }

    /// Unlinks `entry`'s held copy when it is sealed to a generation below
    /// `generation`, or does not decode, and syncs the directory.
    fn drop_held_below(&self, entry: GuardEntry, generation: u32) -> Result<(), KeydError> {
        let path = self.held_path(entry);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(());
        };
        let old = copy::decode_guarded(&bytes).map_or(true, |(h, _, _)| h.generation < generation);
        if old {
            std::fs::remove_file(&path).map_err(|_| KeydError::Io("unlink a held copy"))?;
            crate::epoch::sync_dir(&self.volume)?;
        }
        Ok(())
    }

    /// Stores `copy` as `entry`'s held copy (ADR-004 "The custodian's
    /// copy"). It must be a guarded copy of `entry` sealed to `generation`,
    /// and that must be the entry's newest live generation.
    fn put_for(&mut self, entry: GuardEntry, generation: u32, bytes: &[u8]) -> Result<(), Refusal> {
        let (header, _, _) = copy::decode_guarded(bytes).map_err(|_| Refusal::BadRequest)?;
        if header.entry != entry || header.generation != generation {
            return Err(Refusal::BadRequest);
        }
        let (live, newest) = generations(self, entry);
        match live.last() {
            Some(g) if *g == generation => {}
            _ if generation <= newest => return Err(Refusal::Destroyed),
            _ => return Err(Refusal::BadRequest),
        }
        let path = self.held_path(entry);
        let tmp = path.with_extension("fgc.new");
        let _ = std::fs::remove_file(&tmp);
        let written =
            crate::volume::private(std::fs::OpenOptions::new().write(true).create_new(true))
                .open(&tmp)
                .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
                .and_then(|()| std::fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(Refusal::Internal);
        }
        crate::epoch::sync_dir(&self.volume).map_err(|_| Refusal::Internal)
    }

    /// `entry`'s held copy and its generation, when it is sealed to a live
    /// generation. A copy left by a failed unlink is unlinked now.
    fn fetch_for(&self, entry: GuardEntry) -> Result<(u32, Vec<u8>), Refusal> {
        let (live, _) = generations(self, entry);
        let newest = live.last().copied().unwrap_or(0);
        let _ = self.drop_held_below(entry, newest);
        let bytes = match std::fs::read(self.held_path(entry)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Refusal::UnknownRoot),
            Err(_) => return Err(Refusal::Internal),
        };
        let (header, _, _) = copy::decode_guarded(&bytes).map_err(|_| Refusal::Internal)?;
        if !live.contains(&header.generation) {
            return Err(Refusal::UnknownRoot);
        }
        Ok((header.generation, bytes))
    }

    /// Serves one request of the guard link from the pilot entry `peer`,
    /// which the TLS client certificate names (`None` when it names no
    /// guard client). A request for another entry than the peer's is
    /// refused with [`Refusal::NotPermitted`]. Every request is logged in
    /// `guard.log`, and one that cannot be logged is refused.
    pub(crate) fn guard_serve(
        &mut self,
        peer: Option<GuardEntry>,
        bytes: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        let request = decode_guard_request(bytes);
        let (op, entry, id) = match &request {
            Ok(GuardRequest::Public { id, entry }) => (1, entry.code(), *id),
            Ok(GuardRequest::Rotate { entry, event, .. }) => (2, entry.code(), *event),
            Ok(GuardRequest::Open { id, entry, .. }) => (3, entry.code(), *id),
            Ok(GuardRequest::Put { id, entry, .. }) => (4, entry.code(), *id),
            Ok(GuardRequest::Fetch { id, entry }) => (5, entry.code(), *id),
            Err(_) => (0, 0, [0u8; 16]),
        };
        let reply_id = request.as_ref().map_or([0u8; 16], GuardRequest::id);
        let (response, generation, next) = match request {
            Err(_) => (Err(Refusal::BadRequest), 0, 0),
            Ok(r) if Some(r.entry()) != peer => (Err(Refusal::NotPermitted), 0, 0),
            Ok(GuardRequest::Public { id, entry }) => match self.public_of(entry) {
                Ok((g, pk)) => (
                    Ok(GuardResponse::Public {
                        id,
                        generation: g,
                        public: Box::new(pk.to_bytes()),
                    }),
                    g,
                    0,
                ),
                Err(e) => (Err(e), 0, 0),
            },
            Ok(GuardRequest::Rotate { id, entry, event }) => match self.rotate_for(entry, event) {
                Ok(r) => (
                    Ok(GuardResponse::Rotated {
                        id,
                        destroyed: r.destroyed,
                        generation: r.generation,
                        public: Box::new(r.public),
                        receipt: r.receipt,
                    }),
                    r.destroyed,
                    r.generation,
                ),
                Err(e) => (Err(e), 0, 0),
            },
            Ok(GuardRequest::Open {
                id,
                entry,
                generation,
                header,
                ciphertext,
            }) => {
                let named = copy::decode_header(&header).ok();
                let opened = if named.is_none_or(|h| h.entry != entry || h.generation != generation)
                {
                    Err(Refusal::BadRequest)
                } else {
                    self.open_guard(entry, generation).and_then(|secret| {
                        copy::derive_on_custodian(&secret, &header, &ciphertext)
                            .map_err(|_| Refusal::Internal)
                    })
                };
                match opened {
                    Ok(kek) => (Ok(GuardResponse::Opened { id, kek }), generation, 0),
                    Err(e) => (Err(e), generation, 0),
                }
            }
            Ok(GuardRequest::Put {
                id,
                entry,
                generation,
                copy,
            }) => match self.put_for(entry, generation, &copy) {
                Ok(()) => (Ok(GuardResponse::Stored { id, generation }), generation, 0),
                Err(e) => (Err(e), generation, 0),
            },
            Ok(GuardRequest::Fetch { id, entry }) => match self.fetch_for(entry) {
                Ok((generation, copy)) => (
                    Ok(GuardResponse::Copy {
                        id,
                        generation,
                        copy,
                    }),
                    generation,
                    0,
                ),
                Err(e) => (Err(e), 0, 0),
            },
        };
        let outcome = match &response {
            Ok(_) => OUTCOME_SERVED,
            Err(r) => r.code(),
        };
        let logged = append_log(
            &self.volume,
            &LogRecord {
                time: super::state::now(),
                op,
                entry,
                outcome,
                generation,
                next,
                id,
            },
        );
        let response = match (logged, response) {
            (Ok(()), Ok(r)) => r,
            (Ok(()), Err(refusal)) => GuardResponse::Refused {
                id: reply_id,
                refusal,
            },
            (Err(_), _) => GuardResponse::Refused {
                id: reply_id,
                refusal: Refusal::Internal,
            },
        };
        response
            .encode()
            .unwrap_or_else(|_| Zeroizing::new(Vec::new()))
    }
}

fn write_file(volume: &Path, name: &str, bytes: &[u8]) -> Result<(), KeydError> {
    let mut f = crate::volume::private(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true),
    )
    .open(volume.join(name))
    .map_err(|_| KeydError::Io("create a guard file"))?;
    crate::volume::fix_file_mode(&f)?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write a guard file"))?;
    crate::epoch::sync_dir(volume)
}

// ---------------------------------------------------------------------------
// Answers, shared by every client.

fn check_id(sent: [u8; 16], got: [u8; 16]) -> Result<(), GuardFault> {
    if sent == got {
        Ok(())
    } else {
        Err(GuardFault::Unreachable)
    }
}

/// Reads the answer to a `public` request.
pub(crate) fn answer_public(
    sent: [u8; 16],
    reply: &[u8],
) -> Result<(u32, HybridPublicKey), GuardFault> {
    match decode_guard_response(reply).map_err(|_| GuardFault::Unreachable)? {
        GuardResponse::Public {
            id,
            generation,
            public,
        } => {
            check_id(sent, id)?;
            let pk =
                HybridPublicKey::from_bytes(&public[..]).map_err(|_| GuardFault::Unreachable)?;
            Ok((generation, pk))
        }
        GuardResponse::Refused { refusal, .. } => Err(GuardFault::Refused(refusal)),
        _ => Err(GuardFault::Unreachable),
    }
}

/// Reads the answer to a `rotate` request.
pub(crate) fn answer_rotate(
    sent: [u8; 16],
    entry: GuardEntry,
    reply: &[u8],
) -> Result<Rotated, GuardFault> {
    match decode_guard_response(reply).map_err(|_| GuardFault::Unreachable)? {
        GuardResponse::Rotated {
            id,
            destroyed,
            generation,
            public,
            receipt,
        } => {
            check_id(sent, id)?;
            if destroyed != 0 {
                let r = fstp_custody::keyd::decode_sign_receipt(&receipt)
                    .map_err(|_| GuardFault::Unreachable)?;
                if r.handle[..] != guard_name(entry, destroyed).handle()[..] {
                    return Err(GuardFault::Unreachable);
                }
            }
            Ok(Rotated {
                destroyed,
                generation,
                public: *public,
                receipt,
            })
        }
        GuardResponse::Refused { refusal, .. } => Err(GuardFault::Refused(refusal)),
        _ => Err(GuardFault::Unreachable),
    }
}

/// Reads the answer to an `open` request.
pub(crate) fn answer_open(sent: [u8; 16], reply: &[u8]) -> Result<Zeroizing<[u8; 32]>, GuardFault> {
    match decode_guard_response(reply).map_err(|_| GuardFault::Unreachable)? {
        GuardResponse::Opened { id, kek } => {
            check_id(sent, id)?;
            Ok(kek)
        }
        GuardResponse::Refused { refusal, .. } => Err(GuardFault::Refused(refusal)),
        _ => Err(GuardFault::Unreachable),
    }
}

/// Reads the answer to a `put` request.
pub(crate) fn answer_put(sent: [u8; 16], reply: &[u8]) -> Result<u32, GuardFault> {
    match decode_guard_response(reply).map_err(|_| GuardFault::Unreachable)? {
        GuardResponse::Stored { id, generation } => {
            check_id(sent, id)?;
            Ok(generation)
        }
        GuardResponse::Refused { refusal, .. } => Err(GuardFault::Refused(refusal)),
        _ => Err(GuardFault::Unreachable),
    }
}

/// Reads the answer to a `fetch` request: the held copy, checked to be a
/// guarded copy of `entry` sealed to the generation the answer names.
pub(crate) fn answer_fetch(
    sent: [u8; 16],
    entry: GuardEntry,
    reply: &[u8],
) -> Result<Vec<u8>, GuardFault> {
    match decode_guard_response(reply).map_err(|_| GuardFault::Unreachable)? {
        GuardResponse::Copy {
            id,
            generation,
            copy: bytes,
        } => {
            check_id(sent, id)?;
            let (h, _, _) = copy::decode_guarded(&bytes).map_err(|_| GuardFault::Unreachable)?;
            if h.entry != entry || h.generation != generation {
                return Err(GuardFault::Unreachable);
            }
            Ok(bytes)
        }
        GuardResponse::Refused { refusal, .. } => Err(GuardFault::Refused(refusal)),
        _ => Err(GuardFault::Unreachable),
    }
}

// ---------------------------------------------------------------------------
// The custodian in process.

/// A custodian served in this process from its own key volume: the
/// requests and answers of the link pass through the same frames, with no
/// TLS. For tests and a restore drill on one machine. It holds the
/// volume's lock while it lives.
pub struct LocalCustodian {
    server: Mutex<Server>,
}

impl std::fmt::Debug for LocalCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCustodian").finish_non_exhaustive()
    }
}

impl LocalCustodian {
    /// Opens the custodian's key volume `volume` under `passphrase`.
    ///
    /// # Errors
    ///
    /// As the server's open: a wrong passphrase, a locked volume.
    pub fn open(volume: &Path, passphrase: &Passphrase) -> Result<LocalCustodian, KeydError> {
        Ok(LocalCustodian {
            server: Mutex::new(Server::open(volume, passphrase)?),
        })
    }

    /// Serves `request` bytes as if a client certificate named `peer`.
    #[must_use]
    pub fn serve_as(&self, peer: Option<GuardEntry>, request: &[u8]) -> Vec<u8> {
        let mut s = self.server.lock().unwrap_or_else(PoisonError::into_inner);
        s.guard_serve(peer, request).to_vec()
    }

    /// The generations of `entry` that are live on the custodian.
    #[must_use]
    pub fn live_generations(&self, entry: GuardEntry) -> Vec<u32> {
        let s = self.server.lock().unwrap_or_else(PoisonError::into_inner);
        generations(&s, entry).0
    }
}

impl GuardClient for LocalCustodian {
    fn public(&self, entry: GuardEntry) -> Result<(u32, HybridPublicKey), GuardFault> {
        let id = fresh_id()?;
        let reply = self.serve_as(Some(entry), &GuardRequest::Public { id, entry }.encode());
        answer_public(id, &reply)
    }

    fn rotate(&self, entry: GuardEntry, event: [u8; 16]) -> Result<Rotated, GuardFault> {
        let id = fresh_id()?;
        let reply = self.serve_as(
            Some(entry),
            &GuardRequest::Rotate { id, entry, event }.encode(),
        );
        answer_rotate(id, entry, &reply)
    }

    fn open(
        &self,
        entry: GuardEntry,
        generation: u32,
        header: &[u8; HEADER_LEN],
        ciphertext: &[u8; hybrid_kem::CIPHERTEXT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, GuardFault> {
        let id = fresh_id()?;
        let request = GuardRequest::Open {
            id,
            entry,
            generation,
            header: Box::new(*header),
            ciphertext: Box::new(*ciphertext),
        };
        let reply = self.serve_as(Some(entry), &request.encode());
        answer_open(id, &reply)
    }

    fn put(&self, entry: GuardEntry, copy: &[u8]) -> Result<u32, GuardFault> {
        let id = fresh_id()?;
        let generation = copy::decode_guarded(copy).map_or(1, |(h, _, _)| h.generation);
        let request = GuardRequest::Put {
            id,
            entry,
            generation,
            copy: copy.to_vec(),
        };
        let reply = self.serve_as(Some(entry), &request.encode());
        answer_put(id, &reply)
    }

    fn fetch(&self, entry: GuardEntry) -> Result<Vec<u8>, GuardFault> {
        let id = fresh_id()?;
        let reply = self.serve_as(Some(entry), &GuardRequest::Fetch { id, entry }.encode());
        answer_fetch(id, entry, &reply)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    /// ADR-004 record of lane `m10/guard-key`: the guard file, the event
    /// file and the log read back in one spelling, and a guard name maps
    /// to its entry and generation only.
    #[test]
    fn adr004_guard_store_formats_round_trip_in_one_spelling() {
        let ev = GuardEvent {
            event: [3; 16],
            done: true,
            from: 4,
            to: 5,
        };
        assert_eq!(decode_event(&ev.encode()).unwrap(), ev);
        let rec = LogRecord {
            time: 9,
            op: 2,
            entry: 1,
            outcome: 0,
            generation: 4,
            next: 5,
            id: [7; 16],
        };
        let mut log = rec.encode().to_vec();
        log.extend(rec.encode());
        assert_eq!(decode_log(&log).unwrap(), vec![rec, rec]);
        log[3] ^= 1;
        assert!(decode_log(&log).is_err());
        let name = guard_name(GuardEntry::Vault, 258);
        assert_eq!(of_name(name), Some((GuardEntry::Vault, 258)));
        assert_eq!(of_name(guard_name(GuardEntry::Vault, 0)), None);
        let k = EpochKey::generate().unwrap();
        let secret = hybrid_kem::generate().unwrap();
        let file = seal_file(&k, name, &secret).unwrap();
        assert_eq!(file.len(), GUARD_FILE_LEN);
        assert_eq!(decode_guard_file(&file).unwrap(), (GuardEntry::Vault, 258));
        let back = open_file(&k, name, &file).unwrap();
        assert_eq!(back.public().to_bytes(), secret.public().to_bytes());
        assert!(open_file(&k, guard_name(GuardEntry::Vault, 259), &file).is_err());
    }
}

//! The off-host sealed copy of a key volume (ADR-004 record of lane L16,
//! ADR-012 record of lane L16, I-80, I-81).
//!
//! Decided by Daniel on 2026-11-21: on the single-host pilot the key that
//! opens every backup must survive the loss of the host. An operator
//! command copies the state of one `fstp-keyd` entry off the host, still
//! sealed, and another imports it onto a fresh host.
//!
//! ```text
//! header = "FKX1" | version u8 = 1 | kdf u8 = 1 | iterations u32 | salt 16
//!          | export id 16 | created u64                                  50 bytes
//! file   = header | nonce 12 | AES-256-GCM(copy key, aad = header, body) | tag 16
//! key    = PBKDF2-HMAC-SHA-256(passphrase, salt, iterations)
//! body   = count u16 | count times (name_len u8 | name | len u32 | bytes)
//! ```
//!
//! # I-80
//!
//! The body holds the key table, re-encoded under the passphrase, and the
//! epoch and sign-key files of live keys, each as sealed as on the volume.
//! No root, no `K(e)` and no table key is ever in it in the clear, not
//! even under the outer seal. Only this crate makes or opens a copy, and
//! the [`fstp_custody::Custody`] trait gains no export operation.
//!
//! # I-81
//!
//! 1. A copy never holds a destroyed key: it is built from the opened
//!    table, which holds a destroyed entry as a tombstone of zeros.
//! 2. An imported volume is held ([`HOLD_FILE`]). The server then answers
//!    only unwrap and usage requests on the backup chains.
//! 3. [`release_import`] destroys every epoch of an erasable chain below
//!    the current one the restored keystore names, and refuses a copy that
//!    lacks the current epoch, keeping the hold.
//! 4. The source volume records each copy ([`REGISTER_FILE`]). A copy
//!    that holds a key destroyed since lowers the volume's I-81 assurance
//!    until the operator retires it ([`retire_export`]).

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use fstp_crypto::aead;
use fstp_custody::{Chain, Epoch};
use fstp_obs::assurance::ReducedReason;
use zeroize::Zeroizing;

use crate::table::{
    DEFAULT_ITERATIONS, EpochKey, KeyTable, KeyTableEntry, MAX_ITERATIONS, MIN_ITERATIONS,
    SALT_LEN, SignKeyEntry, SignKeyName, TABLE_FILE,
};
use crate::{KeydError, Passphrase};

/// The magic of a copy.
pub const EXPORT_MAGIC: [u8; 4] = *b"FKX1";
/// The version of a copy.
pub const EXPORT_VERSION: u8 = 1;
/// The KDF code of a copy: PBKDF2-HMAC-SHA-256, as the key table's.
pub const EXPORT_KDF: u8 = 1;
/// The length of the clear header of a copy.
pub const EXPORT_HEADER_LEN: usize = 50;
/// The longest copy accepted: room for a usage log at twice its size
/// bound, as create and destroy may grow it (ADR-004 record of lane L16,
/// Q-L16-2).
pub const MAX_EXPORT_LEN: usize = 160 << 20;
/// The name of the usage log in a copy and on the volume.
pub const USAGE_LOG_FILE: &str = crate::usage::USAGE_FILE;
/// The longest file name in a copy.
pub const MAX_NAME_LEN: usize = 64;
/// The hold marker of an imported volume.
pub const HOLD_FILE: &str = "import.hold";
/// The register of copies on the source volume.
pub const REGISTER_FILE: &str = "exports.log";
/// The lock file of a key volume.
pub const LOCK_FILE: &str = "keyd.lock";
/// The longest register read.
pub const MAX_REGISTER_LEN: usize = 1 << 20;
/// How long a holder of the lock is waited for.
pub const LOCK_WAIT: Duration = Duration::from_secs(5);

const TAG_TAKEN: u8 = 1;
const TAG_RETIRED: u8 = 2;
const TAG_GUARDED: u8 = 3;
const HEAD_LEN: usize = 9;
const SIGN_FLAG: u8 = 0x80;

/// The random id of a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExportId(pub [u8; 16]);

impl ExportId {
    /// The id as 32 lowercase hex digits.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The id of 32 hex digits, or `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<ExportId> {
        let bytes = text.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (o, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let s = std::str::from_utf8(pair).ok()?;
            if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            *o = u8::from_str_radix(s, 16).ok()?;
        }
        Some(ExportId(out))
    }
}

/// The clear header of a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportHeader {
    /// The PBKDF2 iteration count.
    pub iterations: u32,
    /// The PBKDF2 salt.
    pub salt: [u8; SALT_LEN],
    /// The copy's id.
    pub id: ExportId,
    /// When the copy was made, in Unix seconds.
    pub created: u64,
}

impl ExportHeader {
    /// The header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; EXPORT_HEADER_LEN] {
        let mut out = [0u8; EXPORT_HEADER_LEN];
        let parts: [&[u8]; 7] = [
            &EXPORT_MAGIC,
            &[EXPORT_VERSION],
            &[EXPORT_KDF],
            &self.iterations.to_be_bytes(),
            &self.salt,
            &self.id.0,
            &self.created.to_be_bytes(),
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

    fn key(&self, passphrase: &Passphrase) -> Result<aead::Key, KeydError> {
        let iterations = std::num::NonZeroU32::new(self.iterations).ok_or(KeydError::WeakKdf)?;
        let mut out = Zeroizing::new([0u8; 32]);
        fstp_crypto::try_pbkdf2_hmac_sha256(
            passphrase.bytes(),
            &self.salt,
            iterations,
            &mut out[..],
        )
        .map_err(KeydError::Crypto)?;
        aead::Key::from_bytes(&out).map_err(KeydError::Crypto)
    }
}

fn bad(rule: &'static str) -> KeydError {
    KeydError::Malformed(rule)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KeydError> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(bad("a copy is cut short"))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeydError> {
        self.take(N)?
            .try_into()
            .map_err(|_| bad("a copy is cut short"))
    }

    fn u8(&mut self) -> Result<u8, KeydError> {
        Ok(self.array::<1>()?[0])
    }
}

/// Decodes the clear header of a copy and returns it with the sealed
/// rest. Fuzzed (`keyd_export_decode`).
///
/// # Errors
///
/// Refuses a copy above [`MAX_EXPORT_LEN`], a wrong magic, version or KDF
/// code, an iteration count outside the key table's range, and a sealed
/// part shorter than a nonce and a tag.
pub fn decode_export(bytes: &[u8]) -> Result<(ExportHeader, &[u8]), KeydError> {
    if bytes.len() > MAX_EXPORT_LEN {
        return Err(bad("a copy is too long"));
    }
    let mut r = Reader(bytes);
    if r.array::<4>()? != EXPORT_MAGIC {
        return Err(bad("a copy has the wrong magic"));
    }
    if r.array::<2>()? != [EXPORT_VERSION, EXPORT_KDF] {
        return Err(bad("a copy has an unknown version or KDF"));
    }
    let iterations = u32::from_be_bytes(r.array()?);
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(KeydError::WeakKdf);
    }
    let salt = r.array()?;
    let id = ExportId(r.array()?);
    let created = u64::from_be_bytes(r.array()?);
    if r.0.len() < aead::NONCE_LEN.saturating_add(aead::TAG_LEN) {
        return Err(bad("a copy is cut short"));
    }
    Ok((
        ExportHeader {
            iterations,
            salt,
            id,
            created,
        },
        r.0,
    ))
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !name.starts_with('.')
}

/// Encodes the body of a copy.
///
/// # Errors
///
/// Refuses more than `u16::MAX` files, a bad name and a file above
/// [`MAX_EXPORT_LEN`].
pub fn encode_export_body(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, KeydError> {
    let count = u16::try_from(files.len()).map_err(|_| bad("a copy holds too many files"))?;
    let mut out = count.to_be_bytes().to_vec();
    for (name, bytes) in files {
        if !name_ok(name) {
            return Err(bad("a copy names a file badly"));
        }
        let len = u32::try_from(bytes.len()).map_err(|_| bad("a copy file is too long"))?;
        if bytes.len() > MAX_EXPORT_LEN {
            return Err(bad("a copy file is too long"));
        }
        out.push(u8::try_from(name.len()).map_err(|_| bad("a copy names a file badly"))?);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

/// Decodes the opened body of a copy into its files. The first file is
/// the key table, no name repeats and nothing follows the last file.
/// Fuzzed (`keyd_export_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] naming the first rule the body breaks.
pub fn decode_export_body(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, KeydError> {
    let mut r = Reader(bytes);
    let count = u16::from_be_bytes(r.array()?);
    if count == 0 {
        return Err(bad("a copy holds no key table"));
    }
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for _ in 0..count {
        let len = usize::from(r.u8()?);
        let name = std::str::from_utf8(r.take(len)?)
            .map_err(|_| bad("a copy names a file badly"))?
            .to_owned();
        if !name_ok(&name) {
            return Err(bad("a copy names a file badly"));
        }
        if files.iter().any(|(n, _)| *n == name) {
            return Err(bad("a copy names a file twice"));
        }
        let size = usize::try_from(u32::from_be_bytes(r.array()?))
            .map_err(|_| bad("a copy file is too long"))?;
        let body = r.take(size)?.to_vec();
        files.push((name, body));
    }
    if !r.0.is_empty() {
        return Err(bad("a copy has bytes after its last file"));
    }
    if files.first().is_none_or(|(n, _)| n != TABLE_FILE) {
        return Err(bad("a copy does not start with its key table"));
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// The register of copies.

/// One key a copy holds: a root epoch or a sign key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeldKey {
    /// A root of a chain and epoch.
    Root(Chain, Epoch),
    /// A CA sign key.
    Sign(SignKeyName),
}

impl HeldKey {
    fn head(self) -> [u8; HEAD_LEN] {
        let mut out = [0u8; HEAD_LEN];
        let (first, rest) = match self {
            HeldKey::Root(c, e) => (c.code(), e.0.to_be_bytes()),
            HeldKey::Sign(n) => (SIGN_FLAG | n.class, n.name),
        };
        let (a, b) = out.split_at_mut(1);
        a.copy_from_slice(&[first]);
        b.copy_from_slice(&rest);
        out
    }

    fn from_head(head: [u8; HEAD_LEN]) -> Result<HeldKey, KeydError> {
        let (first, rest) = head
            .split_first()
            .ok_or(bad("a register entry is cut short"))?;
        let rest: [u8; 8] = rest
            .try_into()
            .map_err(|_| bad("a register entry is cut short"))?;
        if first & SIGN_FLAG != 0 {
            let mut handle = [0u8; 9];
            let (a, b) = handle.split_at_mut(1);
            a.copy_from_slice(&[first & !SIGN_FLAG]);
            b.copy_from_slice(&rest);
            return SignKeyName::from_handle(&handle)
                .map(HeldKey::Sign)
                .ok_or(bad("a register entry names an unknown sign key class"));
        }
        let chain =
            Chain::from_code(*first).ok_or(bad("a register entry names an unknown chain"))?;
        let epoch = u64::from_be_bytes(rest);
        if epoch == 0 {
            return Err(bad("a register entry names epoch 0"));
        }
        Ok(HeldKey::Root(chain, Epoch(epoch)))
    }
}

/// One record of the register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterRecord {
    /// A copy was taken, at `created`, holding `keys`.
    Taken {
        /// The copy.
        id: ExportId,
        /// When, in Unix seconds.
        created: u64,
        /// The live keys it holds.
        keys: Vec<HeldKey>,
    },
    /// A guarded copy was taken, at `created`, sealed to the guard
    /// `generation` of its entry, holding `keys` (ADR-004 record of lane
    /// `m10/guard-key`).
    Guarded {
        /// The copy.
        id: ExportId,
        /// When, in Unix seconds.
        created: u64,
        /// The guard generation it is sealed to.
        generation: u32,
        /// The live keys it holds.
        keys: Vec<HeldKey>,
    },
    /// The operator stated that every copy of `id` is destroyed.
    Retired {
        /// The copy.
        id: ExportId,
    },
}

/// Encodes one register record.
///
/// # Errors
///
/// Refuses more than `u16::MAX` keys.
pub fn encode_register_record(r: &RegisterRecord) -> Result<Vec<u8>, KeydError> {
    match r {
        RegisterRecord::Taken { id, created, keys } => {
            let count = u16::try_from(keys.len()).map_err(|_| bad("a copy holds too many keys"))?;
            let mut out = vec![TAG_TAKEN];
            out.extend_from_slice(&id.0);
            out.extend_from_slice(&created.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            for k in keys {
                out.extend_from_slice(&k.head());
            }
            Ok(out)
        }
        RegisterRecord::Guarded {
            id,
            created,
            generation,
            keys,
        } => {
            let count = u16::try_from(keys.len()).map_err(|_| bad("a copy holds too many keys"))?;
            let mut out = vec![TAG_GUARDED];
            out.extend_from_slice(&id.0);
            out.extend_from_slice(&created.to_be_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            for k in keys {
                out.extend_from_slice(&k.head());
            }
            Ok(out)
        }
        RegisterRecord::Retired { id } => {
            let mut out = vec![TAG_RETIRED];
            out.extend_from_slice(&id.0);
            Ok(out)
        }
    }
}

/// Decodes a register. Fuzzed (`keyd_export_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for an unknown tag, an unknown chain or sign
/// key class, epoch 0, and a cut record.
pub fn decode_register(bytes: &[u8]) -> Result<Vec<RegisterRecord>, KeydError> {
    if bytes.len() > MAX_REGISTER_LEN {
        return Err(bad("the register is too long"));
    }
    let mut r = Reader(bytes);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let tag = r.u8()?;
        let id = ExportId(r.array()?);
        match tag {
            TAG_TAKEN => {
                let created = u64::from_be_bytes(r.array()?);
                let count = u16::from_be_bytes(r.array()?);
                let mut keys = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    keys.push(HeldKey::from_head(r.array()?)?);
                }
                out.push(RegisterRecord::Taken { id, created, keys });
            }
            TAG_GUARDED => {
                let created = u64::from_be_bytes(r.array()?);
                let generation = u32::from_be_bytes(r.array()?);
                if generation == 0 {
                    return Err(bad("a register entry names guard generation 0"));
                }
                let count = u16::from_be_bytes(r.array()?);
                let mut keys = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    keys.push(HeldKey::from_head(r.array()?)?);
                }
                out.push(RegisterRecord::Guarded {
                    id,
                    created,
                    generation,
                    keys,
                });
            }
            TAG_RETIRED => out.push(RegisterRecord::Retired { id }),
            _ => return Err(bad("a register record has an unknown tag")),
        }
    }
    Ok(out)
}

fn read_register(volume: &Path) -> Result<Vec<RegisterRecord>, KeydError> {
    let path = volume.join(REGISTER_FILE);
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_REGISTER_LEN as u64 => return Err(bad("the register is too long")),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(KeydError::Io("read the register")),
    }
    let bytes = std::fs::read(&path).map_err(|_| KeydError::Io("read the register"))?;
    decode_register(&bytes)
}

fn append_register(volume: &Path, record: &RegisterRecord) -> Result<(), KeydError> {
    let bytes = encode_register_record(record)?;
    let mut f = crate::volume::private(std::fs::OpenOptions::new().append(true).create(true))
        .open(volume.join(REGISTER_FILE))
        .map_err(|_| KeydError::Io("open the register"))?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write the register"))?;
    crate::epoch::sync_dir(volume)
}

fn is_live(table: &KeyTable, key: HeldKey) -> bool {
    match key {
        HeldKey::Root(c, e) => table.get(c, e).is_some_and(KeyTableEntry::is_live),
        HeldKey::Sign(n) => table.sign_key(n).is_some_and(SignKeyEntry::is_live),
    }
}

/// The reduced I-81 reason a register gives against `table`: a copy not
/// retired that holds a key no longer live. A register that does not
/// decode counts as such a copy, since nothing then shows the contrary.
pub(crate) fn register_reason(volume: &Path, table: &KeyTable) -> Option<ReducedReason> {
    let Ok(records) = read_register(volume) else {
        return Some(ReducedReason::ExportHoldsErasedEpoch);
    };
    let retired: Vec<ExportId> = records
        .iter()
        .filter_map(|r| match r {
            RegisterRecord::Retired { id } => Some(*id),
            RegisterRecord::Taken { .. } | RegisterRecord::Guarded { .. } => None,
        })
        .collect();
    // A guarded copy whose guard generation the custodian has since
    // destroyed opens nowhere, so it holds nothing (ADR-004 record of lane
    // `m10/guard-key`). A state that does not read counts as no rotation.
    let current = crate::guard::state::read_state(volume).map_or(0, |s| s.generation);
    let erased = records.iter().any(|r| match r {
        RegisterRecord::Taken { id, keys, .. } => {
            !retired.contains(id) && keys.iter().any(|k| !is_live(table, *k))
        }
        RegisterRecord::Guarded {
            id,
            keys,
            generation,
            ..
        } => {
            *generation >= current
                && !retired.contains(id)
                && keys.iter().any(|k| !is_live(table, *k))
        }
        RegisterRecord::Retired { .. } => false,
    });
    erased.then_some(ReducedReason::ExportHoldsErasedEpoch)
}

/// The reduced I-81 reason the register of `volume` gives, or `None`
/// (rule 4). The server reports it at start.
///
/// # Errors
///
/// As [`crate::open_key_table`].
pub fn export_reason(
    volume: &Path,
    passphrase: &Passphrase,
) -> Result<Option<ReducedReason>, KeydError> {
    let table = crate::open_key_table(volume, passphrase)?;
    Ok(register_reason(volume, &table))
}

/// Records that every copy of `id` is destroyed (rule 4).
///
/// # Errors
///
/// Refuses an id the register holds no copy of, or one already retired,
/// and a volume another holder has locked.
pub fn retire_export(volume: &Path, id: ExportId) -> Result<(), KeydError> {
    let _lock = lock_volume(volume, LOCK_WAIT)?;
    let records = read_register(volume)?;
    let taken = records.iter().any(|r| match r {
        RegisterRecord::Taken { id: t, .. } | RegisterRecord::Guarded { id: t, .. } => *t == id,
        RegisterRecord::Retired { .. } => false,
    });
    let retired = records
        .iter()
        .any(|r| matches!(r, RegisterRecord::Retired { id: t } if *t == id));
    if !taken || retired {
        return Err(bad("the register holds no live copy of this id"));
    }
    append_register(volume, &RegisterRecord::Retired { id })
}

// ---------------------------------------------------------------------------
// The lock.

/// An exclusive lock on a key volume, released on drop.
pub(crate) struct VolumeLock {
    _file: std::fs::File,
}

/// Takes the exclusive lock of `volume`, waiting up to `wait` for another
/// holder.
///
/// # Errors
///
/// [`KeydError::AlreadyRunning`] when another holder keeps it.
pub(crate) fn lock_volume(volume: &Path, wait: Duration) -> Result<VolumeLock, KeydError> {
    let file = crate::volume::private(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
    )
    .open(volume.join(LOCK_FILE))
    .map_err(|_| KeydError::Io("open the volume lock"))?;
    let deadline = std::time::Instant::now().checked_add(wait);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(VolumeLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => return Err(KeydError::Io("lock the volume")),
        }
        if deadline.is_none_or(|d| std::time::Instant::now() >= d) {
            return Err(KeydError::AlreadyRunning);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// Export and import.

/// The files of a copy, by name.
type Files = Vec<(String, Vec<u8>)>;

/// Reads a key volume file by name, or `None` when it is absent.
type ReadFile<'a> = dyn Fn(&str) -> Result<Option<Vec<u8>>, KeydError> + 'a;

fn clone_table(table: &KeyTable) -> KeyTable {
    let copy = |k: &Option<EpochKey>| k.as_ref().map(|k| EpochKey::from_bytes(*k.expose()));
    KeyTable {
        entries: table
            .entries
            .iter()
            .map(|e| KeyTableEntry::new(e.chain, e.epoch, copy(&e.key)))
            .collect(),
        sign_keys: table
            .sign_keys
            .iter()
            .map(|s| SignKeyEntry::new(s.name, copy(&s.key)))
            .collect(),
    }
}

/// The files of the live keys of `table`, each checked to open under its
/// key: `(name, bytes)` from `read(name)`.
fn live_files(table: &KeyTable, read: &ReadFile<'_>) -> Result<Vec<(String, Vec<u8>)>, KeydError> {
    let mut out = Vec::new();
    for e in &table.entries {
        let Some(k) = e.key.as_ref() else { continue };
        let name = crate::epoch::file_name(e.chain, e.epoch);
        let bytes = read(&name)?.ok_or(bad("a live epoch has no epoch file"))?;
        drop(crate::epoch::open(k, e.chain, e.epoch, &bytes)?);
        out.push((name, bytes));
    }
    for s in &table.sign_keys {
        let Some(k) = s.key.as_ref() else { continue };
        let name = crate::sign_key::file_name(s.name);
        let bytes = read(&name)?.ok_or(bad("a live sign key has no file"))?;
        drop(crate::sign_key::open(k, s.name, &bytes)?);
        out.push((name, bytes));
    }
    Ok(out)
}

fn live_keys(table: &KeyTable) -> Vec<HeldKey> {
    let roots = table
        .entries
        .iter()
        .filter(|e| e.is_live())
        .map(|e| HeldKey::Root(e.chain, e.epoch));
    let signs = table
        .sign_keys
        .iter()
        .filter(|s| s.is_live())
        .map(|s| HeldKey::Sign(s.name));
    roots.chain(signs).collect()
}

/// Makes a sealed copy of the key volume `volume` (rule 1), records it in
/// the volume's register (rule 4) and returns its id and bytes. The entry
/// must not be serving: the copy takes the volume's lock.
///
/// # Errors
///
/// [`KeydError::AlreadyRunning`] while the entry serves,
/// [`KeydError::WrongPassphrase`], and a refusal of a damaged table or a
/// live file that does not open.
pub fn export_volume(
    volume: &Path,
    passphrase: &Passphrase,
) -> Result<(ExportId, Vec<u8>), KeydError> {
    let _lock = lock_volume(volume, LOCK_WAIT)?;
    let (header, out, keys) = make_copy(volume, passphrase)?;
    append_register(
        volume,
        &RegisterRecord::Taken {
            id: header.id,
            created: header.created,
            keys,
        },
    )?;
    Ok((header.id, out))
}

/// Makes a guarded copy of `volume` (ADR-004 record of lane
/// `m10/guard-key`): the copy of [`export_volume`], sealed once more to
/// the current guard of the entry `link` names. A rotation still owed is
/// finished first, so the copy is sealed to the newest guard. The copy is
/// recorded in the register with its guard generation.
///
/// # Errors
///
/// As [`export_volume`], and [`KeydError::Guard`] when the custodian does
/// not answer.
pub fn export_guarded(
    volume: &Path,
    passphrase: &Passphrase,
    link: &crate::guard::GuardLink,
) -> Result<(ExportId, Vec<u8>), KeydError> {
    use crate::guard::state::{now, read_state, write_state};
    let _lock = lock_volume(volume, LOCK_WAIT)?;
    let mut st = read_state(volume)?;
    if let Some(event) = st.owed {
        let r = link
            .client
            .rotate(link.entry, event)
            .map_err(KeydError::Guard)?;
        st.generation = r.generation;
        st.rotated = now();
        st.owed = None;
        write_state(volume, &st)?;
    }
    let (generation, public) = link.client.public(link.entry).map_err(KeydError::Guard)?;
    if st.generation != generation {
        st.generation = generation;
        write_state(volume, &st)?;
    }
    let (header, inner, keys) = make_copy(volume, passphrase)?;
    let outer = crate::guard::copy::seal(
        &crate::guard::copy::GuardedHeader {
            entry: link.entry,
            generation,
            id: header.id,
            created: header.created,
        },
        &public,
        &inner,
    )?;
    append_register(
        volume,
        &RegisterRecord::Guarded {
            id: header.id,
            created: header.created,
            generation,
            keys,
        },
    )?;
    Ok((header.id, outer))
}

/// The header, bytes and held keys of a new copy of `volume`. The caller
/// holds the volume's lock. A custodian's volume, which holds a guard, is
/// never copied: a copy of the guard would outlive its destroy.
pub(crate) fn make_copy(
    volume: &Path,
    passphrase: &Passphrase,
) -> Result<(ExportHeader, Vec<u8>, Vec<HeldKey>), KeydError> {
    let raw =
        std::fs::read(volume.join(TABLE_FILE)).map_err(|_| KeydError::Io("read the key table"))?;
    let sealed = crate::table::SealedTable::decode(&raw)?;
    let table = sealed.open(passphrase)?;
    if crate::server::Server::holds_guard(&table) {
        return Err(KeydError::Volume(
            "a custodian's key volume holds a guard and is never copied",
        ));
    }
    let read = |name: &str| match std::fs::read(volume.join(name)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(KeydError::Io("read a key volume file")),
    };
    let mut files = vec![(
        TABLE_FILE.to_owned(),
        crate::table::encode_key_table(passphrase, sealed.iterations(), &clone_table(&table))?,
    )];
    files.extend(live_files(&table, &read)?);
    // Q-L16-2, decided by Daniel on 2026-11-21: the copy carries the
    // usage log, so reconciliation after a restore covers the time before
    // the loss. It holds no key bytes.
    if let Some(log) = read(USAGE_LOG_FILE)? {
        files.push((USAGE_LOG_FILE.to_owned(), log));
    }
    let header = ExportHeader {
        iterations: DEFAULT_ITERATIONS,
        salt: fstp_crypto::random_array().map_err(KeydError::Crypto)?,
        id: ExportId(fstp_crypto::random_array().map_err(KeydError::Crypto)?),
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    };
    let body = Zeroizing::new(encode_export_body(&files)?);
    let hb = header.encode();
    let s = aead::seal(&header.key(passphrase)?, &hb, &body).map_err(KeydError::Crypto)?;
    let mut out = Vec::with_capacity(
        hb.len()
            .saturating_add(aead::NONCE_LEN)
            .saturating_add(s.body.len()),
    );
    out.extend_from_slice(&hb);
    out.extend_from_slice(&s.nonce);
    out.extend_from_slice(&s.body);
    if out.len() > MAX_EXPORT_LEN {
        return Err(bad("a copy is too long"));
    }
    Ok((header, out, live_keys(&table)))
}

/// Opens a copy under `passphrase` and returns its header and files,
/// checked: the files are exactly the key table and the files of its live
/// keys, and each opens under its key.
fn open_copy(copy: &[u8], passphrase: &Passphrase) -> Result<(ExportHeader, Files), KeydError> {
    let (header, sealed) = decode_export(copy)?;
    let (nonce, body) = sealed
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(bad("a copy is cut short"))?;
    let hb = header.encode();
    let plain = aead::open(&header.key(passphrase)?, nonce, &hb, body)
        .map_err(|_| KeydError::WrongPassphrase)?;
    let files = decode_export_body(&plain)?;
    let table_bytes = files.first().map(|(_, b)| b.as_slice()).unwrap_or_default();
    let table = crate::table::SealedTable::decode(table_bytes)?.open(passphrase)?;
    let find = |name: &str| {
        Ok(files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.clone()))
    };
    let expected = live_files(&table, &find)?;
    let usage = usize::from(files.iter().any(|(n, _)| n == USAGE_LOG_FILE));
    if expected.len().saturating_add(1).saturating_add(usage) != files.len() {
        return Err(bad("a copy holds a file its key table does not name"));
    }
    Ok((header, files))
}

/// Imports the copy `copy` onto the fresh key volume `volume` and holds
/// it (rule 2). Nothing is written unless the whole copy checks.
///
/// # Errors
///
/// [`KeydError::Volume`] for a volume that holds a key table or a hold,
/// [`KeydError::WrongPassphrase`] for a copy that does not open, which a
/// changed byte also gives, and [`KeydError::Malformed`] for a copy
/// whose files do not match its table.
pub fn import_volume(
    copy: &[u8],
    volume: &Path,
    passphrase: &Passphrase,
) -> Result<ExportId, KeydError> {
    if !volume.is_dir() {
        return Err(KeydError::Volume("the key volume is not a directory"));
    }
    let used = || volume.join(TABLE_FILE).exists() || volume.join(HOLD_FILE).exists();
    if used() {
        return Err(KeydError::Volume(
            "the key volume already holds a key table",
        ));
    }
    let (header, files) = open_copy(copy, passphrase)?;
    let _lock = lock_volume(volume, LOCK_WAIT)?;
    if used() {
        return Err(KeydError::Volume(
            "the key volume already holds a key table",
        ));
    }
    for (name, bytes) in &files {
        write_new(&volume.join(name), bytes)?;
    }
    crate::epoch::sync_dir(volume)?;
    write_new(&volume.join(HOLD_FILE), &[])?;
    crate::epoch::sync_dir(volume)?;
    Ok(header.id)
}

/// Imports a copy onto the fresh key volume `volume` and holds it, as
/// [`import_volume`]. A guarded copy (ADR-004 record of lane
/// `m10/guard-key`) opens only when the custodian of `link` opens its
/// outer seal, which it does only while the copy's guard generation
/// lives. A plain copy goes to [`import_volume`] as before: the binary
/// admits one in development mode only.
///
/// # Errors
///
/// As [`import_volume`]; [`KeydError::Guard`] when the custodian does not
/// answer or refuses, which a destroyed generation gives; and
/// [`KeydError::Malformed`] for a copy of another entry or a guarded copy
/// with no link.
pub fn import_guarded(
    copy: &[u8],
    volume: &Path,
    passphrase: &Passphrase,
    link: Option<&crate::guard::GuardLink>,
) -> Result<ExportId, KeydError> {
    use crate::guard::copy as guarded;
    if !guarded::is_guarded(copy) {
        return import_volume(copy, volume, passphrase);
    }
    let link = link.ok_or(bad("a guarded copy needs the custodian"))?;
    let (header, ct, sealed) = guarded::decode_guarded(copy)?;
    if header.entry != link.entry {
        return Err(bad("the copy is of another entry"));
    }
    let kek = link
        .client
        .open(header.entry, header.generation, &header.encode(), &ct)
        .map_err(KeydError::Guard)?;
    let inner = guarded::open(&header, &kek, sealed)?;
    if decode_export(&inner)?.0.id != header.id {
        return Err(bad("the outer and inner copy ids differ"));
    }
    import_volume(&inner, volume, passphrase)
}

/// Imports a copy as the binary does in `mode` (ADR-004, Q-F018-3,
/// decided by Daniel on 2026-11-24): a guarded copy through its custodian,
/// and a plain pre-guard copy in development mode only. In production a
/// plain copy is refused, since no guard can be destroyed for it.
///
/// # Errors
///
/// As [`import_guarded`], and [`KeydError::Guard`] with
/// [`crate::guard::GuardFault::Unreachable`] for a plain copy in
/// production. Nothing is written then.
pub fn import_copy(
    copy: &[u8],
    volume: &Path,
    passphrase: &Passphrase,
    link: Option<&crate::guard::GuardLink>,
    mode: fstp_obs::assurance::DeploymentMode,
) -> Result<ExportId, KeydError> {
    use fstp_obs::assurance::DeploymentMode;
    if !crate::guard::copy::is_guarded(copy) && mode == DeploymentMode::Production {
        return Err(KeydError::Guard(crate::guard::GuardFault::Unreachable));
    }
    import_guarded(copy, volume, passphrase, link)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), KeydError> {
    let mut f = crate::volume::private(std::fs::OpenOptions::new().write(true).create_new(true))
        .open(path)
        .map_err(|_| KeydError::Io("create a key volume file"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write a key volume file"))
}

/// Whether `volume` is held after an import.
#[must_use]
pub fn is_held(volume: &Path) -> bool {
    volume.join(HOLD_FILE).exists()
}

/// Ends the hold of an imported volume (rule 3). `current` names the
/// current epoch of each erasable chain (App, Vault) that the volume holds
/// a live epoch of, as the restored keystore names it. Every live epoch
/// of such a chain below its current one is destroyed. The entry must not
/// be serving.
///
/// # Errors
///
/// [`KeydError::Malformed`] when an erasable chain is not named, a chain
/// is named twice or is not erasable, and [`KeydError::StaleCopy`] when a
/// named epoch is not live: the copy is older than the last erasure. The
/// older epochs are destroyed then too, and the hold stays.
pub fn release_import(
    volume: &Path,
    passphrase: &Passphrase,
    current: &[(Chain, Epoch)],
) -> Result<(), KeydError> {
    release_import_guarded(volume, passphrase, current, None)
}

/// As [`release_import`], on a pilot entry with its custodian: each
/// destroy of the release replaces the entry's guard before it counts
/// (ADR-004 record of lane `m10/guard-key`).
///
/// # Errors
///
/// As [`release_import`], and [`KeydError::Guard`] while the custodian
/// does not answer. The hold then stays, and a new release retries.
pub fn release_import_guarded(
    volume: &Path,
    passphrase: &Passphrase,
    current: &[(Chain, Epoch)],
    guard: Option<crate::guard::GuardLink>,
) -> Result<(), KeydError> {
    if !is_held(volume) {
        return Err(KeydError::Volume("the key volume holds no import"));
    }
    for (i, (c, _)) in current.iter().enumerate() {
        if !ERASABLE.contains(c) {
            return Err(bad("release names a chain that erasure never rotates"));
        }
        if current
            .iter()
            .skip(i.saturating_add(1))
            .any(|(o, _)| o == c)
        {
            return Err(bad("release names a chain twice"));
        }
    }
    crate::server::release(volume, passphrase, current, guard)?;
    std::fs::remove_file(volume.join(HOLD_FILE)).map_err(|_| KeydError::Io("remove the hold"))?;
    crate::epoch::sync_dir(volume)
}

/// The chains that erasure rotates (ADR-004 part 2 "Chains").
pub const ERASABLE: [Chain; 2] = [Chain::App, Chain::Vault];

/// Whether a held volume may serve `request`: unwrap and usage requests
/// on the backup chains only (rule 2): CellBackup, ClusterBackup and,
/// since lane L17, VaultBackup, which no erasure rotates either.
#[must_use]
pub fn held_permits(request: &fstp_custody::keyd::Request) -> bool {
    use fstp_custody::keyd::Request;
    match request {
        Request::Unwrap { root, .. } | Request::UsageSince { root, .. } => {
            matches!(
                root.chain,
                Chain::CellBackup | Chain::ClusterBackup | Chain::VaultBackup
            )
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// The command line of the `fstp-keyd` binary.

/// What the `fstp-keyd` binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// No argument: serve.
    Serve,
    /// `export <volume> <file>`.
    Export {
        /// The key volume.
        volume: std::path::PathBuf,
        /// The new copy file.
        file: std::path::PathBuf,
    },
    /// `import <file> <volume>`.
    Import {
        /// The copy file.
        file: std::path::PathBuf,
        /// The fresh key volume.
        volume: std::path::PathBuf,
    },
    /// `release <volume> <chain>=<epoch> ...`.
    Release {
        /// The held key volume.
        volume: std::path::PathBuf,
        /// The current epoch of each erasable chain.
        current: Vec<(Chain, Epoch)>,
    },
    /// `retire-export <volume> <id>`.
    Retire {
        /// The source key volume.
        volume: std::path::PathBuf,
        /// The copy.
        id: ExportId,
    },
    /// `guard-check <volume>`: whether the custodian answers and a
    /// rotation is owed (ADR-028 record of lane `m10/guard-key`).
    GuardCheck {
        /// The pilot key volume.
        volume: std::path::PathBuf,
    },
    /// `fetch-copy <file>`: the custodian's held copy of this entry
    /// (ADR-004 "The custodian's copy").
    FetchCopy {
        /// The new copy file.
        file: std::path::PathBuf,
    },
}

fn chain_epoch(arg: &str) -> Option<(Chain, Epoch)> {
    let (c, e) = arg.split_once('=')?;
    let chain = ERASABLE.into_iter().find(|ch| ch.name() == c)?;
    if !e.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let epoch = e.parse::<u64>().ok().filter(|n| *n > 0)?;
    Some((chain, Epoch(epoch)))
}

/// Parses the binary's arguments, without the program name.
///
/// # Errors
///
/// [`KeydError::Malformed`] (`arguments`) for any other form.
pub fn parse_command(args: &[String]) -> Result<Command, KeydError> {
    let usage = bad("arguments");
    let p = std::path::PathBuf::from;
    match args {
        [] => Ok(Command::Serve),
        [c, v, f] if c == "export" => Ok(Command::Export {
            volume: p(v),
            file: p(f),
        }),
        [c, f, v] if c == "import" => Ok(Command::Import {
            file: p(f),
            volume: p(v),
        }),
        [c, v, rest @ ..] if c == "release" => Ok(Command::Release {
            volume: p(v),
            current: rest
                .iter()
                .map(|a| chain_epoch(a))
                .collect::<Option<Vec<_>>>()
                .ok_or(usage)?,
        }),
        [c, v, id] if c == "retire-export" => Ok(Command::Retire {
            volume: p(v),
            id: ExportId::parse(id).ok_or(usage)?,
        }),
        [c, v] if c == "guard-check" => Ok(Command::GuardCheck { volume: p(v) }),
        [c, f] if c == "fetch-copy" => Ok(Command::FetchCopy { file: p(f) }),
        _ => Err(usage),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;
    use crate::server::Server;
    use fstp_custody::keyd::{Request, RequestId, Response, RootHandle};

    fn pass() -> Passphrase {
        Passphrase::from_bytes(b"lane L16 unit test passphrase").unwrap()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fstp-keyd-l16-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// I-81, ADR-004 record of lane L17: a held volume serves unwrap and
    /// usage on VaultBackup, as on the other backup chains, and never on
    /// an erasable chain or another request.
    #[test]
    fn i81_held_volume_serves_vault_backup_unwrap_only() {
        let unwrap = |chain| Request::Unwrap {
            id: RequestId([2; 16]),
            root: RootHandle {
                chain,
                epoch: Epoch(1),
            },
            aad: Vec::new(),
            wrapped: Vec::new(),
        };
        for chain in [Chain::CellBackup, Chain::ClusterBackup, Chain::VaultBackup] {
            assert!(held_permits(&unwrap(chain)), "{chain:?}");
        }
        for chain in [Chain::App, Chain::Vault, Chain::ControlPlane] {
            assert!(!held_permits(&unwrap(chain)), "{chain:?}");
        }
        let destroy = Request::Destroy {
            id: RequestId([3; 16]),
            root: RootHandle {
                chain: Chain::VaultBackup,
                epoch: Epoch(1),
            },
        };
        assert!(!held_permits(&destroy));
    }

    fn create(s: &mut Server, chain: Chain, epoch: u64) -> RootHandle {
        let r = s.handle(&Request::CreateRoot {
            id: RequestId([1; 16]),
            cell: None,
            chain,
            epoch: Epoch(epoch),
        });
        match r {
            Response::Root(h) => h,
            other => panic!("{other:?}"),
        }
    }

    /// The root bytes and `K(e)` of every live epoch of `volume`.
    fn secrets(volume: &Path) -> Vec<Vec<u8>> {
        let table = crate::open_key_table(volume, &pass()).unwrap();
        let mut out = Vec::new();
        for e in &table.entries {
            if let Some(k) = e.key.as_ref() {
                let bytes = crate::epoch::read(volume, e.chain, e.epoch)
                    .unwrap()
                    .unwrap();
                let root = crate::epoch::open(k, e.chain, e.epoch, &bytes).unwrap();
                out.push(root.bytes().to_vec());
                out.push(k.expose().to_vec());
            }
        }
        out
    }

    fn body_of(copy: &[u8]) -> Vec<u8> {
        let (header, sealed) = decode_export(copy).unwrap();
        let (nonce, body) = sealed.split_first_chunk::<{ aead::NONCE_LEN }>().unwrap();
        aead::open(&header.key(&pass()).unwrap(), nonce, &header.encode(), body)
            .unwrap()
            .to_vec()
    }

    /// I-80, ADR-004 record of lane L16: neither a copy nor its opened body
    /// holds a root or an epoch key `K(e)` in the clear.
    #[test]
    fn i80_offhost_copy_never_holds_a_root_or_epoch_key_in_the_clear() {
        let dir = scratch("clear");
        let mut s = Server::open(&dir, &pass()).unwrap();
        create(&mut s, Chain::ClusterBackup, 1);
        create(&mut s, Chain::App, 1);
        create(&mut s, Chain::Vault, 1);
        drop(s);
        let held = secrets(&dir);
        assert_eq!(held.len(), 6);
        let (_, copy) = export_volume(&dir, &pass()).unwrap();
        let body = body_of(&copy);
        for secret in &held {
            assert!(!contains(&copy, secret), "a secret is in the copy");
            assert!(!contains(&body, secret), "a secret is in the opened body");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// I-81, ADR-004 record of lane L16 rule 1: the opened body of a copy
    /// made after a destroy holds neither the destroyed root nor its
    /// `K(e)`, nor its epoch file.
    #[test]
    fn i81_destroyed_epoch_bytes_never_in_a_later_copy_body() {
        let dir = scratch("later-body");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r1 = create(&mut s, Chain::App, 1);
        create(&mut s, Chain::App, 2);
        drop(s);
        let gone = secrets(&dir);
        let mut s = Server::open(&dir, &pass()).unwrap();
        assert!(matches!(
            s.handle(&Request::Destroy {
                id: RequestId([2; 16]),
                root: r1
            }),
            Response::Destroyed(_)
        ));
        drop(s);
        let (_, copy) = export_volume(&dir, &pass()).unwrap();
        let body = body_of(&copy);
        let files = decode_export_body(&body).unwrap();
        assert!(
            files
                .iter()
                .all(|(n, _)| *n != crate::epoch::file_name(Chain::App, Epoch(1)))
        );
        // `gone` holds epoch 1's root and K(1) first, then epoch 2's.
        for secret in &gone[..2] {
            assert!(!contains(&body, secret));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-004 record of lane L16: the header, body and register decoders
    /// read back what the encoders write, and refuse cut and trailing
    /// input.
    #[test]
    fn adr004_copy_formats_round_trip_in_one_spelling() {
        let h = ExportHeader {
            iterations: MIN_ITERATIONS,
            salt: [3; 16],
            id: ExportId([4; 16]),
            created: 77,
        };
        let mut bytes = h.encode().to_vec();
        bytes.extend_from_slice(&[0u8; 28]);
        assert_eq!(decode_export(&bytes).unwrap().0, h);
        assert!(decode_export(&bytes[..EXPORT_HEADER_LEN + 27]).is_err());
        let files = vec![
            (TABLE_FILE.to_owned(), vec![1, 2]),
            ("epoch-app-1.key".to_owned(), vec![3]),
        ];
        let body = encode_export_body(&files).unwrap();
        assert_eq!(decode_export_body(&body).unwrap(), files);
        let mut long = body.clone();
        long.push(0);
        assert!(decode_export_body(&long).is_err());
        assert!(decode_export_body(&body[..body.len() - 1]).is_err());
        let twice = encode_export_body(&[files[0].clone(), files[0].clone()]).unwrap();
        assert!(decode_export_body(&twice).is_err());
        assert!(encode_export_body(&[("../x".to_owned(), vec![])]).is_err());
        let recs = vec![
            RegisterRecord::Taken {
                id: ExportId([5; 16]),
                created: 9,
                keys: vec![HeldKey::Root(Chain::Vault, Epoch(3))],
            },
            RegisterRecord::Retired {
                id: ExportId([5; 16]),
            },
        ];
        let mut reg = Vec::new();
        for r in &recs {
            reg.extend(encode_register_record(r).unwrap());
        }
        assert_eq!(decode_register(&reg).unwrap(), recs);
        assert!(decode_register(&reg[..reg.len() - 1]).is_err());
    }

    /// ADR-004 record of lane L16: the binary takes five command forms.
    #[test]
    fn adr004_keyd_binary_takes_five_command_forms() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(parse_command(&s(&[])).unwrap(), Command::Serve);
        assert!(matches!(
            parse_command(&s(&["export", "/v", "/f"])).unwrap(),
            Command::Export { .. }
        ));
        assert!(matches!(
            parse_command(&s(&["import", "/f", "/v"])).unwrap(),
            Command::Import { .. }
        ));
        assert_eq!(
            parse_command(&s(&["release", "/v", "app=3", "vault=1"])).unwrap(),
            Command::Release {
                volume: "/v".into(),
                current: vec![(Chain::App, Epoch(3)), (Chain::Vault, Epoch(1))]
            }
        );
        assert!(matches!(
            parse_command(&s(&["retire-export", "/v", &"ab".repeat(16)])).unwrap(),
            Command::Retire { .. }
        ));
        for bad in [
            &["serve"][..],
            &["release", "/v", "clusterbackup=1"],
            &["release", "/v", "app=0"],
            &["release", "/v", "app=+1"],
            &["retire-export", "/v", "zz"],
            &["export", "/v"],
        ] {
            assert!(parse_command(&s(bad)).is_err(), "{bad:?}");
        }
    }
}

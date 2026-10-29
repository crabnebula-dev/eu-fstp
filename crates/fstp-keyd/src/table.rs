//! The key table of file custody (ADR-004 part 2 "File custody").
//!
//! The table holds the per-epoch keys `K(e)`. It is sealed under a key
//! derived from the passphrase with PBKDF2-HMAC-SHA-256 from aws-lc-rs,
//! at least 600 000 iterations, with a random salt in its header. No ADR
//! fixed its bytes before this lane. Lane W2f writes them at first use,
//! and their record in ADR-004 is with the lead. Integers are big-endian.
//!
//! ```text
//! header = "FKT2" | version u8 = 2 | kdf u8 = 1 | iterations u32 | salt 16    26 bytes
//! check  = nonce 12 | AES-256-GCM(table key, aad = header, empty) tag 16       28 bytes
//! file   = header | check | slot*
//! slot   = 70 zero bytes (free)
//!        | chain u8 | epoch u64 | nonce 12 | AES-256-GCM(table key, aad, state u8 | key 32)   70 bytes
//! aad    = "fstp-keyd-slot-v1" | header | slot index u32 | chain u8 | epoch u64
//! ```
//!
//! State 1 is live, with `K(e)` in the key field. State 2 is destroyed,
//! with 32 zero bytes there. The check tells a wrong passphrase apart
//! from a damaged slot.
//!
//! # Why one seal per slot
//!
//! Each create writes one slot, and each destroy overwrites one slot, in
//! place, at the same offset and length, and fsyncs. The new ciphertext
//! overwrites every byte of the old one, so `K(e)` leaves the volume
//! (I-81). A crash or a full volume part way through a write damages
//! that one slot at most. A torn create loses only the root it was
//! creating, which no caller holds yet. A torn destroy loses only the
//! root it was destroying. Every other root still opens: "A crash at any
//! step loses nothing" (ADR-004 part 2). The next start overwrites a
//! damaged slot with zeros.
//!
//! Two more states can follow a failed write, and the running server
//! repairs both rather than refusing the table. A short append leaves a
//! partial slot after the last whole one: the next start overwrites it
//! with a zero slot. A create whose write landed but whose fsync failed
//! leaves its slot blocked: a retried create of the same epoch
//! overwrites that slot in place, so one epoch never gets two slots. If
//! two slots of one epoch reach the disk all the same, the next start
//! keeps a destroyed one if any, or else the one whose `K(e)` opens the
//! epoch file, and scrubs the other. The offline decoder
//! [`crate::decode_custody_file`] stays strict and refuses both states.
//!
//! # Reclaimed slots
//!
//! Once a destroy is read back, the older destroyed entries of the same
//! chain are zeroed and their slots reused. The newest destroyed entry of
//! each chain stays, with every live one, so the chain's newest epoch is
//! kept: a create of an older epoch is still refused, and a retried
//! destroy of the newest one finds it. The table thus holds a few slots
//! per chain, however many rotations ran.

use std::path::{Path, PathBuf};

use fstp_crypto::aead;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use fstp_custody::{Chain, Epoch};

use crate::{KeydError, Passphrase};

/// The magic of the key table.
pub const TABLE_MAGIC: [u8; 4] = *b"FKT2";
/// The format version.
pub const TABLE_VERSION: u8 = 2;
/// The KDF code of PBKDF2-HMAC-SHA-256.
pub const KDF_PBKDF2_SHA256: u8 = 1;
/// The least PBKDF2 iteration count ADR-004 part 2 allows.
pub const MIN_ITERATIONS: u32 = 600_000;
/// The most PBKDF2 iterations the decoder accepts, so a crafted table
/// cannot stall a start.
pub const MAX_ITERATIONS: u32 = 10_000_000;
/// The iteration count of a new key table.
pub const DEFAULT_ITERATIONS: u32 = MIN_ITERATIONS;
/// Length of the salt.
pub const SALT_LEN: usize = 16;
/// Length of the header.
pub const HEADER_LEN: usize = 26;
/// Length of the passphrase check: a nonce and the tag of an empty seal.
pub const CHECK_LEN: usize = aead::NONCE_LEN + aead::TAG_LEN;
/// Length of the header and the check, before the first slot.
pub const PREFIX_LEN: usize = HEADER_LEN + CHECK_LEN;
/// Length of one slot.
pub const SLOT_LEN: usize = SLOT_HEAD_LEN + aead::NONCE_LEN + SEALED_LEN + aead::TAG_LEN;
/// Length of one entry of the plaintext body that
/// [`decode_key_table_body`] reads: `chain u8 | epoch u64 | state u8 |
/// key 32`.
pub const ENTRY_LEN: usize = 42;
/// The most slots a key table holds.
pub const MAX_ENTRIES: usize = 65_536;
/// The name of the key table file on the key volume.
pub const TABLE_FILE: &str = "keytable";

const STATE_LIVE: u8 = 1;
const STATE_DESTROYED: u8 = 2;
const COUNT_LEN: usize = 4;
/// The clear chain and epoch at the start of a slot.
const SLOT_HEAD_LEN: usize = 9;
/// The plaintext of a slot: state and key.
const SEALED_LEN: usize = 33;
/// The label at the start of every slot AAD.
const SLOT_LABEL: &[u8; 17] = b"fstp-keyd-slot-v1";
/// Length of a slot AAD.
const SLOT_AAD_LEN: usize = 17 + HEADER_LEN + 4 + SLOT_HEAD_LEN;

/// One per-epoch key `K(e)`. No `Clone`, no `Debug`, wiped on drop. Its
/// bytes never leave this crate: `K(e)` opens the epoch file, so it and
/// the epoch file together are the root (I-80, layering rule 7).
pub struct EpochKey(Zeroizing<[u8; 32]>);

impl ZeroizeOnDrop for EpochKey {}

impl EpochKey {
    /// A key from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> EpochKey {
        EpochKey(Zeroizing::new(bytes))
    }

    /// A fresh key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`KeydError::Crypto`] when the generator fails.
    pub fn generate() -> Result<EpochKey, KeydError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fstp_crypto::random_bytes(&mut bytes[..]).map_err(KeydError::Crypto)?;
        Ok(EpochKey(bytes))
    }

    /// Whether `self` and `other` are the same key, in constant time. It
    /// tells a caller only what it already holds.
    #[must_use]
    pub fn same_as(&self, other: &EpochKey) -> bool {
        fstp_crypto::constant_time_eq(&self.0[..], &other.0[..])
    }

    /// The key bytes, inside this crate only.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One entry of the key table.
pub struct KeyTableEntry {
    /// The chain of the epoch.
    pub chain: Chain,
    /// The epoch.
    pub epoch: Epoch,
    /// `K(e)`, or `None` once destroy has overwritten it.
    pub(crate) key: Option<EpochKey>,
}

impl KeyTableEntry {
    /// An entry of `chain` and `epoch`, live with `key` or destroyed.
    #[must_use]
    pub fn new(chain: Chain, epoch: Epoch, key: Option<EpochKey>) -> KeyTableEntry {
        KeyTableEntry { chain, epoch, key }
    }

    /// Whether the entry still holds `K(e)`.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.key.is_some()
    }

    /// Whether the entry holds exactly `key`, in constant time.
    #[must_use]
    pub fn holds(&self, key: &EpochKey) -> bool {
        self.key.as_ref().is_some_and(|k| k.same_as(key))
    }
}

/// The opened key table. No `Clone` and no `Debug`.
#[derive(Default)]
pub struct KeyTable {
    /// The entries, in slot order.
    pub entries: Vec<KeyTableEntry>,
}

impl KeyTable {
    /// The entry of `chain` and `epoch`, if any.
    #[must_use]
    pub fn get(&self, chain: Chain, epoch: Epoch) -> Option<&KeyTableEntry> {
        self.entries
            .iter()
            .find(|e| e.chain == chain && e.epoch == epoch)
    }

    /// The newest epoch of `chain`, if any.
    pub(crate) fn newest(&self, chain: Chain) -> Option<Epoch> {
        self.entries
            .iter()
            .filter(|e| e.chain == chain)
            .map(|e| e.epoch)
            .max()
    }
}

/// Decodes the plaintext body of a key table, as the opened slots give
/// it: `count u32 | count times entry`. Fuzzed (`custody_file_decode`).
///
/// # Errors
///
/// Refuses a count that does not match the length, an unknown chain or
/// state, a destroyed entry with key bytes, epoch 0, and two entries of
/// one chain and epoch.
pub fn decode_key_table_body(bytes: &[u8]) -> Result<KeyTable, KeydError> {
    let (count, rest) = bytes
        .split_first_chunk::<COUNT_LEN>()
        .ok_or(KeydError::Malformed("the key table body is too short"))?;
    let count = usize::try_from(u32::from_be_bytes(*count))
        .map_err(|_| KeydError::Malformed("the key table has too many entries"))?;
    if count > MAX_ENTRIES {
        return Err(KeydError::Malformed("the key table has too many entries"));
    }
    if Some(rest.len()) != count.checked_mul(ENTRY_LEN) {
        return Err(KeydError::Malformed(
            "the key table body length does not match its count",
        ));
    }
    let mut table = KeyTable {
        entries: Vec::with_capacity(count),
    };
    for raw in rest.chunks_exact(ENTRY_LEN) {
        push_unique(&mut table, decode_entry(raw)?)?;
    }
    Ok(table)
}

/// Adds `entry` to `table`, refusing a second entry of one chain and
/// epoch.
fn push_unique(table: &mut KeyTable, entry: KeyTableEntry) -> Result<(), KeydError> {
    if table.get(entry.chain, entry.epoch).is_some() {
        return Err(KeydError::Malformed("two key table entries name one epoch"));
    }
    table.entries.push(entry);
    Ok(())
}

/// Decodes one plaintext entry: `chain u8 | epoch u64 | state u8 | key
/// 32`.
fn decode_entry(raw: &[u8]) -> Result<KeyTableEntry, KeydError> {
    let (head, key) = raw
        .split_first_chunk::<10>()
        .ok_or(KeydError::Malformed("a key table entry is too short"))?;
    let [chain, e0, e1, e2, e3, e4, e5, e6, e7, state] = *head;
    let chain = Chain::from_code(chain).ok_or(KeydError::Malformed(
        "a key table entry names an unknown chain",
    ))?;
    let epoch = Epoch(u64::from_be_bytes([e0, e1, e2, e3, e4, e5, e6, e7]));
    if epoch.0 == 0 {
        return Err(KeydError::Malformed("a key table entry names epoch 0"));
    }
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| KeydError::Malformed("a key table entry is too short"))?;
    let key = Zeroizing::new(key);
    let key = match state {
        STATE_LIVE => Some(EpochKey::from_bytes(*key)),
        STATE_DESTROYED if key.iter().all(|b| *b == 0) => None,
        STATE_DESTROYED => {
            return Err(KeydError::Malformed(
                "a destroyed key table entry still holds key bytes",
            ));
        }
        _ => {
            return Err(KeydError::Malformed(
                "a key table entry has an unknown state",
            ));
        }
    };
    Ok(KeyTableEntry { chain, epoch, key })
}

/// The header of a sealed table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableHeader {
    iterations: u32,
    salt: [u8; SALT_LEN],
}

impl TableHeader {
    fn fresh(iterations: u32) -> Result<TableHeader, KeydError> {
        check_iterations(iterations)?;
        Ok(TableHeader {
            iterations,
            salt: fstp_crypto::random_array().map_err(KeydError::Crypto)?,
        })
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (magic, rest) = out.split_at_mut(4);
        magic.copy_from_slice(&TABLE_MAGIC);
        let (codes, rest) = rest.split_at_mut(2);
        codes.copy_from_slice(&[TABLE_VERSION, KDF_PBKDF2_SHA256]);
        let (iterations, salt) = rest.split_at_mut(4);
        iterations.copy_from_slice(&self.iterations.to_be_bytes());
        salt.copy_from_slice(&self.salt);
        out
    }

    /// The table key under `passphrase`.
    fn derive(&self, passphrase: &Passphrase) -> Result<aead::Key, KeydError> {
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

fn check_iterations(iterations: u32) -> Result<(), KeydError> {
    if (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        Ok(())
    } else {
        Err(KeydError::WeakKdf)
    }
}

/// The AAD of slot `index` that names `chain` and `epoch` in clear.
fn slot_aad(header: &[u8; HEADER_LEN], index: u32, chain: u8, epoch: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SLOT_AAD_LEN);
    out.extend_from_slice(SLOT_LABEL);
    out.extend_from_slice(header);
    out.extend_from_slice(&index.to_be_bytes());
    out.push(chain);
    out.extend_from_slice(&epoch);
    out
}

/// The sealed bytes of slot `index` for `chain` and `epoch`, live with
/// `key` or destroyed.
fn seal_slot(
    table_key: &aead::Key,
    header: &[u8; HEADER_LEN],
    index: usize,
    chain: Chain,
    epoch: Epoch,
    key: Option<&EpochKey>,
) -> Result<[u8; SLOT_LEN], KeydError> {
    let index = u32::try_from(index).map_err(|_| KeydError::Malformed("the key table is full"))?;
    let epoch_bytes = epoch.0.to_be_bytes();
    let mut plain = Zeroizing::new([0u8; SEALED_LEN]);
    let (state, bytes) = plain.split_at_mut(1);
    match key {
        Some(k) => {
            state.copy_from_slice(&[STATE_LIVE]);
            bytes.copy_from_slice(k.expose());
        }
        None => state.copy_from_slice(&[STATE_DESTROYED]),
    }
    let aad = slot_aad(header, index, chain.code(), epoch_bytes);
    let sealed = aead::seal(table_key, &aad, &plain[..]).map_err(KeydError::Crypto)?;
    let mut out = [0u8; SLOT_LEN];
    let (head, rest) = out.split_at_mut(SLOT_HEAD_LEN);
    let (c, e) = head.split_at_mut(1);
    c.copy_from_slice(&[chain.code()]);
    e.copy_from_slice(&epoch_bytes);
    let (nonce, body) = rest.split_at_mut(aead::NONCE_LEN);
    nonce.copy_from_slice(&sealed.nonce);
    if sealed.body.len() != body.len() {
        return Err(KeydError::Malformed("a sealed slot has the wrong length"));
    }
    body.copy_from_slice(&sealed.body);
    Ok(out)
}

/// The passphrase check of `header` under `table_key`.
fn seal_check(
    table_key: &aead::Key,
    header: &[u8; HEADER_LEN],
) -> Result<[u8; CHECK_LEN], KeydError> {
    let sealed = aead::seal(table_key, header, &[]).map_err(KeydError::Crypto)?;
    let mut out = [0u8; CHECK_LEN];
    let (nonce, tag) = out.split_at_mut(aead::NONCE_LEN);
    nonce.copy_from_slice(&sealed.nonce);
    if sealed.body.len() != tag.len() {
        return Err(KeydError::Malformed("a sealed check has the wrong length"));
    }
    tag.copy_from_slice(&sealed.body);
    Ok(out)
}

/// A key table as opened: each opened slot with its entry, in slot
/// order, and the slots that did not open. Two slots may name one
/// epoch here: [`TableStore::open_or_create`] resolves them.
pub(crate) struct Opened {
    pub(crate) entries: Vec<(usize, KeyTableEntry)>,
    pub(crate) damaged: Vec<usize>,
    pub(crate) slots: usize,
}

impl Opened {
    /// The entries as one table, refusing two entries of one epoch.
    fn into_strict_table(self) -> Result<KeyTable, KeydError> {
        let mut table = KeyTable {
            entries: Vec::with_capacity(self.entries.len()),
        };
        for (_, entry) in self.entries {
            push_unique(&mut table, entry)?;
        }
        Ok(table)
    }
}

/// A key table as stored: its header, check and whole slots, and
/// whether a partial slot followed them.
pub(crate) struct SealedTable {
    header: TableHeader,
    check: [u8; CHECK_LEN],
    slots: Vec<[u8; SLOT_LEN]>,
    partial_tail: bool,
}

impl SealedTable {
    /// Decodes the stored form without opening it. A length that holds
    /// no whole number of slots is refused.
    pub(crate) fn decode(bytes: &[u8]) -> Result<SealedTable, KeydError> {
        let sealed = SealedTable::decode_lenient(bytes)?;
        if sealed.partial_tail {
            return Err(KeydError::Malformed(
                "the key table length holds no whole number of slots",
            ));
        }
        Ok(sealed)
    }

    /// Decodes the stored form as [`SealedTable::decode`] does, but
    /// keeps a partial slot after the whole ones apart instead of
    /// refusing the table. A create whose append stopped part way, as a
    /// full key volume leaves it, leaves such a slot. Only the running
    /// server reads the table this way, and it scrubs that slot.
    pub(crate) fn decode_lenient(bytes: &[u8]) -> Result<SealedTable, KeydError> {
        let (header, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        let (magic, h) = header
            .split_first_chunk::<4>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        if *magic != TABLE_MAGIC {
            return Err(KeydError::Malformed("the key table has the wrong magic"));
        }
        let (codes, h) = h
            .split_first_chunk::<2>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        if *codes != [TABLE_VERSION, KDF_PBKDF2_SHA256] {
            return Err(KeydError::Malformed(
                "the key table has an unknown version or KDF",
            ));
        }
        let (iterations, salt) = h
            .split_first_chunk::<4>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        let iterations = u32::from_be_bytes(*iterations);
        check_iterations(iterations)?;
        let salt: [u8; SALT_LEN] = salt
            .try_into()
            .map_err(|_| KeydError::Malformed("the key table is too short"))?;
        let (check, rest) = rest
            .split_first_chunk::<CHECK_LEN>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        let whole = rest.len() / SLOT_LEN;
        if whole > MAX_ENTRIES {
            return Err(KeydError::Malformed("the key table has too many slots"));
        }
        let chunks = rest.chunks_exact(SLOT_LEN);
        let partial_tail = !chunks.remainder().is_empty();
        let mut slots = Vec::with_capacity(whole);
        for raw in chunks {
            let slot: [u8; SLOT_LEN] = raw
                .try_into()
                .map_err(|_| KeydError::Malformed("a key table slot is too short"))?;
            slots.push(slot);
        }
        Ok(SealedTable {
            header: TableHeader { iterations, salt },
            check: *check,
            slots,
            partial_tail,
        })
    }

    /// The number of slots that are not free.
    pub(crate) fn entry_count(&self) -> usize {
        self.slots.iter().filter(|s| !is_free(s)).count()
    }

    pub(crate) fn iterations(&self) -> u32 {
        self.header.iterations
    }

    pub(crate) fn open(&self, passphrase: &Passphrase) -> Result<KeyTable, KeydError> {
        let key = self.header.derive(passphrase)?;
        self.open_with(&key)?.into_strict_table()
    }

    /// Opens every slot under the table key. A wrong key fails the check.
    /// A slot that does not open is reported as damaged, and every other
    /// slot still opens.
    pub(crate) fn open_with(&self, key: &aead::Key) -> Result<Opened, KeydError> {
        let hb = self.header.encode();
        let (nonce, tag) = self
            .check
            .split_first_chunk::<{ aead::NONCE_LEN }>()
            .ok_or(KeydError::Malformed("the key table is too short"))?;
        let empty = aead::open(key, nonce, &hb, tag).map_err(|_| KeydError::WrongPassphrase)?;
        if !empty.is_empty() {
            return Err(KeydError::Malformed("the key table check is not empty"));
        }
        let mut entries = Vec::new();
        let mut damaged = Vec::new();
        for (ix, slot) in self.slots.iter().enumerate() {
            if is_free(slot) {
                continue;
            }
            let (head, rest) = slot
                .split_first_chunk::<SLOT_HEAD_LEN>()
                .ok_or(KeydError::Malformed("a key table slot is too short"))?;
            let (chain, epoch) = head
                .split_first_chunk::<1>()
                .ok_or(KeydError::Malformed("a key table slot is too short"))?;
            let epoch: [u8; 8] = epoch
                .try_into()
                .map_err(|_| KeydError::Malformed("a key table slot is too short"))?;
            let (nonce, sealed) = rest
                .split_first_chunk::<{ aead::NONCE_LEN }>()
                .ok_or(KeydError::Malformed("a key table slot is too short"))?;
            let index = u32::try_from(ix)
                .map_err(|_| KeydError::Malformed("the key table has too many slots"))?;
            let [chain_code] = *chain;
            let aad = slot_aad(&hb, index, chain_code, epoch);
            let Ok(plain) = aead::open(key, nonce, &aad, sealed) else {
                damaged.push(ix);
                continue;
            };
            if plain.len() != SEALED_LEN {
                return Err(KeydError::Malformed(
                    "a key table slot has the wrong length",
                ));
            }
            let mut raw = Zeroizing::new([0u8; ENTRY_LEN]);
            let (c, rest) = raw.split_at_mut(1);
            c.copy_from_slice(chain);
            let (e, sealed) = rest.split_at_mut(8);
            e.copy_from_slice(&epoch);
            sealed.copy_from_slice(&plain);
            entries.push((ix, decode_entry(&raw[..])?));
        }
        Ok(Opened {
            entries,
            damaged,
            slots: self.slots.len(),
        })
    }
}

/// Whether a slot is free: all zero bytes.
fn is_free(slot: &[u8; SLOT_LEN]) -> bool {
    slot.iter().all(|b| *b == 0)
}

/// Seals `table` under a key derived from `passphrase` with `iterations`
/// PBKDF2 rounds and a fresh random salt, one slot per entry.
///
/// # Errors
///
/// Refuses fewer than [`MIN_ITERATIONS`] or more than
/// [`MAX_ITERATIONS`], and a table above [`MAX_ENTRIES`].
pub fn encode_key_table(
    passphrase: &Passphrase,
    iterations: u32,
    table: &KeyTable,
) -> Result<Vec<u8>, KeydError> {
    if table.entries.len() > MAX_ENTRIES {
        return Err(KeydError::Malformed("the key table has too many entries"));
    }
    let header = TableHeader::fresh(iterations)?;
    let key = header.derive(passphrase)?;
    let hb = header.encode();
    let mut out =
        Vec::with_capacity(PREFIX_LEN.saturating_add(SLOT_LEN.saturating_mul(table.entries.len())));
    out.extend_from_slice(&hb);
    out.extend_from_slice(&seal_check(&key, &hb)?);
    for (ix, e) in table.entries.iter().enumerate() {
        out.extend_from_slice(&seal_slot(&key, &hb, ix, e.chain, e.epoch, e.key.as_ref())?);
    }
    Ok(out)
}

/// Opens the key table on the key volume `volume` under `passphrase`,
/// for an offline check of what it holds. A slot that does not open is
/// left out. The result tells which epochs are live, and gives no key
/// bytes out of this crate.
///
/// # Errors
///
/// Refuses a missing or unreadable table, and as [`crate::CustodyFile::open`].
pub fn open_key_table(volume: &Path, passphrase: &Passphrase) -> Result<KeyTable, KeydError> {
    let bytes =
        std::fs::read(volume.join(TABLE_FILE)).map_err(|_| KeydError::Io("read the key table"))?;
    SealedTable::decode(&bytes)?.open(passphrase)
}

/// What one slot of the table file holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotUse {
    /// Zero bytes, free for the next create.
    Free,
    /// The entry of a chain and epoch.
    Entry(Chain, Epoch),
    /// A write to it failed, so its bytes are unknown until it is
    /// overwritten. It names the chain and epoch whose live entry it may
    /// hold, if any. A retried create of that epoch overwrites it in
    /// place, and a destroy of that epoch scrubs it.
    Blocked(Option<(Chain, Epoch)>),
}

impl SlotUse {
    /// Whether the slot holds, or may hold, the entry of `chain` and
    /// `epoch`.
    fn names(self, chain: Chain, epoch: Epoch) -> bool {
        match self {
            SlotUse::Entry(c, e) | SlotUse::Blocked(Some((c, e))) => c == chain && e == epoch,
            SlotUse::Free | SlotUse::Blocked(None) => false,
        }
    }
}

/// The key table of a running server: the opened entries, the header,
/// the table key, which the server derives once at start, and what each
/// slot of the file holds.
pub(crate) struct TableStore {
    path: PathBuf,
    header: TableHeader,
    key: aead::Key,
    pub(crate) table: KeyTable,
    slots: Vec<SlotUse>,
}

impl TableStore {
    /// Opens the table of `volume`, or creates an empty one.
    ///
    /// The open repairs what a crash or a full volume can leave. A
    /// damaged slot, and a partial slot after the last whole one, are
    /// overwritten with zeros, so a torn write leaves no partial key
    /// bytes behind. Two slots of one epoch, which a create that was
    /// retried after a failed fsync can leave, are resolved: the slot
    /// that is kept is a destroyed one if any, or else the live one
    /// whose `K(e)` opens the epoch file. The other is scrubbed.
    pub(crate) fn open_or_create(
        volume: &Path,
        passphrase: &Passphrase,
    ) -> Result<TableStore, KeydError> {
        let path = volume.join(TABLE_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let sealed = SealedTable::decode_lenient(&bytes)?;
                let key = sealed.header.derive(passphrase)?;
                let opened = sealed.open_with(&key)?;
                let mut store = TableStore {
                    path,
                    header: sealed.header,
                    key,
                    table: KeyTable::default(),
                    slots: vec![SlotUse::Free; opened.slots],
                };
                let mut scrub: Vec<(usize, Option<(Chain, Epoch)>)> =
                    opened.damaged.iter().map(|ix| (*ix, None)).collect();
                for (ix, entry) in keep_one_per_epoch(volume, opened.entries, &mut scrub) {
                    if let Some(s) = store.slots.get_mut(ix) {
                        *s = SlotUse::Entry(entry.chain, entry.epoch);
                    }
                    store.table.entries.push(entry);
                }
                if sealed.partial_tail {
                    scrub.push((store.slots.len(), None));
                    store.slots.push(SlotUse::Blocked(None));
                }
                for (ix, held) in scrub {
                    if let Some(s) = store.slots.get_mut(ix) {
                        *s = SlotUse::Blocked(held);
                    }
                    store.scrub(ix);
                }
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let header = TableHeader::fresh(DEFAULT_ITERATIONS)?;
                let key = header.derive(passphrase)?;
                let hb = header.encode();
                let mut prefix = Vec::with_capacity(PREFIX_LEN);
                prefix.extend_from_slice(&hb);
                prefix.extend_from_slice(&seal_check(&key, &hb)?);
                write_new(&path, &prefix)?;
                crate::epoch::sync_dir(volume)?;
                Ok(TableStore {
                    path,
                    header,
                    key,
                    table: KeyTable::default(),
                    slots: Vec::new(),
                })
            }
            Err(_) => Err(KeydError::Io("read the key table")),
        }
    }

    fn slot_index(&self, chain: Chain, epoch: Epoch) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| *s == SlotUse::Entry(chain, epoch))
    }

    /// Overwrites slot `ix` with zeros and frees it. A failed write
    /// blocks the slot, with what it held, until it is overwritten.
    fn scrub(&mut self, ix: usize) -> bool {
        let ok = write_slot(&self.path, ix, &[0u8; SLOT_LEN]).is_ok();
        if let Some(s) = self.slots.get_mut(ix) {
            *s = match *s {
                _ if ok => SlotUse::Free,
                SlotUse::Entry(c, e) => SlotUse::Blocked(Some((c, e))),
                SlotUse::Free => SlotUse::Blocked(None),
                other => other,
            };
        }
        ok
    }

    /// Adds the live entry of `chain` and `epoch` with `key`, and fsyncs.
    /// A slot that already names the epoch, as a create whose fsync
    /// failed leaves it, is overwritten in place. Otherwise the entry
    /// takes a free slot, or a new slot at the end. So a retried create
    /// never leaves two slots of one epoch.
    pub(crate) fn insert(
        &mut self,
        chain: Chain,
        epoch: Epoch,
        key: EpochKey,
    ) -> Result<(), KeydError> {
        let ix = self
            .slots
            .iter()
            .position(|s| s.names(chain, epoch))
            .or_else(|| self.slots.iter().position(|s| *s == SlotUse::Free))
            .unwrap_or(self.slots.len());
        if ix >= MAX_ENTRIES {
            return Err(KeydError::Malformed("the key table is full"));
        }
        let bytes = seal_slot(
            &self.key,
            &self.header.encode(),
            ix,
            chain,
            epoch,
            Some(&key),
        )?;
        let written = write_slot(&self.path, ix, &bytes);
        let state = if written.is_ok() {
            SlotUse::Entry(chain, epoch)
        } else {
            SlotUse::Blocked(Some((chain, epoch)))
        };
        match self.slots.get_mut(ix) {
            Some(s) => *s = state,
            None => self.slots.push(state),
        }
        written?;
        self.table
            .entries
            .retain(|e| !(e.chain == chain && e.epoch == epoch));
        self.table
            .entries
            .push(KeyTableEntry::new(chain, epoch, Some(key)));
        Ok(())
    }

    /// Overwrites the slot of `chain` and `epoch` in place with a
    /// destroyed entry, at the same offset and length, and fsyncs. Only
    /// then is `K(e)` dropped from memory, so a failed write can be
    /// retried.
    pub(crate) fn mark_destroyed(&mut self, chain: Chain, epoch: Epoch) -> Result<(), KeydError> {
        let ix = self
            .slot_index(chain, epoch)
            .ok_or(KeydError::Io("the key table has no slot for the epoch"))?;
        let bytes = seal_slot(&self.key, &self.header.encode(), ix, chain, epoch, None)?;
        write_slot(&self.path, ix, &bytes)?;
        if let Some(e) = self
            .table
            .entries
            .iter_mut()
            .find(|e| e.chain == chain && e.epoch == epoch)
        {
            e.key = None;
        }
        Ok(())
    }

    /// Scrubs every blocked slot that may hold a live entry of `chain`
    /// and `epoch`, so a destroy leaves no copy of `K(e)` behind.
    ///
    /// # Errors
    ///
    /// Fails when any such slot cannot be overwritten. A retried
    /// destroy tries again.
    pub(crate) fn scrub_blocked(&mut self, chain: Chain, epoch: Epoch) -> Result<(), KeydError> {
        let blocked: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == SlotUse::Blocked(Some((chain, epoch))))
            .map(|(ix, _)| ix)
            .collect();
        let mut all = true;
        for ix in blocked {
            all &= self.scrub(ix);
        }
        if all {
            Ok(())
        } else {
            Err(KeydError::Io("scrub a blocked key table slot"))
        }
    }

    /// Zeroes and frees every destroyed entry of `chain` but the newest.
    /// A slot whose write fails stays as it is, a destroyed entry, and is
    /// tried again after the next destroy.
    pub(crate) fn reclaim(&mut self, chain: Chain) {
        let newest = self
            .table
            .entries
            .iter()
            .filter(|e| e.chain == chain && e.key.is_none())
            .map(|e| e.epoch)
            .max();
        let older: Vec<Epoch> = self
            .table
            .entries
            .iter()
            .filter(|e| e.chain == chain && e.key.is_none() && Some(e.epoch) != newest)
            .map(|e| e.epoch)
            .collect();
        for epoch in older {
            let Some(ix) = self.slot_index(chain, epoch) else {
                continue;
            };
            if write_slot(&self.path, ix, &[0u8; SLOT_LEN]).is_ok() {
                if let Some(s) = self.slots.get_mut(ix) {
                    *s = SlotUse::Free;
                }
                self.table
                    .entries
                    .retain(|e| !(e.chain == chain && e.epoch == epoch));
            }
        }
    }

    /// Reads the table back from disk under the table key, and tells
    /// whether no slot holds a live `K(e)` of `chain` and `epoch`. The
    /// slot of the entry must open, as a destroyed entry. A partial slot
    /// at the end, which a failed append leaves, does not fail the read.
    pub(crate) fn read_back_gone(&self, chain: Chain, epoch: Epoch) -> Result<bool, KeydError> {
        let bytes =
            std::fs::read(&self.path).map_err(|_| KeydError::Io("read the key table back"))?;
        let sealed = SealedTable::decode_lenient(&bytes)?;
        if sealed.header != self.header {
            return Err(KeydError::Io("the key table header changed"));
        }
        let opened = sealed.open_with(&self.key)?;
        let torn = self
            .slot_index(chain, epoch)
            .is_some_and(|ix| opened.damaged.contains(&ix));
        let live = opened
            .entries
            .iter()
            .any(|(_, e)| e.chain == chain && e.epoch == epoch && e.is_live());
        Ok(!torn && !live)
    }
}

/// Keeps one entry per chain and epoch of `entries`, and adds the slot
/// of every other one to `scrub`. A destroyed entry is kept if there is
/// one, so a destroy is never undone. Otherwise the live entry whose
/// `K(e)` opens the epoch file on `volume` is kept, or else the first.
fn keep_one_per_epoch(
    volume: &Path,
    entries: Vec<(usize, KeyTableEntry)>,
    scrub: &mut Vec<(usize, Option<(Chain, Epoch)>)>,
) -> Vec<(usize, KeyTableEntry)> {
    let mut groups: std::collections::BTreeMap<(Chain, Epoch), Vec<(usize, KeyTableEntry)>> =
        std::collections::BTreeMap::new();
    for (ix, entry) in entries {
        groups
            .entry((entry.chain, entry.epoch))
            .or_default()
            .push((ix, entry));
    }
    let mut kept = Vec::with_capacity(groups.len());
    for ((chain, epoch), mut group) in groups {
        let pick = if group.len() == 1 {
            0
        } else {
            let file = crate::epoch::read(volume, chain, epoch).ok().flatten();
            let opens = |e: &KeyTableEntry| {
                e.key.as_ref().is_some_and(|k| {
                    file.as_ref()
                        .is_some_and(|f| crate::epoch::open(k, chain, epoch, f).is_ok())
                })
            };
            group
                .iter()
                .position(|(_, e)| !e.is_live())
                .or_else(|| group.iter().position(|(_, e)| opens(e)))
                .unwrap_or(0)
        };
        let mut rest = Vec::with_capacity(group.len().saturating_sub(1));
        let mut chosen = None;
        for (n, item) in group.drain(..).enumerate() {
            if n == pick {
                chosen = Some(item);
            } else {
                rest.push((item.0, Some((chain, epoch))));
            }
        }
        scrub.extend(rest);
        if let Some(item) = chosen {
            kept.push(item);
        }
    }
    kept.sort_by_key(|(ix, _)| *ix);
    kept
}

/// Creates the table file with `bytes` and fsyncs it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), KeydError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| KeydError::Io("create the key table"))?;
    file.write_all(bytes)
        .map_err(|_| KeydError::Io("write the key table"))?;
    file.sync_all()
        .map_err(|_| KeydError::Io("fsync the key table"))
}

/// Overwrites slot `ix` of the table file at `path` in place with
/// `bytes`, without replacing the file, and fsyncs. The inode stays the
/// same. A slot one past the end extends the file.
fn write_slot(path: &Path, ix: usize, bytes: &[u8; SLOT_LEN]) -> Result<(), KeydError> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let offset = ix
        .checked_mul(SLOT_LEN)
        .and_then(|n| n.checked_add(PREFIX_LEN))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(KeydError::Malformed("the key table is full"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| KeydError::Io("open the key table"))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| KeydError::Io("seek in the key table"))?;
    file.write_all(bytes)
        .map_err(|_| KeydError::Io("write the key table"))?;
    file.sync_all()
        .map_err(|_| KeydError::Io("fsync the key table"))
}

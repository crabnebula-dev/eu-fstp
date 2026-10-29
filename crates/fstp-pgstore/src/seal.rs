//! The ledger key and the sealed forms it makes (ADR-007 "Sealed
//! bodies", "Random nonces" and "Projections in memory with sealed
//! checkpoints", ADR-004 part 1).
//!
//! Every seal goes through `fstp_crypto::aead::seal`, which draws a fresh
//! random nonce. No function here takes a nonce, and none derives one from
//! a sequence number, row id or counter. A sealed form is
//! `nonce (12) || ciphertext || tag (16)`.
//!
//! Each form binds what it belongs to as AAD, so a body moved to another
//! row does not open:
//!
//! ```text
//! ledger body : "fstp-ledger-v1"     || cell || be64(seq) || be64(at) || command || be16(schema)
//! checkpoint  : "fstp-checkpoint-v1" || cell || be64(seq)
//! outbox body : "fstp-outbox-v1"     || cell || id || be16(kind) || idem
//! ```
//!
//! The ledger key seals ledger bodies and checkpoints only (ADR-004
//! "Seal-count limit"). An outbox body is sealed under its own data key
//! (`crate::outbox`).

use std::sync::atomic::{AtomicU64, Ordering};

use fstp_crypto::aead::{self, NONCE_LEN};
use fstp_keys::DekId;

use crate::error::StoreFault;
use crate::stored::StoredEntry;

/// The seals one ledger key generation makes before it is replaced:
/// 2^20, counting bodies and checkpoints together (ADR-004 part 1,
/// ADR-007). The store refuses to seal past it, so the composer must draw
/// a new generation.
pub const LEDGER_KEY_SEALS: u64 = 1 << 20;

/// One generation of the ledger key: its index in `key_ix`, the id of its
/// data key row, and the key.
pub struct LedgerKey {
    key_ix: u32,
    dek: DekId,
    key: aead::Key,
    /// Seals taken from the [`LEDGER_KEY_SEALS`] budget. A seal reserves
    /// its place by compare and swap before it runs, so concurrent seals
    /// through one shared [`LedgerKeys`] never pass the limit together.
    reserved: AtomicU64,
}

impl LedgerKey {
    /// The generation `key_ix` of the ledger key, with data key id `dek`.
    /// The keystore of lane W2f opens `key` from its sealed row.
    ///
    /// ADR-004 gives every process start a new generation, since a seal
    /// count lives in memory only. The store and the checkpoints refuse a
    /// generation whose index already names a stored row before this
    /// process seals with it.
    pub fn new(key_ix: u32, dek: DekId, key: aead::Key) -> LedgerKey {
        let reserved = AtomicU64::new(key.seal_count());
        LedgerKey {
            key_ix,
            dek,
            key,
            reserved,
        }
    }

    /// The generation index.
    pub fn key_ix(&self) -> u32 {
        self.key_ix
    }

    /// The data key id.
    pub fn dek(&self) -> DekId {
        self.dek
    }

    /// The seals this process made or reserved with the generation.
    pub fn seal_count(&self) -> u64 {
        self.reserved.load(Ordering::SeqCst)
    }

    /// Takes one seal from the budget, or refuses at the limit. The check
    /// and the count are one atomic step.
    fn reserve(&self) -> Result<(), StoreFault> {
        let mut count = self.reserved.load(Ordering::SeqCst);
        loop {
            if count >= LEDGER_KEY_SEALS {
                return Err(StoreFault::SealRefused);
            }
            let next = count.saturating_add(1);
            match self.reserved.compare_exchange_weak(
                count,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => count = actual,
            }
        }
    }
}

/// The ledger key generations a process holds: the current one, which
/// seals, and older ones, which only open.
pub struct LedgerKeys {
    current: LedgerKey,
    older: Vec<LedgerKey>,
}

impl LedgerKeys {
    /// Keys whose current generation is `current`.
    pub fn new(current: LedgerKey) -> LedgerKeys {
        LedgerKeys {
            current,
            older: Vec::new(),
        }
    }

    /// Adds an older generation, which opens what it sealed before.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] when a held generation has the same index
    /// or the same data key id.
    pub fn with_older(mut self, older: LedgerKey) -> Result<LedgerKeys, StoreFault> {
        let clash = |k: &LedgerKey| k.key_ix == older.key_ix || k.dek == older.dek;
        if clash(&self.current) || self.older.iter().any(clash) {
            return Err(StoreFault::Refused("a ledger key generation is held twice"));
        }
        self.older.push(older);
        Ok(self)
    }

    /// The current generation.
    pub fn current(&self) -> &LedgerKey {
        &self.current
    }

    fn all(&self) -> impl Iterator<Item = &LedgerKey> {
        std::iter::once(&self.current).chain(self.older.iter())
    }

    fn by_ix(&self, key_ix: u32) -> Option<&LedgerKey> {
        self.all().find(|k| k.key_ix == key_ix)
    }

    /// Seals `plain` under the current generation. It gives the
    /// generation and the sealed form.
    pub(crate) fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<(u32, Vec<u8>), StoreFault> {
        let k = &self.current;
        k.reserve()?;
        let sealed = aead::seal(&k.key, aad, plain).map_err(|_| StoreFault::SealRefused)?;
        let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(sealed.body.len()));
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.body);
        Ok((k.key_ix, out))
    }

    /// Opens a sealed form of generation `key_ix`.
    pub(crate) fn open(
        &self,
        key_ix: u32,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, StoreFault> {
        let k = self.by_ix(key_ix).ok_or(StoreFault::OpenFailed)?;
        open_sealed(&k.key, aad, sealed)
    }
}

/// Opens the body of the stored ledger row `e` of `cell` under `keys`,
/// with the row's own AAD. This is the open step of every ledger read,
/// and the fuzz target `stored_entry_decode` drives it.
///
/// # Errors
///
/// [`StoreFault::OpenFailed`] for an unknown generation, a body shorter
/// than a nonce, or a body that does not open under the row's AAD.
pub fn open_stored_entry(
    keys: &LedgerKeys,
    cell: &[u8; 16],
    e: &StoredEntry,
) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, StoreFault> {
    let aad = ledger_aad(cell, e.seq, e.at, &e.command, e.schema);
    keys.open(e.key_ix, &aad, &e.sealed)
}

/// Splits `nonce || body` and opens it under `key` and `aad`.
pub(crate) fn open_sealed(
    key: &aead::Key,
    aad: &[u8],
    sealed: &[u8],
) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, StoreFault> {
    let (nonce, body) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(StoreFault::OpenFailed)?;
    aead::open(key, nonce, aad, body).map_err(|_| StoreFault::OpenFailed)
}

fn aad(label: &[u8], cell: &[u8; 16], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(label);
    out.extend_from_slice(cell);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// The AAD of a ledger body (ADR-007 "The AAD"):
/// `"fstp-ledger-v1" || cell || be64(seq) || be64(at) || command || be16(schema)`.
pub fn ledger_aad(cell: &[u8; 16], seq: u64, at: i64, command: &[u8; 16], schema: u16) -> Vec<u8> {
    aad(
        b"fstp-ledger-v1",
        cell,
        &[
            &seq.to_be_bytes(),
            &at.to_be_bytes(),
            command,
            &schema.to_be_bytes(),
        ],
    )
}

/// The AAD of a checkpoint body: `"fstp-checkpoint-v1" || cell || be64(seq)`.
pub fn checkpoint_aad(cell: &[u8; 16], seq: u64) -> Vec<u8> {
    aad(b"fstp-checkpoint-v1", cell, &[&seq.to_be_bytes()])
}

/// The AAD of an outbox body:
/// `"fstp-outbox-v1" || cell || id || be16(kind) || idem`.
pub fn outbox_aad(cell: &[u8; 16], id: &[u8; 16], kind: u16, idem: &[u8]) -> Vec<u8> {
    aad(b"fstp-outbox-v1", cell, &[id, &kind.to_be_bytes(), idem])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use super::*;

    fn keys(ix: u32) -> LedgerKeys {
        LedgerKeys::new(LedgerKey::new(
            ix,
            DekId([u8::try_from(ix).unwrap(); 16]),
            aead::Key::generate().unwrap(),
        ))
    }

    /// ADR-007 "The AAD": a ledger body opens under its own AAD only.
    #[test]
    fn adr007_ledger_body_opens_under_its_own_aad_only() {
        let k = keys(1);
        let cell = [3u8; 16];
        let a = ledger_aad(&cell, 1, 5, &[1; 16], 1);
        let (ix, sealed) = k.seal(&a, b"record").unwrap();
        assert_eq!(ix, 1);
        assert_eq!(k.open(1, &a, &sealed).unwrap().as_slice(), b"record");
        for other in [
            ledger_aad(&[4; 16], 1, 5, &[1; 16], 1),
            ledger_aad(&cell, 2, 5, &[1; 16], 1),
            ledger_aad(&cell, 1, 6, &[1; 16], 1),
            ledger_aad(&cell, 1, 5, &[2; 16], 1),
            ledger_aad(&cell, 1, 5, &[1; 16], 2),
        ] {
            assert!(k.open(1, &other, &sealed).is_err(), "a moved body opened");
        }
        assert!(k.open(2, &a, &sealed).is_err(), "an unknown generation");
    }

    /// R-NF-08, ADR-007 "Random nonces": two seals of one plaintext under
    /// one AAD never share their nonce.
    #[test]
    fn r_nf_08_two_seals_never_share_a_nonce() {
        let k = keys(1);
        let a = checkpoint_aad(&[1; 16], 1);
        let (_, x) = k.seal(&a, b"same").unwrap();
        let (_, y) = k.seal(&a, b"same").unwrap();
        assert_ne!(x[..NONCE_LEN], y[..NONCE_LEN]);
    }

    /// ADR-004 part 1: an older generation opens, and a generation held
    /// twice is refused.
    #[test]
    fn adr004_older_generation_opens_and_duplicates_are_refused() {
        let old = keys(1);
        let a = checkpoint_aad(&[1; 16], 1);
        let (_, sealed) = old.seal(&a, b"old").unwrap();
        let both = keys(2).with_older(old.current).unwrap();
        assert_eq!(both.open(1, &a, &sealed).unwrap().as_slice(), b"old");
        let again = LedgerKey::new(2, DekId([9; 16]), aead::Key::generate().unwrap());
        assert!(both.with_older(again).is_err());
    }

    /// ADR-004 "Seal-count limit": the budget check and the count are one
    /// step. Many threads sealing through one shared key two seals short
    /// of [`LEDGER_KEY_SEALS`] make exactly two seals between them.
    #[test]
    fn adr004_concurrent_seals_never_pass_the_ledger_key_budget() {
        let bytes = [7u8; 32];
        let key = aead::Key::from_bytes_with_count(&bytes, LEDGER_KEY_SEALS - 2).unwrap();
        let k = std::sync::Arc::new(LedgerKeys::new(LedgerKey::new(1, DekId([1; 16]), key)));
        let a = checkpoint_aad(&[1; 16], 1);
        let made: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let k = std::sync::Arc::clone(&k);
                    let a = a.clone();
                    scope.spawn(move || (0..4).filter(|_| k.seal(&a, b"x").is_ok()).count())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(made, 2, "ADR-004: seals past the ledger key budget");
        assert_eq!(k.current().seal_count(), LEDGER_KEY_SEALS);
    }

    /// ADR-007 "The AAD": `open_stored_entry` opens a row under the AAD
    /// of its own fields, and a row moved to another sequence does not
    /// open.
    #[test]
    fn adr007_open_stored_entry_binds_the_row_fields() {
        let k = keys(1);
        let cell = [3u8; 16];
        let (key_ix, sealed) = k.seal(&ledger_aad(&cell, 4, 9, &[2; 16], 1), b"r").unwrap();
        let mut e = StoredEntry {
            seq: 4,
            at: 9,
            command: [2; 16],
            schema: 1,
            key_ix,
            sealed,
        };
        assert_eq!(
            open_stored_entry(&k, &cell, &e).unwrap().as_slice(),
            b"r",
            "the row's own AAD"
        );
        e.seq = 5;
        assert!(open_stored_entry(&k, &cell, &e).is_err(), "a moved row");
    }
}

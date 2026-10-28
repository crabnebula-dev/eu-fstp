//! The PostgreSQL record store of a cell: the append protocol, the chain
//! writer's tables, the keystore, the text store, the schema catalogue and
//! per-role pools (M3 design sections 4 and 5.3, ADR-007).
//!
//! The store is generic over the record type. It encodes through
//! `fstp_ledger::Canonical` and decodes through a function the composer
//! passes in, so it never names `CellRecord`.
//!
//! Status: W0 stub. Lane W2e fills the crate, once lane W2c adds
//! `fstp_ledger::AsyncRecordStore`. Every operation refuses with
//! [`StoreError::NotImplemented`].

use std::marker::PhantomData;

use fstp_migrate::catalogue::TableSpec;

/// The tables of the application database (`c_<cell>`). Lane W2e lists
/// them next to its migrations.
pub const CATALOGUE: &[TableSpec] = &[];

/// Why a stored row did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoder is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Decodes a record from its canonical text at a schema version.
pub type Decode<T> = fn(canonical: &[u8], schema: u16) -> Result<T, DecodeError>;

/// A stored ledger row, before decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The ledger sequence.
    pub seq: u64,
    /// UTC microseconds.
    pub at: i64,
    /// The command id.
    pub command: [u8; 16],
    /// The schema version.
    pub schema: u16,
    /// The sealed canonical text.
    pub sealed: Vec<u8>,
}

/// Decodes a stored row. Fuzzed (`stored_entry_decode`).
pub fn decode_stored_entry(bytes: &[u8]) -> Result<StoredEntry, DecodeError> {
    let _ = bytes;
    Err(DecodeError::NotImplemented(
        "fstp_pgstore::decode_stored_entry",
    ))
}

/// A pool of clients for one role of one cell (ADR-005).
#[derive(Debug)]
pub struct Pool<R> {
    runtime: PhantomData<R>,
    max_clients: usize,
}

impl<R> Pool<R> {
    /// The most clients the pool keeps.
    pub fn max_clients(&self) -> usize {
        self.max_clients
    }
}

/// The record store of one cell.
pub struct PgRecordStore<R, T, W> {
    pool: Pool<R>,
    witness: W,
    decode: Decode<T>,
}

impl<R, T, W> PgRecordStore<R, T, W> {
    /// Opens the store over `pool` with the witness client `witness`.
    pub fn open(pool: Pool<R>, witness: W, decode: Decode<T>) -> Result<Self, StoreError> {
        let _ = (pool, witness, decode);
        Err(StoreError::NotImplemented(
            "fstp_pgstore::PgRecordStore::open",
        ))
    }

    /// The pool, the witness client and the decoder.
    pub fn parts(&self) -> (&Pool<R>, &W, Decode<T>) {
        (&self.pool, &self.witness, self.decode)
    }
}

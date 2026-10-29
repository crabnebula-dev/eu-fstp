//! Sealed fold checkpoints in `ops.checkpoint` (ADR-007 "Projections in
//! memory with sealed checkpoints", design section 5.5).
//!
//! A checkpoint is the engine's folded state at a ledger sequence, sealed
//! under the ledger key with a random nonce and the AAD
//! `"fstp-checkpoint-v1" || cell || be64(seq)`. A body moved to another
//! sequence does not open. The latest checkpoint is the one at the
//! highest sequence. It runs as `c_<cell>_app`, which holds full rights on
//! `ops` except the outbox (design section 4.1).

use std::sync::Arc;

use fstp_ledger::Seq;
use fstp_rt::Runtime;

use crate::error::StoreFault;
use crate::pool::{Pool, Role};
use crate::seal::{LedgerKeys, checkpoint_aad};

/// The largest state a checkpoint holds: 64 MiB.
pub const MAX_CHECKPOINT_LEN: usize = 64 << 20;

const LEDGER_HEAD_SQL: &str = "SELECT coalesce(max(seq), 0)::pg_catalog.int8 FROM ledger.entry";
const INSERT_SQL: &str = "INSERT INTO ops.checkpoint (seq, key_ix, body) VALUES ($1, $2, $3)";
const LATEST_SQL: &str = "SELECT seq, key_ix, body FROM ops.checkpoint ORDER BY seq DESC LIMIT 1";
const KEY_IX_USED_SQL: &str = "SELECT EXISTS (SELECT 1 FROM ledger.entry WHERE key_ix = $1) \
     OR EXISTS (SELECT 1 FROM ops.checkpoint WHERE key_ix = $1)";

/// A checkpoint: its ledger sequence and the opened state.
#[derive(Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The ledger sequence the state folds up to.
    pub seq: Seq,
    /// The folded state.
    pub state: Vec<u8>,
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// The checkpoints of one cell over its app role.
pub struct Checkpoints<R: Runtime> {
    pool: Pool<R>,
    keys: Arc<LedgerKeys>,
}

impl<R: Runtime> Checkpoints<R> {
    /// The checkpoints over `pool`, which must serve the app role, sealed
    /// under `keys`.
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>, keys: Arc<LedgerKeys>) -> Result<Self, StoreFault> {
        if pool.role() != Role::App {
            return Err(StoreFault::WrongRole);
        }
        Ok(Checkpoints { pool, keys })
    }

    /// Replaces the ledger keys.
    pub fn set_keys(&mut self, keys: Arc<LedgerKeys>) {
        self.keys = keys;
    }

    /// Writes the sealed checkpoint of `state` at `seq`.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for sequence 0, a sequence past the ledger
    /// head, or a state over [`MAX_CHECKPOINT_LEN`];
    /// [`StoreFault::KeyGenerationReused`] when this process has not sealed
    /// with the current ledger key generation yet and a stored ledger row
    /// or checkpoint already names it (ADR-004); a seal fault; a database
    /// fault, such as a second checkpoint at one sequence.
    pub async fn put(&self, seq: Seq, state: &[u8]) -> Result<(), StoreFault> {
        if state.len() > MAX_CHECKPOINT_LEN {
            return Err(StoreFault::Refused("a checkpoint over its limit"));
        }
        let at = i64::try_from(seq.raw())
            .map_err(|_| StoreFault::Refused("a checkpoint past the ledger head"))?;
        if at == 0 {
            return Err(StoreFault::Refused("a checkpoint at sequence 0"));
        }
        let mut client = self.pool.get().await?;
        let head: i64 = client.query_one(LEDGER_HEAD_SQL, &[]).await?.get(0)?;
        if at > head {
            client.release();
            return Err(StoreFault::Refused("a checkpoint past the ledger head"));
        }
        let current = self.keys.current();
        if current.seal_count() == 0 {
            let ix = i32::from_be_bytes(current.key_ix().to_be_bytes());
            let used: bool = client.query_one(KEY_IX_USED_SQL, &[&ix]).await?.get(0)?;
            if used {
                client.release();
                return Err(StoreFault::KeyGenerationReused);
            }
        }
        let pool_cell = self.pool.cell();
        let (key_ix, body) = self
            .keys
            .seal(&checkpoint_aad(&pool_cell, seq.raw()), state)?;
        client
            .execute(
                INSERT_SQL,
                &[&at, &i32::from_be_bytes(key_ix.to_be_bytes()), &body],
            )
            .await?;
        client.release();
        Ok(())
    }

    /// The checkpoint at the highest sequence, opened, or `None`.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or [`StoreFault::OpenFailed`] when its
    /// body does not open at its sequence.
    pub async fn latest(&self) -> Result<Option<Checkpoint>, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client.query_opt(LATEST_SQL, &[]).await?;
        client.release();
        let Some(row) = row else {
            return Ok(None);
        };
        let seq: i64 = row.get(0)?;
        let key_ix: i32 = row.get(1)?;
        let body: Vec<u8> = row.get(2)?;
        let seq =
            u64::try_from(seq).map_err(|_| StoreFault::Corrupt("a negative checkpoint seq"))?;
        let plain = self.keys.open(
            u32::from_be_bytes(key_ix.to_be_bytes()),
            &checkpoint_aad(&self.pool.cell(), seq),
            &body,
        )?;
        Ok(Some(Checkpoint {
            seq: Seq::from_raw(seq),
            state: plain.to_vec(),
        }))
    }
}

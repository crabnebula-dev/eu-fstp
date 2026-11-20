//! The API core's state beside the ledger (ADR-026, migration
//! `0009_api.sql`): pending actions (I-85) and sealed workspaces (I-21).
//!
//! [`ApiStore`] runs as `c_<cell>_app`. It writes `api.pending_actions`
//! and `workspace.drafts`, and only reads `api.pending_confirmed`, which
//! the ledger writer inserts inside the append that executes a pending
//! action ([`crate::SideEffects::pending_confirmed`]).
//!
//! - A pending request is sealed under the current ledger key generation
//!   with the AAD of [`pending_aad`]. Its row keeps the generation index.
//! - A workspace value is sealed by [`seal_workspace`], under the same
//!   generation and the AAD of [`workspace_aad`]. The store keeps the
//!   sealed bytes as given and opens nothing.
//! - A pending action is confirmed when its `api.pending_confirmed` row
//!   exists. A discard or an expiry mark updates an open, unconfirmed row
//!   only, so it never closes a confirmed action.

use std::sync::Arc;

use fstp_rt::Runtime;

use crate::error::StoreFault;
use crate::pool::{Pool, Role};
use fstp_crypto::aead::NONCE_LEN;

use crate::seal::LedgerKeys;

/// The longest plaintext of a pending request or a workspace value, so
/// its sealed form fits the column checks of `0009_api.sql`.
pub const MAX_API_PLAIN: usize = 2_097_152 - 4 - 12 - 16;

const INSERT_PENDING_SQL: &str = "INSERT INTO api.pending_actions \
     (id, account, client_id, op_kind, key_ix, request, digest, created_at, expires_at, status, closed_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', NULL)";
const PENDING_SQL: &str = "SELECT p.id, p.account, p.client_id, p.op_kind, p.key_ix, p.request, \
     p.digest, p.created_at, p.expires_at, p.status, p.closed_at, \
     (SELECT c.ledger_seq FROM api.pending_confirmed c WHERE c.id = p.id) \
     FROM api.pending_actions p WHERE p.id = $1";
const PENDING_OF_SQL: &str = "SELECT p.id, p.account, p.client_id, p.op_kind, p.key_ix, p.request, \
     p.digest, p.created_at, p.expires_at, p.status, p.closed_at, \
     (SELECT c.ledger_seq FROM api.pending_confirmed c WHERE c.id = p.id) \
     FROM api.pending_actions p WHERE p.account = $1 ORDER BY p.id";
const OPEN_COUNT_SQL: &str = "SELECT count(*)::pg_catalog.int8 FROM api.pending_actions p \
     WHERE p.account = $1 AND p.status = 'open' AND p.expires_at > $2 \
     AND NOT EXISTS (SELECT 1 FROM api.pending_confirmed c WHERE c.id = p.id)";
const CLOSE_SQL: &str = "UPDATE api.pending_actions p SET status = $2, closed_at = $3 \
     WHERE p.id = $1 AND p.status = 'open' \
     AND NOT EXISTS (SELECT 1 FROM api.pending_confirmed c WHERE c.id = p.id)";
const SWEEP_SQL: &str = "DELETE FROM api.pending_actions p \
     WHERE NOT EXISTS (SELECT 1 FROM api.pending_confirmed c WHERE c.id = p.id) \
     AND ((p.status <> 'open' AND p.closed_at <= $1) OR (p.status = 'open' AND p.expires_at <= $1))";
const DELETE_PENDING_SQL: &str = "DELETE FROM api.pending_actions p WHERE p.id = $1 \
     AND NOT EXISTS (SELECT 1 FROM api.pending_confirmed c WHERE c.id = p.id)";
const PUT_WORKSPACE_SQL: &str = "INSERT INTO workspace.drafts \
     (proposal, slot, revision, key_ix, sealed, updated_at) VALUES ($1, $2, 1, $3, $4, $5) \
     ON CONFLICT (proposal, slot) DO UPDATE SET revision = workspace.drafts.revision + 1, \
     key_ix = EXCLUDED.key_ix, sealed = EXCLUDED.sealed, updated_at = EXCLUDED.updated_at";
const GET_WORKSPACE_SQL: &str =
    "SELECT key_ix, sealed FROM workspace.drafts WHERE proposal = $1 AND slot = $2";

/// The stored status of a pending action. A confirmation is not stored
/// here: it is the row of `api.pending_confirmed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoredPendingStatus {
    /// Awaiting a confirmation, until its expiry.
    Open,
    /// Marked expired.
    Expired,
    /// Discarded by its user.
    Discarded,
}

impl StoredPendingStatus {
    /// The `status` column value.
    pub const fn as_str(self) -> &'static str {
        match self {
            StoredPendingStatus::Open => "open",
            StoredPendingStatus::Expired => "expired",
            StoredPendingStatus::Discarded => "discarded",
        }
    }

    fn parse(s: &str) -> Result<StoredPendingStatus, StoreFault> {
        match s {
            "open" => Ok(StoredPendingStatus::Open),
            "expired" => Ok(StoredPendingStatus::Expired),
            "discarded" => Ok(StoredPendingStatus::Discarded),
            _ => Err(StoreFault::Corrupt("a pending status outside its list")),
        }
    }
}

/// One pending action as the store holds it, with its request opened.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRow {
    /// The pending action.
    pub id: [u8; 16],
    /// The account whose agent prepared it.
    pub account: [u8; 16],
    /// The agent client.
    pub client: [u8; 16],
    /// The operation name.
    pub op: String,
    /// The request plaintext: what a confirmation replays and the user
    /// sees, in the caller's encoding.
    pub request: Vec<u8>,
    /// The digest the confirmation is bound to.
    pub digest: [u8; 32],
    /// When it was prepared, UTC microseconds.
    pub created: i64,
    /// When it stops being confirmable.
    pub expires: i64,
    /// Its stored status.
    pub status: StoredPendingStatus,
    /// When a discard or an expiry mark closed it.
    pub closed: Option<i64>,
    /// The ledger entry of its confirmation, once confirmed.
    pub confirmed: Option<u64>,
}

impl std::fmt::Debug for PendingRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The request is user content: the debug form never shows it.
        f.debug_struct("PendingRow")
            .field("op", &self.op)
            .field("status", &self.status)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

/// The AAD of a pending request: `"fstp-api-pending-v1" || cell || id`.
pub fn pending_aad(cell: &[u8; 16], id: &[u8; 16]) -> Vec<u8> {
    let mut out = b"fstp-api-pending-v1".to_vec();
    out.extend_from_slice(cell);
    out.extend_from_slice(id);
    out
}

/// The AAD of a workspace value: `"fstp-workspace-v1" || cell || proposal`.
pub fn workspace_aad(cell: &[u8; 16], proposal: &[u8; 16]) -> Vec<u8> {
    let mut out = b"fstp-workspace-v1".to_vec();
    out.extend_from_slice(cell);
    out.extend_from_slice(proposal);
    out
}

/// Seals a workspace value of `proposal` under the current ledger key
/// generation: `be32(key_ix) || nonce || ciphertext || tag`.
///
/// # Errors
///
/// [`StoreFault::Refused`] for a value over [`MAX_API_PLAIN`], and the
/// seal's fault.
pub fn seal_workspace(
    keys: &LedgerKeys,
    cell: &[u8; 16],
    proposal: &[u8; 16],
    plain: &[u8],
) -> Result<Vec<u8>, StoreFault> {
    if plain.len() > MAX_API_PLAIN {
        return Err(StoreFault::Refused("a workspace value over its limit"));
    }
    let (key_ix, sealed) = keys.seal(&workspace_aad(cell, proposal), plain)?;
    let mut out = Vec::with_capacity(sealed.len().saturating_add(4));
    out.extend_from_slice(&key_ix.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a value [`seal_workspace`] sealed for `proposal`.
///
/// # Errors
///
/// [`StoreFault::OpenFailed`] for a short value, an unknown generation,
/// or bytes sealed for another cell or proposal.
pub fn open_workspace(
    keys: &LedgerKeys,
    cell: &[u8; 16],
    proposal: &[u8; 16],
    sealed: &[u8],
) -> Result<Vec<u8>, StoreFault> {
    let (ix, rest) = split_ix(sealed)?;
    let plain = keys.open(ix, &workspace_aad(cell, proposal), rest)?;
    Ok(plain.to_vec())
}

fn split_ix(sealed: &[u8]) -> Result<(u32, &[u8]), StoreFault> {
    let (ix, rest) = sealed
        .split_first_chunk::<4>()
        .ok_or(StoreFault::OpenFailed)?;
    if rest.len() < NONCE_LEN {
        return Err(StoreFault::OpenFailed);
    }
    Ok((u32::from_be_bytes(*ix), rest))
}

/// The `int4` of a key generation index, bit for bit.
fn ix_column(key_ix: u32) -> i32 {
    i32::from_be_bytes(key_ix.to_be_bytes())
}

fn ix_of(column: i32) -> u32 {
    u32::from_be_bytes(column.to_be_bytes())
}

fn id16(bytes: &[u8]) -> Result<[u8; 16], StoreFault> {
    <[u8; 16]>::try_from(bytes).map_err(|_| StoreFault::Corrupt("an id that is not 16 bytes"))
}

/// The API core's tables of one cell, over its app role.
pub struct ApiStore<R: Runtime> {
    pool: Pool<R>,
    keys: Arc<LedgerKeys>,
}

impl<R: Runtime> ApiStore<R> {
    /// The store over `pool`, which must serve the app role, sealing under
    /// `keys`.
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>, keys: Arc<LedgerKeys>) -> Result<ApiStore<R>, StoreFault> {
        if pool.role() != Role::App {
            return Err(StoreFault::WrongRole);
        }
        Ok(ApiStore { pool, keys })
    }

    fn cell(&self) -> [u8; 16] {
        self.pool.cell()
    }

    /// The open, unconfirmed and unexpired actions of `account` at `now`.
    ///
    /// # Errors
    ///
    /// A pool or database fault.
    pub async fn open_count(&self, account: [u8; 16], now: i64) -> Result<u64, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client
            .query_one(OPEN_COUNT_SQL, &[&account.as_slice(), &now])
            .await?;
        client.release();
        let n: i64 = row.get(0)?;
        u64::try_from(n).map_err(|_| StoreFault::Corrupt("a negative count"))
    }

    /// Stores a new open action, its request sealed.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for a request over its limit, the seal's
    /// fault, and a database fault, such as a taken id.
    pub async fn insert_pending(&self, row: &PendingRow) -> Result<(), StoreFault> {
        if row.request.len() > MAX_API_PLAIN {
            return Err(StoreFault::Refused("a pending request over its limit"));
        }
        let (key_ix, sealed) = self
            .keys
            .seal(&pending_aad(&self.cell(), &row.id), &row.request)?;
        let mut client = self.pool.get().await?;
        client
            .execute(
                INSERT_PENDING_SQL,
                &[
                    &row.id.as_slice(),
                    &row.account.as_slice(),
                    &row.client.as_slice(),
                    &row.op.as_str(),
                    &ix_column(key_ix),
                    &sealed,
                    &row.digest.as_slice(),
                    &row.created,
                    &row.expires,
                ],
            )
            .await?;
        client.release();
        Ok(())
    }

    /// The action `id`, or `None`.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or a row that does not open.
    pub async fn pending(&self, id: [u8; 16]) -> Result<Option<PendingRow>, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client.query_opt(PENDING_SQL, &[&id.as_slice()]).await?;
        client.release();
        row.map(|r| self.decode(&r)).transpose()
    }

    /// Every action of `account`, in id order.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or a row that does not open.
    pub async fn pending_of(&self, account: [u8; 16]) -> Result<Vec<PendingRow>, StoreFault> {
        let mut client = self.pool.get().await?;
        let rows = client.query(PENDING_OF_SQL, &[&account.as_slice()]).await?;
        client.release();
        rows.iter().map(|r| self.decode(r)).collect()
    }

    /// Closes the open, unconfirmed action `id` as `to` at `at`. `false`
    /// when it is not open or is confirmed.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for `to` open, and a database fault.
    pub async fn close_pending(
        &self,
        id: [u8; 16],
        to: StoredPendingStatus,
        at: i64,
    ) -> Result<bool, StoreFault> {
        if to == StoredPendingStatus::Open {
            return Err(StoreFault::Refused("a close to the open status"));
        }
        let mut client = self.pool.get().await?;
        let n = client
            .execute(CLOSE_SQL, &[&id.as_slice(), &to.as_str(), &at])
            .await?;
        client.release();
        Ok(n == 1)
    }

    /// Deletes the unconfirmed action `id`, such as a preparation whose
    /// audit entry could not be written. `false` when none was deleted.
    ///
    /// # Errors
    ///
    /// A pool or database fault.
    pub async fn delete_pending(&self, id: [u8; 16]) -> Result<bool, StoreFault> {
        let mut client = self.pool.get().await?;
        let n = client
            .execute(DELETE_PENDING_SQL, &[&id.as_slice()])
            .await?;
        client.release();
        Ok(n == 1)
    }

    /// Deletes every unconfirmed action that ended at or before `floor`.
    /// A confirmed action stays, since its confirmation row names it.
    ///
    /// # Errors
    ///
    /// A pool or database fault.
    pub async fn sweep_pending(&self, floor: i64) -> Result<u64, StoreFault> {
        let mut client = self.pool.get().await?;
        let n = client.execute(SWEEP_SQL, &[&floor]).await?;
        client.release();
        Ok(n)
    }

    /// Stores the sealed workspace value `sealed` of `proposal` in `slot`,
    /// replacing what the slot held.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for a value that is not one
    /// [`seal_workspace`] form, and a database fault.
    pub async fn put_workspace(
        &self,
        proposal: [u8; 16],
        slot: &str,
        sealed: &[u8],
        at: i64,
    ) -> Result<(), StoreFault> {
        let (ix, _) = split_ix(sealed).map_err(|_| StoreFault::Refused("a sealed value"))?;
        let mut client = self.pool.get().await?;
        client
            .execute(
                PUT_WORKSPACE_SQL,
                &[&proposal.as_slice(), &slot, &ix_column(ix), &sealed, &at],
            )
            .await?;
        client.release();
        Ok(())
    }

    /// The sealed value of `proposal` in `slot`, or `None`.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or a row whose generation differs from
    /// its value's.
    pub async fn workspace(
        &self,
        proposal: [u8; 16],
        slot: &str,
    ) -> Result<Option<Vec<u8>>, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client
            .query_opt(GET_WORKSPACE_SQL, &[&proposal.as_slice(), &slot])
            .await?;
        client.release();
        let Some(row) = row else {
            return Ok(None);
        };
        let ix: i32 = row.get(0)?;
        let sealed: Vec<u8> = row.get(1)?;
        match split_ix(&sealed) {
            Ok((v, _)) if v == ix_of(ix) => Ok(Some(sealed)),
            _ => Err(StoreFault::Corrupt(
                "a workspace row whose generation differs",
            )),
        }
    }

    fn decode(&self, r: &fstp_pgwire::Row) -> Result<PendingRow, StoreFault> {
        let id = id16(&r.get::<Vec<u8>>(0)?)?;
        let account = id16(&r.get::<Vec<u8>>(1)?)?;
        let client = id16(&r.get::<Vec<u8>>(2)?)?;
        let op: String = r.get(3)?;
        let key_ix: i32 = r.get(4)?;
        let sealed: Vec<u8> = r.get(5)?;
        let digest = <[u8; 32]>::try_from(r.get::<Vec<u8>>(6)?.as_slice())
            .map_err(|_| StoreFault::Corrupt("a digest that is not 32 bytes"))?;
        let created: i64 = r.get(7)?;
        let expires: i64 = r.get(8)?;
        let status: String = r.get(9)?;
        let closed: Option<i64> = r.get(10)?;
        let confirmed: Option<i64> = r.get(11)?;
        let request = self
            .keys
            .open(ix_of(key_ix), &pending_aad(&self.cell(), &id), &sealed)?
            .to_vec();
        Ok(PendingRow {
            id,
            account,
            client,
            op,
            request,
            digest,
            created,
            expires,
            status: StoredPendingStatus::parse(&status)?,
            closed,
            confirmed: confirmed
                .map(|s| u64::try_from(s).map_err(|_| StoreFault::Corrupt("a negative sequence")))
                .transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::seal::LedgerKey;
    use fstp_keys::DekId;

    fn keys() -> LedgerKeys {
        let key = fstp_crypto::aead::Key::from_bytes(&[7; 32]).unwrap();
        LedgerKeys::new(LedgerKey::new(3, DekId([1; 16]), key))
    }

    /// I-21, ADR-026: a workspace value opens only for its own cell and
    /// proposal, and its sealed form never holds the plaintext.
    #[test]
    fn i21_workspace_seal_binds_cell_and_proposal() {
        let k = keys();
        let plain = b"synthetic draft narrative".to_vec();
        let sealed = seal_workspace(&k, &[1; 16], &[2; 16], &plain).unwrap();
        assert!(!sealed.windows(plain.len()).any(|w| w == plain.as_slice()));
        assert_eq!(&sealed[..4], &3u32.to_be_bytes());
        assert_eq!(
            open_workspace(&k, &[1; 16], &[2; 16], &sealed).unwrap(),
            plain
        );
        assert!(open_workspace(&k, &[1; 16], &[3; 16], &sealed).is_err());
        assert!(open_workspace(&k, &[9; 16], &[2; 16], &sealed).is_err());
        assert!(open_workspace(&k, &[1; 16], &[2; 16], &sealed[..10]).is_err());
    }
}

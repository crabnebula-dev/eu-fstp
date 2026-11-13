//! The witness database store over the in-house `fstp-pgwire` (design
//! section 4.4, ADR-010 "Witnesses", open point 4). Lane int5.
//!
//! The service connects as `witness_service`, which holds INSERT and
//! SELECT only. Every record is written before the witness answers, so a
//! receipt never leaves the witness for a prepare it did not store.
//!
//! [`load_chain`] rebuilds a chain's [`WitnessState`] from its rows, in
//! witness order. It recomputes every witness link from the genesis of the
//! chain and refuses a gap, a repeat or a link that does not recompute,
//! so a witness never serves from rows that were changed behind it.

use std::collections::BTreeSet;

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, ReceiptFields};
use fstp_audit::witness::{RecordKind, WitnessRecord, witness_genesis, witness_link};
use fstp_audit::{CellId, ChainId, Link};
use fstp_pgwire::Client;
use fstp_rt::Runtime;

use crate::chain_witness::{Withdrawal, WitnessState};

/// Why a store operation failed. It names the step only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The database refused or could not be reached.
    Unavailable(&'static str),
    /// A stored row does not decode or does not recompute.
    Corrupt(&'static str),
    /// A registration names another CA for a registered cell.
    Conflict,
}

fn db(step: &'static str) -> impl Fn(fstp_pgwire::Error) -> StoreError {
    move |_| StoreError::Unavailable(step)
}

fn int(n: u64, what: &'static str) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Corrupt(what))
}

fn uint(n: i64, what: &'static str) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt(what))
}

fn chain_code(chain: ChainId) -> i16 {
    i16::from(chain.byte())
}

fn arr<const N: usize>(v: &[u8], what: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt(what))
}

/// The placement marker of the connected database: 4 for a witness
/// database (I-83).
///
/// # Errors
///
/// [`StoreError`] when the table does not hold exactly one row.
pub async fn placement_kind<R: Runtime>(client: &mut Client<R>) -> Result<i16, StoreError> {
    let rows = client
        .query("SELECT kind FROM fstp_meta.placement", &[])
        .await
        .map_err(db("placement"))?;
    let [row] = rows.as_slice() else {
        return Err(StoreError::Corrupt("placement"));
    };
    row.get(0).map_err(|_| StoreError::Corrupt("placement"))
}

/// One registered cell: its CA certificate and the anchor key history of
/// each chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredCell {
    /// The cell.
    pub cell: CellId,
    /// The cell CA certificate, DER.
    pub ca_cert: Vec<u8>,
    /// The anchor public keys of the App chain, encoded.
    pub app_keys: Vec<Vec<u8>>,
    /// The anchor public keys of the Vault chain, encoded.
    pub vault_keys: Vec<Vec<u8>>,
}

/// Every registered cell.
///
/// # Errors
///
/// [`StoreError`] when the rows cannot be read.
pub async fn load_registry<R: Runtime>(
    client: &mut Client<R>,
) -> Result<Vec<RegisteredCell>, StoreError> {
    let cas = client
        .query(
            "SELECT cell_id, ca_cert FROM witness.cell_ca ORDER BY cell_id",
            &[],
        )
        .await
        .map_err(db("cell CAs"))?;
    let mut out = Vec::with_capacity(cas.len());
    for row in &cas {
        let cell: Vec<u8> = row.get(0).map_err(|_| StoreError::Corrupt("cell id"))?;
        let ca_cert: Vec<u8> = row.get(1).map_err(|_| StoreError::Corrupt("CA"))?;
        out.push(RegisteredCell {
            cell: CellId(arr(&cell, "cell id")?),
            ca_cert,
            app_keys: Vec::new(),
            vault_keys: Vec::new(),
        });
    }
    let keys = client
        .query(
            "SELECT cell_id, chain, public_key FROM witness.anchor_key ORDER BY registered_at, public_key",
            &[],
        )
        .await
        .map_err(db("anchor keys"))?;
    for row in &keys {
        let cell: Vec<u8> = row.get(0).map_err(|_| StoreError::Corrupt("cell id"))?;
        let chain: i16 = row.get(1).map_err(|_| StoreError::Corrupt("chain"))?;
        let key: Vec<u8> = row.get(2).map_err(|_| StoreError::Corrupt("anchor key"))?;
        let cell = CellId(arr(&cell, "cell id")?);
        let Some(entry) = out.iter_mut().find(|c| c.cell == cell) else {
            return Err(StoreError::Corrupt("anchor key of an unknown cell"));
        };
        match u8::try_from(chain).ok().and_then(ChainId::from_byte) {
            Some(ChainId::App) => entry.app_keys.push(key),
            Some(ChainId::Vault) => entry.vault_keys.push(key),
            None => return Err(StoreError::Corrupt("chain")),
        }
    }
    Ok(out)
}

/// Registers `cell` with its CA certificate `ca_cert` (DER) at `at`. A
/// second registration with the same certificate changes nothing.
///
/// # Errors
///
/// [`StoreError::Conflict`] when the cell is registered with another CA.
pub async fn register_cell<R: Runtime>(
    client: &mut Client<R>,
    cell: CellId,
    ca_cert: &[u8],
    at: i64,
) -> Result<(), StoreError> {
    let id = cell.0.to_vec();
    let cert = ca_cert.to_vec();
    let existing = client
        .query_opt(
            "SELECT ca_cert FROM witness.cell_ca WHERE cell_id = $1",
            &[&id],
        )
        .await
        .map_err(db("cell CA"))?;
    if let Some(row) = existing {
        let have: Vec<u8> = row.get(0).map_err(|_| StoreError::Corrupt("CA"))?;
        return if have == cert {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
    }
    client
        .execute(
            "INSERT INTO witness.cell_ca (cell_id, ca_cert, registered_at) VALUES ($1, $2, $3)",
            &[&id, &cert, &at],
        )
        .await
        .map(drop)
        .map_err(db("cell CA"))
}

/// Adds `key` to the anchor key history of `cell`'s `chain` at `at`. A key
/// in the history already changes nothing.
///
/// # Errors
///
/// [`StoreError`] when the row cannot be written.
pub async fn register_anchor_key<R: Runtime>(
    client: &mut Client<R>,
    cell: CellId,
    chain: ChainId,
    key: &[u8],
    at: i64,
) -> Result<(), StoreError> {
    let id = cell.0.to_vec();
    let key = key.to_vec();
    client
        .execute(
            "INSERT INTO witness.anchor_key (cell_id, chain, public_key, registered_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&id, &chain_code(chain), &key, &at],
        )
        .await
        .map(drop)
        .map_err(db("anchor key"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Writing to a String does not fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The SQL text that registers `cell` with its CA certificate `ca_cert`
/// (DER) and the anchor keys `anchor_keys` at `at`, for the provisioning
/// path (design section 9.2, ADR-010 "Witnesses").
///
/// `witness_service` holds SELECT only on `witness.cell_ca` and
/// `witness.anchor_key`, so the service cannot pin a CA or an anchor key
/// of its own. Provisioning runs this text as `witness_migrator`, then
/// the service reloads the registry ([`load_registry`]). Every value is
/// bytes rendered as a hex `bytea` literal, or an integer, so no input
/// reaches the text unquoted. A second registration with the same CA
/// changes nothing. One with another CA raises an error, and the
/// transaction changes nothing.
pub fn registration_sql(
    cell: CellId,
    ca_cert: &[u8],
    anchor_keys: &[(ChainId, Vec<u8>)],
    at: i64,
) -> String {
    let id = hex(&cell.0);
    let ca = hex(ca_cert);
    let mut sql = format!(
        "BEGIN;\n\
         INSERT INTO witness.cell_ca (cell_id, ca_cert, registered_at) \
         VALUES ('\\x{id}'::bytea, '\\x{ca}'::bytea, {at}) ON CONFLICT (cell_id) DO NOTHING;\n\
         DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM witness.cell_ca \
         WHERE cell_id = '\\x{id}'::bytea AND ca_cert = '\\x{ca}'::bytea) THEN \
         RAISE EXCEPTION 'the cell is registered with another CA'; END IF; END $r$;\n"
    );
    for (chain, key) in anchor_keys {
        sql.push_str(&format!(
            "INSERT INTO witness.anchor_key (cell_id, chain, public_key, registered_at) \
             VALUES ('\\x{id}'::bytea, {}, '\\x{}'::bytea, {at}) ON CONFLICT DO NOTHING;\n",
            chain_code(*chain),
            hex(key)
        ));
    }
    sql.push_str("COMMIT;\n");
    sql
}

/// A chain as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedChain {
    /// The witness state the rows rebuild.
    pub state: WitnessState,
    /// The receipt of the outstanding prepare, when it is the last record.
    pub held: Option<ReceiptFields>,
    /// The witness log, in witness order.
    pub log: Vec<WitnessRecord>,
}

/// One stored record, before the replay.
pub(crate) enum Stored {
    Prepare {
        seq: u64,
        row: AnchorRow,
    },
    Withdrawn {
        seq: u64,
        kind: RecordKind,
        n: u64,
        link: Link,
        witness_link: Link,
    },
}

impl Stored {
    fn seq(&self) -> u64 {
        match self {
            Stored::Prepare { seq, .. } | Stored::Withdrawn { seq, .. } => *seq,
        }
    }
}

/// Rebuilds `cell`'s `chain` from its rows.
///
/// # Errors
///
/// [`StoreError::Corrupt`] for a gap, a repeat, a link that does not
/// recompute or a row that does not decode.
pub async fn load_chain<R: Runtime>(
    client: &mut Client<R>,
    cell: CellId,
    chain: ChainId,
) -> Result<LoadedChain, StoreError> {
    let id = cell.0.to_vec();
    let code = chain_code(chain);
    let anchors = client
        .query(
            "SELECT a.witness_seq, a.n, a.link, a.at, a.signature, a.received_at, a.witness_link, r.signature \
             FROM witness.anchor a JOIN witness.receipt r \
               ON r.cell_id = a.cell_id AND r.chain = a.chain AND r.witness_seq = a.witness_seq \
             WHERE a.cell_id = $1 AND a.chain = $2",
            &[&id, &code],
        )
        .await
        .map_err(db("prepares"))?;
    let mut stored = Vec::with_capacity(anchors.len());
    for row in &anchors {
        let c = StoreError::Corrupt("prepare");
        let seq = uint(row.get::<i64>(0).map_err(|_| c)?, "witness sequence")?;
        let n = uint(row.get::<i64>(1).map_err(|_| c)?, "row number")?;
        let link = Link(arr(&row.get::<Vec<u8>>(2).map_err(|_| c)?, "link")?);
        let at: i64 = row.get(3).map_err(|_| c)?;
        let signature: Vec<u8> = row.get(4).map_err(|_| c)?;
        let received_at: i64 = row.get(5).map_err(|_| c)?;
        let witness_link = Link(arr(&row.get::<Vec<u8>>(6).map_err(|_| c)?, "witness link")?);
        let receipt_signature: Vec<u8> = row.get(7).map_err(|_| c)?;
        // The service stores composite signatures only. A row with any
        // other length could not go out in a log page, so it does not load.
        if signature.len() != fstp_audit::SIGNATURE_LEN
            || receipt_signature.len() != fstp_audit::SIGNATURE_LEN
        {
            return Err(StoreError::Corrupt("signature length"));
        }
        stored.push(Stored::Prepare {
            seq,
            row: AnchorRow {
                anchor: Anchor {
                    cell,
                    chain,
                    n,
                    link,
                    at,
                    signature,
                },
                receipt: Receipt {
                    cell,
                    chain,
                    fields: ReceiptFields {
                        n,
                        link,
                        witness_seq: seq,
                        witness_link,
                        received_at,
                    },
                    signature: receipt_signature,
                },
            },
        });
    }
    let withdrawals = client
        .query(
            "SELECT witness_seq, kind, n, link, witness_link FROM witness.withdrawal \
             WHERE cell_id = $1 AND chain = $2",
            &[&id, &code],
        )
        .await
        .map_err(db("withdrawals"))?;
    for row in &withdrawals {
        let c = StoreError::Corrupt("withdrawal");
        let seq = uint(row.get::<i64>(0).map_err(|_| c)?, "witness sequence")?;
        let kind = match row.get::<i16>(1).map_err(|_| c)? {
            2 => RecordKind::Abort,
            3 => RecordKind::InDoubtAbsent,
            _ => return Err(c),
        };
        let n = uint(row.get::<i64>(2).map_err(|_| c)?, "row number")?;
        let link = Link(arr(&row.get::<Vec<u8>>(3).map_err(|_| c)?, "link")?);
        let witness_link = Link(arr(&row.get::<Vec<u8>>(4).map_err(|_| c)?, "witness link")?);
        stored.push(Stored::Withdrawn {
            seq,
            kind,
            n,
            link,
            witness_link,
        });
    }
    stored.sort_by_key(Stored::seq);
    replay(cell, chain, stored)
}

/// Replays `stored`, in witness order, into the chain's state and log.
pub(crate) fn replay(
    cell: CellId,
    chain: ChainId,
    stored: Vec<Stored>,
) -> Result<LoadedChain, StoreError> {
    let mut state = WitnessState {
        confirmed: (0, fstp_audit::chain::genesis(cell, chain)),
        outstanding: None,
        withdrawn: BTreeSet::new(),
        seq: 0,
        head: witness_genesis(cell, chain),
    };
    let mut held = None;
    let mut log = Vec::with_capacity(stored.len());
    for s in stored {
        let seq = state
            .seq
            .checked_add(1)
            .ok_or(StoreError::Corrupt("witness sequence"))?;
        if s.seq() != seq {
            return Err(StoreError::Corrupt("witness sequence gap"));
        }
        match s {
            Stored::Prepare { row, .. } => {
                let (n, link) = (row.anchor.n, row.anchor.link);
                let head =
                    witness_link(&state.head, cell, chain, RecordKind::Prepare, seq, n, &link);
                if head != row.receipt.fields.witness_link {
                    return Err(StoreError::Corrupt("witness link"));
                }
                if let Some(o) = state.outstanding {
                    state.confirmed = o;
                }
                state.outstanding = Some((n, link));
                state.seq = seq;
                state.head = head;
                held = Some(row.receipt.fields);
                log.push(WitnessRecord::Prepare(row));
            }
            Stored::Withdrawn {
                kind,
                n,
                link,
                witness_link: stored_link,
                ..
            } => {
                let head = witness_link(&state.head, cell, chain, kind, seq, n, &link);
                if head != stored_link || state.outstanding != Some((n, link)) {
                    return Err(StoreError::Corrupt("withdrawal"));
                }
                state.outstanding = None;
                state.withdrawn.insert((n, link));
                state.seq = seq;
                state.head = head;
                held = None;
                log.push(match kind {
                    RecordKind::Abort => WitnessRecord::Abort { n, link },
                    _ => WitnessRecord::InDoubtAbsent { n, link },
                });
            }
        }
    }
    Ok(LoadedChain { state, held, log })
}

/// Stores a receipted prepare: its anchor row and its receipt row, in one
/// transaction.
///
/// # Errors
///
/// [`StoreError::Unavailable`] when the transaction fails. Nothing is
/// stored then.
pub async fn insert_prepare<R: Runtime>(
    client: &mut Client<R>,
    row: &AnchorRow,
) -> Result<(), StoreError> {
    let a = &row.anchor;
    let f = &row.receipt.fields;
    let id = a.cell.0.to_vec();
    let code = chain_code(a.chain);
    let n = int(a.n, "row number")?;
    let seq = int(f.witness_seq, "witness sequence")?;
    let link = a.link.0.to_vec();
    let witness_link = f.witness_link.0.to_vec();
    let mut tx = client.transaction().await.map_err(db("prepare"))?;
    tx.execute(
        "INSERT INTO witness.anchor (cell_id, chain, n, link, at, signature, received_at, witness_seq, witness_link) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &id,
            &code,
            &n,
            &link,
            &a.at,
            &a.signature,
            &f.received_at,
            &seq,
            &witness_link,
        ],
    )
    .await
    .map_err(db("prepare"))?;
    tx.execute(
        "INSERT INTO witness.receipt (cell_id, chain, witness_seq, signature) VALUES ($1, $2, $3, $4)",
        &[&id, &code, &seq, &row.receipt.signature],
    )
    .await
    .map_err(db("receipt"))?;
    tx.commit().await.map_err(db("prepare"))
}

/// Stores an abort or an in-doubt record of `(n, link)`.
///
/// # Errors
///
/// [`StoreError::Unavailable`] when the row cannot be written.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one column of the record"
)]
pub async fn insert_withdrawal<R: Runtime>(
    client: &mut Client<R>,
    cell: CellId,
    chain: ChainId,
    kind: RecordKind,
    n: u64,
    link: &Link,
    received_at: i64,
    w: &Withdrawal,
) -> Result<(), StoreError> {
    let id = cell.0.to_vec();
    let code = chain_code(chain);
    let kind = i16::from(kind.code());
    let n = int(n, "row number")?;
    let seq = int(w.witness_seq, "witness sequence")?;
    let link = link.0.to_vec();
    let witness_link = w.witness_link.0.to_vec();
    client
        .execute(
            "INSERT INTO witness.withdrawal (cell_id, chain, witness_seq, kind, n, link, received_at, witness_link) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&id, &code, &seq, &kind, &n, &link, &received_at, &witness_link],
        )
        .await
        .map(drop)
        .map_err(db("withdrawal"))
}

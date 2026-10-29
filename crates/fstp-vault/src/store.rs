//! The vault database `v_<cell>` through the in-house `fstp-pgwire`
//! (design sections 4.3 and 4.6).
//!
//! - [`migrate`] applies [`crate::MIGRATIONS`] with `fstp-migrate`.
//! - [`persist`] writes the journal of one vault call in one transaction.
//!   A second use of a ticket violates the primary key of
//!   `vault.ticket_used`, so the database refuses a replay even if memory
//!   were wrong (ADR-009 "Single use").
//! - [`load`] rebuilds a [`Vault`] from the rows, replaying every write
//!   and acknowledgement through `fstp-vault-core`, so a restarted vault
//!   holds exactly the epochs it acknowledged.
//!
//! Every fact body, affected set and negotiation account set is sealed by
//! a [`Sealer`] before it is stored. The production sealer is the vault
//! chain's data key from `fstp-keys`, which lane W2f writes. A query is
//! stored only as a keyed digest.
//!
//! Reading, reported to Daniel: design section 4.3 has no table for the
//! P-17 conditions. `vault.p17_condition` holds them, insert-only, so a
//! condition stays fixed across restarts.
//!
//! [`load`] fails closed on a gap between epochs, an epoch with no fact,
//! a fact whose kind column is not its body's kind, or a write that does
//! not replay to its own epoch.

use std::collections::BTreeSet;

use fstp_pgwire::{Client, Uuid};
use fstp_rt::Runtime;
use fstp_vault_core::{Fact, Person, VaultEvent};
use fstp_vault_proto::json::{self, parse_canonical, response_limits};
use fstp_vault_proto::{WireAccount, WireProgramme, WireProposal};

use crate::origin::{JournalEntry, Vault};
use crate::{MATCH_KEY_LEN, VaultError, codec};

/// A sealed value and the data key that sealed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedValue {
    /// The data key id (`vault.fact.dek`).
    pub dek: [u8; 16],
    /// The sealed bytes. They name their data key, so [`Sealer::open`]
    /// needs nothing else.
    pub bytes: Vec<u8>,
}

/// Seals and opens the vault's stored values, and digests queries under a
/// key that erasure rotates.
pub trait Sealer: Send + Sync {
    /// Seals `plain`, bound to `aad`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when no key can seal.
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<SealedValue, VaultError>;

    /// Opens `sealed`, bound to `aad`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] when the value does not open.
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// The keyed digest of `data`.
    fn digest(&self, data: &[u8]) -> [u8; 32];
}

const DB: &str = "vault database";

fn db(_: fstp_pgwire::Error) -> VaultError {
    VaultError::Unavailable(DB)
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_bytes(n.to_be_bytes())
}

fn from_uuid(u: &Uuid) -> u128 {
    u128::from_be_bytes(*u.as_bytes())
}

fn int(n: u64) -> Result<i64, VaultError> {
    i64::try_from(n).map_err(|_| VaultError::Malformed("an integer beyond the database range"))
}

fn uint(n: i64) -> Result<u64, VaultError> {
    u64::try_from(n).map_err(|_| VaultError::Malformed("a negative stored integer"))
}

fn aad(table: &[u8], key: &[u8]) -> Vec<u8> {
    [table, b"|", key].concat()
}

fn accounts_bytes(set: &BTreeSet<WireAccount>) -> Result<Vec<u8>, VaultError> {
    json::to_canonical(&json::id_list_json(set.iter().map(|a| a.0)))
        .map_err(|_| VaultError::Malformed("an account set"))
}

fn accounts_of(bytes: &[u8]) -> Result<BTreeSet<WireAccount>, VaultError> {
    let bad = |_| VaultError::Malformed("a stored account set");
    let v = parse_canonical(bytes, &response_limits()).map_err(bad)?;
    Ok(json::id_list_value(&v, "a stored account set")
        .map_err(bad)?
        .into_iter()
        .map(WireAccount)
        .collect())
}

fn countries_bytes(set: &BTreeSet<u16>) -> Result<Vec<u8>, VaultError> {
    let bad = |_| VaultError::Malformed("a P-17 condition");
    let items = set
        .iter()
        .map(|c| json::uint_json(u64::from(*c), "a P-17 condition"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    json::to_canonical(&fstp_json::Value::Array(items.into_iter().collect())).map_err(bad)
}

fn countries_of(bytes: &[u8]) -> Result<BTreeSet<u16>, VaultError> {
    let bad = VaultError::Malformed("a stored P-17 condition");
    let v = parse_canonical(bytes, &json::limits()).map_err(|_| bad)?;
    let items = v.as_array().ok_or(bad)?;
    let mut out = BTreeSet::new();
    for item in items.iter() {
        let c = json::uint_value(item, "a stored P-17 condition").map_err(|_| bad)?;
        let c = u16::try_from(c).map_err(|_| bad)?;
        if out.last().is_some_and(|last| *last >= c) {
            return Err(bad);
        }
        out.insert(c);
    }
    Ok(out)
}

/// The id the stored fact row names as its subject.
fn subject_of(f: &Fact) -> u128 {
    match f {
        Fact::ProximityListDeclared { list, .. } => list.0,
        Fact::ConsentWithdrawn { proposal } => proposal.0,
        other => other.subject().map_or(0, |a| a.0),
    }
}

/// Applies the vault migrations.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the migration set does not apply.
pub async fn migrate<R: Runtime>(client: &mut Client<R>) -> Result<(), VaultError> {
    let set = fstp_migrate::MigrationSet::new(crate::MIGRATIONS)
        .map_err(|_| VaultError::Malformed("vault migrations"))?;
    set.apply(client)
        .await
        .map(|_| ())
        .map_err(|_| VaultError::Unavailable("vault migrations"))
}

/// Writes `entries` in one transaction.
///
/// # Errors
///
/// [`VaultError::Conflict`] when a ticket was used before, and
/// [`VaultError::Unavailable`] for any other database failure. Nothing is
/// written then.
pub async fn persist<R: Runtime>(
    client: &mut Client<R>,
    sealer: &dyn Sealer,
    entries: &[JournalEntry],
) -> Result<(), VaultError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut tx = client.transaction().await.map_err(db)?;
    for e in entries {
        match e {
            JournalEntry::Written {
                epoch,
                fact,
                affected,
                at,
            } => {
                let key = epoch.to_be_bytes();
                let sealed_affected = sealer.seal(
                    &aad(b"vault.epoch.affected", &key),
                    &accounts_bytes(affected)?,
                )?;
                let body = sealer.seal(
                    &aad(b"vault.fact.body", &key),
                    &codec::encode_fact_body(fact)?,
                )?;
                let fact_id = Uuid::new_v4().map_err(|_| VaultError::Unavailable("randomness"))?;
                let e = int(*epoch)?;
                tx.execute(
                    "INSERT INTO vault.epoch (epoch, state, created_at, affected) VALUES ($1, 1, $2, $3)",
                    &[&e, at, &sealed_affected.bytes],
                )
                .await
                .map_err(db)?;
                tx.execute(
                    "INSERT INTO vault.fact (fact_id, epoch, kind, subject, dek, body) VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &fact_id,
                        &e,
                        &i16::try_from(fact.kind()).map_err(|_| VaultError::Malformed("fact kind"))?,
                        &uuid(subject_of(fact)),
                        &Uuid::from_bytes(body.dek),
                        &body.bytes,
                    ],
                )
                .await
                .map_err(db)?;
            }
            JournalEntry::Acked {
                epoch,
                seq,
                link,
                affected,
                at,
            } => {
                let key = epoch.to_be_bytes();
                let sealed_affected = sealer.seal(
                    &aad(b"vault.epoch.affected", &key),
                    &accounts_bytes(affected)?,
                )?;
                let link = link.map(|l| l.to_vec());
                let n = tx
                    .execute(
                        "UPDATE vault.epoch SET state = 2, ack_seq = $2, ack_link = $3, acked_at = $4, affected = $5 WHERE epoch = $1 AND state = 1",
                        &[&int(*epoch)?, &int(*seq)?, &link, at, &sealed_affected.bytes],
                    )
                    .await
                    .map_err(db)?;
                if n != 1 {
                    return Err(VaultError::Unavailable(DB));
                }
            }
            JournalEntry::TicketUsed { nonce, at } => {
                let r = tx
                    .execute(
                        "INSERT INTO vault.ticket_used (ticket_id, used_at) VALUES ($1, $2)",
                        &[&nonce.to_vec(), at],
                    )
                    .await;
                if let Err(err) = r {
                    return Err(if err.code() == Some("23505") {
                        VaultError::Conflict("a used ticket")
                    } else {
                        VaultError::Unavailable(DB)
                    });
                }
            }
            JournalEntry::NegotiationOpened {
                proposal,
                accounts,
                seq,
            } => {
                let sealed = sealer.seal(
                    &aad(b"vault.negotiation", &proposal.0.to_be_bytes()),
                    &accounts_bytes(accounts)?,
                )?;
                // The row changes only for a sequence newer than any it
                // holds, as in memory, so a stale open never reopens it.
                let n = tx
                    .execute(
                        "INSERT INTO vault.negotiation (proposal_id, sealed_accounts, opened_seq, closed_seq) VALUES ($1, $2, $3, NULL) ON CONFLICT (proposal_id) DO UPDATE SET sealed_accounts = EXCLUDED.sealed_accounts, opened_seq = EXCLUDED.opened_seq, closed_seq = NULL WHERE greatest(vault.negotiation.opened_seq, coalesce(vault.negotiation.closed_seq, -1)) < EXCLUDED.opened_seq",
                        &[&uuid(proposal.0), &sealed.bytes, &int(*seq)?],
                    )
                    .await
                    .map_err(db)?;
                if n != 1 {
                    return Err(VaultError::Unavailable(DB));
                }
            }
            JournalEntry::NegotiationClosed { proposal, seq } => {
                // A close with no open row still records its sequence, so a
                // reordered older open stays refused after a restart.
                let sealed = sealer.seal(
                    &aad(b"vault.negotiation", &proposal.0.to_be_bytes()),
                    &accounts_bytes(&BTreeSet::new())?,
                )?;
                let n = tx
                    .execute(
                        "INSERT INTO vault.negotiation (proposal_id, sealed_accounts, opened_seq, closed_seq) VALUES ($1, $2, $3, $3) ON CONFLICT (proposal_id) DO UPDATE SET closed_seq = EXCLUDED.closed_seq WHERE greatest(vault.negotiation.opened_seq, coalesce(vault.negotiation.closed_seq, -1)) < EXCLUDED.closed_seq",
                        &[&uuid(proposal.0), &sealed.bytes, &int(*seq)?],
                    )
                    .await
                    .map_err(db)?;
                if n != 1 {
                    return Err(VaultError::Unavailable(DB));
                }
            }
            JournalEntry::Asked {
                at,
                query,
                holds,
                epoch,
            } => {
                let digest = sealer.digest(&[&query.kind.to_be_bytes()[..], &query.args].concat());
                tx.execute(
                    "INSERT INTO vault.query_log (n, at, query_digest, holds, epoch) SELECT coalesce(max(n), 0) + 1, $1::bigint, $2::bytea, $3::boolean, $4::bigint FROM vault.query_log",
                    &[at, &digest.to_vec(), holds, &int(*epoch)?],
                )
                .await
                .map_err(db)?;
            }
            JournalEntry::P17Set {
                programme,
                countries,
            } => {
                tx.execute(
                    "INSERT INTO vault.p17_condition (programme_id, countries) VALUES ($1, $2)",
                    &[&uuid(programme.0), &countries_bytes(countries)?],
                )
                .await
                .map_err(db)?;
            }
            JournalEntry::IdentityAssigned {
                identity,
                match_key,
            } => {
                tx.execute(
                    "INSERT INTO vault.identity (identity_id, match_key) VALUES ($1, $2)",
                    &[&uuid(identity.0), &match_key.to_vec()],
                )
                .await
                .map_err(db)?;
            }
            JournalEntry::AccountVerified {
                account,
                identity,
                epoch,
            } => {
                tx.execute(
                    "INSERT INTO vault.account (account_id, identity_id, verified_epoch) VALUES ($1, $2, $3) ON CONFLICT (account_id) DO UPDATE SET identity_id = EXCLUDED.identity_id, verified_epoch = EXCLUDED.verified_epoch",
                    &[&uuid(account.0), &uuid(identity.0), &int(*epoch)?],
                )
                .await
                .map_err(db)?;
            }
        }
    }
    tx.commit().await.map_err(db)
}

/// Rebuilds the vault of `cell` from its database, with the pinned ticket
/// keys `pinned`.
///
/// Every stored write and acknowledgement is replayed through
/// `fstp-vault-core` in epoch order. A row that does not open, decode or
/// replay to its own epoch fails the load closed (NOTE 2).
///
/// # Errors
///
/// [`VaultError::Malformed`] for a corrupt row and
/// [`VaultError::Unavailable`] for a database failure.
pub async fn load<R: Runtime>(
    client: &mut Client<R>,
    sealer: &dyn Sealer,
    cell: [u8; 16],
    pinned: &[[u8; 32]],
) -> Result<Vault, VaultError> {
    let corrupt = VaultError::Malformed("a stored vault row");
    let mut v = Vault::new(cell, pinned)?;
    // The P-17 conditions first: a condition is set before any country of
    // its programme, so it replays before the facts.
    let conditions = client
        .query(
            "SELECT programme_id, countries FROM vault.p17_condition ORDER BY programme_id",
            &[],
        )
        .await
        .map_err(db)?;
    for row in &conditions {
        let id: Uuid = row.get(0).map_err(|_| corrupt)?;
        let countries: Vec<u8> = row.get(1).map_err(|_| corrupt)?;
        v.replay_p17(WireProgramme(from_uuid(&id)), &countries_of(&countries)?)
            .map_err(|_| corrupt)?;
    }
    let identities = client
        .query("SELECT identity_id, match_key FROM vault.identity", &[])
        .await
        .map_err(db)?;
    for row in &identities {
        let id: Uuid = row.get(0).map_err(|_| corrupt)?;
        let key: Vec<u8> = row.get(1).map_err(|_| corrupt)?;
        let key = <[u8; MATCH_KEY_LEN]>::try_from(key.as_slice()).map_err(|_| corrupt)?;
        v.replay_identity(Person(from_uuid(&id)), key)?;
    }
    // Every epoch row with its fact, if any: an epoch without a fact is a
    // corrupt row, so the join keeps it to refuse it.
    let rows = client
        .query(
            "SELECT e.epoch, e.state, e.created_at, e.ack_seq, e.ack_link, f.body, f.kind FROM vault.epoch e LEFT JOIN vault.fact f ON f.epoch = e.epoch ORDER BY e.epoch",
            &[],
        )
        .await
        .map_err(db)?;
    let mut expected: u64 = 0;
    for row in &rows {
        // Epochs are consecutive from 1: every write takes the next one.
        expected = expected.checked_add(1).ok_or(corrupt)?;
        let epoch = uint(row.get::<i64>(0).map_err(|_| corrupt)?)?;
        if epoch != expected {
            return Err(corrupt);
        }
        let state: i16 = row.get(1).map_err(|_| corrupt)?;
        let at: i64 = row.get(2).map_err(|_| corrupt)?;
        let ack_seq: Option<i64> = row.get(3).map_err(|_| corrupt)?;
        let ack_link: Option<Vec<u8>> = row.get(4).map_err(|_| corrupt)?;
        let body: Option<Vec<u8>> = row.get(5).map_err(|_| corrupt)?;
        let kind: Option<i16> = row.get(6).map_err(|_| corrupt)?;
        let (Some(body), Some(kind)) = (body, kind) else {
            return Err(corrupt);
        };
        let plain = sealer.open(&aad(b"vault.fact.body", &epoch.to_be_bytes()), &body)?;
        let fact = codec::stored_fact(&plain)?;
        if i16::try_from(fact.kind()).ok() != Some(kind) {
            return Err(corrupt);
        }
        let events = v.replay_write(fact, at).map_err(|_| corrupt)?;
        let opened = events.contains(&VaultEvent::Provisional { epoch });
        // A queued write takes the epoch after the provisional one and the
        // writes queued before it.
        let queued = events.is_empty()
            && u64::try_from(v.state().queued())
                .ok()
                .and_then(|q| v.state().current().checked_add(q))
                == Some(epoch);
        if !opened && !queued {
            return Err(corrupt);
        }
        if state == 2 {
            let seq = uint(ack_seq.ok_or(corrupt)?)?;
            let link = match ack_link {
                Some(l) => Some(<[u8; 32]>::try_from(l.as_slice()).map_err(|_| corrupt)?),
                None => None,
            };
            let acked = v.replay_ack(epoch, seq, link).map_err(|_| corrupt)?;
            if !acked.contains(&VaultEvent::Effective { epoch }) {
                return Err(corrupt);
            }
        } else if state != 1 {
            return Err(corrupt);
        }
    }
    let tickets = client
        .query("SELECT ticket_id FROM vault.ticket_used", &[])
        .await
        .map_err(db)?;
    for row in &tickets {
        let id: Vec<u8> = row.get(0).map_err(|_| corrupt)?;
        v.replay_ticket(<[u8; 16]>::try_from(id.as_slice()).map_err(|_| corrupt)?);
    }
    // Every negotiation row, open or closed: a closed row keeps the
    // highest sequence, so a stale open stays refused after a restart.
    let negotiations = client
        .query(
            "SELECT proposal_id, sealed_accounts, opened_seq, closed_seq FROM vault.negotiation",
            &[],
        )
        .await
        .map_err(db)?;
    for row in &negotiations {
        let id: Uuid = row.get(0).map_err(|_| corrupt)?;
        let sealed: Vec<u8> = row.get(1).map_err(|_| corrupt)?;
        let opened_seq = uint(row.get::<i64>(2).map_err(|_| corrupt)?)?;
        let closed_seq = match row.get::<Option<i64>>(3).map_err(|_| corrupt)? {
            Some(s) => Some(uint(s)?),
            None => None,
        };
        let proposal = WireProposal(from_uuid(&id));
        let plain = sealer.open(
            &aad(b"vault.negotiation", &proposal.0.to_be_bytes()),
            &sealed,
        )?;
        v.replay_negotiation(proposal, &accounts_of(&plain)?, opened_seq, closed_seq)
            .map_err(|_| corrupt)?;
    }
    Ok(v)
}

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
//! `vault.country_condition` holds the P-17 country conditions (design
//! section 4.3), insert-only, so a condition stays fixed across restarts.
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

    /// The id of the shared `Fact` data key, which a stored row names in
    /// its `dek` column. `None`, the default, reads every stored row as
    /// sealed by [`Sealer::open`]: a sealer with no identity fact keys.
    fn shared_dek(&self) -> Option<[u8; 16]> {
        None
    }

    /// Seals `plain` under the fact key `F(X)` of `identity`, bound to
    /// `aad` (ADR-004 record of lane L13). The value names `identity` as
    /// its data key.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when the sealer holds no key of
    /// `identity`, which the default never does.
    fn seal_identity(
        &self,
        identity: Person,
        aad: &[u8],
        plain: &[u8],
    ) -> Result<SealedValue, VaultError> {
        let _ = (identity, aad, plain);
        Err(VaultError::Unavailable("the identity fact keys"))
    }

    /// Opens `sealed` under the fact key of `identity`, bound to `aad`.
    /// `None` when the sealer holds no key of `identity`: it is erased, or
    /// was never registered, and its facts read as erased.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] when the key is held and the value does
    /// not open.
    fn open_identity(
        &self,
        identity: Person,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let _ = (identity, aad, sealed);
        Ok(None)
    }

    /// Whether the sealer holds the fact key of `identity`.
    fn has_identity(&self, identity: Person) -> bool {
        let _ = identity;
        false
    }
}

/// The kind codes of the identity facts ([`crate::origin::is_identity_fact`]).
pub const IDENTITY_FACT_KINDS: [i16; 2] = [14, 17];

/// The start check of ADR-004 record of lane L13, row "Existing facts":
/// refuses a vault that holds an identity fact sealed under the shared
/// `Fact` data key of `sealer`, since no erasure could make it unreadable.
///
/// # Errors
///
/// [`VaultError::Malformed`] when such a fact is stored or the sealer
/// names no shared key, and [`VaultError::Unavailable`] for a database
/// failure.
pub async fn check_identity_facts<R: Runtime>(
    client: &mut Client<R>,
    sealer: &dyn Sealer,
) -> Result<(), VaultError> {
    let refused = VaultError::Malformed(
        "an identity fact sealed under the shared Fact key: recreate this pilot vault",
    );
    let dek = sealer.shared_dek().ok_or(refused)?;
    let rows = client
        .query(
            "SELECT count(*) FROM vault.fact WHERE kind IN ($1, $2) AND dek = $3",
            &[
                &IDENTITY_FACT_KINDS[0],
                &IDENTITY_FACT_KINDS[1],
                &Uuid::from_bytes(dek),
            ],
        )
        .await
        .map_err(db)?;
    let n: i64 = rows
        .first()
        .and_then(|r| r.get(0).ok())
        .ok_or(VaultError::Unavailable(DB))?;
    if n == 0 { Ok(()) } else { Err(refused) }
}

/// The AAD of an identity fact body at `epoch`, sealed for `identity`
/// (ADR-004 record of lane L13, row "Fact seal").
#[must_use]
pub fn identity_fact_aad(epoch: u64, identity: Person) -> Vec<u8> {
    let mut out = b"vault.identity_fact.body|".to_vec();
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&identity.0.to_be_bytes());
    out
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
    persist_in(&mut tx, sealer, entries).await?;
    tx.commit().await.map_err(db)
}

/// The digest of one stored row: SHA-256 over each stored column value,
/// each with its 4-byte big-endian length, after the table name. Sealed
/// values enter as their stored bytes, so the digest needs no key.
fn row_digest(table: &[u8], columns: &[&[u8]]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    for part in std::iter::once(table).chain(columns.iter().copied()) {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        h.update(&len.to_be_bytes());
        h.update(part);
    }
    h.finish()
}

/// Writes `entries` inside the open transaction `tx`, and returns the
/// digest of each row it inserted or changed, in order. The vault chain
/// writer binds these digests in the entry of its kind 1 row
/// (`crate::chain`, ADR-010 open point 5).
///
/// # Errors
///
/// As [`persist`]. The caller rolls the transaction back.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per journal entry, as the tables list them"
)]
pub async fn persist_in<R: Runtime>(
    tx: &mut fstp_pgwire::Transaction<'_, R>,
    sealer: &dyn Sealer,
    entries: &[JournalEntry],
) -> Result<Vec<[u8; 32]>, VaultError> {
    let mut digests = Vec::with_capacity(entries.len());
    for e in entries {
        match e {
            JournalEntry::Written {
                epoch,
                fact,
                affected,
                at,
                sealed_for,
            } => {
                let key = epoch.to_be_bytes();
                let sealed_affected = sealer.seal(
                    &aad(b"vault.epoch.affected", &key),
                    &accounts_bytes(affected)?,
                )?;
                let plain = codec::encode_fact_body(fact)?;
                let body = match sealed_for {
                    Some(p) => sealer.seal_identity(*p, &identity_fact_aad(*epoch, *p), &plain)?,
                    None => sealer.seal(&aad(b"vault.fact.body", &key), &plain)?,
                };
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
                digests.push(row_digest(
                    b"vault.fact",
                    &[&key, &sealed_affected.bytes, &body.dek, &body.bytes],
                ));
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
                digests.push(row_digest(
                    b"vault.epoch",
                    &[&key, &seq.to_be_bytes(), &sealed_affected.bytes],
                ));
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
                digests.push(row_digest(
                    b"vault.ticket_used",
                    &[nonce, &at.to_be_bytes()],
                ));
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
                digests.push(row_digest(
                    b"vault.negotiation",
                    &[&proposal.0.to_be_bytes(), &sealed.bytes, &seq.to_be_bytes()],
                ));
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
                digests.push(row_digest(
                    b"vault.negotiation.closed",
                    &[&proposal.0.to_be_bytes(), &seq.to_be_bytes()],
                ));
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
                digests.push(row_digest(
                    b"vault.query_log",
                    &[
                        &at.to_be_bytes(),
                        &digest,
                        &[u8::from(*holds)],
                        &epoch.to_be_bytes(),
                    ],
                ));
            }
            JournalEntry::P17Set {
                programme,
                countries,
            } => {
                tx.execute(
                    "INSERT INTO vault.country_condition (programme_id, countries) VALUES ($1, $2)",
                    &[&uuid(programme.0), &countries_bytes(countries)?],
                )
                .await
                .map_err(db)?;
                digests.push(row_digest(
                    b"vault.country_condition",
                    &[&programme.0.to_be_bytes(), &countries_bytes(countries)?],
                ));
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
                digests.push(row_digest(
                    b"vault.identity",
                    &[&identity.0.to_be_bytes(), match_key],
                ));
            }
            JournalEntry::IdentityRekeyed {
                identity,
                match_key,
            } => {
                let n = tx
                    .execute(
                        "UPDATE vault.identity SET match_key = $2 WHERE identity_id = $1",
                        &[&uuid(identity.0), &match_key.to_vec()],
                    )
                    .await
                    .map_err(db)?;
                if n != 1 {
                    return Err(VaultError::Unavailable(DB));
                }
                digests.push(row_digest(
                    b"vault.identity",
                    &[&identity.0.to_be_bytes(), match_key],
                ));
            }
            // Step 7 of an erasure batch (ADR-004 record of lane L11): the
            // records write no vault table, since the keystore rows belong
            // to the keys role. The chain entry binds their digests.
            JournalEntry::KeyEpochDestroyed {
                epoch,
                receipt_digest,
            } => {
                digests.push(row_digest(
                    b"vault.key_epoch_destroyed",
                    &[
                        &[fstp_keys::Chain::Vault.code()],
                        &epoch.to_be_bytes(),
                        receipt_digest,
                    ],
                ));
            }
            JournalEntry::IdentityErased { identity } => {
                // ADR-004 record of lane L13 "Erasure": the identity's
                // accounts are unbound, so they register again as a new
                // identity before any identity fact of theirs is taken.
                tx.execute(
                    "UPDATE vault.identity_account SET identity_id = NULL WHERE identity_id = $1",
                    &[&uuid(identity.0)],
                )
                .await
                .map_err(db)?;
                digests.push(row_digest(
                    b"vault.identity_erased",
                    &[&identity.0.to_be_bytes()],
                ));
            }
            JournalEntry::IdentityRegistered {
                account,
                identity,
                at,
            } => {
                // A new binding, or one an erasure ended (ADR-004 record of
                // lane L13). A live binding never moves: the vault refuses
                // that in memory, and the row refuses it here.
                let n = tx
                    .execute(
                        "INSERT INTO vault.identity_account (account_id, identity_id, registered_at) VALUES ($1, $2, $3) ON CONFLICT (account_id) DO UPDATE SET identity_id = EXCLUDED.identity_id, registered_at = EXCLUDED.registered_at WHERE vault.identity_account.identity_id IS NULL",
                        &[&uuid(account.0), &uuid(identity.0), at],
                    )
                    .await
                    .map_err(db)?;
                if n != 1 {
                    return Err(VaultError::Conflict("an account of another identity"));
                }
                digests.push(row_digest(
                    b"vault.identity_account",
                    &[
                        &account.0.to_be_bytes(),
                        &identity.0.to_be_bytes(),
                        &at.to_be_bytes(),
                    ],
                ));
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
                digests.push(row_digest(
                    b"vault.account",
                    &[
                        &account.0.to_be_bytes(),
                        &identity.0.to_be_bytes(),
                        &epoch.to_be_bytes(),
                    ],
                ));
            }
        }
    }
    Ok(digests)
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
            "SELECT programme_id, countries FROM vault.country_condition ORDER BY programme_id",
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
    // The bindings of live identities (ADR-004 record of lane L13, row
    // "Load"): a binding to an identity whose fact key the sealer does not
    // hold names an erased identity, and is dropped.
    let bindings = client
        .query(
            "SELECT account_id, identity_id FROM vault.identity_account WHERE identity_id IS NOT NULL ORDER BY account_id",
            &[],
        )
        .await
        .map_err(db)?;
    for row in &bindings {
        let account: Uuid = row.get(0).map_err(|_| corrupt)?;
        let identity = Person(from_uuid(&row.get::<Uuid>(1).map_err(|_| corrupt)?));
        if sealer.has_identity(identity) {
            v.replay_binding(WireAccount(from_uuid(&account)), identity)?;
        }
    }
    // Every epoch row with its fact, if any: an epoch without a fact is a
    // corrupt row, so the join keeps it to refuse it.
    let rows = client
        .query(
            "SELECT e.epoch, e.state, e.created_at, e.ack_seq, e.ack_link, f.body, f.kind, f.dek FROM vault.epoch e LEFT JOIN vault.fact f ON f.epoch = e.epoch ORDER BY e.epoch",
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
        let dek: Option<Uuid> = row.get(7).map_err(|_| corrupt)?;
        let (Some(body), Some(kind), Some(dek)) = (body, kind, dek) else {
            return Err(corrupt);
        };
        let shared = sealer.shared_dek().is_none_or(|d| d == *dek.as_bytes());
        let plain = if shared {
            Some(sealer.open(&aad(b"vault.fact.body", &epoch.to_be_bytes()), &body)?)
        } else {
            let identity = Person(from_uuid(&dek));
            sealer.open_identity(identity, &identity_fact_aad(epoch, identity), &body)?
        };
        let events = match plain {
            Some(plain) => {
                let fact = codec::stored_fact(&plain)?;
                if i16::try_from(fact.kind()).ok() != Some(kind)
                    || (!shared && !crate::origin::is_identity_fact(&fact))
                {
                    return Err(corrupt);
                }
                v.replay_write(fact, at).map_err(|_| corrupt)?
            }
            // ADR-004 record of lane L13 "Load": the fact key of its identity
            // is gone, so the write is erased. Only identity fact kinds are
            // sealed for an identity.
            None if IDENTITY_FACT_KINDS.contains(&kind) => {
                v.replay_erased(at).map_err(|_| corrupt)?
            }
            None => return Err(corrupt),
        };
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

//! The erasure runner of the Vault chain (design section 3.5, I-81,
//! R-KY-02, G24, ADR-004 record of lane L11).
//!
//! The planner is `fstp_keys::erasure`. [`Runner`] is its shell over the
//! vault keystore ([`crate::keystore`]), written through the keys login
//! only, and the vault's own custody entry. The vault's identity rows move
//! through the vault login, as a [`Journal`] of [`crate::origin::Vault`].
//!
//! # One batch, from epoch `e` to `e + 1`
//!
//! Each call of [`Runner::step`] does one unit of work and returns its
//! [`ErasureEvent`], so a crash can fall between any two of them:
//!
//! 1. [`Runner::request_erasure`]: the identity's tuple data key joins the
//!    chain state, and the intent row is written. The tuple is refused for
//!    open from here on.
//! 2. [`ErasureEvent::GroupsRotated`] and one [`ErasureEvent::KeysResealed`]
//!    per affected group: new key pairs for the identity's `Attribute`
//!    group and the `Match` group, and every surviving tuple key sealed to
//!    the new generation.
//! 3. [`ErasureEvent::RootCreated`]: `R(e+1)` is created in custody and
//!    written as pending at once, so a restart reuses it. `S(e+1)` is drawn
//!    and wrapped. [`ErasureEvent::GroupsResealed`]: every live group
//!    secret is sealed under `S(e+1)`.
//! 4. [`ErasureEvent::Committed`]: one transaction of the keys login.
//!    [`ErasureEvent::IdentitiesRekeyed`]: the live identities move to
//!    their match keys under the new `Match` key, and each erased identity
//!    gets 32 random bytes, through `Vault::rekey_identities` (G24).
//! 5. [`ErasureEvent::SnapshotTaken`] and [`ErasureEvent::SnapshotVerified`]:
//!    the committed rows are read back from the database, as the vault
//!    cluster's backups hold them, and opened from that copy under
//!    `R(e+1)` through custody.
//! 6. [`ErasureEvent::RootDestroyed`]: `R(e)` is destroyed in custody, and
//!    its row keeps the receipt. `S(e)` and the old group secrets are
//!    dropped, which wipes them.
//! 7. [`ErasureEvent::CompletionRecorded`]: `KeyEpochDestroyed` and one
//!    `IdentityErased` per identity, in one vault journal.
//!
//! # Durability
//!
//! The chain state is written with the request and with every step from
//! the commit on. Steps 2 and 3 live in memory until the commit, so a
//! restart before it starts the batch again from step 2, with the same
//! batch (`ChainState::restart`). The rekey repeats after a restart until
//! the snapshot step is durable. A key mapped to itself changes nothing,
//! so only the erased identities get fresh random bytes again.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;

use fstp_crypto::aead;
use fstp_crypto::composite::CompositeSigningKey;
use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_custody::{CellId, Custody, CustodyHandle, RootLabel, RootRef, SealKey, WrappedSealKey};
use fstp_keys::envelope::{self, DataKey};
use fstp_keys::erasure::{self as plan, ChainState, GROUP_LIMIT, Phase, Step, codec};
use fstp_keys::{DekId, Epoch, GroupId, Purpose};
use fstp_pgwire::Client;
use fstp_rt::Runtime;
use fstp_vault_core::Person;
use fstp_vault_proto::WireAccount;

use crate::keystore::{
    self, CHAIN, Change, DataKeyRow, GroupRow, IdentityKeys, IntentRow, KeystoreRows, MAX_TUPLE,
    RootRow, STATE_DESTROYED, STATE_LIVE, STATE_PENDING, TupleRow, VaultKeys,
};
use crate::origin::{JournalEntry, Vault};
use crate::{MATCH_KEY_LEN, VaultError};

/// The AAD label of the sealed chain state.
pub const CHAIN_STATE_AAD: &[u8] = b"fstp-vault-chain-state-v1";

/// One unit of the runner's work, in design order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureEvent {
    /// Step 2: the affected groups got new key pairs.
    GroupsRotated,
    /// Step 2: the surviving keys of one group were sealed to its new
    /// generation.
    KeysResealed,
    /// Step 3: `R(epoch)` exists and `S(epoch)` is wrapped under it.
    RootCreated {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 3: every live group secret was sealed under `S(epoch)`.
    GroupsResealed {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 4: the new rows of `epoch` were committed.
    Committed {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 4: the identities moved to their match keys under the new
    /// `Match` key (G24).
    IdentitiesRekeyed {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 5: the committed rows were read back.
    SnapshotTaken {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 5: the copy opened under `R(epoch)`.
    SnapshotVerified {
        /// The new epoch.
        epoch: u64,
    },
    /// Step 6: `R(epoch)` was destroyed and its receipt kept.
    RootDestroyed {
        /// The old epoch.
        epoch: u64,
    },
    /// Step 7: the destroyed epoch and the erased identities were
    /// journaled.
    CompletionRecorded {
        /// The old epoch.
        epoch: u64,
    },
}

/// Where the vault's identity rows go: the vault chain writer in the
/// vault process, `crate::store::persist` in a test.
pub trait Journal {
    /// Commits `entries` whole, or nothing.
    fn commit(
        &mut self,
        entries: &[JournalEntry],
        now: i64,
    ) -> impl Future<Output = Result<(), VaultError>>;
}

fn bad(rule: &'static str) -> VaultError {
    VaultError::Malformed(rule)
}

fn keys(rule: &'static str) -> VaultError {
    VaultError::Unavailable(rule)
}

fn planner(_: plan::KeyFoldError) -> VaultError {
    VaultError::Malformed("the erasure planner refused a step")
}

/// The planner phase as `keystore.erasure_intent.phase` holds it.
#[must_use]
pub const fn phase_code(p: Phase) -> i16 {
    match p {
        Phase::Idle => 0,
        Phase::Planned => 1,
        Phase::Resealed => 2,
        Phase::Committed => 3,
        Phase::SnapshotVerified => 4,
        Phase::Destroyed => 5,
    }
}

fn chain_aad(cell: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut aad = CHAIN_STATE_AAD.to_vec();
    aad.extend_from_slice(cell);
    aad.push(CHAIN.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn aead_key(s: &SealKey) -> Result<aead::Key, VaultError> {
    aead::Key::from_bytes(s.expose()).map_err(|_| bad("the seal key"))
}

fn seal_state(s: &SealKey, cell: &[u8; 16], state: &ChainState) -> Result<Vec<u8>, VaultError> {
    let plain = codec::encode(state).map_err(|_| bad("the chain state"))?;
    let sealed = aead::seal(&aead_key(s)?, &chain_aad(cell, state.epoch().0), &plain)
        .map_err(|_| keys("sealing"))?;
    let mut out = sealed.nonce.to_vec();
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

fn open_state(
    s: &SealKey,
    cell: &[u8; 16],
    epoch: u64,
    bytes: &[u8],
) -> Result<ChainState, VaultError> {
    let refused = bad("the sealed chain state");
    let (nonce, body) = bytes.split_at_checked(aead::NONCE_LEN).ok_or(refused)?;
    let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| refused)?;
    let plain =
        aead::open(&aead_key(s)?, &nonce, &chain_aad(cell, epoch), body).map_err(|_| refused)?;
    let state = codec::decode(&plain).map_err(|_| refused)?;
    if state.epoch().0 != epoch {
        return Err(refused);
    }
    Ok(state)
}

fn root_ref(cell: &[u8; 16], r: &RootRow) -> Result<RootRef, VaultError> {
    let backend = match r.backend {
        1 => fstp_custody::BackendId::Okms,
        2 => fstp_custody::BackendId::Keyd,
        3 => fstp_custody::BackendId::Simulator,
        _ => return Err(bad("the root backend")),
    };
    Ok(RootRef {
        backend,
        cell: Some(CellId(*cell)),
        chain: CHAIN,
        epoch: Epoch(r.epoch),
        handle: CustodyHandle(r.handle.clone()),
    })
}

async fn unwrap_root<C: Custody>(
    custody: &C,
    cell: &[u8; 16],
    r: &RootRow,
) -> Result<SealKey, VaultError> {
    custody
        .unwrap(
            &root_ref(cell, r)?,
            &WrappedSealKey(r.wrapped.clone()),
            &keystore::seal_aad(cell, r.epoch),
        )
        .await
        .map_err(|_| keys("custody unwrap"))
}

/// An open group secret.
enum Secret {
    Anchor(CompositeSigningKey),
    Kem(Box<HybridSecretKey>),
}

impl Secret {
    fn kem(&self) -> Result<&HybridSecretKey, VaultError> {
        match self {
            Secret::Kem(k) => Ok(k),
            Secret::Anchor(_) => Err(bad("the keystore groups")),
        }
    }
}

/// One live group: its purpose, its committed generation and its secret.
struct Open {
    purpose: Purpose,
    generation: u32,
    public: Vec<u8>,
    secret: Secret,
}

fn copy_kem(k: &HybridSecretKey) -> Result<HybridSecretKey, VaultError> {
    HybridSecretKey::from_bytes(&k.to_bytes()[..]).map_err(|_| bad("a group secret"))
}

/// Opens the group `g` under the seal key `s` of its epoch.
fn open_row(s: &aead::Key, cell: &[u8; 16], g: &GroupRow) -> Result<Open, VaultError> {
    let purpose = Purpose::from_code(g.purpose).ok_or(bad("a group purpose"))?;
    let secret = match purpose {
        Purpose::Anchor => Secret::Anchor(keystore::open_anchor(s, cell, g)?),
        Purpose::Fact | Purpose::Match | Purpose::Attribute => {
            Secret::Kem(Box::new(keystore::open_kem(s, cell, purpose, g)?))
        }
        _ => return Err(bad("a group purpose")),
    };
    Ok(Open {
        purpose,
        generation: g.generation,
        public: g.public_key.clone(),
        secret,
    })
}

/// The work of a batch before its commit, and of its snapshot. It lives
/// in memory only.
#[derive(Default)]
struct Work {
    /// The new key pair of each affected group.
    new_secrets: BTreeMap<[u8; 16], HybridSecretKey>,
    /// The surviving data keys, sealed to their group's new generation.
    resealed: BTreeMap<[u8; 16], DataKeyRow>,
    /// `R(e+1)`, its wrapped `S(e+1)` and `S(e+1)`.
    new_root: Option<(RootRow, SealKey)>,
    /// Every live group row sealed under `S(e+1)`.
    rewrapped: Vec<GroupRow>,
    /// Whether this process rekeyed the identities of the committed batch.
    rekeyed: bool,
    /// The committed rows read back in step 5.
    snapshot: Option<KeystoreRows>,
}

/// The erasure runner of one vault (module documentation).
pub struct Runner<'c, R: Runtime, C: Custody> {
    cell: [u8; 16],
    client: Client<R>,
    custody: &'c C,
    rows: KeystoreRows,
    chain: ChainState,
    intent: [u8; 16],
    seal: SealKey,
    open: BTreeMap<[u8; 16], Open>,
    work: Work,
    /// The fact keys `F(X)` of the live identities (ADR-004 record of lane
    /// L13), shared with the sealer of the vault's rows.
    identities: Arc<IdentityKeys>,
}

impl<R: Runtime, C: Custody> std::fmt::Debug for Runner<'_, R, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runner")
            .field("epoch", &self.chain.epoch().0)
            .field("phase", &self.chain.phase())
            .finish_non_exhaustive()
    }
}

/// The chain state of a keystore that genesis wrote and no change has
/// touched since (ADR-004 record of lane L11, row "A keystore from
/// genesis").
fn state_from_rows(rows: &KeystoreRows) -> Result<ChainState, VaultError> {
    let refused = bad("the keystore groups");
    let mut chain = ChainState::genesis(Epoch(rows.root.epoch));
    let mut fact = None;
    for g in &rows.groups {
        let purpose = Purpose::from_code(g.purpose).ok_or(refused)?;
        if g.generation != keystore::GENERATION {
            return Err(refused);
        }
        let id = GroupId(g.group);
        match purpose {
            Purpose::Anchor => chain.add_group_for(id, purpose).map_err(planner)?,
            Purpose::Fact => {
                chain.add_group_for(id, purpose).map_err(planner)?;
                fact = Some(id);
            }
            Purpose::Match => chain.add_digest_group(id, &[]).map_err(planner)?,
            _ => return Err(refused),
        }
    }
    let fact = fact.ok_or(refused)?;
    for d in &rows.data_keys {
        if d.group != fact.0 {
            return Err(bad("the keystore data keys"));
        }
        chain.admit(fact, DekId(d.id)).map_err(planner)?;
    }
    if !rows.tuples.is_empty() {
        return Err(bad("the keystore tuples"));
    }
    Ok(chain)
}

fn person_of(dek: DekId) -> Person {
    Person(u128::from_be_bytes(dek.0))
}

impl<'c, R: Runtime, C: Custody> Runner<'c, R, C> {
    /// Loads the keystore of `cell` over the keys login `client`, opens it
    /// through `custody`, and resumes the stored phase. A batch stored
    /// before its commit starts again from step 2.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] for an empty keystore, a failed read or
    /// a refused unwrap, and [`VaultError::Malformed`] for rows that do
    /// not open.
    pub async fn load(
        mut client: Client<R>,
        cell: [u8; 16],
        custody: &'c C,
    ) -> Result<Runner<'c, R, C>, VaultError> {
        let rows = keystore::read_rows(&mut client)
            .await?
            .ok_or(VaultError::Unavailable(
                "the vault keystore: run fstp-vault init-keys",
            ))?;
        let seal = unwrap_root(custody, &cell, &rows.root).await?;
        let (chain, intent) = match &rows.intent {
            Some(i) => (
                open_state(&seal, &cell, rows.root.epoch, &i.plan)?.restart(),
                i.id,
            ),
            None => (
                state_from_rows(&rows)?,
                fstp_crypto::random_array::<16>().map_err(|_| keys("randomness"))?,
            ),
        };
        let s = aead_key(&seal)?;
        let mut open = BTreeMap::new();
        for g in &rows.groups {
            let committed = chain.generation(GroupId(g.group));
            if committed != Some(g.generation) || g.epoch != rows.root.epoch {
                return Err(bad("the keystore groups"));
            }
            if open.insert(g.group, open_row(&s, &cell, g)?).is_some() {
                return Err(bad("the keystore groups"));
            }
        }
        let mut runner = Runner {
            cell,
            client,
            custody,
            rows,
            chain,
            intent,
            seal,
            open,
            work: Work::default(),
            identities: Arc::default(),
        };
        // Every group of the chain state has its row.
        for g in runner.chain_groups() {
            if !runner.open.contains_key(&g.0) {
                return Err(bad("the keystore groups"));
            }
        }
        runner.fill_identity_keys()?;
        Ok(runner)
    }

    fn chain_groups(&self) -> Vec<GroupId> {
        self.rows
            .groups
            .iter()
            .map(|g| GroupId(g.group))
            .filter(|g| self.chain.group(*g).is_some())
            .collect()
    }

    /// The current root epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.chain.epoch().0
    }

    /// Where the running batch stands.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.chain.phase()
    }

    /// The one group of `purpose`.
    fn group_of(&self, purpose: Purpose) -> Result<([u8; 16], &Open), VaultError> {
        let mut found = self.open.iter().filter(|(_, o)| o.purpose == purpose);
        match (found.next(), found.next()) {
            (Some((g, o)), None) => Ok((*g, o)),
            _ => Err(bad("the keystore groups")),
        }
    }

    /// The keys the vault service starts with: the anchor key, the `Fact`
    /// data key and the `Match` secret of the current generation.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] when a key does not open.
    pub fn service_keys(&self) -> Result<VaultKeys, VaultError> {
        let (anchor_group, anchor) = self.group_of(Purpose::Anchor)?;
        let Secret::Anchor(anchor) = &anchor.secret else {
            return Err(bad("the keystore groups"));
        };
        let anchor = CompositeSigningKey::from_bytes(
            &anchor.to_bytes().map_err(|_| bad("the anchor key"))?[..],
        )
        .map_err(|_| bad("the anchor key"))?;
        let (fact_group, fact) = self.group_of(Purpose::Fact)?;
        let fact = copy_kem(fact.secret.kem()?)?;
        let (match_group, matcher) = self.group_of(Purpose::Match)?;
        let match_secret = copy_kem(matcher.secret.kem()?)?;
        let mut in_fact = self.rows.data_keys.iter().filter(|d| d.group == fact_group);
        let (Some(d), None) = (in_fact.next(), in_fact.next()) else {
            return Err(bad("the keystore data keys"));
        };
        let data_key = keystore::open_fact_key(&self.cell, &fact, d)?;
        Ok(VaultKeys {
            anchor_group,
            anchor,
            fact_group,
            fact,
            match_group,
            match_secret,
            dek: d.id,
            data_key,
        })
    }

    /// The identity match key of `tuple` under the current `Match` key.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] when the `Match` group is missing.
    pub fn match_key(&self, tuple: &[u8]) -> Result<[u8; MATCH_KEY_LEN], VaultError> {
        let (_, m) = self.group_of(Purpose::Match)?;
        let key = keystore::match_hmac_key(m.secret.kem()?)?;
        Ok(fstp_crypto::hmac_sha256(key.expose(), tuple))
    }

    /// Opens the tuple of `identity` from the live store.
    ///
    /// # Errors
    ///
    /// [`VaultError::Conflict`] for an identity whose erasure was
    /// requested or completed, or that has no tuple, and
    /// [`VaultError::Malformed`] when its rows do not open.
    pub fn tuple(&self, identity: Person) -> Result<Vec<u8>, VaultError> {
        let id = identity.0.to_be_bytes();
        if self.chain.refused_for_open(DekId(id)) {
            return Err(VaultError::Conflict("an erased or unknown identity tuple"));
        }
        let d = self
            .rows
            .data_keys
            .iter()
            .find(|d| d.id == id)
            .ok_or(VaultError::Conflict("an erased or unknown identity tuple"))?;
        let t = self
            .rows
            .tuples
            .iter()
            .find(|t| t.identity == id)
            .ok_or(VaultError::Conflict("an erased or unknown identity tuple"))?;
        let dk = self.open_tuple_key(d)?;
        open_tuple(&self.cell, &dk, t)
    }

    fn open_tuple_key(&self, d: &DataKeyRow) -> Result<DataKey, VaultError> {
        let g = self.open.get(&d.group).ok_or(bad("a tuple data key"))?;
        if g.purpose != Purpose::Attribute || g.generation != d.generation {
            return Err(bad("a tuple data key"));
        }
        open_attribute_key(&self.cell, g.secret.kem()?, d)
    }

    /// Reads the rows back after a write.
    async fn reread(&mut self) -> Result<(), VaultError> {
        self.rows = keystore::read_rows(&mut self.client)
            .await?
            .ok_or(bad("the keystore rows"))?;
        Ok(())
    }

    /// The identity of `tuple`: a known match key gives its identity, and
    /// a new one is assigned through `journal` (ADR-004 record of lane
    /// L11, row "Registering an identity"). The tuple is then sealed and
    /// stored, if it is not yet.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] while a batch runs or when a write
    /// fails, and [`VaultError::Malformed`] for an empty or too long
    /// tuple.
    pub async fn register_identity<J: Journal>(
        &mut self,
        vault: &mut Vault,
        journal: &mut J,
        tuple: &[u8],
        now: i64,
    ) -> Result<Person, VaultError> {
        if tuple.is_empty() || tuple.len() > MAX_TUPLE {
            return Err(bad("an identity tuple"));
        }
        if self.chain.phase() != Phase::Idle {
            return Err(VaultError::Unavailable("an erasure batch runs"));
        }
        let mk = self.match_key(tuple)?;
        let known = vault
            .identity_keys()
            .find(|(k, _)| *k == mk)
            .map(|(_, p)| p);
        let person = match known {
            Some(p) => p,
            None => {
                let mut next = vault.clone();
                let p = next.resolve_identity(mk)?;
                let entries = next.take_journal();
                journal.commit(&entries, now).await?;
                *vault = next;
                p
            }
        };
        let id = person.0.to_be_bytes();
        if self.rows.tuples.iter().any(|t| t.identity == id) {
            return Ok(person);
        }
        self.store_tuple(id, tuple, now).await?;
        Ok(person)
    }

    async fn store_tuple(
        &mut self,
        id: [u8; 16],
        tuple: &[u8],
        now: i64,
    ) -> Result<(), VaultError> {
        let dek = DekId(id);
        if self.chain.group_of(dek).is_some() || self.chain.is_requested(dek) {
            return Err(bad("an identity data key"));
        }
        let mut chain = self.chain.clone();
        let mut changes = Vec::new();
        let room = self
            .open
            .iter()
            .filter(|(_, o)| o.purpose == Purpose::Attribute)
            .map(|(g, _)| *g)
            .find(|g| {
                self.chain
                    .group(GroupId(*g))
                    .is_some_and(|s| s.members.len() < GROUP_LIMIT)
            });
        let epoch = self.epoch();
        let (group, new_open) = match room {
            Some(g) => (g, None),
            None => {
                let g = fstp_crypto::random_array::<16>().map_err(|_| keys("randomness"))?;
                let sk = hybrid_kem::generate().map_err(|_| keys("key generation"))?;
                chain
                    .add_group_for(GroupId(g), Purpose::Attribute)
                    .map_err(planner)?;
                let row = keystore::seal_group_at(
                    &aead_key(&self.seal)?,
                    &self.cell,
                    Purpose::Attribute,
                    g,
                    1,
                    epoch,
                    sk.public().to_bytes().to_vec(),
                    &sk.to_bytes()[..],
                )?;
                changes.push(Change::PutGroup(row));
                let open = Open {
                    purpose: Purpose::Attribute,
                    generation: 1,
                    public: sk.public().to_bytes().to_vec(),
                    secret: Secret::Kem(Box::new(sk)),
                };
                (g, Some(open))
            }
        };
        let (generation, public) = match (&new_open, self.open.get(&group)) {
            (Some(o), _) | (None, Some(o)) => (o.generation, o.secret.kem()?.public().clone()),
            (None, None) => return Err(bad("the keystore groups")),
        };
        chain.admit(GroupId(group), dek).map_err(planner)?;
        let (match_group, _) = self.group_of(Purpose::Match)?;
        chain
            .add_digest_subject(GroupId(match_group), dek)
            .map_err(planner)?;
        let dk = DataKey::generate().map_err(|_| keys("key generation"))?;
        let ctx = keystore::attribute_ctx(&self.cell, &group, generation, &id);
        let sealed = envelope::seal_key(&public, &dk, &ctx).map_err(|_| keys("sealing"))?;
        let blob = envelope::seal_blob(&dk, &keystore::tuple_ctx(&self.cell, &group, &id), tuple)
            .map_err(|_| keys("sealing"))?;
        changes.push(Change::PutDataKey(DataKeyRow {
            id,
            group,
            generation,
            sealed: envelope::encode_sealed_key(&sealed).map_err(|_| keys("sealing"))?,
        }));
        changes.push(Change::PutTuple(TupleRow {
            identity: id,
            group,
            envelope: envelope::encode_sealed_blob(&blob).map_err(|_| keys("sealing"))?,
        }));
        write(
            &mut self.client,
            &self.cell,
            self.intent,
            changes,
            &chain,
            &self.seal,
            now,
        )
        .await?;
        self.chain = chain;
        if let Some(o) = new_open {
            self.open.insert(group, o);
        }
        self.identities.insert(
            u128::from_be_bytes(id),
            keystore::identity_fact_key(&self.cell, &id, &dk)?,
        );
        self.reread().await
    }

    /// Step 1: requests the erasure of `identity`, whose tuple key joins
    /// the chain state. The intent row is written before this returns, and
    /// the tuple is refused for open from then on. A request while a
    /// batch runs joins the next one.
    ///
    /// # Errors
    ///
    /// [`VaultError::Conflict`] for an identity with no stored tuple
    /// (ADR-004 record of lane L11), and [`VaultError::Unavailable`] when
    /// the write fails. Nothing changes then.
    pub async fn request_erasure(&mut self, identity: Person) -> Result<(), VaultError> {
        let dek = DekId(identity.0.to_be_bytes());
        if self.chain.is_requested(dek) {
            return Ok(());
        }
        let stored = self.rows.tuples.iter().any(|t| t.identity == dek.0);
        if !stored || self.chain.group_of(dek).is_none() {
            return Err(VaultError::Conflict(
                "an identity without a stored attribute tuple",
            ));
        }
        let mut chain = self.chain.clone();
        // The vault has no ledger, so the request names sequence 0.
        chain.request(dek, 0).map_err(planner)?;
        write(
            &mut self.client,
            &self.cell,
            self.intent,
            Vec::new(),
            &chain,
            &self.seal,
            0,
        )
        .await?;
        // Its facts are refused for sealing and opening from here on
        // (ADR-004 record of lane L13).
        self.identities.remove(identity.0);
        if self.chain.phase() == Phase::Idle {
            self.work = Work::default();
        }
        self.chain = chain;
        Ok(())
    }

    /// Runs units until the chain is idle, and returns their events.
    ///
    /// # Errors
    ///
    /// The first unit that fails. The stored phase stays, so a later run
    /// or a restart resumes from it.
    pub async fn run_to_idle<J: Journal>(
        &mut self,
        vault: &mut Vault,
        journal: &mut J,
        now: i64,
    ) -> Result<Vec<ErasureEvent>, VaultError> {
        let mut events = Vec::new();
        while let Some(e) = self.step(vault, journal, now).await? {
            events.push(e);
        }
        Ok(events)
    }

    /// Does one unit of the running batch (module documentation), or
    /// returns `None` when the chain is idle.
    ///
    /// # Errors
    ///
    /// The unit's failure. A failed unit changes no stored row, except
    /// that a root created in custody is kept as pending.
    pub async fn step<J: Journal>(
        &mut self,
        vault: &mut Vault,
        journal: &mut J,
        now: i64,
    ) -> Result<Option<ErasureEvent>, VaultError> {
        let Some(step) = plan::next(&self.chain).map_err(planner)? else {
            return Ok(None);
        };
        let event = match &step {
            Step::NewGroups { groups } => self.new_groups(groups, &step)?,
            Step::Reseal { group, keep } => self.reseal(*group, keep, &step)?,
            Step::NewEpoch(e) => self.new_epoch(*e, &step, now).await?,
            Step::RewrapGroups(e) => self.rewrap(*e, &step)?,
            Step::Commit(e) => self.commit(*e, &step, now).await?,
            Step::Snapshot(e) if !self.work.rekeyed => {
                self.rekey(vault, journal, now).await?;
                ErasureEvent::IdentitiesRekeyed { epoch: e.0 }
            }
            Step::Snapshot(e) => {
                let mut c = self.chain.clone();
                plan::apply(&mut c, &step).map_err(planner)?;
                self.persist(&c, now).await?;
                self.work.snapshot = keystore::read_rows(&mut self.client).await?;
                ErasureEvent::SnapshotTaken { epoch: e.0 }
            }
            Step::VerifySnapshot(e) => self.verify_snapshot(*e, &step, now).await?,
            Step::DestroyRoot(e) => self.destroy(*e, now).await?,
            Step::Complete { epoch, erased } => {
                self.complete(*epoch, erased, &step, vault, journal, now)
                    .await?
            }
        };
        Ok(Some(event))
    }

    /// Writes the chain state `c` alone, then keeps it.
    async fn persist(&mut self, c: &ChainState, now: i64) -> Result<(), VaultError> {
        write(
            &mut self.client,
            &self.cell,
            self.intent,
            Vec::new(),
            c,
            &self.seal,
            now,
        )
        .await?;
        self.chain = c.clone();
        Ok(())
    }

    fn apply_in_memory(&mut self, step: &Step) -> Result<(), VaultError> {
        plan::apply(&mut self.chain, step).map_err(planner)
    }

    /// Step 2: new key pairs for the affected groups.
    fn new_groups(&mut self, groups: &[GroupId], step: &Step) -> Result<ErasureEvent, VaultError> {
        let mut fresh = BTreeMap::new();
        for g in groups {
            let o = self.open.get(&g.0).ok_or(bad("an affected group"))?;
            if !matches!(o.purpose, Purpose::Attribute | Purpose::Match) {
                return Err(bad("an affected group"));
            }
            fresh.insert(
                g.0,
                hybrid_kem::generate().map_err(|_| keys("key generation"))?,
            );
        }
        self.work = Work {
            new_secrets: fresh,
            ..Work::default()
        };
        self.apply_in_memory(step)?;
        Ok(ErasureEvent::GroupsRotated)
    }

    /// Step 2: the surviving keys of `group` sealed to its new generation.
    fn reseal(
        &mut self,
        group: GroupId,
        keep: &[DekId],
        step: &Step,
    ) -> Result<ErasureEvent, VaultError> {
        let o = self.open.get(&group.0).ok_or(bad("an affected group"))?;
        let next = o
            .generation
            .checked_add(1)
            .ok_or(bad("a group generation"))?;
        let new_public = self
            .work
            .new_secrets
            .get(&group.0)
            .ok_or(bad("an affected group"))?
            .public()
            .clone();
        let mut out = Vec::new();
        for dek in keep {
            let d = self
                .rows
                .data_keys
                .iter()
                .find(|d| d.id == dek.0)
                .ok_or(bad("a surviving data key"))?;
            let dk = self.open_tuple_key(d)?;
            let ctx = keystore::attribute_ctx(&self.cell, &group.0, next, &dek.0);
            let sealed = envelope::seal_key(&new_public, &dk, &ctx).map_err(|_| keys("sealing"))?;
            out.push(DataKeyRow {
                id: dek.0,
                group: group.0,
                generation: next,
                sealed: envelope::encode_sealed_key(&sealed).map_err(|_| keys("sealing"))?,
            });
        }
        for d in out {
            self.work.resealed.insert(d.id, d);
        }
        self.apply_in_memory(step)?;
        Ok(ErasureEvent::KeysResealed)
    }

    /// Step 3: `R(e+1)`, reused when a pending row names it, and `S(e+1)`
    /// wrapped under it.
    async fn new_epoch(
        &mut self,
        e: Epoch,
        step: &Step,
        now: i64,
    ) -> Result<ErasureEvent, VaultError> {
        let pending = self
            .rows
            .others
            .iter()
            .find(|r| r.epoch == e.0 && r.state == STATE_PENDING)
            .cloned();
        let row = match pending {
            Some(r) => r,
            None => {
                let root = self
                    .custody
                    .create_root(RootLabel {
                        cell: Some(CellId(self.cell)),
                        chain: CHAIN,
                        epoch: e,
                    })
                    .await
                    .map_err(|_| keys("custody create"))?;
                let r = RootRow {
                    epoch: e.0,
                    backend: keystore::backend_code(root.backend),
                    handle: root.handle.0,
                    wrapped: Vec::new(),
                    created_at: now,
                    state: STATE_PENDING,
                    receipt: None,
                };
                // Written at once, so a restart reuses the root.
                keystore::apply_changes(&mut self.client, &[Change::PutRoot(r.clone())], now)
                    .await?;
                self.rows.others.push(r.clone());
                r
            }
        };
        let seal = SealKey::generate().map_err(|_| keys("the seal key"))?;
        let wrapped = self
            .custody
            .wrap(
                &root_ref(&self.cell, &row)?,
                &seal,
                &keystore::seal_aad(&self.cell, e.0),
            )
            .await
            .map_err(|_| keys("custody wrap"))?;
        let live = RootRow {
            wrapped: wrapped.0,
            state: STATE_LIVE,
            ..row
        };
        self.work.new_root = Some((live, seal));
        self.apply_in_memory(step)?;
        Ok(ErasureEvent::RootCreated { epoch: e.0 })
    }

    /// Step 3: every live group secret sealed under `S(e+1)`.
    fn rewrap(&mut self, e: Epoch, step: &Step) -> Result<ErasureEvent, VaultError> {
        let (_, seal) = self.work.new_root.as_ref().ok_or(bad("the new root"))?;
        let s = aead_key(seal)?;
        let mut rows = Vec::new();
        for (g, o) in &self.open {
            let row = match self.work.new_secrets.get(g) {
                Some(sk) => keystore::seal_group_at(
                    &s,
                    &self.cell,
                    o.purpose,
                    *g,
                    o.generation
                        .checked_add(1)
                        .ok_or(bad("a group generation"))?,
                    e.0,
                    sk.public().to_bytes().to_vec(),
                    &sk.to_bytes()[..],
                )?,
                None => {
                    let secret = match &o.secret {
                        Secret::Anchor(a) => {
                            a.to_bytes().map_err(|_| bad("the anchor key"))?.to_vec()
                        }
                        Secret::Kem(k) => k.to_bytes().to_vec(),
                    };
                    let row = keystore::seal_group_at(
                        &s,
                        &self.cell,
                        o.purpose,
                        *g,
                        o.generation,
                        e.0,
                        o.public.clone(),
                        &secret,
                    );
                    zero(secret);
                    row?
                }
            };
            rows.push(row);
        }
        self.work.rewrapped = rows;
        self.apply_in_memory(step)?;
        Ok(ErasureEvent::GroupsResealed { epoch: e.0 })
    }

    /// Step 4: the new rows in one transaction.
    async fn commit(
        &mut self,
        e: Epoch,
        step: &Step,
        now: i64,
    ) -> Result<ErasureEvent, VaultError> {
        let batch = self.chain.running_batch();
        let (root, seal) = self.work.new_root.as_ref().ok_or(bad("the new root"))?;
        let mut changes = vec![Change::PutRoot(root.clone())];
        for g in &self.work.rewrapped {
            changes.push(Change::PutGroup(g.clone()));
        }
        for (g, o) in &self.open {
            if self.work.new_secrets.contains_key(g) {
                changes.push(Change::DropGroup(*g, o.generation));
            }
        }
        for d in self.work.resealed.values() {
            changes.push(Change::PutDataKey(d.clone()));
        }
        for dek in &batch {
            changes.push(Change::DropDataKey(dek.0));
            changes.push(Change::DropTuple(dek.0));
            self.identities.remove(u128::from_be_bytes(dek.0));
        }
        let mut chain = self.chain.clone();
        plan::apply(&mut chain, step).map_err(planner)?;
        write(
            &mut self.client,
            &self.cell,
            self.intent,
            changes,
            &chain,
            seal,
            now,
        )
        .await?;
        // The commit is durable: the new epoch serves from here.
        let (_, seal) = self.work.new_root.take().ok_or(bad("the new root"))?;
        let s = aead_key(&seal)?;
        let mut open = BTreeMap::new();
        for g in &self.work.rewrapped {
            open.insert(g.group, open_row(&s, &self.cell, g)?);
        }
        self.open = open;
        self.seal = seal;
        self.chain = chain;
        self.work.new_secrets.clear();
        self.work.resealed.clear();
        self.work.rewrapped.clear();
        self.work.rekeyed = false;
        self.reread().await?;
        Ok(ErasureEvent::Committed { epoch: e.0 })
    }

    /// Step 4, the vault's side (G24): every identity with a live tuple
    /// moves to its match key under the new `Match` key, and each erased
    /// identity gets 32 random bytes. An identity with no tuple keeps its
    /// key.
    async fn rekey<J: Journal>(
        &mut self,
        vault: &mut Vault,
        journal: &mut J,
        now: i64,
    ) -> Result<(), VaultError> {
        let erased: BTreeSet<Person> = self
            .chain
            .running_batch()
            .into_iter()
            .map(person_of)
            .collect();
        let mut map = BTreeMap::new();
        for (key, person) in vault.identity_keys() {
            let id = person.0.to_be_bytes();
            let to = if erased.contains(&person) {
                fstp_crypto::random_array::<MATCH_KEY_LEN>().map_err(|_| keys("randomness"))?
            } else if self.rows.tuples.iter().any(|t| t.identity == id) {
                let t = self.tuple(person)?;
                let k = self.match_key(&t)?;
                zero(t);
                k
            } else {
                key
            };
            map.insert(key, to);
        }
        let mut next = vault.clone();
        next.rekey_identities(&map)?;
        let entries = next.take_journal();
        if !entries.is_empty() {
            journal.commit(&entries, now).await?;
        }
        *vault = next;
        self.work.rekeyed = true;
        Ok(())
    }

    /// Step 5: the copy read back opens under `R(e+1)` through custody:
    /// every group secret, every data key and every tuple.
    async fn verify_snapshot(
        &mut self,
        e: Epoch,
        step: &Step,
        now: i64,
    ) -> Result<ErasureEvent, VaultError> {
        let snap = match self.work.snapshot.take() {
            Some(s) => s,
            None => keystore::read_rows(&mut self.client)
                .await?
                .ok_or(bad("the snapshot"))?,
        };
        if snap.root.epoch != e.0 {
            return Err(bad("the snapshot root"));
        }
        let seal = unwrap_root(self.custody, &self.cell, &snap.root).await?;
        let s = aead_key(&seal)?;
        let mut open = BTreeMap::new();
        for g in &snap.groups {
            if g.epoch != e.0 {
                return Err(bad("the snapshot groups"));
            }
            open.insert(g.group, open_row(&s, &self.cell, g)?);
        }
        for d in &snap.data_keys {
            let g = open.get(&d.group).ok_or(bad("the snapshot data keys"))?;
            match g.purpose {
                Purpose::Fact => {
                    keystore::open_fact_key(&self.cell, g.secret.kem()?, d)?;
                }
                Purpose::Attribute => {
                    let dk = open_attribute_key(&self.cell, g.secret.kem()?, d)?;
                    let t = snap
                        .tuples
                        .iter()
                        .find(|t| t.identity == d.id)
                        .ok_or(bad("the snapshot tuples"))?;
                    zero(open_tuple(&self.cell, &dk, t)?);
                }
                _ => return Err(bad("the snapshot data keys")),
            }
        }
        let mut c = self.chain.clone();
        plan::apply(&mut c, step).map_err(planner)?;
        self.persist(&c, now).await?;
        Ok(ErasureEvent::SnapshotVerified { epoch: e.0 })
    }

    /// Step 6: `R(e)` destroyed, and its row marked with the receipt.
    async fn destroy(&mut self, e: Epoch, now: i64) -> Result<ErasureEvent, VaultError> {
        let row = self
            .rows
            .all_roots()
            .find(|r| r.epoch == e.0)
            .cloned()
            .ok_or(bad("the old root"))?;
        let receipt = self
            .custody
            .destroy(&root_ref(&self.cell, &row)?)
            .await
            .map_err(|_| keys("custody destroy"))?;
        let digest = fstp_crypto::sha256(&receipt.0);
        let mut c = self.chain.clone();
        plan::apply_destroy(&mut c, e, digest).map_err(planner)?;
        let dead = RootRow {
            state: STATE_DESTROYED,
            receipt: Some(receipt.0),
            ..row
        };
        write(
            &mut self.client,
            &self.cell,
            self.intent,
            vec![Change::PutRoot(dead)],
            &c,
            &self.seal,
            now,
        )
        .await?;
        self.chain = c;
        self.reread().await?;
        Ok(ErasureEvent::RootDestroyed { epoch: e.0 })
    }

    /// Step 7: `KeyEpochDestroyed` and one `IdentityErased` per identity,
    /// in one vault journal, then the chain state.
    async fn complete<J: Journal>(
        &mut self,
        epoch: Epoch,
        erased: &[DekId],
        step: &Step,
        vault: &mut Vault,
        journal: &mut J,
        now: i64,
    ) -> Result<ErasureEvent, VaultError> {
        let old = epoch.0.checked_sub(1).ok_or(bad("the epoch"))?;
        let receipt = self
            .rows
            .all_roots()
            .find(|r| r.epoch == old && r.state == STATE_DESTROYED)
            .and_then(|r| r.receipt.as_ref())
            .ok_or(bad("the destroy receipt"))?;
        let digest = fstp_crypto::sha256(receipt);
        let persons: Vec<Person> = erased.iter().copied().map(person_of).collect();
        let mut next = vault.clone();
        next.record_erasure(old, digest, &persons);
        let entries = next.take_journal();
        journal.commit(&entries, now).await?;
        *vault = next;
        let mut c = self.chain.clone();
        plan::apply(&mut c, step).map_err(planner)?;
        self.persist(&c, now).await?;
        self.work = Work::default();
        Ok(ErasureEvent::CompletionRecorded { epoch: old })
    }
}

/// Opens the tuple data key `d` under its `Attribute` group secret.
fn open_attribute_key(
    cell: &[u8; 16],
    sk: &HybridSecretKey,
    d: &DataKeyRow,
) -> Result<DataKey, VaultError> {
    let sealed = envelope::decode_sealed_key(&d.sealed).map_err(|_| bad("a sealed data key"))?;
    let ctx = keystore::attribute_ctx(cell, &d.group, d.generation, &d.id);
    envelope::open_key(sk, &sealed, &ctx).map_err(|_| bad("a sealed data key"))
}

fn open_tuple(cell: &[u8; 16], dk: &DataKey, t: &TupleRow) -> Result<Vec<u8>, VaultError> {
    let blob = envelope::decode_sealed_blob(&t.envelope).map_err(|_| bad("a sealed tuple"))?;
    let ctx = keystore::tuple_ctx(cell, &t.group, &t.identity);
    envelope::open_blob(dk, &ctx, &blob)
        .map(|p| p.to_vec())
        .map_err(|_| bad("a sealed tuple"))
}

/// Overwrites a buffer of key or tuple bytes before it is dropped. The
/// crate holds no `zeroize` dependency (ADR-001 A1), so this is a plain
/// overwrite through `black_box`, best effort.
fn zero(mut v: Vec<u8>) {
    v.fill(0);
    std::hint::black_box(&v);
}

/// Writes `changes` and the chain state `chain`, sealed under `seal`, in
/// one transaction of the keys login.
async fn write<R: Runtime>(
    client: &mut Client<R>,
    cell: &[u8; 16],
    intent: [u8; 16],
    mut changes: Vec<Change>,
    chain: &ChainState,
    seal: &SealKey,
    now: i64,
) -> Result<(), VaultError> {
    changes.push(Change::PutIntent(IntentRow {
        id: intent,
        plan: seal_state(seal, cell, chain)?,
        phase: phase_code(chain.phase()),
    }));
    keystore::apply_changes(client, &changes, now).await
}

impl<'c, R: Runtime, C: Custody> Runner<'c, R, C> {
    /// Opens every live tuple key whose erasure was not requested, and
    /// keeps its identity's fact key `F(X)` (ADR-004 record of lane L13,
    /// row "Load"). A key row that does not open fails the load closed.
    fn fill_identity_keys(&mut self) -> Result<(), VaultError> {
        for d in &self.rows.data_keys {
            let in_attribute = self
                .open
                .get(&d.group)
                .is_some_and(|g| g.purpose == Purpose::Attribute);
            if !in_attribute || self.chain.refused_for_open(DekId(d.id)) {
                continue;
            }
            let dk = self.open_tuple_key(d)?;
            self.identities.insert(
                u128::from_be_bytes(d.id),
                keystore::identity_fact_key(&self.cell, &d.id, &dk)?,
            );
        }
        Ok(())
    }

    /// The fact keys `F(X)` of the live identities, which the sealer of
    /// the vault's rows shares ([`crate::service::AeadSealer::with_identities`]).
    #[must_use]
    pub fn identity_keys(&self) -> Arc<IdentityKeys> {
        Arc::clone(&self.identities)
    }

    /// Registers `account` with the attribute tuple `tuple` (ADR-004
    /// record of lane L13, rows "Registration steps" and "Idempotence"):
    /// the identity of the tuple, assigned if new, its tuple and data key
    /// stored if not yet, then the binding of the account, journaled.
    /// From then on the account's identity facts are sealed under the
    /// identity's fact key. A repeat changes no row.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] for an empty or too long tuple, and for
    /// an account bound to another identity, before anything is written.
    /// [`VaultError::Unavailable`] while a batch runs or when a write
    /// fails; a retry completes what was written.
    pub async fn register_account<J: Journal>(
        &mut self,
        vault: &mut Vault,
        journal: &mut J,
        account: WireAccount,
        tuple: &[u8],
        now: i64,
    ) -> Result<Person, VaultError> {
        if tuple.is_empty() || tuple.len() > MAX_TUPLE {
            return Err(bad("an identity tuple"));
        }
        if let Some(bound) = vault.registered(account) {
            let mk = self.match_key(tuple)?;
            let resolved = vault
                .identity_keys()
                .find(|(k, _)| *k == mk)
                .map(|(_, p)| p);
            if resolved != Some(bound) {
                return Err(bad("an account of another identity"));
            }
        }
        let person = self.register_identity(vault, journal, tuple, now).await?;
        let mut next = vault.clone();
        if next.bind_account(account, person, now)? {
            let entries = next.take_journal();
            journal.commit(&entries, now).await?;
            *vault = next;
        }
        Ok(person)
    }
}

/// The custody of a [`Registrar`]: it refuses every call. A registrar
/// only registers identities, which needs no custody call once the seal
/// key of the current epoch is open.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCustody;

static NO_CUSTODY: NoCustody = NoCustody;

fn no_custody() -> fstp_custody::CustodyError {
    fstp_custody::CustodyError::Refused(fstp_custody::Refusal::Internal)
}

impl Custody for NoCustody {
    async fn create_root(&self, _: RootLabel) -> Result<RootRef, fstp_custody::CustodyError> {
        Err(no_custody())
    }

    async fn wrap(
        &self,
        _: &RootRef,
        _: &SealKey,
        _: &fstp_custody::Aad,
    ) -> Result<WrappedSealKey, fstp_custody::CustodyError> {
        Err(no_custody())
    }

    async fn unwrap(
        &self,
        _: &RootRef,
        _: &WrappedSealKey,
        _: &fstp_custody::Aad,
    ) -> Result<SealKey, fstp_custody::CustodyError> {
        Err(no_custody())
    }

    async fn destroy(
        &self,
        _: &RootRef,
    ) -> Result<fstp_custody::DestroyReceipt, fstp_custody::CustodyError> {
        Err(no_custody())
    }

    async fn sign(
        &self,
        _: &fstp_custody::SignKeyRef,
        _: &[u8; 32],
    ) -> Result<fstp_custody::EcdsaSignature, fstp_custody::CustodyError> {
        Err(no_custody())
    }

    async fn usage_since(
        &self,
        _: &RootRef,
        _: fstp_custody::UsageCursor,
    ) -> Result<fstp_custody::UsagePage, fstp_custody::CustodyError> {
        Err(no_custody())
    }
}

/// The keystore of a serving vault: an idle [`Runner`] that keeps the
/// keys connection, and with it the keystore lock, and registers
/// identities (ADR-004 record of lane L13). It holds no custody, so it
/// runs no erasure step.
pub type Registrar<R> = Runner<'static, R, NoCustody>;

impl<R: Runtime, C: Custody> Runner<'_, R, C> {
    /// The registrar of a serving vault, once no batch runs.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] while a batch runs: it completes first.
    pub fn into_registrar(self) -> Result<Registrar<R>, VaultError> {
        if self.chain.phase() != Phase::Idle {
            return Err(VaultError::Unavailable("an erasure batch runs"));
        }
        Ok(Runner {
            cell: self.cell,
            client: self.client,
            custody: &NO_CUSTODY,
            rows: self.rows,
            chain: self.chain,
            intent: self.intent,
            seal: self.seal,
            open: self.open,
            work: Work::default(),
            identities: self.identities,
        })
    }
}

impl<'c, R: Runtime, C: Custody> Runner<'c, R, C> {
    /// The keys connection, once the runner is done with it. The vault
    /// keeps it while it serves, since it holds the keystore lock
    /// (`crate::run`).
    #[must_use]
    pub fn into_client(self) -> Client<R> {
        self.client
    }
}

/// The vault chain writer as a [`Journal`]: each commit is one kind 1 row
/// of the Vault chain, anchored at the witness (`crate::chain`).
pub struct ChainJournal<R: Runtime> {
    /// The vault login.
    pub client: Client<R>,
    /// The chain writer, opened and verified.
    pub chain: crate::chain::VaultChain<R>,
    /// The sealer of the entry bodies.
    pub sealer: std::sync::Arc<dyn crate::store::Sealer>,
}

impl<R: Runtime> std::fmt::Debug for ChainJournal<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainJournal").finish_non_exhaustive()
    }
}

impl<R: Runtime> Journal for ChainJournal<R> {
    async fn commit(&mut self, entries: &[JournalEntry], now: i64) -> Result<(), VaultError> {
        self.chain
            .commit(&mut self.client, self.sealer.as_ref(), entries, now)
            .await
    }
}

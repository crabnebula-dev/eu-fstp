//! The Vault chain keystore of a world cell (design sections 3.1, 3.5,
//! 3.6 and 3.7, I-81, R-ID-03, R-SW-02). Lane m3/erase-steps. Test only.
//!
//! `fstp-vault` holds no keystore yet (`fstp_vault::run` refuses with
//! it), and the seeded vault of a world cell kept its Match key as random
//! bytes in the test process. So the harness plays the vault keystore,
//! through the cell's own world custody, as [`crate::backups`] plays the
//! CellBackup chain. Interim, pending Daniel:
//!
//! - **Roots.** `R(e)` of the cell's Vault chain is a custody root of the
//!   cell's [`WorldCustody`], labelled with chain Vault. A fresh `S(e)` is
//!   wrapped under it. Every group secret is sealed under `S(e)`.
//! - **Match key.** One `Match` group. Its HMAC key is derived from the
//!   group secret as the App chain derives its `Lookup` key
//!   (`fstp_cell::tasks::erasure::KEYED_DIGEST_LABEL` and the purpose
//!   code). The identity match key is `fstp_vault::match_key` under it.
//! - **Erasure batch.** An identity erasure or a document verification
//!   runs design section 3.5 on the Vault chain: a new `Match` generation
//!   when an identity is erased, the erased document's group dropped,
//!   `R(e+1)` and `S(e+1)` created, every live group secret resealed,
//!   the vault's rows moved in one journal ("commit"), a scratch copy of
//!   the new rows opened under `R(e+1)` (step 5), and `R(e)` destroyed.
//! - **Step 5.** ADR-012 leaves open how a Vault chain snapshot is sealed
//!   and verified (option A or B). No vault snapshot container is
//!   written, and the FBC1 decoder admits the CellBackup and
//!   ClusterBackup chains only. The check opens the committed rows from a
//!   scratch copy in the test process, under the new root, before the old
//!   root dies.
//! - **Rows that copies can hold.** The keystore rows are kept in the
//!   test process, not in `keystore.*` of `v_<cell>`. So every root and
//!   group row the harness ever wrote is kept, and stands for every copy
//!   of the keystore tables: a reader of copies is given all of them.
//! - **Identity tuples.** The seeded vault stores no attribute tuple. The
//!   harness keeps the tuple of each identity it seeded, and recomputes
//!   the live identities' match keys from those. An erased identity's
//!   match key is replaced by 32 random bytes, so no tuple recomputes it
//!   and its account keeps its identity row.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_custody::{Aad, Custody, RootLabel, RootRef, SealKey, WrappedSealKey};
use fstp_keys::{CellId, Chain, Epoch, GroupId, Purpose};
use fstp_rt::future::block_on;

use crate::canary::Canary;
use crate::world::{WorldCustody, WorldError};

/// The AAD label of a Vault chain seal key wrapped under its root.
const SEAL_AAD: &[u8] = b"fstp-vault-seal-key-v1";
/// The AAD label of a Vault chain group secret under a seal key.
const GROUP_AAD: &[u8] = b"fstp-vault-group-v1";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn err(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("vault keys: {what}: {e}"))
}

/// One root row: its epoch, custody reference and wrapped seal key.
#[derive(Clone)]
struct RootRow {
    epoch: u64,
    root: RootRef,
    wrapped: WrappedSealKey,
}

/// One group secret row, sealed under the seal key of `epoch`.
#[derive(Clone)]
struct GroupRow {
    purpose: Purpose,
    group: GroupId,
    generation: u32,
    epoch: u64,
    nonce: [u8; aead::NONCE_LEN],
    body: Vec<u8>,
}

/// One identity the world seeded: its attribute tuple, the name canary
/// in it, if any, and whether it was erased.
#[derive(Clone, Debug)]
struct Identity {
    tuple: Vec<u8>,
    name: Option<Canary>,
    erased: bool,
}

/// The live state of the chain.
struct State {
    root: RootRow,
    /// The live group rows, all under the current epoch.
    live: BTreeMap<GroupId, GroupRow>,
    /// The `Match` group.
    matcher: GroupId,
    /// Every root row ever written.
    roots: Vec<RootRow>,
    /// Every group row ever written.
    groups: Vec<GroupRow>,
    identities: Vec<Identity>,
}

/// The Vault chain keystore of one cell (module documentation).
pub(crate) struct VaultKeys {
    cell: [u8; 16],
    custody: WorldCustody,
    state: Mutex<State>,
}

impl std::fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKeys").finish_non_exhaustive()
    }
}

fn seal_aad(cell: [u8; 16], epoch: u64) -> Aad {
    let mut aad = SEAL_AAD.to_vec();
    aad.extend_from_slice(&cell);
    aad.push(Chain::Vault.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    Aad(aad)
}

fn group_aad(
    cell: [u8; 16],
    purpose: Purpose,
    group: GroupId,
    generation: u32,
    epoch: u64,
) -> Vec<u8> {
    let mut aad = GROUP_AAD.to_vec();
    aad.extend_from_slice(&cell);
    aad.push(purpose.code());
    aad.extend_from_slice(&group.0);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn seal_group(
    s: &SealKey,
    cell: [u8; 16],
    purpose: Purpose,
    group: GroupId,
    generation: u32,
    epoch: u64,
    secret: &HybridSecretKey,
) -> Result<GroupRow, WorldError> {
    let key = aead::Key::from_bytes(s.expose()).map_err(|e| err("a seal key", &e))?;
    let sealed = aead::seal(
        &key,
        &group_aad(cell, purpose, group, generation, epoch),
        &secret.to_bytes()[..],
    )
    .map_err(|e| err("a group secret", &e))?;
    Ok(GroupRow {
        purpose,
        group,
        generation,
        epoch,
        nonce: sealed.nonce,
        body: sealed.body,
    })
}

fn open_group(s: &SealKey, cell: [u8; 16], row: &GroupRow) -> Option<HybridSecretKey> {
    let key = aead::Key::from_bytes(s.expose()).ok()?;
    let aad = group_aad(cell, row.purpose, row.group, row.generation, row.epoch);
    let bytes = aead::open(&key, &row.nonce, &aad, &row.body).ok()?;
    HybridSecretKey::from_bytes(&bytes).ok()
}

/// The HMAC key of the `Match` group whose secret is `sk`: the keyed
/// digest derivation of the App chain's `Lookup` key, with the `Match`
/// purpose code.
fn match_hmac(sk: &HybridSecretKey) -> Result<[u8; 32], WorldError> {
    let mut info = fstp_cell::tasks::erasure::KEYED_DIGEST_LABEL.to_vec();
    info.push(Purpose::Match.code());
    let mut out = [0u8; 32];
    fstp_crypto::kdf::hkdf_sha256(&[], &sk.to_bytes()[..], &info, &mut out)
        .map_err(|e| err("the Match key", &e))?;
    Ok(out)
}

fn random16(what: &str) -> Result<[u8; 16], WorldError> {
    fstp_crypto::random_array::<16>().map_err(|e| err(what, &e))
}

impl VaultKeys {
    /// The chain at epoch 0: `R(0)` in custody, `S(0)` wrapped under it,
    /// and the `Match` group at generation 1.
    pub(crate) fn genesis(custody: WorldCustody, cell: [u8; 16]) -> Result<VaultKeys, WorldError> {
        let (root, s) = new_root(&custody, cell, 0)?;
        let matcher = GroupId(random16("a group id")?);
        let secret = hybrid_kem::generate().map_err(|e| err("a group key", &e))?;
        let row = seal_group(&s, cell, Purpose::Match, matcher, 1, 0, &secret)?;
        Ok(VaultKeys {
            cell,
            custody,
            state: Mutex::new(State {
                root: root.clone(),
                live: BTreeMap::from([(matcher, row.clone())]),
                matcher,
                roots: vec![root],
                groups: vec![row],
                identities: Vec::new(),
            }),
        })
    }

    /// `S(e)` of the current epoch, through custody.
    fn seal_key(&self, st: &State) -> Result<SealKey, WorldError> {
        block_on(self.custody.unwrap(
            &st.root.root,
            &st.root.wrapped,
            &seal_aad(self.cell, st.root.epoch),
        ))
        .map_err(|e| err("the Vault chain unwrap", &e))
    }

    /// The secret of the live group `group`.
    fn secret(&self, st: &State, group: GroupId) -> Result<HybridSecretKey, WorldError> {
        let s = self.seal_key(st)?;
        let row = st
            .live
            .get(&group)
            .ok_or_else(|| err("a group", &"is not live"))?;
        open_group(&s, self.cell, row).ok_or_else(|| err("a group secret", &"does not open"))
    }

    /// The identity match key of `tuple` under the live `Match` key, and
    /// the tuple kept as a seeded identity's ([`VaultKeys`] docs).
    pub(crate) fn match_key(
        &self,
        tuple: &[u8],
        name: Option<Canary>,
    ) -> Result<[u8; 32], WorldError> {
        let mut st = lock(&self.state);
        let key = match_hmac(&self.secret(&st, st.matcher)?)?;
        if !st.identities.iter().any(|i| i.tuple == tuple) {
            st.identities.push(Identity {
                tuple: tuple.to_vec(),
                name,
                erased: false,
            });
        }
        Ok(fstp_vault::match_key(&key, tuple))
    }

    /// The name canaries of the erased identities, or of the live ones.
    pub(crate) fn name_canaries(&self, erased: bool) -> Vec<Canary> {
        lock(&self.state)
            .identities
            .iter()
            .filter(|i| i.erased == erased)
            .filter_map(|i| i.name.clone())
            .collect()
    }

    /// The tuples of the seeded identities whose name canary has the text
    /// `name`.
    pub(crate) fn tuples_named(&self, name: &[u8]) -> Vec<Vec<u8>> {
        lock(&self.state)
            .identities
            .iter()
            .filter(|i| i.name.as_ref().is_some_and(|n| n.text().as_bytes() == name))
            .map(|i| i.tuple.clone())
            .collect()
    }

    /// The oldest live identity with a name canary, other than the newest
    /// identity, by tuple.
    pub(crate) fn erasure_victim(&self) -> Option<Vec<u8>> {
        let st = lock(&self.state);
        let newest = st.identities.last().map(|i| i.tuple.clone());
        st.identities
            .iter()
            .find(|i| !i.erased && i.name.is_some() && Some(&i.tuple) != newest.as_ref())
            .map(|i| i.tuple.clone())
    }

    /// One erasure batch on the Vault chain (module documentation). The
    /// groups `drop` die with the old epoch. When `erase` names a tuple,
    /// that identity is erased and the `Match` group takes a new
    /// generation. `commit` gets the vault's identity rekey: each current
    /// match key of a seeded identity to its new one, empty when no
    /// identity is erased. `R(e)` is destroyed only after `commit`
    /// succeeded and the scratch check passed.
    pub(crate) fn erasure_batch(
        &self,
        drop: &BTreeSet<GroupId>,
        erase: Option<&[u8]>,
        commit: impl FnOnce(&BTreeMap<[u8; 32], [u8; 32]>) -> Result<(), WorldError>,
    ) -> Result<(), WorldError> {
        let mut st = lock(&self.state);
        let cell = self.cell;
        let s = self.seal_key(&st)?;
        // Step 2: open every live secret, and a new `Match` generation when
        // an identity is erased.
        let mut secrets = BTreeMap::new();
        for (g, row) in &st.live {
            if drop.contains(g) {
                continue;
            }
            let sk =
                open_group(&s, cell, row).ok_or_else(|| err("a group secret", &"does not open"))?;
            secrets.insert(*g, (row.purpose, row.generation, sk));
        }
        let matcher = st.matcher;
        let mut rekey = BTreeMap::new();
        if let Some(tuple) = erase {
            let (_, generation, old) = secrets
                .remove(&matcher)
                .ok_or_else(|| err("the Match group", &"is not live"))?;
            let new = hybrid_kem::generate().map_err(|e| err("a group key", &e))?;
            let (old_key, new_key) = (match_hmac(&old)?, match_hmac(&new)?);
            for i in &st.identities {
                let from = fstp_vault::match_key(&old_key, &i.tuple);
                let to = if i.erased || i.tuple == tuple {
                    fstp_crypto::random_array::<32>().map_err(|e| err("a tombstone", &e))?
                } else {
                    fstp_vault::match_key(&new_key, &i.tuple)
                };
                if !i.erased {
                    rekey.insert(from, to);
                }
            }
            let next = generation
                .checked_add(1)
                .ok_or_else(|| err("the Match generation", &"overflow"))?;
            secrets.insert(matcher, (Purpose::Match, next, new));
        }
        // Step 3: `R(e+1)`, `S(e+1)`, and every live secret resealed.
        let epoch = st
            .root
            .epoch
            .checked_add(1)
            .ok_or_else(|| err("the Vault epoch", &"overflow"))?;
        let (root, s1) = new_root(&self.custody, cell, epoch)?;
        let mut live = BTreeMap::new();
        for (g, (purpose, generation, sk)) in &secrets {
            live.insert(
                *g,
                seal_group(&s1, cell, *purpose, *g, *generation, epoch, sk)?,
            );
        }
        st.roots.push(root.clone());
        st.groups.extend(live.values().cloned());
        // Step 4: the vault's rows move in one journal.
        if erase.is_some() {
            commit(&rekey)?;
        }
        if let Some(tuple) = erase {
            for i in st.identities.iter_mut().filter(|i| i.tuple == tuple) {
                i.erased = true;
            }
        }
        let old = std::mem::replace(&mut st.root, root);
        st.live = live;
        // Step 5: a scratch copy of the committed rows opens under the new
        // root.
        let scratch = self.seal_key(&st)?;
        for row in st.live.values() {
            if open_group(&scratch, cell, row).is_none() {
                return Err(err("the step 5 check", &"a live group does not open"));
            }
        }
        // Step 6: `R(e)` dies.
        block_on(self.custody.destroy(&old.root)).map_err(|e| err("the Vault destroy", &e))?;
        Ok(())
    }

    /// Every `Match` HMAC key that a row ever written gives under a live
    /// custody root of the cell (I-81): each root row's wrapped key is
    /// tried under every live handle, and each group row under every seal
    /// key that opened.
    pub(crate) fn reachable_match_keys(&self) -> Vec<[u8; 32]> {
        let st = lock(&self.state);
        let live = self.custody.live_handles();
        let mut seals = Vec::new();
        for row in &st.roots {
            for handle in &live {
                let mut root = row.root.clone();
                root.handle = fstp_custody::CustodyHandle(handle.clone());
                if let Ok(s) = block_on(self.custody.unwrap(
                    &root,
                    &row.wrapped,
                    &seal_aad(self.cell, row.epoch),
                )) {
                    seals.push(s);
                }
            }
        }
        let mut out = Vec::new();
        for row in &st.groups {
            for s in &seals {
                if let Some(sk) = open_group(s, self.cell, row)
                    && let Ok(k) = match_hmac(&sk)
                {
                    out.push(k);
                }
            }
        }
        out
    }
}

/// A new Vault chain root of epoch `epoch` and a fresh seal key wrapped
/// under it.
fn new_root(
    custody: &WorldCustody,
    cell: [u8; 16],
    epoch: u64,
) -> Result<(RootRow, SealKey), WorldError> {
    let root = block_on(custody.create_root(RootLabel {
        cell: Some(CellId(cell)),
        chain: Chain::Vault,
        epoch: Epoch(epoch),
    }))
    .map_err(|e| err("a Vault root", &e))?;
    let s = SealKey::generate().map_err(|e| err("a seal key", &e))?;
    let wrapped = block_on(custody.wrap(&root, &s, &seal_aad(cell, epoch)))
        .map_err(|e| err("the Vault wrap", &e))?;
    Ok((
        RootRow {
            epoch,
            root,
            wrapped,
        },
        s,
    ))
}

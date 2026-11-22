//! The keystore in its tables (ADR-004, decided by Daniel on 2026-11-20;
//! `fstp_pgstore::KeystoreTables`). Lane L3 `prod/keystore-pg`.
//!
//! A [`Keystore`] with a [`KeystoreSink`] writes through: each change to
//! its rows is marked, and [`Keystore::flush`] writes every marked row in
//! one batch, which the sink commits in one transaction. The runner
//! flushes after each request it serves and around each step of an
//! erasure (`ErasureRunner::step`), so:
//!
//! - no reply claims a change that is not durable;
//! - no step, and so no custody call, follows a step whose rows are not
//!   durable. A destroy of `R(e)` follows only a durable commit of
//!   `R(e+1)` and every resealed row (I-81);
//! - the start-up unwrap's request id is durable before the call (ADR-004
//!   "Reconciliation").
//!
//! A flush that fails keeps the marks, and the change stays in memory.
//! The request that made it is refused, and the next flush writes it.
//!
//! The chain state is sealed under the seal key `S(e)` of its epoch, with
//! the AAD [`CHAIN_STATE_AAD`], cell, chain and epoch. The epoch is in
//! clear beside it, so the start-up knows which root to unwrap. A loaded
//! keystore holds its chain state sealed until [`Keystore::open_groups`]
//! opens it under `S(e)`. So every column that holds key material or
//! content is sealed or wrapped (R-CR-01), and the chain state dies with
//! its root (I-81).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use fstp_crypto::aead;
use fstp_custody::{CustodyHandle, RequestId, RootRef, SealKey, WrappedSealKey};
use fstp_keys::envelope::{
    decode_sealed_blob, decode_sealed_key, encode_sealed_blob, encode_sealed_key,
};
use fstp_keys::erasure::{ChainState, codec};
use fstp_keys::{CellId, Chain, DekId, Epoch, GroupId, Purpose};
use fstp_pgstore::{
    ChainRow, Change, DataKeyRow, GroupKeyRow, KeystoreChanges, KeystoreRows, KeystoreTables,
    KeystoreTextRow, LoginDigestRow, LoginTextRow, RootRow as TableRoot, RootStatus,
    SignerRow as TableSigner,
};
use fstp_rt::Runtime;

use super::snapshot::{backend_code, backend_of};
use super::{GroupRow, Keystore, LoginIndex, RootRow, SignerRow, TextRow, keys_err};
use crate::CellError;

/// The AAD label of the sealed chain state.
pub const CHAIN_STATE_AAD: &[u8] = b"fstp-chain-state-v1";

/// A future of a keystore write.
pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), CellError>> + Send + 'a>>;

/// Where a keystore writes its rows: the keystore tables over the keys
/// role in a cell process, or a test's own sink.
pub trait KeystoreSink: Send + Sync {
    /// Writes `changes` whole, or nothing.
    fn apply<'a>(&'a self, changes: &'a KeystoreChanges) -> SinkFuture<'a>;
}

impl<R: Runtime> KeystoreSink for KeystoreTables<R> {
    fn apply<'a>(&'a self, changes: &'a KeystoreChanges) -> SinkFuture<'a> {
        Box::pin(async move {
            KeystoreTables::apply(self, changes)
                .await
                .map_err(|_| keys_err("the keystore tables refused a write"))
        })
    }
}

/// The rows changed since the last flush (module documentation).
#[derive(Clone, Default)]
pub(super) struct Dirty {
    /// The keystore's own fields of the chain row: the keyed index groups
    /// and the start-up unwrap's request id. A change of the chain state
    /// itself is found by comparison with the last one written.
    pub(super) meta: bool,
    pub(super) roots: BTreeSet<u64>,
    pub(super) groups: BTreeSet<(GroupId, u32)>,
    pub(super) keys: BTreeSet<DekId>,
    pub(super) texts: BTreeSet<[u8; 16]>,
    pub(super) signers: BTreeSet<(Purpose, u32)>,
    pub(super) digests: BTreeSet<[u8; 32]>,
    pub(super) logins: BTreeSet<u128>,
    pub(super) requested: BTreeSet<[u8; 16]>,
}

/// The persistence state of a keystore.
#[derive(Clone, Default)]
pub(super) struct Persist {
    /// The sink, when the keystore writes through.
    pub(super) sink: Option<std::sync::Arc<dyn KeystoreSink>>,
    /// The marks.
    pub(super) dirty: Dirty,
    /// The chain state as last written, to find a change.
    pub(super) written: Option<ChainState>,
    /// The sealed chain state as last written or loaded, with its epoch.
    pub(super) sealed: Option<(u64, Vec<u8>)>,
    /// Whether the chain state is still sealed: loaded, and not opened by
    /// [`Keystore::open_groups`] yet.
    pub(super) closed: bool,
}

fn chain_aad(cell: CellId, epoch: u64) -> Vec<u8> {
    let mut aad = CHAIN_STATE_AAD.to_vec();
    aad.extend_from_slice(&cell.0);
    aad.push(Chain::App.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn seal_state(s: &SealKey, cell: CellId, state: &ChainState) -> Result<Vec<u8>, CellError> {
    let plain = codec::encode(state).map_err(|_| keys_err("chain state encode"))?;
    let key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let sealed = aead::seal(&key, &chain_aad(cell, state.epoch().0), &plain)
        .map_err(|_| keys_err("chain state seal"))?;
    let mut out = sealed.nonce.to_vec();
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

fn open_state(
    s: &SealKey,
    cell: CellId,
    epoch: u64,
    bytes: &[u8],
) -> Result<ChainState, CellError> {
    let (nonce, body) = bytes
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(keys_err("chain state open"))?;
    let key = aead::Key::from_bytes(s.expose()).map_err(|_| keys_err("seal key"))?;
    let plain = aead::open(&key, nonce, &chain_aad(cell, epoch), body)
        .map_err(|_| keys_err("chain state open"))?;
    let state = codec::decode(&plain).map_err(|_| keys_err("chain state decode"))?;
    if state.epoch().0 != epoch {
        return Err(keys_err("chain state epoch"));
    }
    Ok(state)
}

fn split_sealed(bytes: &[u8]) -> Result<([u8; aead::NONCE_LEN], Vec<u8>), CellError> {
    let (nonce, body) = bytes
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(keys_err("a sealed keystore row"))?;
    Ok((*nonce, body.to_vec()))
}

fn joined(nonce: &[u8; aead::NONCE_LEN], body: &[u8]) -> Vec<u8> {
    let mut out = nonce.to_vec();
    out.extend_from_slice(body);
    out
}

fn purpose_of(code: u8) -> Result<Purpose, CellError> {
    Purpose::from_code(code).ok_or(keys_err("a keystore purpose code"))
}

impl Keystore {
    /// The keystore loaded from `rows` of `cell`, writing through `sink`.
    /// Its chain state stays sealed until [`Keystore::open_groups`] opens
    /// it under the seal key of its epoch.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] for rows with no chain row, no live root of the
    /// chain row's epoch, or a row that does not decode.
    pub fn from_rows(
        cell: [u8; 16],
        rows: KeystoreRows,
        sink: std::sync::Arc<dyn KeystoreSink>,
    ) -> Result<Keystore, CellError> {
        let chain = rows.chain.ok_or(keys_err("no keystore chain row"))?;
        let cell_id = CellId(cell);
        let mut roots = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        let mut pending_root = None;
        for r in rows.roots {
            let backend = u8::try_from(r.backend)
                .ok()
                .and_then(backend_of)
                .ok_or(keys_err("a keystore backend code"))?;
            let row = RootRow {
                root: RootRef {
                    backend,
                    cell: Some(cell_id),
                    chain: Chain::App,
                    epoch: Epoch(r.epoch),
                    handle: CustodyHandle(r.handle),
                },
                wrapped: WrappedSealKey(r.wrapped),
            };
            match r.status {
                RootStatus::Live => {
                    roots.insert(r.epoch, row);
                }
                RootStatus::Destroyed(d) => {
                    roots.insert(r.epoch, row);
                    receipts.insert(r.epoch, d);
                }
                RootStatus::Pending => {
                    if pending_root.replace(row).is_some() {
                        return Err(keys_err("two pending roots"));
                    }
                }
            }
        }
        if !roots.contains_key(&chain.epoch) || receipts.contains_key(&chain.epoch) {
            return Err(keys_err("no live root of the chain row's epoch"));
        }
        let mut groups = BTreeMap::new();
        for g in rows.groups {
            let (nonce, body) = split_sealed(&g.sealed_secret)?;
            groups.insert(
                (GroupId(g.group), g.generation),
                GroupRow {
                    epoch: g.epoch,
                    nonce,
                    body,
                    public: g.public_key,
                },
            );
        }
        let mut keys = BTreeMap::new();
        for k in rows.keys {
            let sealed = decode_sealed_key(&k.sealed).map_err(|_| keys_err("a data key row"))?;
            keys.insert(DekId(k.id), (GroupId(k.group), k.generation, sealed));
        }
        let mut texts = BTreeMap::new();
        for t in rows.texts {
            let blob = decode_sealed_blob(&t.envelope).map_err(|_| keys_err("a text row"))?;
            texts.insert(
                t.id,
                TextRow {
                    dek: DekId(t.dek),
                    generation: t.generation,
                    blob,
                },
            );
        }
        let mut signers = BTreeMap::new();
        let mut retired = BTreeMap::new();
        for s in rows.signers {
            let purpose = purpose_of(s.purpose)?;
            match s.sealed {
                Some((epoch, sealed)) => {
                    let (nonce, body) = split_sealed(&sealed)?;
                    let row = SignerRow {
                        generation: s.generation,
                        epoch,
                        nonce,
                        body,
                        public: s.public_key,
                        created_us: s.created_at,
                    };
                    if signers.insert(purpose, row).is_some() {
                        return Err(keys_err("two current signing keys of one purpose"));
                    }
                }
                None => {
                    retired.insert((purpose, s.generation), s.public_key);
                }
            }
        }
        let logins = LoginIndex {
            lookup: chain.lookup_group.map(GroupId),
            group: chain.login_group.map(GroupId),
            texts: rows
                .logins
                .iter()
                .map(|l| (u128::from_be_bytes(l.account), l.text))
                .collect(),
            digests: rows
                .digests
                .iter()
                .map(|d| (d.digest, u128::from_be_bytes(d.account)))
                .collect(),
        };
        Ok(Keystore {
            cell: cell_id,
            // A stand-in of the right epoch until the sealed state opens.
            chain_state: ChainState::genesis(Epoch(chain.epoch)),
            roots,
            receipts,
            groups,
            keys,
            texts,
            signers,
            retired,
            pending_root,
            requested: rows.requested.into_iter().collect(),
            logins,
            startup_unwrap: chain.startup_unwrap.map(RequestId),
            snapshots: None,
            persist: Persist {
                sink: Some(sink),
                dirty: Dirty::default(),
                written: None,
                sealed: Some((chain.epoch, chain.state)),
                closed: true,
            },
        })
    }

    /// Opens the sealed chain state of a loaded keystore under `s`. A
    /// keystore whose chain state is open is left as it is.
    pub(super) fn open_chain_state(&mut self, s: &SealKey) -> Result<(), CellError> {
        if !self.persist.closed {
            return Ok(());
        }
        let (epoch, bytes) = self
            .persist
            .sealed
            .as_ref()
            .ok_or(keys_err("no sealed chain state"))?;
        let state = open_state(s, self.cell, *epoch, bytes)?;
        self.persist.written = Some(state.clone());
        self.chain_state = state;
        self.persist.closed = false;
        Ok(())
    }

    /// Whether the keystore writes through to its tables.
    pub fn writes_through(&self) -> bool {
        self.persist.sink.is_some()
    }

    /// Makes the keystore write through `sink`, with every row marked, so
    /// the next flush writes the whole keystore.
    pub(super) fn attach(&mut self, sink: std::sync::Arc<dyn KeystoreSink>) {
        self.persist.sink = Some(sink);
        self.persist.written = None;
        self.persist.sealed = None;
        let d = &mut self.persist.dirty;
        d.meta = true;
        d.roots.extend(self.roots.keys().copied());
        d.roots
            .extend(self.pending_root.iter().map(|r| r.root.epoch.0));
        d.groups.extend(self.groups.keys().copied());
        d.keys.extend(self.keys.keys().copied());
        d.texts.extend(self.texts.keys().copied());
        d.signers
            .extend(self.signers.iter().map(|(p, r)| (*p, r.generation)));
        d.signers.extend(self.retired.keys().copied());
        d.digests.extend(self.logins.digests.keys().copied());
        d.logins.extend(self.logins.texts.keys().copied());
        d.requested.extend(self.requested.iter().copied());
    }

    /// The chain row, sealing the chain state under `seal` when it changed
    /// since the last write.
    fn chain_row(&mut self, seal: Option<&SealKey>) -> Result<Option<ChainRow>, CellError> {
        let changed =
            !self.persist.closed && self.persist.written.as_ref() != Some(&self.chain_state);
        if !changed && !self.persist.dirty.meta {
            return Ok(None);
        }
        let sealed = match (&self.persist.sealed, changed) {
            (Some(s), false) => s.clone(),
            _ => {
                let s = seal.ok_or(keys_err("no seal key to seal the chain state"))?;
                let bytes = seal_state(s, self.cell, &self.chain_state)?;
                (self.chain_state.epoch().0, bytes)
            }
        };
        self.persist.sealed = Some(sealed.clone());
        Ok(Some(ChainRow {
            epoch: sealed.0,
            state: sealed.1,
            lookup_group: self.logins.lookup.map(|g| g.0),
            login_group: self.logins.group.map(|g| g.0),
            startup_unwrap: self.startup_unwrap.map(|r| r.0),
        }))
    }

    fn root_change(&self, epoch: u64) -> Change<u64, TableRoot> {
        let row = |r: &RootRow, wrapped: Vec<u8>, status| {
            Change::Put(TableRoot {
                epoch,
                backend: i16::from(backend_code(r.root.backend)),
                handle: r.root.handle.0.clone(),
                wrapped,
                status,
            })
        };
        if let Some(r) = self.roots.get(&epoch) {
            let status = match self.receipts.get(&epoch) {
                Some(d) => RootStatus::Destroyed(*d),
                None => RootStatus::Live,
            };
            row(r, r.wrapped.0.clone(), status)
        } else {
            match &self.pending_root {
                Some(r) if r.root.epoch.0 == epoch => row(r, Vec::new(), RootStatus::Pending),
                _ => Change::Delete(epoch),
            }
        }
    }

    fn group_purpose(&self, g: GroupId) -> u8 {
        if self.logins.lookup == Some(g) {
            return Purpose::Lookup.code();
        }
        self.chain_state
            .group(g)
            .and_then(|s| s.purpose)
            .unwrap_or(Purpose::Text)
            .code()
    }

    /// The batch of every marked row.
    fn changes(&mut self, seal: Option<&SealKey>) -> Result<KeystoreChanges, CellError> {
        let mut c = KeystoreChanges {
            chain: self.chain_row(seal)?,
            ..KeystoreChanges::default()
        };
        let d = self.persist.dirty.clone();
        for e in &d.roots {
            c.roots.push(self.root_change(*e));
        }
        for (g, generation) in &d.groups {
            c.groups.push(match self.groups.get(&(*g, *generation)) {
                Some(r) => Change::Put(GroupKeyRow {
                    group: g.0,
                    generation: *generation,
                    purpose: self.group_purpose(*g),
                    public_key: r.public.clone(),
                    sealed_secret: joined(&r.nonce, &r.body),
                    epoch: r.epoch,
                }),
                None => Change::Delete((g.0, *generation)),
            });
        }
        for dek in &d.keys {
            c.keys.push(match self.keys.get(dek) {
                Some((g, generation, sealed)) => Change::Put(DataKeyRow {
                    id: dek.0,
                    group: g.0,
                    generation: *generation,
                    sealed: encode_sealed_key(sealed).map_err(|_| keys_err("a data key row"))?,
                }),
                None => Change::Delete(dek.0),
            });
        }
        for id in &d.texts {
            c.texts.push(match self.texts.get(id) {
                Some(t) => Change::Put(KeystoreTextRow {
                    id: *id,
                    dek: t.dek.0,
                    generation: t.generation,
                    envelope: encode_sealed_blob(&t.blob).map_err(|_| keys_err("a text row"))?,
                }),
                None => Change::Delete(*id),
            });
        }
        for (p, generation) in &d.signers {
            let current = self.signers.get(p).filter(|r| r.generation == *generation);
            c.signers
                .push(match (current, self.retired.get(&(*p, *generation))) {
                    (Some(r), _) => Change::Put(TableSigner {
                        purpose: p.code(),
                        generation: *generation,
                        public_key: r.public.clone(),
                        created_at: r.created_us,
                        sealed: Some((r.epoch, joined(&r.nonce, &r.body))),
                    }),
                    // A replaced generation keeps its public key. The row
                    // keeps its creation time (`keystore.signer` upsert).
                    (None, Some(public)) => Change::Put(TableSigner {
                        purpose: p.code(),
                        generation: *generation,
                        public_key: public.clone(),
                        created_at: 0,
                        sealed: None,
                    }),
                    (None, None) => Change::Delete((p.code(), *generation)),
                });
        }
        for digest in &d.digests {
            c.digests.push(match self.logins.digests.get(digest) {
                Some(a) => Change::Put(LoginDigestRow {
                    digest: *digest,
                    account: a.to_be_bytes(),
                }),
                None => Change::Delete(*digest),
            });
        }
        for account in &d.logins {
            c.logins.push(match self.logins.texts.get(account) {
                Some(t) => Change::Put(LoginTextRow {
                    account: account.to_be_bytes(),
                    text: *t,
                }),
                None => Change::Delete(account.to_be_bytes()),
            });
        }
        for id in &d.requested {
            c.requested.push(if self.requested.contains(id) {
                Change::Put(*id)
            } else {
                Change::Delete(*id)
            });
        }
        Ok(c)
    }

    /// Writes every marked row through the sink in one batch (module
    /// documentation). `seal` is the seal key of the chain state's epoch,
    /// needed when the chain state changed. Without a sink the marks are
    /// dropped, as the keystore lives in memory only.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] when the sink refuses or a row does not seal.
    /// The marks are kept, so the next flush writes them.
    pub async fn flush(&mut self, seal: Option<&SealKey>) -> Result<(), CellError> {
        let Some(sink) = self.persist.sink.clone() else {
            self.persist.dirty = Dirty::default();
            return Ok(());
        };
        let before = self.persist.sealed.clone();
        let changes = match self.changes(seal) {
            Ok(c) => c,
            Err(e) => {
                self.persist.sealed = before;
                return Err(e);
            }
        };
        if changes.is_empty() {
            return Ok(());
        }
        if let Err(e) = sink.apply(&changes).await {
            self.persist.sealed = before;
            return Err(e);
        }
        self.persist.dirty = Dirty::default();
        if !self.persist.closed {
            self.persist.written = Some(self.chain_state.clone());
        }
        Ok(())
    }

    /// A SHA-256 over every row of the keystore in a canonical form, with
    /// the chain state in its plain stored form. Two keystores with the
    /// same fingerprint hold the same rows and chain state. A test compares
    /// a keystore before a restart with the one loaded after it.
    ///
    /// # Errors
    ///
    /// [`CellError::Keys`] while the chain state is still sealed, or for a
    /// row that does not encode.
    pub fn fingerprint(&self) -> Result<[u8; 32], CellError> {
        if self.persist.closed {
            return Err(keys_err("the chain state is still sealed"));
        }
        let mut out = Vec::new();
        let mut put = |b: &[u8]| {
            out.extend_from_slice(&u64::try_from(b.len()).unwrap_or(u64::MAX).to_be_bytes());
            out.extend_from_slice(b);
        };
        put(&self.cell.0);
        put(&codec::encode(&self.chain_state).map_err(|_| keys_err("chain state encode"))?);
        for (e, r) in &self.roots {
            put(&e.to_be_bytes());
            put(&[backend_code(r.root.backend)]);
            put(&r.root.handle.0);
            put(&r.wrapped.0);
            put(self.receipts.get(e).map_or(&[][..], |d| &d[..]));
        }
        if let Some(r) = &self.pending_root {
            put(b"pending");
            put(&r.root.epoch.0.to_be_bytes());
            put(&r.root.handle.0);
        }
        for ((g, generation), r) in &self.groups {
            put(&g.0);
            put(&generation.to_be_bytes());
            put(&r.epoch.to_be_bytes());
            put(&joined(&r.nonce, &r.body));
            put(&r.public);
        }
        for (dek, (g, generation, sealed)) in &self.keys {
            put(&dek.0);
            put(&g.0);
            put(&generation.to_be_bytes());
            put(&encode_sealed_key(sealed).map_err(|_| keys_err("a data key row"))?);
        }
        for (id, t) in &self.texts {
            put(id);
            put(&t.dek.0);
            put(&t.generation.to_be_bytes());
            put(&encode_sealed_blob(&t.blob).map_err(|_| keys_err("a text row"))?);
        }
        for (p, r) in &self.signers {
            put(&[p.code()]);
            put(&r.generation.to_be_bytes());
            put(&r.epoch.to_be_bytes());
            put(&joined(&r.nonce, &r.body));
            put(&r.public);
            put(&r.created_us.to_be_bytes());
        }
        for ((p, generation), public) in &self.retired {
            put(&[p.code()]);
            put(&generation.to_be_bytes());
            put(public);
        }
        put(self.logins.lookup.as_ref().map_or(&[][..], |g| &g.0[..]));
        put(self.logins.group.as_ref().map_or(&[][..], |g| &g.0[..]));
        for (a, t) in &self.logins.texts {
            put(&a.to_be_bytes());
            put(t);
        }
        for (d, a) in &self.logins.digests {
            put(d);
            put(&a.to_be_bytes());
        }
        for id in &self.requested {
            put(id);
        }
        put(self.startup_unwrap.as_ref().map_or(&[][..], |r| &r.0[..]));
        Ok(fstp_crypto::sha256(&out))
    }
}

//! The vault keystore (ADR-004, records of lanes L8 and L11, gap G12).
//!
//! It gives the vault process its keys: the Vault chain's composite anchor
//! key, the data key that seals every stored vault value, the key of the
//! `vault.query_log` digests and the identity `Match` key. Its rows live
//! in the `keystore` tables of the vault database `v_<cell>`, written and
//! read through `v_<cell>_keys` only (I-82):
//!
//! ```text
//! root      chain Vault, epoch e, backend, custody handle, wrapped S(e),
//!           state 1 live, 2 destroyed, 3 pending
//!           wrap AAD = "fstp-vault-seal-key-v1" || cell || chain || be64(epoch)
//! group     purpose Anchor, Fact, Match or Attribute, generation g, public
//!           key, secret sealed under S(e) as nonce || AES-256-GCM ciphertext
//!           AAD = "fstp-vault-group-v1" || cell || purpose || group
//!                 || be32(generation) || be64(epoch)
//! data key  the Fact data key, and one data key per identity tuple in an
//!           Attribute group, each sealed to its group key (FSK1)
//! tuple     an identity's attribute tuple, FSB1 under its data key
//! intent    the planner's chain state, sealed under S(e) (lane L11)
//! ```
//!
//! The query digest key is `HKDF-SHA-256(Match secret,
//! "fstp-vault-query-digest-v1")`. The identity match key is
//! `HMAC-SHA-256(M, tuple)` with `M = HKDF-SHA-256(Match secret,
//! "fstp-keyed-digest-v1" || Match code)` ([`match_hmac_key`]). The root
//! lives in the vault's own `fstp-keyd` entry, whose `vault` socket role
//! reaches the Vault chain only. No row holds an open key (I-80). An error
//! names a rule and never quotes row bytes (R-NF-02).
//!
//! [`genesis`] and [`open`] run the custody calls over pure row codecs
//! ([`seal_rows`], [`open_rows`]). [`read_rows`] and [`write_rows`] move
//! the rows. Rotation and erasure on the Vault chain are
//! `crate::erasure` (ADR-004 record of lane L11). The current epoch is the
//! highest live root. [`open_rows`] opens the groups of that epoch, at
//! whatever generation the last rotation left them.

use fstp_crypto::composite::CompositeSigningKey;
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_crypto::{aead, kdf};
use fstp_custody::{
    Aad, BackendId, CellId, Chain, Custody, CustodyHandle, Epoch, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_keys::envelope::{self, DataKey, SealContext};
use fstp_keys::{GroupId, ObjectId, Purpose};
use fstp_pgwire::{Client, Uuid};
use fstp_rt::Runtime;

use crate::VaultError;
use crate::service::AeadSealer;

/// The AAD label of the seal key wrapped under its root.
pub const SEAL_AAD: &[u8] = b"fstp-vault-seal-key-v1";
/// The AAD label of a group secret sealed under the seal key.
pub const GROUP_AAD: &[u8] = b"fstp-vault-group-v1";
/// The HKDF label of the query digest key.
pub const QUERY_DIGEST_LABEL: &[u8] = b"fstp-vault-query-digest-v1";

/// The HKDF label of the identity `Match` HMAC key, followed by the
/// `Match` purpose code: the keyed digest derivation of the App chain's
/// `Lookup` key (ADR-004 record of lane L11).
pub const KEYED_DIGEST_LABEL: &[u8] = b"fstp-keyed-digest-v1";

/// The chain of every row.
pub const CHAIN: Chain = Chain::Vault;
/// The epoch of the root genesis creates.
pub const ROOT_EPOCH: u64 = 1;
/// The generation of every group at genesis.
pub const GENERATION: u32 = 1;
/// The `state` of a live row.
pub const STATE_LIVE: i16 = 1;
/// The `keystore.root.state` of a destroyed root.
pub const STATE_DESTROYED: i16 = 2;
/// The `keystore.root.state` of a root created for a batch not yet
/// committed. Its wrapped key is empty.
pub const STATE_PENDING: i16 = 3;
/// The longest identity attribute tuple the keystore seals.
pub const MAX_TUPLE: usize = 4096;

/// The backend code of `keystore.root.backend`, as the App chain stores
/// it (`fstp_cell::tasks::erasure::snapshot`).
#[must_use]
pub const fn backend_code(b: BackendId) -> i16 {
    match b {
        BackendId::Okms => 1,
        BackendId::Keyd => 2,
        BackendId::Simulator => 3,
    }
}

fn backend_of(code: i16) -> Option<BackendId> {
    match code {
        1 => Some(BackendId::Okms),
        2 => Some(BackendId::Keyd),
        3 => Some(BackendId::Simulator),
        _ => None,
    }
}

fn bad(rule: &'static str) -> VaultError {
    VaultError::Malformed(rule)
}

/// The `keystore.root` row.
#[derive(Clone, PartialEq, Eq)]
pub struct RootRow {
    /// The epoch.
    pub epoch: u64,
    /// The backend code ([`backend_code`]).
    pub backend: i16,
    /// The custody handle.
    pub handle: Vec<u8>,
    /// `S(e)` wrapped under the root. Empty while the root is pending.
    pub wrapped: Vec<u8>,
    /// When the root was created, in microseconds.
    pub created_at: i64,
    /// [`STATE_LIVE`], [`STATE_DESTROYED`] or [`STATE_PENDING`].
    pub state: i16,
    /// The custody destroy receipt of a destroyed root.
    pub receipt: Option<Vec<u8>>,
}

/// One `keystore.group_key` row.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupRow {
    /// The purpose code.
    pub purpose: u8,
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The group public key.
    pub public_key: Vec<u8>,
    /// The group secret sealed under `S(epoch)`, `nonce || ciphertext`.
    pub sealed_secret: Vec<u8>,
    /// The epoch of the seal key.
    pub epoch: u64,
}

/// One `keystore.data_key` row.
#[derive(Clone, PartialEq, Eq)]
pub struct DataKeyRow {
    /// The data key id.
    pub id: [u8; 16],
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The key sealed to its group key (FSK1).
    pub sealed: Vec<u8>,
}

/// One `keystore.identity_tuple` row (ADR-004 record of lane L11).
#[derive(Clone, PartialEq, Eq)]
pub struct TupleRow {
    /// The identity id, which is also its data key id.
    pub identity: [u8; 16],
    /// The `Attribute` group of its data key.
    pub group: [u8; 16],
    /// The tuple sealed under its data key (FSB1).
    pub envelope: Vec<u8>,
}

/// The `keystore.erasure_intent` row of the Vault chain.
#[derive(Clone, PartialEq, Eq)]
pub struct IntentRow {
    /// The row id.
    pub id: [u8; 16],
    /// The chain state sealed under `S(e)` of the current epoch.
    pub plan: Vec<u8>,
    /// The planner phase code.
    pub phase: i16,
}

/// Every row of a vault keystore.
#[derive(Clone, PartialEq, Eq)]
pub struct KeystoreRows {
    /// The root of the current epoch: the highest live one.
    pub root: RootRow,
    /// Every other root row: an older live root while an erasure runs, a
    /// pending one, and the destroyed ones.
    pub others: Vec<RootRow>,
    /// The live groups.
    pub groups: Vec<GroupRow>,
    /// The live data keys.
    pub data_keys: Vec<DataKeyRow>,
    /// The identity tuples.
    pub tuples: Vec<TupleRow>,
    /// The intent row, once the chain state was written.
    pub intent: Option<IntentRow>,
}

impl KeystoreRows {
    /// Every root row, the current one first.
    pub fn all_roots(&self) -> impl Iterator<Item = &RootRow> {
        std::iter::once(&self.root).chain(self.others.iter())
    }
}

impl std::fmt::Debug for KeystoreRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoreRows")
            .field("epoch", &self.root.epoch)
            .field("groups", &self.groups.len())
            .field("data_keys", &self.data_keys.len())
            .finish()
    }
}

/// The open keys of a vault. Every secret is wiped on drop by its own
/// type. It implements no `Clone`, and its debug form shows no key.
pub struct VaultKeys {
    pub(crate) anchor_group: [u8; 16],
    pub(crate) anchor: CompositeSigningKey,
    pub(crate) fact_group: [u8; 16],
    pub(crate) fact: HybridSecretKey,
    pub(crate) match_group: [u8; 16],
    pub(crate) match_secret: HybridSecretKey,
    pub(crate) dek: [u8; 16],
    pub(crate) data_key: DataKey,
}

impl std::fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKeys").finish_non_exhaustive()
    }
}

fn random16() -> Result<[u8; 16], VaultError> {
    fstp_crypto::random_array::<16>().map_err(|_| VaultError::Unavailable("randomness"))
}

impl VaultKeys {
    /// Fresh keys, with `anchor` as the Vault chain's anchor key. The test
    /// world passes the key its witness already pins.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when a key cannot be made.
    pub fn with_anchor(anchor: CompositeSigningKey) -> Result<VaultKeys, VaultError> {
        let unavailable = |_| VaultError::Unavailable("key generation");
        let (anchor_group, fact_group, match_group) = (random16()?, random16()?, random16()?);
        let mut dek = random16()?;
        while dek == fact_group {
            dek = random16()?;
        }
        Ok(VaultKeys {
            anchor_group,
            anchor,
            fact_group,
            fact: hybrid_kem::generate().map_err(unavailable)?,
            match_group,
            match_secret: hybrid_kem::generate().map_err(unavailable)?,
            dek,
            data_key: DataKey::generate().map_err(|_| VaultError::Unavailable("key generation"))?,
        })
    }

    /// Fresh keys (`fstp-vault init-keys`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when a key cannot be made.
    pub fn generate() -> Result<VaultKeys, VaultError> {
        let anchor = fstp_crypto::composite::generate()
            .map_err(|_| VaultError::Unavailable("key generation"))?;
        VaultKeys::with_anchor(anchor)
    }

    /// The Vault chain's anchor public key, which the witness registers.
    #[must_use]
    pub fn anchor_public(&self) -> Vec<u8> {
        self.anchor.public_key().to_bytes().to_vec()
    }

    /// The id of the data key that seals the stored values.
    #[must_use]
    pub fn dek(&self) -> [u8; 16] {
        self.dek
    }

    /// The query digest key (module documentation).
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when the derivation fails.
    pub fn query_digest_key(&self) -> Result<SealKey, VaultError> {
        let mut out = fstp_custody::zeroed_key_box();
        kdf::hkdf_sha256(
            &[],
            &self.match_secret.to_bytes()[..],
            QUERY_DIGEST_LABEL,
            &mut out[..],
        )
        .map_err(|_| VaultError::Unavailable("the query digest key"))?;
        Ok(SealKey::from_box(out))
    }

    /// The anchor key and the sealer the service starts with.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when a key does not read.
    pub fn into_service_keys(self) -> Result<(CompositeSigningKey, AeadSealer), VaultError> {
        let key = aead::Key::from_bytes(self.data_key.expose())
            .map_err(|_| VaultError::Unavailable("the data key"))?;
        let sealer = AeadSealer::with_digest_key(self.dek, key, self.query_digest_key()?);
        Ok((self.anchor, sealer))
    }
}

fn group_aad(
    cell: &[u8; 16],
    purpose: Purpose,
    group: &[u8; 16],
    generation: u32,
    epoch: u64,
) -> Vec<u8> {
    let mut aad = GROUP_AAD.to_vec();
    aad.extend_from_slice(cell);
    aad.push(purpose.code());
    aad.extend_from_slice(group);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// The AAD of the seal key wrapped under the root of `epoch`.
#[must_use]
pub fn seal_aad(cell: &[u8; 16], epoch: u64) -> Aad {
    let mut aad = SEAL_AAD.to_vec();
    aad.extend_from_slice(cell);
    aad.push(CHAIN.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    Aad(aad)
}

fn fact_ctx(cell: &[u8; 16], group: &[u8; 16], generation: u32, dek: &[u8; 16]) -> SealContext {
    SealContext {
        cell: CellId(*cell),
        chain: CHAIN,
        purpose: Purpose::Fact,
        group: GroupId(*group),
        generation,
        object: ObjectId(*dek),
    }
}

/// The seal context of the data key `dek` of an identity tuple, sealed to
/// generation `generation` of the `Attribute` group `group` (FSK1).
#[must_use]
pub fn attribute_ctx(
    cell: &[u8; 16],
    group: &[u8; 16],
    generation: u32,
    dek: &[u8; 16],
) -> SealContext {
    SealContext {
        cell: CellId(*cell),
        chain: CHAIN,
        purpose: Purpose::Attribute,
        group: GroupId(*group),
        generation,
        object: ObjectId(*dek),
    }
}

/// The seal context of the tuple of `identity` under its data key (FSB1).
/// It names generation 0, so a re-seal of the data key to a later group
/// generation still opens the tuple.
#[must_use]
pub fn tuple_ctx(cell: &[u8; 16], group: &[u8; 16], identity: &[u8; 16]) -> SealContext {
    attribute_ctx(cell, group, 0, identity)
}

/// The identity `Match` HMAC key of the `Match` group secret `sk` (module
/// documentation).
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the derivation fails.
pub fn match_hmac_key(sk: &HybridSecretKey) -> Result<SealKey, VaultError> {
    let mut info = KEYED_DIGEST_LABEL.to_vec();
    info.push(Purpose::Match.code());
    let mut out = fstp_custody::zeroed_key_box();
    kdf::hkdf_sha256(&[], &sk.to_bytes()[..], &info, &mut out[..])
        .map_err(|_| VaultError::Unavailable("the Match key"))?;
    Ok(SealKey::from_box(out))
}

/// The group row of `purpose` and `group` at `generation`, its secret
/// sealed under `seal` of `epoch`.
#[allow(
    clippy::too_many_arguments,
    reason = "each part of the group row and its AAD, as ADR-004 lists them"
)]
pub(crate) fn seal_group_at(
    seal: &aead::Key,
    cell: &[u8; 16],
    purpose: Purpose,
    group: [u8; 16],
    generation: u32,
    epoch: u64,
    public_key: Vec<u8>,
    secret: &[u8],
) -> Result<GroupRow, VaultError> {
    let aad = group_aad(cell, purpose, &group, generation, epoch);
    let s = aead::seal(seal, &aad, secret).map_err(|_| VaultError::Unavailable("sealing"))?;
    let mut sealed_secret = s.nonce.to_vec();
    sealed_secret.extend_from_slice(&s.body);
    Ok(GroupRow {
        purpose: purpose.code(),
        group,
        generation,
        public_key,
        sealed_secret,
        epoch,
    })
}

fn seal_group(
    seal: &aead::Key,
    cell: &[u8; 16],
    purpose: Purpose,
    group: [u8; 16],
    public_key: Vec<u8>,
    secret: &[u8],
) -> Result<GroupRow, VaultError> {
    seal_group_at(
        seal, cell, purpose, group, GENERATION, ROOT_EPOCH, public_key, secret,
    )
}

/// The rows of `keys` for `cell`, with every group secret sealed under
/// `seal` and the root row `root`.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when a seal fails.
pub fn seal_rows(
    cell: &[u8; 16],
    keys: &VaultKeys,
    seal: &SealKey,
    root: RootRow,
) -> Result<KeystoreRows, VaultError> {
    let s = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("the seal key"))?;
    let unavailable = |_| VaultError::Unavailable("sealing");
    let anchor_secret = keys.anchor.to_bytes().map_err(unavailable)?;
    let groups = vec![
        seal_group(
            &s,
            cell,
            Purpose::Anchor,
            keys.anchor_group,
            keys.anchor_public(),
            &anchor_secret[..],
        )?,
        seal_group(
            &s,
            cell,
            Purpose::Fact,
            keys.fact_group,
            keys.fact.public().to_bytes().to_vec(),
            &keys.fact.to_bytes()[..],
        )?,
        seal_group(
            &s,
            cell,
            Purpose::Match,
            keys.match_group,
            keys.match_secret.public().to_bytes().to_vec(),
            &keys.match_secret.to_bytes()[..],
        )?,
    ];
    let ctx = fact_ctx(cell, &keys.fact_group, GENERATION, &keys.dek);
    let sealed = envelope::seal_key(keys.fact.public(), &keys.data_key, &ctx)
        .map_err(|_| VaultError::Unavailable("sealing"))?;
    let data_key = DataKeyRow {
        id: keys.dek,
        group: keys.fact_group,
        generation: GENERATION,
        sealed: envelope::encode_sealed_key(&sealed)
            .map_err(|_| VaultError::Unavailable("sealing"))?,
    };
    Ok(KeystoreRows {
        root,
        others: Vec::new(),
        groups,
        data_keys: vec![data_key],
        tuples: Vec::new(),
        intent: None,
    })
}

/// The one group of `purpose`, sealed under the current epoch.
fn group_of(rows: &KeystoreRows, purpose: Purpose) -> Result<&GroupRow, VaultError> {
    let mut found = rows.groups.iter().filter(|g| g.purpose == purpose.code());
    match (found.next(), found.next()) {
        (Some(g), None) if g.epoch == rows.root.epoch => Ok(g),
        _ => Err(bad("the keystore groups")),
    }
}

/// Opens the secret of the group row `g` of `cell` under the seal key
/// `seal`. The bytes are wiped on drop.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the row does not open under `seal`.
pub fn open_group_secret(
    seal: &SealKey,
    cell: &[u8; 16],
    g: &GroupRow,
) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, VaultError> {
    let s = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("the seal key"))?;
    let purpose = Purpose::from_code(g.purpose).ok_or(bad("a group purpose"))?;
    open_group(&s, cell, purpose, g)
}

fn open_group(
    seal: &aead::Key,
    cell: &[u8; 16],
    purpose: Purpose,
    g: &GroupRow,
) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, VaultError> {
    let (nonce, body) = g
        .sealed_secret
        .split_at_checked(aead::NONCE_LEN)
        .ok_or(bad("a sealed group secret"))?;
    let nonce: [u8; aead::NONCE_LEN] =
        nonce.try_into().map_err(|_| bad("a sealed group secret"))?;
    let aad = group_aad(cell, purpose, &g.group, g.generation, g.epoch);
    aead::open(seal, &nonce, &aad, body).map_err(|_| bad("a sealed group secret"))
}

/// Opens the hybrid KEM secret of the group row `g` under `seal`, and
/// checks it against the row's public key.
pub(crate) fn open_kem(
    seal: &aead::Key,
    cell: &[u8; 16],
    purpose: Purpose,
    g: &GroupRow,
) -> Result<HybridSecretKey, VaultError> {
    let secret = open_group(seal, cell, purpose, g)?;
    let sk = HybridSecretKey::from_bytes(&secret).map_err(|_| bad("a group secret"))?;
    let public =
        HybridPublicKey::from_bytes(&g.public_key).map_err(|_| bad("a group public key"))?;
    if sk.public().to_bytes() != public.to_bytes() {
        return Err(bad("a group public key"));
    }
    Ok(sk)
}

/// Opens the anchor key of the group row `g` under `seal`, and checks it
/// against the row's public key.
pub(crate) fn open_anchor(
    seal: &aead::Key,
    cell: &[u8; 16],
    g: &GroupRow,
) -> Result<CompositeSigningKey, VaultError> {
    let anchor = {
        let secret = open_group(seal, cell, Purpose::Anchor, g)?;
        CompositeSigningKey::from_bytes(&secret).map_err(|_| bad("the anchor key"))?
    };
    if anchor.public_key().to_bytes()[..] != g.public_key[..] {
        return Err(bad("the anchor public key"));
    }
    Ok(anchor)
}

/// Opens the `Fact` data key row `d` under the `Fact` group secret.
pub(crate) fn open_fact_key(
    cell: &[u8; 16],
    fact: &HybridSecretKey,
    d: &DataKeyRow,
) -> Result<DataKey, VaultError> {
    let sealed = envelope::decode_sealed_key(&d.sealed).map_err(|_| bad("a sealed data key"))?;
    let ctx = fact_ctx(cell, &d.group, d.generation, &d.id);
    envelope::open_key(fact, &sealed, &ctx).map_err(|_| bad("a sealed data key"))
}

/// Opens `rows` of `cell` under the unwrapped seal key `seal` of the
/// current epoch: the `Anchor`, `Fact` and `Match` groups and the `Fact`
/// data key. `Attribute` groups and tuple data keys are the erasure
/// runner's (`crate::erasure`).
///
/// # Errors
///
/// [`VaultError::Malformed`] when a row does not open, a public key does
/// not match its secret, or a group or data key is missing or repeated.
pub fn open_rows(
    cell: &[u8; 16],
    rows: &KeystoreRows,
    seal: &SealKey,
) -> Result<VaultKeys, VaultError> {
    let s = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("the seal key"))?;
    let anchor_row = group_of(rows, Purpose::Anchor)?;
    let anchor = open_anchor(&s, cell, anchor_row)?;
    let fact_row = group_of(rows, Purpose::Fact)?;
    let fact = open_kem(&s, cell, Purpose::Fact, fact_row)?;
    let match_row = group_of(rows, Purpose::Match)?;
    let match_secret = open_kem(&s, cell, Purpose::Match, match_row)?;
    let mut in_fact = rows.data_keys.iter().filter(|d| d.group == fact_row.group);
    let (Some(d), None) = (in_fact.next(), in_fact.next()) else {
        return Err(bad("the keystore data keys"));
    };
    if d.generation != fact_row.generation {
        return Err(bad("the keystore data keys"));
    }
    let data_key = open_fact_key(cell, &fact, d)?;
    Ok(VaultKeys {
        anchor_group: anchor_row.group,
        anchor,
        fact_group: fact_row.group,
        fact,
        match_group: match_row.group,
        match_secret,
        dek: d.id,
        data_key,
    })
}

/// Genesis of the keystore of `cell` (ADR-004 record of lane L8): creates
/// the root through `custody`, draws `S(1)`, wraps it, and seals `keys`.
/// The caller writes the rows ([`write_rows`]).
///
/// # Errors
///
/// [`VaultError::Unavailable`] when custody refuses or a seal fails.
pub async fn genesis<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    keys: &VaultKeys,
    now: i64,
) -> Result<KeystoreRows, VaultError> {
    let root = custody
        .create_root(RootLabel {
            cell: Some(CellId(cell)),
            chain: CHAIN,
            epoch: Epoch(ROOT_EPOCH),
        })
        .await
        .map_err(|_| VaultError::Unavailable("custody create"))?;
    let seal = SealKey::generate().map_err(|_| VaultError::Unavailable("the seal key"))?;
    let wrapped = custody
        .wrap(&root, &seal, &seal_aad(&cell, ROOT_EPOCH))
        .await
        .map_err(|_| VaultError::Unavailable("custody wrap"))?;
    let row = RootRow {
        epoch: ROOT_EPOCH,
        backend: backend_code(root.backend),
        handle: root.handle.0,
        wrapped: wrapped.0,
        created_at: now,
        state: STATE_LIVE,
        receipt: None,
    };
    seal_rows(&cell, keys, &seal, row)
}

/// Opens the keystore `rows` of `cell` through `custody`.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when custody refuses the unwrap, and the
/// errors of [`open_rows`].
pub async fn open<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    rows: &KeystoreRows,
) -> Result<VaultKeys, VaultError> {
    let root = RootRef {
        backend: backend_of(rows.root.backend).ok_or(bad("the root backend"))?,
        cell: Some(CellId(cell)),
        chain: CHAIN,
        epoch: Epoch(rows.root.epoch),
        handle: CustodyHandle(rows.root.handle.clone()),
    };
    let seal = custody
        .unwrap(
            &root,
            &WrappedSealKey(rows.root.wrapped.clone()),
            &seal_aad(&cell, rows.root.epoch),
        )
        .await
        .map_err(|_| VaultError::Unavailable("custody unwrap"))?;
    open_rows(&cell, rows, &seal)
}

const DB: &str = "the vault keystore tables";

fn db(_: fstp_pgwire::Error) -> VaultError {
    VaultError::Unavailable(DB)
}

fn int(n: u64) -> Result<i64, VaultError> {
    i64::try_from(n).map_err(|_| bad("a keystore integer"))
}

fn int32(n: u32) -> Result<i32, VaultError> {
    i32::try_from(n).map_err(|_| bad("a keystore integer"))
}

fn uint(n: i64) -> Result<u64, VaultError> {
    u64::try_from(n).map_err(|_| bad("a keystore integer"))
}

fn uint32(n: i32) -> Result<u32, VaultError> {
    u32::try_from(n).map_err(|_| bad("a keystore integer"))
}

/// Whether the keystore holds any root row of the Vault chain.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the read fails.
pub async fn has_root<R: Runtime>(client: &mut Client<R>) -> Result<bool, VaultError> {
    let chain = i16::from(CHAIN.code());
    let rows = client
        .query(
            "SELECT 1 FROM keystore.root WHERE chain = $1 LIMIT 1",
            &[&chain],
        )
        .await
        .map_err(db)?;
    Ok(!rows.is_empty())
}

/// Writes `rows` in one transaction. A keystore that holds a root row
/// already is refused, so genesis never runs twice.
///
/// # Errors
///
/// [`VaultError::Conflict`] when a root row exists, and
/// [`VaultError::Unavailable`] when the write fails. Nothing is written
/// then.
pub async fn write_rows<R: Runtime>(
    client: &mut Client<R>,
    rows: &KeystoreRows,
) -> Result<(), VaultError> {
    let chain = i16::from(CHAIN.code());
    let mut tx = client.transaction().await.map_err(db)?;
    let existing = tx
        .query(
            "SELECT 1 FROM keystore.root WHERE chain = $1 LIMIT 1",
            &[&chain],
        )
        .await
        .map_err(db)?;
    if !existing.is_empty() {
        let _ = tx.rollback().await;
        return Err(VaultError::Conflict("a vault keystore genesis"));
    }
    let r = &rows.root;
    tx.execute(
        "INSERT INTO keystore.root (chain, epoch, backend, handle, wrapped_seal_key, state, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &chain,
            &int(r.epoch)?,
            &r.backend,
            &r.handle,
            &r.wrapped,
            &STATE_LIVE,
            &r.created_at,
        ],
    )
    .await
    .map_err(db)?;
    for g in &rows.groups {
        tx.execute(
            "INSERT INTO keystore.group_key \
             (chain, purpose, group_id, generation, public_key, sealed_secret, epoch, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &chain,
                &i16::from(g.purpose),
                &Uuid::from_bytes(g.group),
                &int32(g.generation)?,
                &g.public_key,
                &g.sealed_secret,
                &int(g.epoch)?,
                &STATE_LIVE,
            ],
        )
        .await
        .map_err(db)?;
    }
    for d in &rows.data_keys {
        tx.execute(
            "INSERT INTO keystore.data_key (id, group_id, generation, sealed, state) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &Uuid::from_bytes(d.id),
                &Uuid::from_bytes(d.group),
                &int32(d.generation)?,
                &d.sealed,
                &STATE_LIVE,
            ],
        )
        .await
        .map_err(db)?;
    }
    tx.commit().await.map_err(db)
}

/// Reads the rows of the keystore, or `None` when it holds no root row:
/// every root row, the live groups and data keys, the identity tuples and
/// the intent row of the Vault chain.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the read fails, and
/// [`VaultError::Malformed`] for root rows with no live one, more than one
/// intent row, or a row outside its column ranges.
pub async fn read_rows<R: Runtime>(
    client: &mut Client<R>,
) -> Result<Option<KeystoreRows>, VaultError> {
    let chain = i16::from(CHAIN.code());
    let corrupt = bad("a keystore row");
    let mut roots = Vec::new();
    for r in client
        .query(
            "SELECT epoch, backend, handle, wrapped_seal_key, created_at, state, receipt \
             FROM keystore.root WHERE chain = $1 ORDER BY epoch",
            &[&chain],
        )
        .await
        .map_err(db)?
    {
        let state: i16 = r.get(5).map_err(|_| corrupt)?;
        if ![STATE_LIVE, STATE_DESTROYED, STATE_PENDING].contains(&state) {
            return Err(corrupt);
        }
        roots.push(RootRow {
            epoch: uint(r.get(0).map_err(|_| corrupt)?)?,
            backend: r.get(1).map_err(|_| corrupt)?,
            handle: r.get(2).map_err(|_| corrupt)?,
            wrapped: r.get(3).map_err(|_| corrupt)?,
            created_at: r.get(4).map_err(|_| corrupt)?,
            state,
            receipt: r.get(6).map_err(|_| corrupt)?,
        });
    }
    if roots.is_empty() {
        return Ok(None);
    }
    let current = roots
        .iter()
        .rposition(|r| r.state == STATE_LIVE)
        .ok_or(bad("a keystore with no live root"))?;
    let root = roots.remove(current);
    let mut groups = Vec::new();
    for r in client
        .query(
            "SELECT purpose, group_id, generation, public_key, sealed_secret, epoch \
             FROM keystore.group_key WHERE chain = $1 AND state = $2 \
             ORDER BY group_id, generation",
            &[&chain, &STATE_LIVE],
        )
        .await
        .map_err(db)?
    {
        let purpose: i16 = r.get(0).map_err(|_| corrupt)?;
        let group: Uuid = r.get(1).map_err(|_| corrupt)?;
        groups.push(GroupRow {
            purpose: u8::try_from(purpose).map_err(|_| corrupt)?,
            group: *group.as_bytes(),
            generation: uint32(r.get(2).map_err(|_| corrupt)?)?,
            public_key: r.get(3).map_err(|_| corrupt)?,
            sealed_secret: r.get(4).map_err(|_| corrupt)?,
            epoch: uint(r.get(5).map_err(|_| corrupt)?)?,
        });
    }
    let mut data_keys = Vec::new();
    for r in client
        .query(
            "SELECT id, group_id, generation, sealed FROM keystore.data_key \
             WHERE state = $1 ORDER BY id",
            &[&STATE_LIVE],
        )
        .await
        .map_err(db)?
    {
        let id: Uuid = r.get(0).map_err(|_| corrupt)?;
        let group: Uuid = r.get(1).map_err(|_| corrupt)?;
        data_keys.push(DataKeyRow {
            id: *id.as_bytes(),
            group: *group.as_bytes(),
            generation: uint32(r.get(2).map_err(|_| corrupt)?)?,
            sealed: r.get(3).map_err(|_| corrupt)?,
        });
    }
    let mut tuples = Vec::new();
    for r in client
        .query(
            "SELECT identity_id, group_id, envelope FROM keystore.identity_tuple \
             ORDER BY identity_id",
            &[],
        )
        .await
        .map_err(db)?
    {
        let id: Uuid = r.get(0).map_err(|_| corrupt)?;
        let group: Uuid = r.get(1).map_err(|_| corrupt)?;
        tuples.push(TupleRow {
            identity: *id.as_bytes(),
            group: *group.as_bytes(),
            envelope: r.get(2).map_err(|_| corrupt)?,
        });
    }
    let intents = client
        .query(
            "SELECT id, plan, phase FROM keystore.erasure_intent WHERE chain = $1",
            &[&chain],
        )
        .await
        .map_err(db)?;
    let intent = match intents.as_slice() {
        [] => None,
        [r] => {
            let id: Uuid = r.get(0).map_err(|_| corrupt)?;
            Some(IntentRow {
                id: *id.as_bytes(),
                plan: r.get(1).map_err(|_| corrupt)?,
                phase: r.get(2).map_err(|_| corrupt)?,
            })
        }
        _ => return Err(bad("more than one erasure intent row")),
    };
    Ok(Some(KeystoreRows {
        root,
        others: roots,
        groups,
        data_keys,
        tuples,
        intent,
    }))
}

/// One row change of the erasure runner (`crate::erasure`). A batch of
/// them is written in one transaction by [`apply_changes`].
#[derive(Clone)]
pub(crate) enum Change {
    /// Inserts or replaces the root row of its epoch.
    PutRoot(RootRow),
    /// Inserts or replaces the group row of its group and generation.
    PutGroup(GroupRow),
    /// Deletes the group row of a group and generation.
    DropGroup([u8; 16], u32),
    /// Inserts or replaces a data key row.
    PutDataKey(DataKeyRow),
    /// Deletes a data key row.
    DropDataKey([u8; 16]),
    /// Inserts or replaces a tuple row.
    PutTuple(TupleRow),
    /// Deletes a tuple row.
    DropTuple([u8; 16]),
    /// Inserts or replaces the intent row.
    PutIntent(IntentRow),
}

/// Writes `changes` in one transaction: all of them, or none.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the write fails. Nothing is written
/// then.
pub(crate) async fn apply_changes<R: Runtime>(
    client: &mut Client<R>,
    changes: &[Change],
    now: i64,
) -> Result<(), VaultError> {
    let chain = i16::from(CHAIN.code());
    let mut tx = client.transaction().await.map_err(db)?;
    for c in changes {
        match c {
            Change::PutRoot(r) => {
                let destroyed_at = (r.state == STATE_DESTROYED).then_some(now);
                tx.execute(
                    "INSERT INTO keystore.root (chain, epoch, backend, handle, wrapped_seal_key, \
                     state, created_at, destroyed_at, receipt) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                     ON CONFLICT (chain, epoch) DO UPDATE SET backend = EXCLUDED.backend, \
                     handle = EXCLUDED.handle, wrapped_seal_key = EXCLUDED.wrapped_seal_key, \
                     state = EXCLUDED.state, \
                     destroyed_at = COALESCE(keystore.root.destroyed_at, EXCLUDED.destroyed_at), \
                     receipt = EXCLUDED.receipt",
                    &[
                        &chain,
                        &int(r.epoch)?,
                        &r.backend,
                        &r.handle,
                        &r.wrapped,
                        &r.state,
                        &r.created_at,
                        &destroyed_at,
                        &r.receipt,
                    ],
                )
                .await
                .map_err(db)?;
            }
            Change::PutGroup(g) => {
                tx.execute(
                    "INSERT INTO keystore.group_key \
                     (chain, purpose, group_id, generation, public_key, sealed_secret, epoch, state) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (group_id, generation) DO UPDATE SET \
                     purpose = EXCLUDED.purpose, public_key = EXCLUDED.public_key, \
                     sealed_secret = EXCLUDED.sealed_secret, epoch = EXCLUDED.epoch, \
                     state = EXCLUDED.state",
                    &[
                        &chain,
                        &i16::from(g.purpose),
                        &Uuid::from_bytes(g.group),
                        &int32(g.generation)?,
                        &g.public_key,
                        &g.sealed_secret,
                        &int(g.epoch)?,
                        &STATE_LIVE,
                    ],
                )
                .await
                .map_err(db)?;
            }
            Change::DropGroup(group, generation) => {
                tx.execute(
                    "DELETE FROM keystore.group_key WHERE group_id = $1 AND generation = $2",
                    &[&Uuid::from_bytes(*group), &int32(*generation)?],
                )
                .await
                .map_err(db)?;
            }
            Change::PutDataKey(d) => {
                tx.execute(
                    "INSERT INTO keystore.data_key (id, group_id, generation, sealed, state) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET \
                     group_id = EXCLUDED.group_id, generation = EXCLUDED.generation, \
                     sealed = EXCLUDED.sealed, state = EXCLUDED.state",
                    &[
                        &Uuid::from_bytes(d.id),
                        &Uuid::from_bytes(d.group),
                        &int32(d.generation)?,
                        &d.sealed,
                        &STATE_LIVE,
                    ],
                )
                .await
                .map_err(db)?;
            }
            Change::DropDataKey(id) => {
                tx.execute(
                    "DELETE FROM keystore.data_key WHERE id = $1",
                    &[&Uuid::from_bytes(*id)],
                )
                .await
                .map_err(db)?;
            }
            Change::PutTuple(t) => {
                tx.execute(
                    "INSERT INTO keystore.identity_tuple (identity_id, group_id, envelope) \
                     VALUES ($1, $2, $3) ON CONFLICT (identity_id) DO UPDATE SET \
                     group_id = EXCLUDED.group_id, envelope = EXCLUDED.envelope",
                    &[
                        &Uuid::from_bytes(t.identity),
                        &Uuid::from_bytes(t.group),
                        &t.envelope,
                    ],
                )
                .await
                .map_err(db)?;
            }
            Change::DropTuple(id) => {
                tx.execute(
                    "DELETE FROM keystore.identity_tuple WHERE identity_id = $1",
                    &[&Uuid::from_bytes(*id)],
                )
                .await
                .map_err(db)?;
            }
            Change::PutIntent(i) => {
                tx.execute(
                    "INSERT INTO keystore.erasure_intent (id, chain, plan, phase) \
                     VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET \
                     plan = EXCLUDED.plan, phase = EXCLUDED.phase",
                    &[&Uuid::from_bytes(i.id), &chain, &i.plan, &i.phase],
                )
                .await
                .map_err(db)?;
            }
        }
    }
    tx.commit().await.map_err(db)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const CELL: [u8; 16] = [0x5c; 16];

    fn root_row() -> RootRow {
        RootRow {
            epoch: ROOT_EPOCH,
            backend: backend_code(BackendId::Keyd),
            handle: b"vault-handle".to_vec(),
            wrapped: vec![0x77; 60],
            created_at: 1,
            state: STATE_LIVE,
            receipt: None,
        }
    }

    fn row_bytes(rows: &KeystoreRows) -> Vec<Vec<u8>> {
        let mut out = vec![rows.root.handle.clone(), rows.root.wrapped.clone()];
        for g in &rows.groups {
            out.push(g.public_key.clone());
            out.push(g.sealed_secret.clone());
        }
        for d in &rows.data_keys {
            out.push(d.sealed.clone());
        }
        out
    }

    /// ADR-004 record of lane L8: the rows sealed under `S(1)` open under
    /// the same `S(1)` into the same keys. Another seal key, another cell
    /// or a changed byte does not open them.
    #[test]
    fn adr004_vault_keystore_rows_round_trip() {
        let keys = VaultKeys::generate().unwrap();
        let seal = SealKey::generate().unwrap();
        let rows = seal_rows(&CELL, &keys, &seal, root_row()).unwrap();
        assert_eq!(rows.groups.len(), 3);
        assert_eq!(rows.data_keys.len(), 1);
        assert_eq!(rows.data_keys[0].id, keys.dek());
        let back = open_rows(&CELL, &rows, &seal).unwrap();
        assert_eq!(back.anchor_public(), keys.anchor_public());
        assert_eq!(back.dek(), keys.dek());
        assert_eq!(
            back.query_digest_key().unwrap().expose(),
            keys.query_digest_key().unwrap().expose()
        );
        // A value sealed by the first opens with the second.
        let (_, s1) = keys.into_service_keys().unwrap();
        let (_, s2) = back.into_service_keys().unwrap();
        use crate::store::Sealer as _;
        let v = s1.seal(b"aad", b"fact").unwrap();
        assert_eq!(s2.open(b"aad", &v.bytes).unwrap(), b"fact");
        assert_eq!(s1.digest(b"q"), s2.digest(b"q"));
        // Refusals.
        assert!(open_rows(&CELL, &rows, &SealKey::generate().unwrap()).is_err());
        assert!(open_rows(&[0x5d; 16], &rows, &seal).is_err());
        let mut changed = rows.clone();
        let last = changed.groups[1].sealed_secret.len() - 1;
        changed.groups[1].sealed_secret[last] ^= 1;
        assert!(open_rows(&CELL, &changed, &seal).is_err());
        let mut twice = rows.clone();
        twice.groups.push(rows.groups[0].clone());
        assert!(open_rows(&CELL, &twice, &seal).is_err());
        let mut swapped = rows.clone();
        swapped.groups[2].public_key = rows.groups[1].public_key.clone();
        assert!(open_rows(&CELL, &swapped, &seal).is_err());
    }

    /// I-80: the keystore rows hold no open key. No secret of the keys,
    /// and no byte run of the seal key, appears in any row.
    #[test]
    fn i80_vault_keystore_rows_hold_no_open_key() {
        let keys = VaultKeys::generate().unwrap();
        let seal = SealKey::generate().unwrap();
        let rows = seal_rows(&CELL, &keys, &seal, root_row()).unwrap();
        let fact = keys.fact.to_bytes();
        let matching = keys.match_secret.to_bytes();
        let digest = keys.query_digest_key().unwrap();
        let secrets: Vec<Vec<u8>> = vec![
            keys.anchor.to_bytes().unwrap()[..16].to_vec(),
            keys.anchor.to_bytes().unwrap()[48..].to_vec(),
            fact[..16].to_vec(),
            fact[fact.len() - 16..].to_vec(),
            matching[..16].to_vec(),
            matching[matching.len() - 16..].to_vec(),
            keys.data_key.expose()[..16].to_vec(),
            digest.expose()[..16].to_vec(),
            seal.expose()[..16].to_vec(),
        ];
        for bytes in row_bytes(&rows) {
            for s in &secrets {
                assert!(
                    !bytes.windows(s.len()).any(|w| w == s.as_slice()),
                    "I-80: an open key is in a keystore row"
                );
            }
        }
        // The debug forms show no key.
        assert_eq!(format!("{keys:?}"), "VaultKeys { .. }");
        assert_eq!(
            format!("{rows:?}"),
            "KeystoreRows { epoch: 1, groups: 3, data_keys: 1 }"
        );
    }

    /// R-NF-02: a refused keystore never quotes its bytes. Each error names
    /// a fixed rule only.
    #[test]
    fn r_nf_02_vault_keystore_errors_never_quote_bytes() {
        let marker = b"s3cr3tm4rk3r";
        let keys = VaultKeys::generate().unwrap();
        let seal = SealKey::generate().unwrap();
        let mut rows = seal_rows(&CELL, &keys, &seal, root_row()).unwrap();
        rows.groups[0].sealed_secret = marker.repeat(4);
        rows.data_keys[0].sealed = marker.to_vec();
        let e = open_rows(&CELL, &rows, &seal).unwrap_err();
        let shown = format!("{e:?} {e}");
        assert!(!shown.contains("s3cr3t"), "R-NF-02: {shown}");
    }
}

/// The HKDF label of an identity's fact key `F(X)` (ADR-004 record of
/// lane L13).
pub const IDENTITY_FACT_LABEL: &[u8] = b"fstp-vault-identity-fact-v1";

/// The fact key `F(X)` of `identity` in `cell`, derived from its tuple
/// data key `dk` (ADR-004 record of lane L13, row "Key hierarchy"):
/// `HKDF-SHA-256(ikm T(X), empty salt, info label || cell || X)`. The
/// batch that erases `T(X)` destroys `F(X)` with it.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the derivation fails.
pub fn identity_fact_key(
    cell: &[u8; 16],
    identity: &[u8; 16],
    dk: &DataKey,
) -> Result<SealKey, VaultError> {
    let mut info = IDENTITY_FACT_LABEL.to_vec();
    info.extend_from_slice(cell);
    info.extend_from_slice(identity);
    let mut out = fstp_custody::zeroed_key_box();
    kdf::hkdf_sha256(&[], dk.expose(), &info, &mut out[..])
        .map_err(|_| VaultError::Unavailable("the identity fact key"))?;
    Ok(SealKey::from_box(out))
}

/// The fact keys `F(X)` of the live identities, shared by the keystore
/// that registers identities and the sealer of the vault's rows (ADR-004
/// record of lane L13). An identity with no key here is erased or was
/// never registered. Each key wipes itself when it is dropped. The debug
/// form shows the count only.
#[derive(Default)]
pub struct IdentityKeys {
    keys: std::sync::RwLock<std::collections::BTreeMap<u128, SealKey>>,
}

impl std::fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeys")
            .field("count", &self.read().len())
            .finish()
    }
}

impl IdentityKeys {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, std::collections::BTreeMap<u128, SealKey>> {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, std::collections::BTreeMap<u128, SealKey>> {
        self.keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sets the fact key of `identity`.
    pub fn insert(&self, identity: u128, key: SealKey) {
        self.write().insert(identity, key);
    }

    /// Drops the fact key of `identity`, which wipes it.
    pub fn remove(&self, identity: u128) {
        self.write().remove(&identity);
    }

    /// Whether `identity` has a fact key.
    #[must_use]
    pub fn contains(&self, identity: u128) -> bool {
        self.read().contains_key(&identity)
    }

    /// Runs `f` with the AES-256-GCM key of `identity`, or returns `None`
    /// when it has none.
    pub(crate) fn with_key<T>(
        &self,
        identity: u128,
        f: impl FnOnce(&aead::Key) -> T,
    ) -> Result<Option<T>, VaultError> {
        let map = self.read();
        let Some(k) = map.get(&identity) else {
            return Ok(None);
        };
        let key = aead::Key::from_bytes(k.expose())
            .map_err(|_| VaultError::Unavailable("the identity fact key"))?;
        Ok(Some(f(&key)))
    }
}

//! The text store (ADR-007 "Retention and erasure", design section 5.6,
//! I-81, R-NF-08).
//!
//! [`TextStore::put`] creates a random text id, a random 32-byte salt and
//! a data key, and stores the sealed blob of `salt || text` in
//! `blob.text`. The [`TextRef`] holds the id and HMAC-SHA-256 of the text
//! keyed by the salt. The salt sits only inside the sealed blob, so once
//! the key is destroyed the digest cannot confirm a guessed text.
//!
//! [`TextStore::get`] returns the text only while its key opens and its
//! row exists. From the moment an erasure is requested the key provider
//! refuses the key, and once the erasure completes the keys role deletes
//! the row. Either way the reference resolves to [`NoText`], and the
//! composer shows the text's erasure-log entry from the ledger fold
//! (ADR-007: "a `TextRef` resolves to the text's entry in the erasure
//! log, never to the text").
//!
//! The store runs as `c_<cell>_app`, which holds INSERT and SELECT on
//! `blob.text` (design section 4.1).

use std::future::Future;

use fstp_keys::envelope::{
    DataKey, SealContext, decode_sealed_blob, encode_sealed_blob, open_blob, seal_blob,
};
use fstp_keys::{Chain, DekId, GroupId, ObjectId, Purpose};
use fstp_pgwire::Uuid;
use fstp_rt::Runtime;

use crate::error::StoreFault;
use crate::pool::{Pool, Role};

/// The salt length: 32 random bytes.
pub const SALT_LEN: usize = 32;

/// The longest text the store keeps: 4 MiB of UTF-8.
pub const MAX_TEXT_LEN: usize = 4 << 20;

const INSERT_TEXT_SQL: &str = "INSERT INTO blob.text (id, dek, envelope) VALUES ($1, $2, $3)";
const TEXT_SQL: &str = "SELECT dek, envelope FROM blob.text WHERE id = $1";

/// A reference to a stored text: its id and its salted digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRef {
    /// The text id.
    pub id: [u8; 16],
    /// HMAC-SHA-256 of the text, keyed by its salt.
    pub digest: [u8; 32],
}

/// The data key of one text, with the group generation it belongs to.
pub struct TextKey {
    /// The data key id (`blob.text.dek`, `keystore.data_key.id`).
    pub dek: DekId,
    /// The key group.
    pub group: GroupId,
    /// The group generation.
    pub generation: u32,
    /// The key.
    pub key: DataKey,
}

/// The keystore side of the text store: lane W2f's keystore over
/// `keystore.data_key`, sealed to `Text` group keys (design sections 3.1
/// and 3.5).
pub trait TextKeys: Send + Sync {
    /// A fresh data key for the new text `text`, admitted to a `Text`
    /// group and durable before it returns.
    ///
    /// # Errors
    ///
    /// The keystore's refusal, named.
    fn create(&self, text: ObjectId) -> impl Future<Output = Result<TextKey, StoreFault>> + Send;

    /// The data key `dek` of text `text`, or `None` from the moment its
    /// erasure is requested (design section 3.4).
    ///
    /// # Errors
    ///
    /// The keystore's refusal, named.
    fn open(
        &self,
        dek: DekId,
        text: ObjectId,
    ) -> impl Future<Output = Result<Option<TextKey>, StoreFault>> + Send;
}

/// Why a reference names no text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoText {
    /// No row holds the text: it was erased, or never stored.
    Absent,
    /// The key provider refuses the key: an erasure is requested or done.
    KeyRefused,
}

/// How a reference resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextLookup {
    /// The text.
    Text(String),
    /// No text. The composer shows the erasure-log entry, if any.
    NoText(NoText),
}

/// The text store of one cell over its app role.
pub struct TextStore<R: Runtime, K> {
    pool: Pool<R>,
    keys: K,
}

impl<R: Runtime, K: TextKeys> TextStore<R, K> {
    /// The text store over `pool`, which must serve the app role.
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>, keys: K) -> Result<Self, StoreFault> {
        if pool.role() != Role::App {
            return Err(StoreFault::WrongRole);
        }
        Ok(TextStore { pool, keys })
    }

    fn context(&self, key: &TextKey, text: ObjectId) -> SealContext {
        SealContext {
            cell: fstp_keys::CellId(self.pool.cell()),
            chain: Chain::App,
            purpose: Purpose::Text,
            group: key.group,
            generation: key.generation,
            object: text,
        }
    }

    /// Stores `text` sealed under a fresh data key with a fresh salt.
    ///
    /// # Errors
    ///
    /// [`StoreFault::Refused`] for a text over [`MAX_TEXT_LEN`], the key
    /// provider's refusal, a seal or a database fault.
    pub async fn put(&self, text: &str) -> Result<TextRef, StoreFault> {
        if text.len() > MAX_TEXT_LEN {
            return Err(StoreFault::Refused("a text over its limit"));
        }
        let id: [u8; 16] = fstp_crypto::random_array().map_err(|_| StoreFault::SealRefused)?;
        let salt: [u8; SALT_LEN] =
            fstp_crypto::random_array().map_err(|_| StoreFault::SealRefused)?;
        let key = self.keys.create(ObjectId(id)).await?;
        let mut plain = Vec::with_capacity(SALT_LEN.saturating_add(text.len()));
        plain.extend_from_slice(&salt);
        plain.extend_from_slice(text.as_bytes());
        let sealed = seal_blob(&key.key, &self.context(&key, ObjectId(id)), &plain);
        plain.fill(0);
        let envelope = encode_sealed_blob(&sealed.map_err(|_| StoreFault::SealRefused)?)
            .map_err(|_| StoreFault::SealRefused)?;
        let mut client = self.pool.get().await?;
        client
            .execute(
                INSERT_TEXT_SQL,
                &[
                    &Uuid::from_bytes(id),
                    &Uuid::from_bytes(key.dek.0),
                    &envelope,
                ],
            )
            .await?;
        client.release();
        Ok(TextRef {
            id,
            digest: fstp_crypto::hmac_sha256(&salt, text.as_bytes()),
        })
    }

    /// Resolves `r`: the text, or why there is none.
    ///
    /// # Errors
    ///
    /// A pool or database fault, the key provider's refusal,
    /// [`StoreFault::OpenFailed`] for a blob that does not open under its
    /// key and context, and [`StoreFault::Corrupt`] for a text that is not
    /// UTF-8 or whose digest is not the reference's.
    pub async fn get(&self, r: &TextRef) -> Result<TextLookup, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client
            .query_opt(TEXT_SQL, &[&Uuid::from_bytes(r.id)])
            .await?;
        client.release();
        let Some(row) = row else {
            return Ok(TextLookup::NoText(NoText::Absent));
        };
        let dek: Uuid = row.get(0)?;
        let envelope: Vec<u8> = row.get(1)?;
        let Some(key) = self
            .keys
            .open(DekId(*dek.as_bytes()), ObjectId(r.id))
            .await?
        else {
            return Ok(TextLookup::NoText(NoText::KeyRefused));
        };
        if key.dek.0 != *dek.as_bytes() {
            return Err(StoreFault::OpenFailed);
        }
        let blob = decode_sealed_blob(&envelope).map_err(|_| StoreFault::OpenFailed)?;
        let plain = open_blob(&key.key, &self.context(&key, ObjectId(r.id)), &blob)
            .map_err(|_| StoreFault::OpenFailed)?;
        let (salt, text) = plain
            .split_first_chunk::<SALT_LEN>()
            .ok_or(StoreFault::Corrupt("a text blob shorter than its salt"))?;
        let mac = fstp_crypto::hmac_sha256(salt, text);
        if !fstp_crypto::constant_time_eq(&mac, &r.digest) {
            return Err(StoreFault::Corrupt(
                "a text whose digest is not the reference's",
            ));
        }
        let text = std::str::from_utf8(text)
            .map_err(|_| StoreFault::Corrupt("a text that is not UTF-8"))?;
        Ok(TextLookup::Text(text.to_owned()))
    }
}

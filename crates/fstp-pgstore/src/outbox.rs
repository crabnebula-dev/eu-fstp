//! Sealed rows of `ops.outbox` (ADR-004 "Seal-count limit", ADR-007
//! "Insert-only side effects", design sections 4.2, 5.3 step 6 and 7.2,
//! design gap G12).
//!
//! Each outbox row is sealed under its own data key, which seals that one
//! object (ADR-004: "Per-object data key (text, outbox row, document)").
//! The ledger key never seals an outbox row. `ops.outbox.dek` names the
//! row's own data key, so an erasure or a dispatcher that acts on a
//! row's key never touches a ledger key generation.
//!
//! The sealed form is `nonce (12) || ciphertext || tag (16)` under the AAD
//! `"fstp-outbox-v1" || cell || id || be16(kind) || idem`, so a body moved
//! to another row, kind or idempotency key does not open.
//!
//! Two writers insert rows, both as `c_<cell>_writer` and both insert
//! only:
//!
//! - an append, for the [`OutboxRow`] entries of its side effects, in the
//!   append transaction (design section 5.3 step 6);
//! - the in-doubt rule of design section 7.2, for a `PossibleDeletion`
//!   alert of kind [`crate::OUTBOX_POSSIBLE_DELETION`].

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use fstp_crypto::aead;
use fstp_keys::{DekId, ObjectId};

use crate::error::StoreFault;
use crate::seal::{open_sealed, outbox_aad};

/// The most outbox rows one append may insert.
pub const MAX_OUTBOX_ROWS: usize = 1024;

/// The longest outbox body the store seals: 1 MiB.
pub const MAX_OUTBOX_BODY: usize = 1 << 20;

/// The data key of one outbox row.
pub struct OutboxKey {
    /// The data key id (`ops.outbox.dek`, `keystore.data_key.id`).
    pub dek: DekId,
    /// The key. A key that has sealed before is refused, so each key
    /// seals one row.
    pub key: aead::Key,
}

/// A boxed future of a key provider call.
pub type KeyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreFault>> + Send + 'a>>;

/// The keystore side of the outbox: lane W2f's keystore over
/// `keystore.data_key` (design sections 3.1 and 3.5). It is the same
/// shape as [`crate::TextKeys`], boxed so the store can hold it as a
/// trait object.
pub trait OutboxKeys: Send + Sync {
    /// A fresh data key for the new outbox row `row`, durable before it
    /// returns.
    ///
    /// # Errors
    ///
    /// The keystore's refusal, named.
    fn create(&self, row: ObjectId) -> KeyFuture<'_, OutboxKey>;

    /// The data key `dek` of the outbox row `row`, or `None` once the
    /// keystore refuses it.
    ///
    /// # Errors
    ///
    /// The keystore's refusal, named.
    fn open(&self, dek: DekId, row: ObjectId) -> KeyFuture<'_, Option<OutboxKey>>;
}

/// One message to enqueue with an append (ADR-007 "Insert-only side
/// effects", design gap G12: magic links and recovery mails). The store
/// draws the row's data key, seals `body` and inserts the row in the
/// append transaction.
///
/// Reading, interim, pending Daniel: `idem` is a 32-byte digest. The M6
/// dispatcher fixes its form (the catalogue leaves the column class
/// open). A second row with the same `id` or `idem` aborts the whole
/// append as [`crate::AppendFault::OutboxDuplicate`].
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OutboxRow {
    /// The row id, random.
    pub id: [u8; 16],
    /// The message kind, from 2. Kind 1 is the store's own
    /// `PossibleDeletion` alert.
    pub kind: u16,
    /// The idempotency key: one message per value (TH-21).
    pub idem: [u8; 32],
    /// The message, sealed before it is stored.
    pub body: Vec<u8>,
}

impl fmt::Debug for OutboxRow {
    /// The body is content, so only its length shows (R-NF-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxRow")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("idem", &self.idem)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The `smallint` of a row kind the store accepts from a caller: 2 to
/// `i16::MAX`.
pub(crate) fn caller_kind(kind: u16) -> Option<i16> {
    i16::try_from(kind)
        .ok()
        .filter(|k| *k > crate::store::OUTBOX_POSSIBLE_DELETION)
}

/// Seals `body` of the row `(id, kind, idem)` of `cell` under `key`.
///
/// # Errors
///
/// [`StoreFault::Refused`] for a key that sealed before, and
/// [`StoreFault::SealRefused`] when the seal fails.
pub(crate) fn seal_outbox_body(
    cell: &[u8; 16],
    key: &OutboxKey,
    id: &[u8; 16],
    kind: u16,
    idem: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, StoreFault> {
    if key.key.seal_count() != 0 {
        return Err(StoreFault::Refused(
            "an outbox data key that has sealed before",
        ));
    }
    let sealed = aead::seal(&key.key, &outbox_aad(cell, id, kind, idem), body)
        .map_err(|_| StoreFault::SealRefused)?;
    let mut out = Vec::with_capacity(aead::NONCE_LEN.saturating_add(sealed.body.len()));
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

/// Opens the sealed body of the row `(id, kind, idem)` of `cell`.
///
/// # Errors
///
/// [`StoreFault::OpenFailed`] when it does not open under its AAD.
pub(crate) fn open_outbox_body(
    cell: &[u8; 16],
    key: &OutboxKey,
    id: &[u8; 16],
    kind: u16,
    idem: &[u8],
    sealed: &[u8],
) -> Result<impl std::ops::Deref<Target = Vec<u8>> + use<>, StoreFault> {
    open_sealed(&key.key, &outbox_aad(cell, id, kind, idem), sealed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code asserts on known-good values")]

    use super::*;

    fn key() -> OutboxKey {
        OutboxKey {
            dek: DekId([1; 16]),
            key: aead::Key::generate().unwrap(),
        }
    }

    /// ADR-004 "Seal-count limit": an outbox data key seals one row. A
    /// second seal under the same key is refused.
    #[test]
    fn adr004_outbox_key_seals_one_row() {
        let k = key();
        let cell = [2u8; 16];
        let sealed = seal_outbox_body(&cell, &k, &[3; 16], 2, &[4; 32], b"m").unwrap();
        assert_eq!(
            open_outbox_body(&cell, &k, &[3; 16], 2, &[4; 32], &sealed)
                .unwrap()
                .as_slice(),
            b"m"
        );
        assert_eq!(
            seal_outbox_body(&cell, &k, &[5; 16], 2, &[6; 32], b"n"),
            Err(StoreFault::Refused(
                "an outbox data key that has sealed before"
            )),
            "ADR-004: a second seal under one outbox key"
        );
    }

    /// ADR-004 part 1: an outbox body moved to another row, kind or idem
    /// does not open.
    #[test]
    fn adr004_outbox_body_opens_under_its_own_row_only() {
        let k = key();
        let cell = [2u8; 16];
        let sealed = seal_outbox_body(&cell, &k, &[3; 16], 2, &[4; 32], b"m").unwrap();
        for (c, id, kind, idem) in [
            ([9u8; 16], [3u8; 16], 2u16, [4u8; 32]),
            (cell, [8; 16], 2, [4; 32]),
            (cell, [3; 16], 3, [4; 32]),
            (cell, [3; 16], 2, [7; 32]),
        ] {
            assert!(
                open_outbox_body(&c, &k, &id, kind, &idem, &sealed).is_err(),
                "a moved outbox body opened"
            );
        }
    }

    /// The caller kinds start at 2: kind 1 is the store's alert.
    #[test]
    fn adr007_outbox_caller_kinds_exclude_the_alert_kind() {
        assert_eq!(caller_kind(0), None);
        assert_eq!(caller_kind(1), None);
        assert_eq!(caller_kind(2), Some(2));
        assert_eq!(caller_kind(32_767), Some(32_767));
        assert_eq!(caller_kind(32_768), None);
    }
}

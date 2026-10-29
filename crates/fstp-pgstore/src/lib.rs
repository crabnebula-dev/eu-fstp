//! The PostgreSQL record store of a cell: the append protocol, the chain
//! writer's tables, the text store, the sealed checkpoints, the schema
//! catalogue and per-role pools (M3 design sections 4, 5.3, 5.5, 5.6 and
//! 7.2, ADR-007, ADR-010).
//!
//! - [`MIGRATIONS`] and [`CATALOGUE`]: the application database
//!   `c_<cell>` and the class of every column (R-NF-08, I-16).
//! - [`Pool`]: the clients of one role of one cell (ADR-005, I-82).
//! - [`PgRecordStore`]: `fstp_ledger::AsyncRecordStore` over the writer
//!   role, with the append protocol of design section 5.3. Every committed
//!   append holds the witness receipt for its head (I-24).
//! - [`TextStore`]: sealed free text behind a [`TextRef`] (ADR-007).
//! - [`Checkpoints`]: sealed fold checkpoints in `ops.checkpoint`.
//! - [`OutboxRow`]: a sealed `ops.outbox` row of an append's side effects.
//! - [`decode_stored_entry`]: the one byte layout of a stored ledger row.
//!   The read path decodes every row through it. Fuzzed
//!   (`stored_entry_decode`).
//!
//! The store is generic over the record type. It encodes through
//! `fstp_ledger::Canonical` and decodes through a function the composer
//! passes in, so it never names `CellRecord` (design section 2.1).
//!
//! # Keys
//!
//! Ledger bodies and checkpoints are sealed under the ledger key of
//! [`LedgerKeys`], with a random nonce from `fstp_crypto::aead`. Texts and
//! outbox rows are sealed under a data key per object, which a
//! [`TextKeys`] or [`OutboxKeys`] provider gives (ADR-004 "Seal-count
//! limit"). The keystore behind them is lane W2f's. This crate holds no
//! custody client and never sees a root key (I-80).
//!
//! # Witness receipts
//!
//! The store pins a set of witness keys (ADR-010 "Keys"). A receipt that
//! no pinned key signed is refused before COMMIT, and its prepare is
//! aborted.
//!
//! # Anchor signatures
//!
//! [`AnchorSigner`] signs each prospective head. Its production
//! implementation on `CompositeSigningKey` calls
//! `fstp_audit::anchor::sign_anchor`. That call refuses until lane W2g
//! lands composite signing, so production appends refuse at the prepare
//! step until then.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod catalogue;
mod checkpoint;
mod error;
mod migrations;
mod outbox;
mod pool;
mod seal;
mod store;
mod stored;
mod text;

pub use catalogue::CATALOGUE;
pub use checkpoint::{Checkpoint, Checkpoints, MAX_CHECKPOINT_LEN};
pub use error::{AppendFault, DbFault, DecodeError, StoreFault};
pub use migrations::MIGRATIONS;
pub use outbox::{KeyFuture, MAX_OUTBOX_BODY, MAX_OUTBOX_ROWS, OutboxKey, OutboxKeys, OutboxRow};
pub use pool::{MAX_POOL_CLIENTS, Pool, PoolError, Role, database_name, role_name};
pub use seal::{
    LEDGER_KEY_SEALS, LedgerKey, LedgerKeys, checkpoint_aad, ledger_aad, open_stored_entry,
    outbox_aad,
};
pub use store::{
    AnchorSigner, Clock, Decode, OUTBOX_POSSIBLE_DELETION, PgRecordStore, SESSION_END_BY_RECORD,
    SessionEnd, SideEffects, StepUpUse, possible_deletion_idem, system_clock,
};
pub use stored::{
    MAX_SEALED_LEN, MIN_SEALED_LEN, STORED_ENTRY_FORMAT, StoredEntry, decode_stored_entry,
    encode_stored_entry,
};
pub use text::{MAX_TEXT_LEN, NoText, SALT_LEN, TextKey, TextKeys, TextLookup, TextRef, TextStore};

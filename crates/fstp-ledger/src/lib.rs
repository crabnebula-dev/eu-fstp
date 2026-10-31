//! Generic append-only record ledger (I-23, ADR-007).
//!
//! - [`Seq`] numbers entries from 1. A head of 0 means an empty ledger.
//! - [`Entry`] wraps one record with its sequence number, time, command id
//!   and schema version. Outside this crate an entry comes from a store,
//!   the decoder or a record conversion, never from a struct literal.
//! - [`RecordStore`] appends atomically against an expected head, refuses a
//!   repeated command id and has no update or delete. [`MemStore`] is the
//!   in-memory store for tests and models.
//! - [`verify_append_only`] checks that a later read of a ledger extends an
//!   earlier one without changing, dropping, inserting or reordering
//!   entries.
//! - [`AsyncRecordStore`] is the same contract with each operation
//!   returning a future. It names only `core::future`, so it ties no store
//!   to a runtime. [`MemStore`] implements it with ready futures.
//! - [`Canonical`] gives the RFC 8785 bytes of a record.
//!
//! # Stored form
//!
//! An entry is stored as the RFC 8785 text of a JSON object with exactly the
//! members `seq`, `at`, `command`, `schema` and `record`:
//!
//! - `seq` is a decimal string from `"1"` to `"18446744073709551615"`;
//! - `at` is a JSON integer of UTC microseconds, at most [`MAX_AT`] in
//!   magnitude, so RFC 8785 writes it exactly;
//! - `command` is 32 lowercase hex digits;
//! - `schema` is a JSON integer from 1 to 65535;
//! - `record` is the record's own JSON form.
//!
//! The decoder accepts one spelling of each envelope member, so the stored
//! bytes are a function of the entry. [`Entry::canonical_text`] gives those
//! bytes.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod async_store;
mod entry;
mod store;
mod verify;

pub use async_store::AsyncRecordStore;
pub use entry::{Entry, EntryTextError, MAX_AT, SCHEMA_V1, Seq};
pub use store::{AppendError, MemStore, RecordStore, StoreError};
pub use verify::{Canonical, Divergence, verify_append_only};

// I-23 compile-fail twins. Doc comments only, owned by the test author.
#[cfg(doctest)]
mod twins;

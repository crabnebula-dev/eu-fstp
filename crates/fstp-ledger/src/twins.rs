//! I-23 `i23_store_api_has_no_mutation`: compile-fail twins for the store
//! API (`docs/handoff/m2-design.md` sections 3.5 and 6.2, ADR-007).
//!
//! This module holds doc comments only. It is compiled under
//! `cfg(doctest)` alone, so it adds nothing to the library.
//!
//! The pinned stable rustdoc 1.97 ignores `compile_fail` error codes. So
//! each forbidden line gets a `compile_fail` doctest and a `no_run` twin.
//! The twin differs only in that one line and must compile. A typo in the
//! shared text then breaks the twin, so no pair passes vacuously.
//!
//! Outside the crate, no code can change, drop or reorder a stored entry,
//! and no code can write an entry as a struct literal. A caller can still
//! decode an entry from text, change the fields of an entry it holds, or
//! convert its record with `Entry::map_record`. None of these reaches an
//! entry inside a store.
//!
//! # `MemStore` has no `remove`
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.remove(0);
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # `MemStore` has no `get_mut`
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.get_mut(0);
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # `MemStore` has no `IndexMut`
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = &mut store[0];
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = &mut store;
//! ```
//!
//! # `MemStore` has no `truncate`
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! store.truncate(1);
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # `MemStore` has no `clear`
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! store.clear();
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # The entries of `MemStore` are private
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! store.entries.clear();
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # The command index of `MemStore` is private
//!
//! Clearing it would let a repeated command id through.
//!
//! ```compile_fail
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! store.commands.clear();
//! ```
//!
//! ```no_run
//! use fstp_ledger::{MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1, 2]);
//! let _ = store.head();
//! ```
//!
//! # `RecordStore` has no update
//!
//! ```compile_fail
//! use fstp_ledger::{RecordStore, Seq};
//! fn edit<S: RecordStore<u8>>(store: &mut S) {
//!     let _ = store.update(Seq::from_raw(1), 9);
//! }
//! ```
//!
//! ```no_run
//! use fstp_ledger::{RecordStore, Seq};
//! fn edit<S: RecordStore<u8>>(store: &mut S) {
//!     let _ = store.head();
//! }
//! ```
//!
//! # `RecordStore` has no delete
//!
//! ```compile_fail
//! use fstp_ledger::{RecordStore, Seq};
//! fn edit<S: RecordStore<u8>>(store: &mut S) {
//!     let _ = store.delete(Seq::from_raw(1));
//! }
//! ```
//!
//! ```no_run
//! use fstp_ledger::{RecordStore, Seq};
//! fn edit<S: RecordStore<u8>>(store: &mut S) {
//!     let _ = store.head();
//! }
//! ```
//!
//! # No entry literal with a chosen sequence number
//!
//! A caller can decode or convert an entry, but cannot write one as a
//! struct literal.
//!
//! ```compile_fail
//! use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1]);
//! let mut out: Vec<Entry<u8>> = Vec::new();
//! let _ = store.read(Seq::from_raw(1), 1, &mut out);
//! let e: Entry<u8> = Entry { seq: Seq::from_raw(7), at: 0, command: [0; 16], schema: 1, record: 1 };
//! let _ = e;
//! ```
//!
//! ```no_run
//! use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1]);
//! let mut out: Vec<Entry<u8>> = Vec::new();
//! let _ = store.read(Seq::from_raw(1), 1, &mut out);
//! let e: Entry<u8> = out.remove(0);
//! let _ = e;
//! ```
//!
//! # No entry update syntax with a chosen sequence number
//!
//! ```compile_fail
//! use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1]);
//! let mut out: Vec<Entry<u8>> = Vec::new();
//! let _ = store.read(Seq::from_raw(1), 1, &mut out);
//! let e: Entry<u8> = Entry { seq: Seq::from_raw(7), ..out.remove(0) };
//! let _ = e;
//! ```
//!
//! ```no_run
//! use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
//! let mut store: MemStore<u8> = MemStore::new();
//! let _ = store.append(Seq::ZERO, 0, [0; 16], vec![1]);
//! let mut out: Vec<Entry<u8>> = Vec::new();
//! let _ = store.read(Seq::from_raw(1), 1, &mut out);
//! let e: Entry<u8> = out.remove(0);
//! let _ = e;
//! ```

//! The anchoring store takes every witness receipt through
//! `Anchorer::signed_receipt` with the pinned witness keys (I-24, I-90,
//! ADR-010 "Keys", design section 7.2).
//!
//! A receipt is committed on only when it names this cell and chain, a
//! pinned witness key verifies its signature, and it is for the prepared
//! head. Any other receipt commits nothing, and the store aborts the
//! prepare it answered before the same row is prepared again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_audit::anchor::{Receipt, ReceiptFields};
use fstp_audit::anchorer::{PrepareWitness, WitnessFault};
use fstp_audit::witness::Prepare;
use fstp_audit::{CellId, CompositeSigningKey, Link};
use fstp_cell::engine::{AppendRequest, CellStore};
use fstp_cell::tasks::system_now;
use fstp_cell::witness::store::{
    AnchoredStore, Database, KeysRefused, MemDatabase, OpenPrepare, StoreKeys,
};
use fstp_cell_core::driver::SideEffects;
use fstp_cell_core::{CellRecord, KeyRecord};
use fstp_crypto::composite;
use fstp_keys::envelope::DataKey;
use fstp_ledger::Seq;

const CELL: [u8; 16] = [0x9C; 16];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A witness that receipts each prepare for its own head, signed with
/// `key`, naming `cell`. It records every abort it is sent.
struct Signing {
    key: CompositeSigningKey,
    cell: CellId,
    aborts: Mutex<Vec<(u64, Link)>>,
}

impl Signing {
    fn new(key: CompositeSigningKey, cell: CellId) -> Signing {
        Signing {
            key,
            cell,
            aborts: Mutex::new(Vec::new()),
        }
    }
}

impl PrepareWitness for Signing {
    fn prepare(&self, p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send {
        let a = &p.anchor;
        let fields = ReceiptFields {
            n: a.n,
            link: a.link,
            witness_seq: a.n,
            witness_link: a.link,
            received_at: a.at,
        };
        std::future::ready(
            fstp_witness::sign_receipt(&self.key, self.cell, a.chain, &fields)
                .map_err(|_| WitnessFault::Refused),
        )
    }

    fn abort(&self, head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        lock(&self.aborts).push(head);
        std::future::ready(Ok(()))
    }

    fn in_doubt_absent(
        &self,
        _head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        std::future::ready(Ok(()))
    }
}

impl OpenPrepare for Signing {
    fn open_prepare(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(None))
    }
}

fn key_op(expected: u64, id: u8) -> AppendRequest {
    AppendRequest {
        expected: Seq::from_raw(expected),
        at: system_now(),
        command: [id; 16],
        batch: vec![CellRecord::Key(KeyRecord::KeyOpRecorded {
            op: format!("{{\"n\":{id}}}").into_bytes(),
        })],
        side: SideEffects::default(),
    }
}

/// What one append over a witness signing as `signer` for `cell`, with
/// `pinned` as the store's witness pins, left behind.
struct Outcome {
    committed: bool,
    rows: usize,
    anchors: usize,
    aborts: Vec<(u64, Link)>,
}

fn append_once(signer: CompositeSigningKey, cell: CellId, pinned: Vec<Vec<u8>>) -> Outcome {
    let keys = StoreKeys {
        anchor: composite::generate().unwrap(),
        ledger: DataKey::generate().unwrap(),
        witness: pinned,
    };
    let mut store =
        AnchoredStore::new(MemDatabase::new(), Signing::new(signer, cell), CELL, keys).unwrap();
    let committed = fstp_rt::future::block_on(async {
        store.start().await.unwrap();
        store.append_cell(key_op(0, 1)).await.is_ok()
    });
    let tables = store.db().tables();
    Outcome {
        committed,
        rows: tables.rows().len(),
        anchors: tables.anchors().len(),
        aborts: lock(&store.witness().aborts).clone(),
    }
}

fn public(key: &CompositeSigningKey) -> Vec<u8> {
    key.public_key().to_bytes().to_vec()
}

/// I-24, ADR-010: the control. A receipt that a pinned witness key
/// signed, for this cell and the prepared head, commits with its anchor
/// row, and nothing is aborted.
#[test]
fn i24_cell_store_commits_on_a_receipt_a_pinned_key_signed() {
    let witness = composite::generate().unwrap();
    let pinned = vec![public(&witness)];
    let o = append_once(witness, CellId(CELL), pinned);
    assert!(
        o.committed && o.rows == 1 && o.anchors == 1 && o.aborts.is_empty(),
        "committed {}, rows {}, anchors {}, aborts {:?}",
        o.committed,
        o.rows,
        o.anchors,
        o.aborts
    );
}

/// I-24, I-90, ADR-010 "Keys": a well-formed receipt signed by a key the
/// cell does not pin commits nothing. The store aborts the prepare for
/// the head it answered.
#[test]
fn i24_cell_store_refuses_a_receipt_no_pinned_key_signed() {
    let witness = composite::generate().unwrap();
    let other = composite::generate().unwrap();
    let o = append_once(witness, CellId(CELL), vec![public(&other)]);
    assert!(
        !o.committed && o.rows == 0 && o.anchors == 0 && o.aborts.len() == 1,
        "committed {}, rows {}, anchors {}, aborts {:?}",
        o.committed,
        o.rows,
        o.anchors,
        o.aborts
    );
}

/// I-24, ADR-010: a receipt that the pinned witness key signed for
/// another cell receipts nothing here. Nothing commits, and the prepare
/// is aborted.
#[test]
fn i24_cell_store_refuses_a_pinned_receipt_for_another_cell() {
    let witness = composite::generate().unwrap();
    let pinned = vec![public(&witness)];
    let o = append_once(witness, CellId([0x9D; 16]), pinned);
    assert!(
        !o.committed && o.rows == 0 && o.anchors == 0 && o.aborts.len() == 1,
        "committed {}, rows {}, anchors {}, aborts {:?}",
        o.committed,
        o.rows,
        o.anchors,
        o.aborts
    );
}

/// The store `AnchoredStore::new` builds with `pinned` as its witness
/// pins, over a witness signing with a fresh key. Only its refusal is
/// read.
fn build(pinned: Vec<Vec<u8>>) -> Result<(), KeysRefused> {
    let keys = StoreKeys {
        anchor: composite::generate().unwrap(),
        ledger: DataKey::generate().unwrap(),
        witness: pinned,
    };
    let witness = Signing::new(composite::generate().unwrap(), CellId(CELL));
    AnchoredStore::new(MemDatabase::new(), witness, CELL, keys).map(|_| ())
}

/// I-24, ADR-010 "Keys": a store with no pinned witness key would accept
/// no receipt. It is refused at construction, as
/// `fstp_pgstore::PgRecordStore::new` refuses it, so no prepare ever
/// reaches the witness and nothing commits.
#[test]
fn i24_cell_store_with_no_pinned_witness_key_is_refused_before_any_prepare() {
    assert_eq!(build(Vec::new()), Err(KeysRefused::NoWitnessPin));
}

/// I-90, ADR-010 "Keys": a pinned witness key that does not decode as a
/// composite public key is refused at construction.
#[test]
fn i90_cell_store_refuses_a_pinned_witness_key_that_does_not_decode() {
    let witness = composite::generate().unwrap();
    let mut bad = public(&witness);
    bad.truncate(bad.len() / 2);
    assert_eq!(
        build(vec![public(&witness), bad]),
        Err(KeysRefused::WitnessPin)
    );
}

//! ADR-004 (decided by Daniel on 2026-11-20), I-82: the keystore tables of
//! migration `0011_keystore.sql` over the keys role. Lane L3.
//!
//! The rows round trip through [`KeystoreTables`], a batch is written
//! whole or not at all, and no other role reaches the tables.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, block_on, fresh16, must, rt};
use fstp_pgstore::{
    ChainRow, Change, DataKeyRow, GroupKeyRow, KeystoreChanges, KeystoreRows, KeystoreTables,
    KeystoreTextRow, LoginDigestRow, LoginTextRow, Pool, Role, RootRow, RootStatus, SignerRow,
    StoreFault,
};
use fstp_rt::tokio::TokioRuntime;

/// The keystore tables of migration 0011, granted to the keys role as the
/// production plan grants them (`fstp_control::pg::cell_role_plan`). The
/// reference plan of the W2e harness predates them.
const NEW_TABLES: [&str; 6] = [
    "keystore.chain",
    "keystore.text",
    "keystore.signer",
    "keystore.login_digest",
    "keystore.login_text",
    "keystore.erasure_request",
];

fn provisioned() -> CellDb {
    let db = must(CellDb::provision());
    let keys = db.role("keys");
    for t in NEW_TABLES {
        db.psql(&format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {keys};"
        ))
        .unwrap();
    }
    db
}

fn pool(db: &CellDb, suffix: &str, role: Role) -> Pool<TokioRuntime> {
    block_on(Pool::open(
        rt().clone(),
        db.cell,
        role,
        db.config(suffix),
        2,
    ))
    .unwrap_or_else(|e| panic!("the {suffix} pool: {e}"))
}

fn tables(db: &CellDb) -> KeystoreTables<TokioRuntime> {
    KeystoreTables::new(pool(db, "keys", Role::Keys)).unwrap()
}

fn rows() -> KeystoreRows {
    let g = fresh16();
    let dek = fresh16();
    KeystoreRows {
        chain: Some(ChainRow {
            epoch: 1,
            state: vec![7; 80],
            lookup_group: Some(g),
            login_group: None,
            startup_unwrap: Some(fresh16()),
        }),
        roots: vec![
            RootRow {
                epoch: 0,
                backend: 3,
                handle: vec![1; 16],
                wrapped: vec![2; 60],
                status: RootStatus::Destroyed([9; 32]),
            },
            RootRow {
                epoch: 1,
                backend: 3,
                handle: vec![3; 16],
                wrapped: vec![4; 60],
                status: RootStatus::Live,
            },
            RootRow {
                epoch: 2,
                backend: 3,
                handle: vec![5; 16],
                wrapped: Vec::new(),
                status: RootStatus::Pending,
            },
        ],
        groups: vec![GroupKeyRow {
            group: g,
            generation: 2,
            purpose: 6,
            public_key: vec![5; 1216],
            sealed_secret: vec![6; 2500],
            epoch: 1,
        }],
        keys: vec![DataKeyRow {
            id: dek,
            group: g,
            generation: 2,
            sealed: vec![8; 1210],
        }],
        texts: vec![KeystoreTextRow {
            id: dek,
            dek,
            generation: 2,
            envelope: vec![9; 70],
        }],
        signers: vec![
            SignerRow {
                purpose: 14,
                generation: 1,
                public_key: vec![1; 1984],
                created_at: 5,
                sealed: None,
            },
            SignerRow {
                purpose: 14,
                generation: 2,
                public_key: vec![2; 1984],
                created_at: 6,
                sealed: Some((1, vec![3; 120])),
            },
        ],
        digests: vec![LoginDigestRow {
            digest: [4; 32],
            account: fresh16(),
        }],
        logins: vec![LoginTextRow {
            account: fresh16(),
            text: dek,
        }],
        requested: vec![dek],
    }
}

fn put_all(r: &KeystoreRows) -> KeystoreChanges {
    KeystoreChanges {
        chain: r.chain.clone(),
        roots: r.roots.iter().cloned().map(Change::Put).collect(),
        groups: r.groups.iter().cloned().map(Change::Put).collect(),
        keys: r.keys.iter().cloned().map(Change::Put).collect(),
        texts: r.texts.iter().cloned().map(Change::Put).collect(),
        signers: r.signers.iter().cloned().map(Change::Put).collect(),
        digests: r.digests.iter().copied().map(Change::Put).collect(),
        logins: r.logins.iter().copied().map(Change::Put).collect(),
        requested: r.requested.iter().copied().map(Change::Put).collect(),
    }
}

fn sorted(mut r: KeystoreRows) -> KeystoreRows {
    r.digests.sort_by_key(|d| d.digest);
    r.logins.sort_by_key(|l| l.account);
    r
}

/// ADR-004 (2026-11-20): every row of every keystore table round trips,
/// a later batch replaces and deletes rows, and an empty keystore loads
/// with no chain row.
#[test]
fn adr004_keystore_round_trips_through_tables() {
    let db = provisioned();
    let t = tables(&db);
    assert_eq!(block_on(t.load()).unwrap(), KeystoreRows::default());
    let mut want = rows();
    block_on(t.apply(&put_all(&want))).unwrap();
    assert_eq!(block_on(t.load()).unwrap(), sorted(want.clone()));
    // A commit: the pending root goes live, the data key leaves, the
    // login digest is replaced, the request leaves.
    let mut next = KeystoreChanges::default();
    want.roots[2].wrapped = vec![6; 60];
    want.roots[2].status = RootStatus::Live;
    next.roots.push(Change::Put(want.roots[2].clone()));
    next.keys.push(Change::Delete(want.keys[0].id));
    want.keys.clear();
    next.digests.push(Change::Delete(want.digests[0].digest));
    want.digests[0].digest = [5; 32];
    next.digests.push(Change::Put(want.digests[0]));
    next.requested.push(Change::Delete(want.requested[0]));
    want.requested.clear();
    block_on(t.apply(&next)).unwrap();
    assert_eq!(block_on(t.load()).unwrap(), sorted(want));
}

/// ADR-004 design section 3.5 step 4: a batch is written whole or not at
/// all. A batch whose last row breaks a check leaves no row behind.
#[test]
fn adr004_keystore_batch_is_one_transaction() {
    let db = provisioned();
    let t = tables(&db);
    let mut bad = put_all(&rows());
    bad.roots.push(Change::Put(RootRow {
        epoch: 9,
        backend: 3,
        // Breaks `root_handle_len`.
        handle: Vec::new(),
        wrapped: vec![1; 60],
        status: RootStatus::Live,
    }));
    assert!(block_on(t.apply(&bad)).is_err());
    assert_eq!(block_on(t.load()).unwrap(), KeystoreRows::default());
    for table in ["keystore.root", "keystore.chain", "keystore.text"] {
        assert_eq!(db.count(&format!("SELECT count(*) FROM {table};")), 0);
    }
}

/// I-82, ADR-004 (2026-11-20): the keystore is written through
/// `c_<cell>_keys` only. The tables refuse a pool of another role, and
/// the app and writer roles hold no right on the new tables.
#[test]
fn i82_keystore_written_by_keys_role_only() {
    let db = provisioned();
    for (suffix, role) in [("app", Role::App), ("writer", Role::Writer)] {
        assert!(matches!(
            KeystoreTables::new(pool(&db, suffix, role)),
            Err(StoreFault::WrongRole)
        ));
        for t in NEW_TABLES {
            assert_eq!(
                db.state_as(suffix, &format!("SELECT count(*) FROM {t};"))
                    .as_deref(),
                Some("42501"),
                "{suffix} on {t}"
            );
        }
    }
}

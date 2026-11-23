//! The deletion of an erased document's sealed row (ADR-007 section
//! "Decided by Daniel on 2026-11-23", decision 2; lane L39; I-81, I-30).
//!
//! Migration `0014_doc_blob_erasure.sql`: `doc.blob` stays append-only
//! for every role but the cell's own `keys` role, which may delete a row
//! once no `keystore.data_key` row holds the row's data key. UPDATE and
//! TRUNCATE stay refused for every role. Every row is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, block_on, bytea, fresh16, must, rt, uuid_text};
use fstp_pgstore::{KeystoreChanges, KeystoreTables, Pool, Role};
use fstp_rt::tokio::TokioRuntime;

/// The grants of the production plan (`fstp_control::pg`) that the W2e
/// reference plan predates: `doc.blob` for the app and keys roles.
fn provisioned() -> CellDb {
    let db = must(CellDb::provision());
    let app = db.role("app");
    let keys = db.role("keys");
    db.psql(&format!(
        "GRANT USAGE ON SCHEMA doc TO {app}, {keys}; \
         GRANT SELECT, INSERT ON doc.blob TO {app}; \
         GRANT SELECT, DELETE ON doc.blob TO {keys};"
    ))
    .unwrap();
    db
}

/// A blob row of data key `dek`, as the superuser.
fn put_blob(db: &CellDb, dek: &[u8; 16]) {
    let digest = fstp_crypto::sha256(&fresh16());
    db.psql(&format!(
        "INSERT INTO doc.blob (digest, kind, dek, envelope, stored_at) VALUES ({}, 5, '{}', {}, 5);",
        bytea(&digest),
        uuid_text(dek),
        bytea(b"sealed synthetic document"),
    ))
    .unwrap();
}

/// A data key row of id `dek`, as the superuser.
fn put_key(db: &CellDb, dek: &[u8; 16]) {
    db.psql(&format!(
        "INSERT INTO keystore.data_key (id, group_id, generation, sealed, state) \
         VALUES ('{}', '{}', 1, {}, 1);",
        uuid_text(dek),
        uuid_text(&fresh16()),
        bytea(&[8; 64]),
    ))
    .unwrap();
}

fn delete(dek: &[u8; 16]) -> String {
    format!("DELETE FROM doc.blob WHERE dek = '{}';", uuid_text(dek))
}

fn rows(db: &CellDb, dek: &[u8; 16]) -> u64 {
    db.count(&format!(
        "SELECT count(*) FROM doc.blob WHERE dek = '{}';",
        uuid_text(dek)
    ))
}

/// I-81, I-30, ADR-007 (Daniel, 2026-11-23, decision 2; lane L39): only
/// the keys role deletes a `doc.blob` row, and only once its data key row
/// is gone. The app role, the migrator that owns the table and the
/// superuser are refused, and no role updates or truncates a row.
#[test]
fn i81_l39_doc_blob_delete_only_by_keys_after_key_row_gone() {
    let db = provisioned();
    let dek = fresh16();
    put_key(&db, &dek);
    put_blob(&db, &dek);
    // While the data key lives, no role deletes the row.
    assert_eq!(db.state_as("keys", &delete(&dek)).as_deref(), Some("42501"));
    for role in ["app", "migrator", "writer", "auditor"] {
        assert_eq!(
            db.state_as(role, &delete(&dek)).as_deref(),
            Some("42501"),
            "{role}"
        );
    }
    assert!(db.psql(&delete(&dek)).is_err(), "the superuser");
    assert_eq!(rows(&db, &dek), 1);
    // The key row leaves, as step 4 of an erasure batch removes it.
    assert_eq!(
        db.state_as(
            "keys",
            &format!(
                "DELETE FROM keystore.data_key WHERE id = '{}';",
                uuid_text(&dek)
            )
        ),
        None
    );
    // Every other role is still refused.
    for role in ["app", "migrator", "writer", "auditor"] {
        assert_eq!(
            db.state_as(role, &delete(&dek)).as_deref(),
            Some("42501"),
            "{role}"
        );
    }
    assert!(db.psql(&delete(&dek)).is_err(), "the superuser");
    // No role rewrites or truncates a row, the keys role included.
    assert_eq!(
        db.state_as("keys", "UPDATE doc.blob SET envelope = '\\x00';")
            .as_deref(),
        Some("42501")
    );
    assert!(db.psql("UPDATE doc.blob SET envelope = '\\x00';").is_err());
    assert!(db.psql("TRUNCATE doc.blob;").is_err());
    assert_eq!(db.state_as("keys", "TRUNCATE doc.blob;").as_deref(), Some("42501"));
    // The keys role deletes it, and a repeat deletes nothing.
    assert_eq!(db.state_as("keys", &delete(&dek)), None);
    assert_eq!(rows(&db, &dek), 0);
    assert_eq!(db.state_as("keys", &delete(&dek)), None);
    // Another document is untouched.
    let other = fresh16();
    put_key(&db, &other);
    put_blob(&db, &other);
    assert_eq!(rows(&db, &other), 1);
}

fn tables(db: &CellDb) -> KeystoreTables<TokioRuntime> {
    let pool: Pool<TokioRuntime> =
        block_on(Pool::open(rt().clone(), db.cell, Role::Keys, db.config("keys"), 2))
            .unwrap_or_else(|e| panic!("the keys pool: {e}"));
    KeystoreTables::new(pool).unwrap()
}

/// I-81, ADR-007 (lane L39): a keystore batch deletes the `doc.blob` rows
/// it names through the keys role. A repeat of the batch is a no-op, and
/// a batch that names a row whose data key still lives is refused whole.
#[test]
fn i81_l39_keystore_batch_deletes_blob_rows_idempotently() {
    let db = provisioned();
    let erased = fresh16();
    let live = fresh16();
    put_blob(&db, &erased);
    put_key(&db, &live);
    put_blob(&db, &live);
    let t = tables(&db);
    let batch = KeystoreChanges {
        blobs: vec![erased],
        ..KeystoreChanges::default()
    };
    assert!(!batch.is_empty());
    block_on(t.apply(&batch)).unwrap();
    assert_eq!(rows(&db, &erased), 0);
    block_on(t.apply(&batch)).unwrap();
    assert_eq!(rows(&db, &erased), 0, "a repeat deletes nothing more");
    let refused = KeystoreChanges {
        blobs: vec![live],
        ..KeystoreChanges::default()
    };
    assert!(block_on(t.apply(&refused)).is_err(), "its key still lives");
    assert_eq!(rows(&db, &live), 1);
}

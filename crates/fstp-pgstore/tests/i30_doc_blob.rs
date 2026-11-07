//! I-30, M5 design section 4.3: `doc.blob` is write-once by digest. A
//! second insert of a digest with other bytes fails, the `app` role can
//! only insert and select, and no role can update, delete or truncate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, bytea, fresh16, must, uuid_text};

fn insert(digest: &[u8; 32], envelope: &[u8]) -> String {
    format!(
        "INSERT INTO doc.blob (digest, kind, dek, envelope, stored_at) VALUES ({}, 1, '{}', {}, 5);",
        bytea(digest),
        uuid_text(&fresh16()),
        bytea(envelope),
    )
}

/// I-30: a digest never maps to other bytes, and rows never change.
#[test]
fn i30_doc_blob_second_insert_with_other_bytes_fails() {
    let db = must(CellDb::provision());
    let app = db.role("app");
    db.psql(&format!(
        "GRANT USAGE ON SCHEMA doc TO {app}; GRANT SELECT, INSERT ON doc.blob TO {app};"
    ))
    .unwrap();
    let digest = fstp_crypto::sha256(b"%PDF-1.7 synthetic revision");
    assert_eq!(db.state_as("app", &insert(&digest, b"sealed-a")), None);
    // Other bytes under the same digest: unique violation.
    assert_eq!(
        db.state_as("app", &insert(&digest, b"sealed-b")).as_deref(),
        Some("23505")
    );
    // The app role holds no UPDATE or DELETE.
    assert_eq!(
        db.state_as("app", "UPDATE doc.blob SET envelope = '\\x00';")
            .as_deref(),
        Some("42501")
    );
    assert_eq!(
        db.state_as("app", "DELETE FROM doc.blob;").as_deref(),
        Some("42501")
    );
    // Even the owner cannot rewrite or remove a row.
    assert!(db.psql("UPDATE doc.blob SET envelope = '\\x00';").is_err());
    assert!(db.psql("DELETE FROM doc.blob;").is_err());
    assert!(db.psql("TRUNCATE doc.blob;").is_err());
    assert_eq!(db.count("SELECT count(*) FROM doc.blob;"), 1);
}

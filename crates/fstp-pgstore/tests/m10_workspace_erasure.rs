//! The deletion of an erased workspace's rows (F-017, M10 fix lane;
//! ADR-026 section "Written by the M10 fix lane"; I-81, I-82, TH-30).
//!
//! Migration `0015_workspace_erasure.sql`: a `workspace.drafts` row is
//! deleted only by the cell's own `keys` role, and only once no
//! `keystore.data_key` row holds its proposal's workspace key, whose id is
//! the proposal id. TRUNCATE stays refused for every role. The app role
//! keeps its saves. Rows sealed under the ledger key leave at the
//! migration, since that key is never destroyed. Every row is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, block_on, bytea, fresh16, must, rt, uuid_text};
use fstp_pgstore::{KeystoreChanges, KeystoreTables, MIGRATIONS, Pool, Role};
use fstp_rt::tokio::TokioRuntime;

/// The grants of the production plan (`fstp_control::pg`) on
/// `workspace.drafts` that the W2e reference plan predates.
fn grant(db: &CellDb) {
    let app = db.role("app");
    let keys = db.role("keys");
    db.psql(&format!(
        "GRANT USAGE ON SCHEMA workspace TO {app}, {keys}; \
         GRANT SELECT, INSERT, UPDATE ON workspace.drafts TO {app}; \
         GRANT SELECT, DELETE ON workspace.drafts TO {keys};"
    ))
    .unwrap();
}

fn provisioned() -> CellDb {
    let db = must(CellDb::provision());
    grant(&db);
    db
}

/// The workspace key row of `proposal`, as the superuser.
fn put_key(db: &CellDb, proposal: &[u8; 16]) {
    db.psql(&format!(
        "INSERT INTO keystore.data_key (id, group_id, generation, sealed, state) \
         VALUES ('{}', '{}', 1, {}, 1);",
        uuid_text(proposal),
        uuid_text(&fresh16()),
        bytea(&[8; 64]),
    ))
    .unwrap();
}

/// The save of `proposal` in `slot`, as the app role stores it.
fn save_sql(proposal: &[u8; 16], slot: &str) -> String {
    format!(
        "INSERT INTO workspace.drafts (proposal, slot, revision, sealed, updated_at) \
         VALUES ({}, '{slot}', 1, {}, 5) ON CONFLICT (proposal, slot) DO UPDATE \
         SET revision = workspace.drafts.revision + 1, sealed = EXCLUDED.sealed, \
         updated_at = EXCLUDED.updated_at;",
        bytea(proposal),
        bytea(&[0x5A; 40]),
    )
}

fn delete(proposal: &[u8; 16]) -> String {
    format!(
        "DELETE FROM workspace.drafts WHERE proposal = {};",
        bytea(proposal)
    )
}

fn rows(db: &CellDb, proposal: &[u8; 16]) -> u64 {
    db.count(&format!(
        "SELECT count(*) FROM workspace.drafts WHERE proposal = {};",
        bytea(proposal)
    ))
}

/// F-017, I-82, I-81, TH-30 (ADR-026 section "Written by the M10 fix
/// lane"): only the keys role deletes a `workspace.drafts` row, and only
/// once the proposal's workspace key row is gone. The app role that saves
/// the rows, the migrator that owns the table, the other roles and the
/// superuser are refused, and no role truncates the table. The app role
/// still saves and replaces a draft. The rows carry no ledger key
/// generation any more.
#[test]
fn m10_f017_i82_only_the_keys_role_deletes_draft_rows() {
    let db = provisioned();
    let p = fresh16();
    put_key(&db, &p);
    for slot in ["draft", "submitted:0123456789abcdef0123456789abcdef"] {
        assert_eq!(db.state_as("app", &save_sql(&p, slot)), None, "{slot}");
    }
    assert_eq!(db.state_as("app", &save_sql(&p, "draft")), None, "a resave");
    assert_eq!(rows(&db, &p), 2);
    // While the key lives, no role deletes a row.
    for role in ["keys", "app", "migrator", "writer", "auditor"] {
        assert_eq!(
            db.state_as(role, &delete(&p)).as_deref(),
            Some("42501"),
            "{role}"
        );
    }
    assert!(db.psql(&delete(&p)).is_err(), "the superuser");
    assert_eq!(rows(&db, &p), 2);
    // The key row leaves, as step 4 of an erasure batch removes it.
    assert_eq!(
        db.state_as(
            "keys",
            &format!(
                "DELETE FROM keystore.data_key WHERE id = '{}';",
                uuid_text(&p)
            )
        ),
        None
    );
    for role in ["app", "migrator", "writer", "auditor"] {
        assert_eq!(
            db.state_as(role, &delete(&p)).as_deref(),
            Some("42501"),
            "{role}"
        );
    }
    assert!(db.psql(&delete(&p)).is_err(), "the superuser");
    assert!(db.psql("TRUNCATE workspace.drafts;").is_err());
    assert_eq!(
        db.state_as("keys", "TRUNCATE workspace.drafts;").as_deref(),
        Some("42501")
    );
    // The keys role deletes them, and a repeat deletes nothing.
    assert_eq!(db.state_as("keys", &delete(&p)), None);
    assert_eq!(rows(&db, &p), 0);
    assert_eq!(db.state_as("keys", &delete(&p)), None);
    // Another workspace is untouched, and the keys role never inserts.
    let other = fresh16();
    put_key(&db, &other);
    assert_eq!(db.state_as("app", &save_sql(&other, "draft")), None);
    assert_eq!(
        db.state_as("keys", &save_sql(&fresh16(), "draft"))
            .as_deref(),
        Some("42501")
    );
    assert_eq!(rows(&db, &other), 1);
    // No ledger key generation names a workspace row any more.
    assert_eq!(
        db.state_as("app", "SELECT key_ix FROM workspace.drafts;")
            .as_deref(),
        Some("42703")
    );
}

fn tables(db: &CellDb) -> KeystoreTables<TokioRuntime> {
    let pool: Pool<TokioRuntime> = block_on(Pool::open(
        rt().clone(),
        db.cell,
        Role::Keys,
        db.config("keys"),
        2,
    ))
    .unwrap_or_else(|e| panic!("the keys pool: {e}"));
    KeystoreTables::new(pool).unwrap()
}

/// F-017, I-81: a keystore batch deletes the `workspace.drafts` rows of
/// the proposals it names through the keys role. A repeat of the batch is
/// a no-op, and a batch that names a workspace whose key still lives is
/// refused whole.
#[test]
fn m10_f017_keystore_batch_deletes_draft_rows_idempotently() {
    let db = provisioned();
    let erased = fresh16();
    let live = fresh16();
    put_key(&db, &live);
    for p in [&erased, &live] {
        db.psql(&save_sql(p, "draft")).unwrap();
    }
    let t = tables(&db);
    let batch = KeystoreChanges {
        workspaces: vec![erased],
        ..KeystoreChanges::default()
    };
    assert!(!batch.is_empty());
    block_on(t.apply(&batch)).unwrap();
    assert_eq!(rows(&db, &erased), 0);
    block_on(t.apply(&batch)).unwrap();
    assert_eq!(rows(&db, &erased), 0, "a repeat deletes nothing more");
    let refused = KeystoreChanges {
        workspaces: vec![live],
        ..KeystoreChanges::default()
    };
    assert!(block_on(t.apply(&refused)).is_err(), "its key still lives");
    assert_eq!(rows(&db, &live), 1);
}

/// F-017, TH-30 (ADR-026 section "Written by the M10 fix lane", row
/// "Existing rows"): migration 15 deletes every row sealed under the
/// ledger key, which no erasure destroys, and drops the `key_ix` column.
#[test]
fn m10_f017_migration_15_deletes_rows_sealed_under_the_ledger_key() {
    let before = MIGRATIONS
        .iter()
        .position(|m| m.name == "workspace_erasure")
        .expect("F-017: migration 15");
    assert_eq!(MIGRATIONS[before].version, 15);
    let db = CellDb::provision_with(&MIGRATIONS[..before]);
    let p = fresh16();
    db.psql(&format!(
        "INSERT INTO workspace.drafts (proposal, slot, revision, key_ix, sealed, updated_at) \
         VALUES ({}, 'draft', 1, 1, {}, 5);",
        bytea(&p),
        bytea(&[0x5A; 40]),
    ))
    .unwrap();
    assert_eq!(rows(&db, &p), 1);
    db.psql_as("migrator", MIGRATIONS[before].sql).unwrap();
    assert_eq!(rows(&db, &p), 0, "TH-30: a row under the ledger key stayed");
    assert!(
        db.psql("SELECT key_ix FROM workspace.drafts;").is_err(),
        "the key_ix column stayed"
    );
}

//! The delivery log `ops.delivery` against PostgreSQL (M6 design sections
//! 3.2 and 5.1, I-25, I-26). Lane L6-REC.
//!
//! The table is insert-only for every role, holds one terminal row per
//! message, and fences the commit point by the attempt number. The
//! dispatcher's crash tests (T1 to T3) build on these rules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, block_on, bytea, fresh16, must, rt, uuid_text};
use fstp_pgstore::{CommitFacts, DELIVERY_LEASE_US, DeliveryLog, Next, Phase, Pool, Role};
use fstp_rt::tokio::TokioRuntime;

/// A time inside the bound, in UTC microseconds (2026-11-06).
const AT: i64 = 1_794_000_000_000_000;

/// A cell whose app role holds INSERT and SELECT on `ops.delivery`, as the
/// cell role plan grants it, and one outbox row.
fn world() -> (CellDb, DeliveryLog<TokioRuntime>, [u8; 16]) {
    let db = must(CellDb::provision());
    db.psql_as(
        "migrator",
        &format!(
            "SELECT pg_catalog.set_config('fstp.cell', '{}', false);\n\
             SELECT fstp_meta.apply_grant('SELECT, INSERT', 'ops.delivery', 'app');",
            db.hex
        ),
    )
    .unwrap_or_else(|e| panic!("grant: {e:?}"));
    let outbox = outbox_row(&db);
    let pool = block_on(Pool::open(
        rt().clone(),
        db.cell,
        Role::App,
        db.config("app"),
        2,
    ))
    .unwrap_or_else(|e| panic!("the app pool: {e}"));
    let log = DeliveryLog::new(pool).unwrap();
    (db, log, outbox)
}

fn outbox_row(db: &CellDb) -> [u8; 16] {
    let id = fresh16();
    db.psql_as(
        "writer",
        &format!(
            "INSERT INTO ops.outbox (id, kind, idem, dek, body, created_at) \
             VALUES ('{}', 2, {}, '{}', {}, 1);",
            uuid_text(&id),
            bytea(&fresh16()),
            uuid_text(&fresh16()),
            bytea(&[0xA5; 40]),
        ),
    )
    .unwrap_or_else(|e| panic!("outbox row: {e:?}"));
    id
}

fn insert(outbox: &[u8; 16], attempt: u32, phase: Phase) -> String {
    let lease = if matches!(phase, Phase::Claimed | Phase::Committing) {
        "1".to_owned()
    } else {
        "NULL".to_owned()
    };
    let (event, version, digest) = if phase == Phase::Committing {
        (bytea(&[1; 32]), "1".to_owned(), bytea(&[2; 32]))
    } else {
        ("NULL".to_owned(), "NULL".to_owned(), "NULL".to_owned())
    };
    format!(
        "INSERT INTO ops.delivery (outbox_id, attempt, phase, at, worker, lease_until, event, \
         template_version, body_digest, reply_code) VALUES ('{}', {attempt}, {}, 1, '{}', \
         {lease}, {event}, {version}, {digest}, NULL);",
        uuid_text(outbox),
        phase.code(),
        uuid_text(&[9; 16]),
    )
}

fn facts() -> CommitFacts {
    CommitFacts {
        event: [3; 32],
        template_version: 1,
        body_digest: [4; 32],
    }
}

/// I-26, I-24, M6 design section 3.2: UPDATE, DELETE and TRUNCATE of
/// `ops.delivery` fail with 42501 for the app role, the owner and the
/// superuser, and no row changes.
#[test]
fn i26_delivery_rows_refuse_update_delete_and_truncate() {
    let (db, _log, outbox) = world();
    db.psql_as("app", &insert(&outbox, 1, Phase::Claimed))
        .unwrap_or_else(|e| panic!("insert as app: {e:?}"));
    for who in ["app", "migrator"] {
        for sql in [
            "UPDATE ops.delivery SET at = at;",
            "DELETE FROM ops.delivery;",
            "TRUNCATE ops.delivery;",
        ] {
            let e = db.psql_as(who, sql).expect_err(sql);
            assert_eq!(e.state.as_deref(), Some("42501"), "{who}: {sql}: {e:?}");
        }
    }
    for sql in [
        "UPDATE ops.delivery SET at = at;",
        "DELETE FROM ops.delivery;",
        "TRUNCATE ops.delivery;",
    ] {
        let e = db.psql(sql).expect_err(sql);
        assert_eq!(e.state.as_deref(), Some("42501"), "superuser: {sql}: {e:?}");
    }
    assert_eq!(db.count("SELECT count(*) FROM ops.delivery;"), 1);
}

/// I-26, M6 design section 3.2: one message holds at most one terminal
/// row (SENT, PERMANENT or IN_DOUBT), and a row outside the phase rules is
/// refused by the table itself.
#[test]
fn i26_delivery_holds_one_terminal_row_per_message() {
    let (db, _log, outbox) = world();
    db.psql_as("app", &insert(&outbox, 1, Phase::Committing))
        .unwrap_or_else(|e| panic!("{e:?}"));
    db.psql_as("app", &insert(&outbox, 1, Phase::InDoubt))
        .unwrap_or_else(|e| panic!("{e:?}"));
    for (attempt, phase) in [(1, Phase::Sent), (2, Phase::Sent), (2, Phase::Permanent)] {
        let e = db
            .psql_as("app", &insert(&outbox, attempt, phase))
            .expect_err("a second terminal row");
        assert_eq!(e.state.as_deref(), Some("23505"), "{phase:?}: {e:?}");
    }
    let bad = format!(
        "INSERT INTO ops.delivery (outbox_id, attempt, phase, at, worker) \
         VALUES ('{}', 3, 2, 1, '{}');",
        uuid_text(&outbox),
        uuid_text(&[9; 16])
    );
    let e = db
        .psql_as("app", &bad)
        .expect_err("COMMITTING without facts");
    assert_eq!(e.state.as_deref(), Some("23514"), "{e:?}");
    let orphan = insert(&fresh16(), 1, Phase::Claimed);
    let e = db
        .psql_as("app", &orphan)
        .expect_err("a row without its message");
    assert_eq!(e.state.as_deref(), Some("23503"), "{e:?}");
}

/// I-26, M6 design section 5.1: a worker whose lease was taken over fails
/// the commit point, the new holder passes it once, SENT follows its own
/// COMMITTING row, and a sent message is never claimed again.
#[test]
fn i26_stalled_worker_fails_the_commit_point() {
    let (_db, log, outbox) = world();
    let (a, b) = ([0xA; 16], [0xB; 16]);
    assert_eq!(
        block_on(log.claim(outbox, a, AT)).unwrap(),
        Next::Claim { attempt: 1 }
    );
    assert!(matches!(
        block_on(log.claim(outbox, b, AT + 1)).unwrap(),
        Next::Busy { .. }
    ));
    let later = AT + DELIVERY_LEASE_US;
    assert_eq!(
        block_on(log.claim(outbox, b, later)).unwrap(),
        Next::Claim { attempt: 2 }
    );
    assert!(
        !block_on(log.commit_point(outbox, a, 1, facts(), later)).unwrap(),
        "I-26: a stalled worker passed the commit point"
    );
    assert!(block_on(log.commit_point(outbox, b, 2, facts(), later)).unwrap());
    assert!(
        !block_on(log.commit_point(outbox, b, 2, facts(), later)).unwrap(),
        "I-26: a second commit point"
    );
    assert!(block_on(log.record(outbox, b, 2, Phase::Sent, Some(250), later + 1)).unwrap());
    assert_eq!(
        block_on(log.claim(outbox, a, i64::MAX)).unwrap(),
        Next::Done
    );
    let rows = block_on(log.rows(outbox)).unwrap();
    let phases: Vec<(u32, Phase)> = rows.iter().map(|r| (r.attempt, r.phase)).collect();
    assert_eq!(
        phases,
        vec![
            (1, Phase::Claimed),
            (2, Phase::Claimed),
            (2, Phase::Committing),
            (2, Phase::Sent),
        ]
    );
    assert_eq!(rows[2].commit, Some(facts()), "I-25: the COMMITTING facts");
    assert_eq!(rows[3].reply_code, Some(250));
}

/// I-26, M6 design section 5.1 recovery: after the commit point, an ended
/// lease turns the message IN_DOUBT. It is never claimed again, and the
/// late reply of the first worker is not recorded over it.
#[test]
fn i26_ended_commit_lease_is_in_doubt_and_never_resent() {
    let (_db, log, outbox) = world();
    let (a, b) = ([0xA; 16], [0xB; 16]);
    assert_eq!(
        block_on(log.claim(outbox, a, AT)).unwrap(),
        Next::Claim { attempt: 1 }
    );
    assert!(block_on(log.commit_point(outbox, a, 1, facts(), AT)).unwrap());
    let later = AT + DELIVERY_LEASE_US;
    assert_eq!(
        block_on(log.claim(outbox, b, later)).unwrap(),
        Next::RecordInDoubt { attempt: 1 }
    );
    assert_eq!(
        block_on(log.head(outbox)).unwrap().map(|h| h.phase),
        Some(Phase::InDoubt)
    );
    assert!(!block_on(log.record(outbox, a, 1, Phase::Sent, Some(250), later)).unwrap());
    assert_eq!(
        block_on(log.claim(outbox, b, i64::MAX)).unwrap(),
        Next::Done
    );
    assert_eq!(
        block_on(log.pending(2, 10)).unwrap(),
        Vec::<[u8; 16]>::new()
    );
}

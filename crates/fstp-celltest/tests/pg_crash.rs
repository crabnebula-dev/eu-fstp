//! T3 of M6 design section 7: two dispatcher instances against the real
//! `ops.delivery` schema and the loopback TLS sink, with the pgwire
//! connection dropped at each delivery write (I-25, I-26).
//!
//! A trigger on `ops.delivery` ends the backend of the session that
//! inserts the `k`-th row after it is armed, as a crash or a lost
//! connection does, following the `store_faults.rs` pattern of
//! `fstp-pgstore`. The two workers then run to the end. Checks:
//!
//! - I-26: the sink accepted each message at most once.
//! - I-25: each accepted message has a COMMITTING row with its digest,
//!   event and template version.
//! - Liveness: every message reaches a terminal phase.
//! - The partial unique index and the no-update trigger still hold.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

#[path = "../../fstp-pgstore/tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;

use common::{CellDb, block_on, bytea, fresh16, must, rt, uuid_text};
use fstp_api_testkit::smtp_sink::{SinkConfig, SmtpSink};
use fstp_dispatch::{Envelope, LoadError, Outcome, Prepared, SmtpTransport, Source, Step, Worker};
use fstp_pgstore::{DELIVERY_LEASE_US, DeliveryLog, Phase, Pool, Role};
use fstp_rt::tokio::TokioRuntime;
use fstp_smtp::client::Staged;

/// A time inside the bound, in UTC microseconds (2026-11-07).
const AT: i64 = 1_794_050_000_000_000;

/// The delivery rows of one message that is sent on its first attempt:
/// CLAIMED, COMMITTING and SENT.
const ROWS_PER_MESSAGE: u64 = 3;

/// Messages per run.
const MESSAGES: usize = 2;

/// Superuser SQL: ends the backend that inserts the `target`-th
/// `ops.delivery` row after the fault is armed.
const DELIVERY_FAULTS: &str = "\
CREATE SCHEMA fstp_dtest;
CREATE TABLE fstp_dtest.fault (target bigint NOT NULL);
INSERT INTO fstp_dtest.fault VALUES (0);
CREATE SEQUENCE fstp_dtest.calls;
CREATE FUNCTION fstp_dtest.after_row() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $$
DECLARE t bigint;
BEGIN
  SELECT target INTO t FROM fstp_dtest.fault;
  IF t > 0 AND nextval('fstp_dtest.calls') = t THEN
    PERFORM pg_terminate_backend(pg_backend_pid());
    PERFORM pg_sleep(10);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER zz_dfault AFTER INSERT ON ops.delivery FOR EACH ROW EXECUTE FUNCTION fstp_dtest.after_row();";

type Tx = SmtpTransport<TokioRuntime>;
type W = Worker<Staged<TokioRuntime, <TokioRuntime as fstp_rt::Runtime>::Tcp>>;

struct World {
    db: CellDb,
    logs: [DeliveryLog<TokioRuntime>; 2],
    sink: SmtpSink,
    tx: [Tx; 2],
}

fn pool(db: &CellDb) -> Pool<TokioRuntime> {
    block_on(Pool::open(
        rt().clone(),
        db.cell,
        Role::App,
        db.config("app"),
        2,
    ))
    .unwrap_or_else(|e| panic!("the app pool: {e}"))
}

fn world() -> World {
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
    db.psql(DELIVERY_FAULTS)
        .unwrap_or_else(|e| panic!("faults: {e:?}"));
    let logs = [
        DeliveryLog::new(pool(&db)).unwrap(),
        DeliveryLog::new(pool(&db)).unwrap(),
    ];
    let sink = block_on(SmtpSink::start(rt(), SinkConfig::default())).unwrap();
    let port = sink.addr().port();
    let tx =
        [0, 1].map(|_| SmtpTransport::new(rt().clone(), sink.client().unwrap(), "127.0.0.1", port));
    World { db, logs, sink, tx }
}

fn arm(db: &CellDb, target: u64) {
    db.psql(&format!(
        "UPDATE fstp_dtest.fault SET target = {target};\n\
         SELECT pg_catalog.setval('fstp_dtest.calls', 1, false);"
    ))
    .unwrap_or_else(|e| panic!("arm: {e:?}"));
}

/// One message: its outbox row and the bytes the timeline composed.
#[derive(Clone)]
struct Msg {
    outbox: [u8; 16],
    prepared: Prepared,
}

fn message(db: &CellDb, n: usize) -> Msg {
    let outbox = fresh16();
    db.psql_as(
        "writer",
        &format!(
            "INSERT INTO ops.outbox (id, kind, idem, dek, body, created_at) \
             VALUES ('{}', 2, {}, '{}', {}, 1);",
            uuid_text(&outbox),
            bytea(&fresh16()),
            uuid_text(&fresh16()),
            bytea(&[0xA5; 40]),
        ),
    )
    .unwrap_or_else(|e| panic!("outbox row: {e:?}"));
    let body = format!(
        "From: <noreply@fund.test>\r\nTo: <lead{n}@example.test>\r\nSubject: m{n}\r\n\
         Message-ID: <{}@fund.test>\r\n\r\nA notice is waiting.\r\n",
        uuid_text(&outbox)
    )
    .into_bytes();
    Msg {
        outbox,
        prepared: Prepared {
            envelope: Envelope {
                from: "noreply@fund.test".to_owned(),
                to: format!("lead{n}@example.test"),
            },
            body,
            event: [u8::try_from(n).unwrap(); 32],
            template_version: 2,
        },
    }
}

struct MapSource(BTreeMap<[u8; 16], Prepared>);

impl Source for MapSource {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        self.0.get(&outbox).cloned().ok_or(LoadError::Unusable)
    }
}

fn settled(log: &DeliveryLog<TokioRuntime>, outbox: [u8; 16]) -> bool {
    block_on(log.rows(outbox))
        .map(|rows| rows.iter().any(|r| r.phase.is_terminal()))
        .unwrap_or(false)
}

/// Runs two workers round-robin over `msgs` until every message is
/// settled, moving time past the lease each round.
fn run(w: &mut World, workers: &mut [W; 2], msgs: &[Msg], mut now: i64) -> Vec<Outcome> {
    let mut source = MapSource(
        msgs.iter()
            .map(|m| (m.outbox, m.prepared.clone()))
            .collect(),
    );
    let ids: Vec<[u8; 16]> = msgs.iter().map(|m| m.outbox).collect();
    let mut outcomes = Vec::new();
    for _ in 0..40 {
        if ids.iter().all(|o| settled(&w.logs[0], *o)) {
            break;
        }
        for i in 0..2 {
            for _ in 0..6 {
                let (logs, tx) = (&mut w.logs, &mut w.tx);
                let out =
                    block_on(workers[i].step(&mut logs[i], &mut source, &mut tx[i], &ids, now));
                outcomes.push(out);
            }
        }
        now += DELIVERY_LEASE_US + 61 * 60 * 1_000_000;
    }
    outcomes
}

fn check(w: &World, msgs: &[Msg], label: &str) {
    let accepted = w.sink.messages();
    for m in msgs {
        let hits: Vec<_> = accepted
            .iter()
            .filter(|a| a.data == m.prepared.body)
            .collect();
        assert!(
            hits.len() <= 1,
            "I-26 ({label}): the sink accepted a message {} times",
            hits.len()
        );
        let rows = block_on(w.logs[0].rows(m.outbox)).unwrap();
        assert!(
            rows.iter().any(|r| r.phase.is_terminal()),
            "liveness ({label}): {rows:?}"
        );
        if !hits.is_empty() {
            let digest = fstp_crypto::sha256(&m.prepared.body);
            assert!(
                rows.iter().any(|r| r.phase == Phase::Committing
                    && r.commit.is_some_and(|c| c.body_digest == digest
                        && c.event == m.prepared.event
                        && c.template_version == m.prepared.template_version)),
                "I-25 ({label}): an accepted message without its COMMITTING row: {rows:?}"
            );
        }
    }
}

fn workers() -> [W; 2] {
    [Worker::new([1; 16]), Worker::new([2; 16])]
}

/// I-25, I-26, M6 design section 7 (T3): with the pgwire connection
/// dropped at each delivery write in turn, two dispatcher instances
/// deliver each message at most once, trace each delivery to its
/// COMMITTING row, and settle every message. The table still refuses an
/// update and a second terminal row.
#[test]
fn i25_i26_pg_dispatchers_send_at_most_once_with_dropped_connections() {
    let mut w = world();
    let mut n = 0;
    for target in 0..=(ROWS_PER_MESSAGE * u64::try_from(MESSAGES).unwrap()) {
        let msgs: Vec<Msg> = (0..MESSAGES)
            .map(|_| {
                n += 1;
                message(&w.db, n)
            })
            .collect();
        arm(&w.db, target);
        let mut ws = workers();
        let now = AT + i64::try_from(target).unwrap() * 1_000_000_000_000;
        let outcomes = run(&mut w, &mut ws, &msgs, now);
        let faulted = outcomes.iter().any(|o| {
            matches!(
                o,
                Outcome::StoreFault { .. } | Outcome::Fenced { .. } | Outcome::Unconfirmed { .. }
            )
        });
        assert_eq!(
            faulted,
            target > 0,
            "the dropped connection at write {target} was seen"
        );
        arm(&w.db, 0);
        check(&w, &msgs, &format!("drop at write {target}"));
    }
    let e =
        w.db.psql_as("app", "UPDATE ops.delivery SET at = at;")
            .expect_err("an update");
    assert_eq!(e.state.as_deref(), Some("42501"), "{e:?}");
    let sent =
        w.db.count("SELECT count(*) FROM ops.delivery WHERE phase = 3;");
    assert!(sent > 0, "nothing was sent");
    let e =
        w.db.psql_as(
            "app",
            "INSERT INTO ops.delivery (outbox_id, attempt, phase, at, worker) \
             SELECT outbox_id, attempt + 100, 5, 1, worker FROM ops.delivery \
             WHERE phase = 3 LIMIT 1;",
        )
        .expect_err("a second terminal row");
    assert_eq!(e.state.as_deref(), Some("23505"), "{e:?}");
}

/// I-26, M6 design section 5.1 (T3): a stalled worker whose lease was
/// taken over fails the commit point against PostgreSQL and never sends
/// the final dot, while the worker that took over delivers once.
#[test]
fn i26_pg_stalled_worker_is_fenced_at_the_commit_point() {
    let mut w = world();
    let msgs = vec![message(&w.db, 1)];
    let mut source = MapSource(
        msgs.iter()
            .map(|m| (m.outbox, m.prepared.clone()))
            .collect(),
    );
    let ids = [msgs[0].outbox];
    let mut ws = workers();
    let mut step = |w: &mut World, ws: &mut [W; 2], i: usize, now: i64| {
        let (logs, tx) = (&mut w.logs, &mut w.tx);
        block_on(ws[i].step(&mut logs[i], &mut source, &mut tx[i], &ids, now))
    };
    // Worker 0 claims, renders and stages, then stalls.
    for _ in 0..3 {
        let _ = step(&mut w, &mut ws, 0, AT);
    }
    assert_eq!(ws[0].next_step(), Step::CommitPoint);
    // Its lease ends. Worker 1 takes over and delivers.
    let later = AT + DELIVERY_LEASE_US + 1;
    let mut last = Outcome::Idle;
    for _ in 0..5 {
        last = step(&mut w, &mut ws, 1, later);
    }
    assert!(
        matches!(
            last,
            Outcome::Recorded {
                phase: Phase::Sent,
                attempt: 2,
                ..
            }
        ),
        "{last:?}"
    );
    // The stalled worker wakes up and is fenced.
    let out = step(&mut w, &mut ws, 0, later + 1);
    assert_eq!(
        out,
        Outcome::Fenced {
            outbox: ids[0],
            attempt: 1
        }
    );
    assert_eq!(w.sink.messages().len(), 1, "I-26: one delivery");
    check(&w, &msgs, "stall");
}

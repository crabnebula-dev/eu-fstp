//! Wire protocol conformance against a real PostgreSQL server (test plan,
//! "Database" layer). Every test gets a fresh database on the server that
//! fstp-pgtest starts for this test binary.
//!
//! Tests named `r_nf_09_*` verify R-NF-09: traffic is encrypted, and with a
//! client certificate mutually authenticated. Tests named `r_nf_02_*`
//! verify R-NF-02: error output carries no data values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::time::{Duration, Instant};

use common::{block_on, config_for, connect, fresh, mutual_tls, rt, server, server_with, tls};
use fstp_pgtest::{MTLS_USER, ServerTls, tls as certs};
use fstp_pgwire::{
    AuthMethod, Client, Config, ErrorKind, IsolationLevel, Limits, Password, RequireAuth,
    TransactionOptions, TransactionStatus, Type,
};
use fstp_rt::{Listener, Runtime};
use fstp_tls::TlsErrorKind;

#[test]
fn r_nf_09_scram_sha_256_plus_over_tls_1_3() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    assert_eq!(c.auth_method(), Some(AuthMethod::ScramSha256Plus));
    let row = block_on(c.query_one(
        "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        &[],
    ))
    .unwrap();
    assert!(row.get::<bool>(0).unwrap());
    assert_eq!(row.get::<String>(1).unwrap(), "TLSv1.3");
    assert!(c.parameter("server_version").is_some());
    assert_eq!(c.parameter("client_encoding"), Some("UTF8"));
    assert_eq!(c.transaction_status(), TransactionStatus::Idle);
    block_on(c.close()).unwrap();
}

#[test]
fn r_nf_09_channel_binding_can_be_required() {
    let (_db, cfg) = fresh();
    let cfg = cfg.require_auth(RequireAuth::SCRAM_PLUS_ONLY);
    let c = connect(&cfg);
    assert_eq!(c.auth_method(), Some(AuthMethod::ScramSha256Plus));
}

#[test]
fn plain_scram_is_used_when_channel_binding_is_excluded() {
    let (_db, cfg) = fresh();
    let cfg = cfg.require_auth(RequireAuth::only(&[AuthMethod::ScramSha256]));
    let c = connect(&cfg);
    assert_eq!(c.auth_method(), Some(AuthMethod::ScramSha256));
}

#[test]
fn require_auth_without_scram_rejects_the_server() {
    let (_db, cfg) = fresh();
    let cfg = cfg.require_auth(RequireAuth::only(&[AuthMethod::Password]));
    let err = block_on(Client::connect(rt(), &cfg)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

#[test]
fn wrong_password_is_rejected_with_28p01() {
    let (db, _) = fresh();
    let mut bad = db.clone();
    bad.password = format!("{}x", db.password);
    let err = block_on(Client::connect(rt(), &config_for(&bad, tls()))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Db, "{err}");
    assert_eq!(err.code(), Some("28P01"));
}

#[test]
fn r_nf_09_untrusted_ca_is_rejected() {
    let (db, _) = fresh();
    let untrusted = fstp_tls::ClientConfig::new(certs::UNTRUSTED_CA_PEM).unwrap();
    let err = block_on(Client::connect(rt(), &config_for(&db, untrusted))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Tls, "{err}");
    assert_eq!(
        err.tls_error().map(fstp_tls::TlsError::kind),
        Some(TlsErrorKind::UntrustedCertificate)
    );
}

#[test]
fn r_nf_09_certificate_name_is_verified() {
    let (db, _) = fresh();
    let cfg = config_for(&db, tls())
        .tls_server_name("db.invalid")
        .unwrap();
    let err = block_on(Client::connect(rt(), &cfg)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Tls, "{err}");
    assert_eq!(
        err.tls_error().map(fstp_tls::TlsError::kind),
        Some(TlsErrorKind::NameMismatch)
    );
    // The DNS name in the certificate works as well as the IP address.
    let ok = config_for(&db, tls()).tls_server_name("localhost").unwrap();
    connect(&ok);
}

#[test]
fn r_nf_09_server_without_tls_is_refused() {
    let plain = server_with(ServerTls::Off);
    let db = plain.fresh_database().unwrap();
    let err = block_on(Client::connect(rt(), &config_for(&db, tls()))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TlsRequired, "{err}");
}

#[test]
fn r_nf_09_tls_is_used_even_when_the_server_allows_plaintext() {
    let optional = server_with(ServerTls::Optional);
    let db = optional.fresh_database().unwrap();
    let mut c = connect(&config_for(&db, tls()));
    assert_eq!(c.auth_method(), Some(AuthMethod::ScramSha256Plus));
    let ssl: bool = block_on(c.query_one(
        "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        &[],
    ))
    .unwrap()
    .get(0)
    .unwrap();
    assert!(ssl);
}

fn mtls_config(tls: fstp_tls::ClientConfig) -> Config {
    let srv = server();
    let db = srv.fresh_database().unwrap();
    Config::new(
        db.host,
        db.port,
        MTLS_USER,
        Password::new(srv.mtls_password()).unwrap(),
        db.dbname,
        tls,
    )
    .unwrap()
}

#[test]
fn r_nf_09_mutual_tls_with_client_certificate() {
    let mut c = connect(&mtls_config(mutual_tls()));
    let row = block_on(c.query_one(
        "SELECT client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        &[],
    ))
    .unwrap();
    let dn: String = row.get(0).unwrap();
    assert!(dn.contains("fstp-test-client"), "{dn}");
}

#[test]
fn r_nf_09_role_requiring_a_client_certificate_rejects_clients_without_one() {
    let err = block_on(Client::connect(rt(), &mtls_config(tls()))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Db, "{err}");
    assert_eq!(err.code(), Some("28000"));
}

#[test]
fn r_nf_09_untrusted_client_certificate_is_rejected() {
    let untrusted = fstp_tls::ClientConfig::mutual(
        certs::CA_PEM,
        certs::UNTRUSTED_CLIENT_CERT_PEM,
        certs::UNTRUSTED_CLIENT_KEY_PEM,
    )
    .unwrap();
    let err = block_on(Client::connect(rt(), &mtls_config(untrusted))).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            ErrorKind::Tls | ErrorKind::Io | ErrorKind::Closed
        ),
        "{err}"
    );
}

#[test]
fn unique_violation_reports_23505_without_values() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(c.execute("CREATE TABLE people (email text PRIMARY KEY)", &[])).unwrap();
    block_on(c.execute(
        "INSERT INTO people (email) VALUES ($1)",
        &[&"canary@example.org"],
    ))
    .unwrap();
    let err = block_on(c.execute(
        "INSERT INTO people (email) VALUES ($1)",
        &[&"canary@example.org"],
    ))
    .unwrap_err();
    assert_eq!(err.code(), Some("23505"));
    let db = err.as_db_error().unwrap();
    assert_eq!(db.constraint(), Some("people_pkey"));
    assert!(db.detail().unwrap().contains("canary@example.org"));
    // R-NF-02: neither Display nor Debug carries the duplicate value.
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("canary"), "{shown}");
    // The connection is still usable.
    let n: i64 = block_on(c.query_one("SELECT count(*) FROM people", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn r_nf_02_detail_hint_and_where_stay_out_of_display() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(c.execute(
        "CREATE FUNCTION fail_with_data() RETURNS int LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'failed' USING DETAIL = 'detail canary', HINT = 'hint canary'; END $$",
        &[],
    ))
    .unwrap();
    let err = block_on(c.query("SELECT fail_with_data()", &[])).unwrap_err();
    let db = err.as_db_error().unwrap();
    assert_eq!(db.detail(), Some("detail canary"));
    assert_eq!(db.hint(), Some("hint canary"));
    assert!(db.where_().is_some());
    let shown = format!("{err} {err:?} {db} {db:?}");
    assert!(!shown.contains("canary"), "{shown}");
    assert!(shown.contains("ERROR P0001"), "{shown}");
    assert_eq!(db.message(), "failed");
}

#[test]
fn syntax_error_reports_42601() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    let err = block_on(c.query("SELEC 1", &[])).unwrap_err();
    assert_eq!(err.code(), Some("42601"));
    assert!(err.as_db_error().unwrap().position().is_some());
    assert_eq!(c.cached_statements(), 0);
    let one: i32 = block_on(c.query_one("SELECT 1", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(one, 1);
}

#[test]
fn multi_statement_string_fails_under_the_extended_protocol() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(c.execute("CREATE TABLE victim (x int)", &[])).unwrap();
    let err = block_on(c.execute("SELECT 1; DROP TABLE victim", &[])).unwrap_err();
    assert_eq!(err.code(), Some("42601"), "{err}");
    let still_there: i64 = block_on(c.query_one(
        "SELECT count(*) FROM pg_tables WHERE tablename = 'victim'",
        &[],
    ))
    .unwrap()
    .get(0)
    .unwrap();
    assert_eq!(still_there, 1);
}

#[test]
fn transaction_commit_and_rollback() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();

        let mut tx = c.transaction().await.unwrap();
        tx.execute("INSERT INTO t VALUES ($1)", &[&1i32])
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = c.transaction().await.unwrap();
        tx.execute("INSERT INTO t VALUES ($1)", &[&2i32])
            .await
            .unwrap();
        let inside: i64 = tx
            .query_one("SELECT count(*) FROM t", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(inside, 2);
        tx.rollback().await.unwrap();

        let total: i64 = c
            .query_one("SELECT count(*) FROM t", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(c.transaction_status(), TransactionStatus::Idle);
    });
}

#[test]
fn dropped_transaction_rolls_back() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        {
            let mut tx = c.transaction().await.unwrap();
            tx.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
            // Dropped without commit.
        }
        let total: i64 = c
            .query_one("SELECT count(*) FROM t", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(total, 0);
        assert_eq!(c.transaction_status(), TransactionStatus::Idle);
    });
}

#[test]
fn commit_after_a_failed_statement_reports_rollback() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        let mut tx = c.transaction().await.unwrap();
        tx.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
        let err = tx.execute("SELECT 1/0", &[]).await.unwrap_err();
        assert_eq!(err.code(), Some("22012"));
        let err = tx.query("SELECT 1", &[]).await.unwrap_err();
        assert_eq!(err.code(), Some("25P02"));
        let err = tx.commit().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::RolledBack);
        let total: i64 = c
            .query_one("SELECT count(*) FROM t", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(total, 0);
    });
}

#[test]
fn isolation_levels_and_read_only() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        for (level, name) in [
            (IsolationLevel::ReadCommitted, "read committed"),
            (IsolationLevel::RepeatableRead, "repeatable read"),
            (IsolationLevel::Serializable, "serializable"),
        ] {
            let mut tx = c
                .transaction_with(TransactionOptions::new().isolation(level))
                .await
                .unwrap();
            let shown: String = tx
                .query_one("SELECT current_setting('transaction_isolation')", &[])
                .await
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(shown, name);
            tx.commit().await.unwrap();
        }
        let mut tx = c
            .transaction_with(
                TransactionOptions::new()
                    .isolation(IsolationLevel::Serializable)
                    .read_only(true)
                    .deferrable(true),
            )
            .await
            .unwrap();
        let err = tx
            .execute("CREATE TABLE nope (x int)", &[])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("25006"));
        tx.rollback().await.unwrap();
    });
}

#[test]
fn statement_cache_reuses_prepared_statements() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        for i in 0..5i32 {
            let v: i32 = c
                .query_one("SELECT $1::int4 + 1", &[&i])
                .await
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(v, i + 1);
        }
        let prepared: i64 = c
            .query_one(
                "SELECT count(*) FROM pg_prepared_statements WHERE statement = 'SELECT $1::int4 + 1'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(prepared, 1, "the statement was parsed once");
        assert_eq!(c.cached_statements(), 2);
    });
}

#[test]
fn statement_cache_evicts_and_closes_old_statements() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg.statement_cache_capacity(2));
    block_on(async {
        c.query("SELECT 1", &[]).await.unwrap();
        c.query("SELECT 2", &[]).await.unwrap();
        c.query("SELECT 3", &[]).await.unwrap();
        assert_eq!(c.cached_statements(), 2);
        let n: i64 = c
            .query_one("SELECT count(*) FROM pg_prepared_statements", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        // Two cached statements remain after this one evicted another.
        assert_eq!(n, 2);
    });
}

#[test]
fn statement_cache_can_be_disabled() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg.statement_cache_capacity(0));
    block_on(async {
        for _ in 0..3 {
            c.query("SELECT 1", &[]).await.unwrap();
        }
        assert_eq!(c.cached_statements(), 0);
        let n: i64 = c
            .query_one("SELECT count(*) FROM pg_prepared_statements", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(n, 0);
    });
}

#[test]
fn changed_result_type_invalidates_the_cached_statement() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        c.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
        c.query("SELECT * FROM t", &[]).await.unwrap();
        c.execute("ALTER TABLE t ADD COLUMN y int", &[])
            .await
            .unwrap();
        let err = c.query("SELECT * FROM t", &[]).await.unwrap_err();
        assert_eq!(err.code(), Some("0A000"));
        let rows = c.query("SELECT * FROM t", &[]).await.unwrap();
        assert_eq!(rows[0].len(), 2);
    });
}

#[test]
fn cancel_token_cancels_pg_sleep() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    let token = c.cancel_token();
    assert!(token.process_id().is_some());
    let canceller = rt().spawn(async move {
        rt().sleep(Duration::from_millis(300)).await;
        token.cancel(rt()).await
    });
    let start = Instant::now();
    let err = block_on(c.query("SELECT pg_sleep(30)", &[])).unwrap_err();
    assert_eq!(err.code(), Some("57014"), "{err}");
    assert!(start.elapsed() < Duration::from_secs(10));
    block_on(canceller).unwrap().unwrap();
    let one: i32 = block_on(c.query_one("SELECT 1", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(one, 1);
}

#[test]
fn statement_timeout_cancels_and_keeps_the_connection() {
    let (_db, cfg) = fresh();
    let cfg = cfg.statement_timeout(Some(Duration::from_millis(300)));
    let mut c = connect(&cfg);
    let start = Instant::now();
    let err = block_on(c.query("SELECT pg_sleep(30)", &[])).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Timeout, "{err}");
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(!c.is_broken());
    let one: i32 = block_on(c.query_one("SELECT 1", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(one, 1);
}

#[test]
fn connect_timeout_applies_to_a_silent_server() {
    block_on(async {
        let mut listener = rt().bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hold = rt().spawn(async move {
            // Accept and never answer.
            let conn = listener.accept().await;
            rt().sleep(Duration::from_secs(5)).await;
            drop(conn);
        });
        let cfg = Config::new(
            "127.0.0.1",
            addr.port(),
            "u",
            Password::new("p").unwrap(),
            "d",
            tls(),
        )
        .unwrap()
        .connect_timeout(Some(Duration::from_millis(300)));
        let start = Instant::now();
        let err = Client::connect(rt(), &cfg).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Timeout, "{err}");
        assert!(start.elapsed() < Duration::from_secs(3));
        hold.abort();
    });
}

#[test]
fn plaintext_after_the_ssl_answer_is_refused() {
    block_on(async {
        let mut listener = rt().bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = rt().spawn(async move {
            use fstp_rt::IoExt;
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 8];
            conn.read_exact(&mut req).await.unwrap();
            // "S" followed by injected bytes in the same segment.
            conn.write_all(b"SR\x00\x00\x00\x08\x00\x00\x00\x00")
                .await
                .unwrap();
            conn.flush().await.unwrap();
            rt().sleep(Duration::from_secs(2)).await;
        });
        let cfg = Config::new(
            "127.0.0.1",
            addr.port(),
            "u",
            Password::new("p").unwrap(),
            "d",
            tls(),
        )
        .unwrap();
        let err = Client::connect(rt(), &cfg).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
        assert!(err.to_string().contains("unencrypted"), "{err}");
        fake.abort();
    });
}

#[test]
fn large_result_sets() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        let rows = c
            .query(
                "SELECT g, repeat('x', 100) FROM generate_series(1, 200000) g",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 200_000);
        assert_eq!(rows[199_999].get::<i32>(0).unwrap(), 200_000);
        assert_eq!(rows[5].get::<String>(1).unwrap().len(), 100);

        // A stream reads rows one at a time.
        let mut stream = c
            .query_stream("SELECT g::int8 FROM generate_series(1, 300000) g", &[])
            .await
            .unwrap();
        let mut sum = 0i64;
        let mut count = 0u64;
        while let Some(row) = stream.next().await.unwrap() {
            sum += row.get::<i64>(0).unwrap();
            count += 1;
        }
        assert_eq!(count, 300_000);
        assert_eq!(sum, 300_000 * 300_001 / 2);
        assert_eq!(stream.rows_affected(), Some(300_000));

        // One value larger than the read buffer.
        let big: Vec<u8> = c
            .query_one("SELECT decode(repeat('ab', 8000000), 'hex')", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(big.len(), 8_000_000);
        assert!(big.iter().all(|b| *b == 0xab));
    });
}

#[test]
fn dropping_a_stream_early_keeps_the_connection_usable() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        {
            let mut stream = c
                .query_stream("SELECT g FROM generate_series(1, 100000) g", &[])
                .await
                .unwrap();
            for _ in 0..10 {
                stream.next().await.unwrap().unwrap();
            }
        }
        let v: i32 = c.query_one("SELECT 42", &[]).await.unwrap().get(0).unwrap();
        assert_eq!(v, 42);
    });
}

#[test]
fn result_limit_is_enforced_and_the_connection_survives() {
    let (_db, cfg) = fresh();
    let limits = Limits {
        max_result_bytes: 100_000,
        ..Limits::default()
    };
    let mut c = connect(&cfg.limits(limits));
    block_on(async {
        let err = c
            .query(
                "SELECT repeat('x', 1000) FROM generate_series(1, 1000)",
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ResultTooLarge);
        assert!(!c.is_broken());
        let v: i32 = c.query_one("SELECT 7", &[]).await.unwrap().get(0).unwrap();
        assert_eq!(v, 7);
    });
}

#[test]
fn th26_oversized_message_breaks_the_connection() {
    let (_db, cfg) = fresh();
    let limits = Limits {
        max_message_len: 1 << 20,
        ..Limits::default()
    };
    let mut c = connect(&cfg.limits(limits));
    block_on(async {
        let err = c
            .query("SELECT repeat('x', 2000000)", &[])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
        assert!(c.is_broken());
        let err = c.query("SELECT 1", &[]).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Closed);
    });
}

#[test]
fn concurrent_connections() {
    let (_db, cfg) = fresh();
    let handles: Vec<_> = (0..16i64)
        .map(|i| {
            let cfg = cfg.clone();
            rt().spawn(async move {
                let mut c = Client::connect(rt(), &cfg).await.unwrap();
                let mut total = 0i64;
                for j in 0..20i64 {
                    let v: i64 = c
                        .query_one("SELECT $1::int8 * $2::int8", &[&i, &j])
                        .await
                        .unwrap()
                        .get(0)
                        .unwrap();
                    total += v;
                }
                c.close().await.unwrap();
                total
            })
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        let total = block_on(h).unwrap();
        assert_eq!(total, i as i64 * (0..20).sum::<i64>());
    }
}

#[test]
fn copy_is_a_protocol_error_that_breaks_the_connection() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        let err = c.execute("COPY t FROM STDIN", &[]).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
        assert!(c.is_broken());
    });
}

#[test]
fn parameter_types_must_match_exactly() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (small int2, big int8, name text)", &[])
            .await
            .unwrap();
        // An i32 for an int8 column is a mismatch, not a widening.
        let err = c
            .execute("INSERT INTO t (big) VALUES ($1)", &[&1i32])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TypeMismatch, "{err}");
        // A NULL of the wrong Rust type is a mismatch too.
        let none: Option<i32> = None;
        let err = c
            .execute("INSERT INTO t (big) VALUES ($1)", &[&none])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TypeMismatch);
        let err = c
            .execute("INSERT INTO t (name) VALUES ($1)", &[&b"bytes".as_slice()])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TypeMismatch);
        let err = c
            .execute("INSERT INTO t (small) VALUES ($1)", &[&1i16, &2i16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ParameterCount);
        // Nothing was sent: the connection is fine.
        let n = c
            .execute(
                "INSERT INTO t (small, big, name) VALUES ($1, $2, $3)",
                &[&1i16, &2i64, &"x"],
            )
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Column types are checked on read.
        let row = c.query_one("SELECT small, big FROM t", &[]).await.unwrap();
        assert_eq!(row.get::<i16>(0).unwrap(), 1);
        assert_eq!(
            row.get::<i32>(0).unwrap_err().kind(),
            ErrorKind::TypeMismatch
        );
        assert_eq!(
            row.get::<i32>(1).unwrap_err().kind(),
            ErrorKind::TypeMismatch
        );
        assert_eq!(row.get::<i64>("big").unwrap(), 2);
        assert_eq!(
            row.get::<i64>("nope").unwrap_err().kind(),
            ErrorKind::ColumnNotFound
        );
        assert_eq!(
            row.get::<i64>(9).unwrap_err().kind(),
            ErrorKind::ColumnNotFound
        );
        // NULL needs an Option.
        let row = c.query_one("SELECT NULL::int8", &[]).await.unwrap();
        assert_eq!(row.get::<i64>(0).unwrap_err().kind(), ErrorKind::Decode);
        assert_eq!(row.get::<Option<i64>>(0).unwrap(), None);
    });
}

#[test]
fn prepare_reports_inferred_types() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    let st = block_on(c.prepare("SELECT $1::int8 AS a, $2::text AS b")).unwrap();
    assert_eq!(st.params(), &[Type::INT8, Type::TEXT]);
    assert_eq!(st.columns()[0].name(), "a");
    assert_eq!(st.columns()[1].type_(), Type::TEXT);
}

#[test]
fn rows_affected_and_row_count_checks() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        let n = c
            .execute("INSERT INTO t SELECT generate_series(1, 5)", &[])
            .await
            .unwrap();
        assert_eq!(n, 5);
        let n = c
            .execute("UPDATE t SET x = x + 1 WHERE x > $1", &[&2i32])
            .await
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            c.query_one("SELECT x FROM t", &[])
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::RowCount
        );
        assert!(
            c.query_opt("SELECT x FROM t WHERE x > 100", &[])
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            c.query_opt("SELECT x FROM t", &[])
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::RowCount
        );
        let n = c.execute("DELETE FROM t", &[]).await.unwrap();
        assert_eq!(n, 5);
        // An empty statement is accepted and affects nothing.
        assert_eq!(c.execute("", &[]).await.unwrap(), 0);
    });
}

#[test]
fn r_nf_02_notices_are_discarded() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("DO $$ BEGIN RAISE NOTICE 'notice canary'; END $$", &[])
            .await
            .unwrap();
        assert!(c.notices_discarded() >= 1);
    });
}

// ----- Regressions from the M1 review -----

/// A deferred foreign key fails when the implicit transaction commits. The
/// server then sends CommandComplete, ErrorResponse and ReadyForQuery. The
/// client must report the SQLSTATE and keep the connection.
#[test]
fn review_pg_err_after_commandcomplete() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE p (id int PRIMARY KEY)", &[])
            .await
            .unwrap();
        c.execute(
            "CREATE TABLE ch (pid int REFERENCES p(id) DEFERRABLE INITIALLY DEFERRED)",
            &[],
        )
        .await
        .unwrap();
        let err = c
            .execute("INSERT INTO ch (pid) VALUES ($1)", &[&1i32])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Db, "{err}");
        assert_eq!(err.code(), Some("23503"), "{err}");
        assert!(!c.is_broken());
        assert_eq!(c.transaction_status(), TransactionStatus::Idle);
        // The row was not committed, and the connection still works.
        let n: i64 = c
            .query_one("SELECT count(*) FROM ch", &[])
            .await
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(n, 0);
        // A collected query and a stream see the same error.
        let err = c
            .query("INSERT INTO ch (pid) VALUES ($1) RETURNING pid", &[&2i32])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("23503"), "{err}");
        let mut stream = c
            .query_stream("INSERT INTO ch (pid) VALUES ($1) RETURNING pid", &[&3i32])
            .await
            .unwrap();
        let first = stream.next().await.unwrap();
        assert!(first.is_some());
        let err = stream.next().await.unwrap_err();
        assert_eq!(err.code(), Some("23503"), "{err}");
        assert_eq!(stream.rows_affected(), None);
        drop(stream);
        assert!(!c.is_broken());
    });
}

/// R-NF-02: the primary message of a class 22 error quotes the offending
/// value. Display and Debug must not show it.
#[test]
fn review_pg_dberror_display_leaks_values() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE docs (body jsonb)", &[])
            .await
            .unwrap();
        let doc = fstp_json::parse(br#"{"age":"canary@example.org"}"#).unwrap();
        c.execute("INSERT INTO docs (body) VALUES ($1)", &[&doc])
            .await
            .unwrap();
        let err = c
            .query("SELECT (body->>'age')::int FROM docs", &[])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("22P02"));
        let db = err.as_db_error().unwrap();
        assert!(db.message().contains("canary"), "the accessor keeps it");
        let shown = format!("{err} | {err:?} | {db} | {db:?}");
        assert!(!shown.contains("canary"), "{shown}");
        assert!(shown.contains("ERROR 22P02"), "{shown}");

        let err = c
            .query("SELECT $1::text::uuid", &[&"canary-identity"])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some("22P02"));
        let shown = format!("{err} | {err:?}");
        assert!(!shown.contains("canary"), "{shown}");
    });
}

/// R-NF-02: numeric and enum casts and a RAISE with a formatted value all
/// put data into the primary message. Display and Debug show severity,
/// SQLSTATE and schema names only.
#[test]
fn review_rnf02_dberror_primary_message_leaks_values() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute(
            "CREATE TABLE grants (id int PRIMARY KEY, amount numeric, note text)",
            &[],
        )
        .await
        .unwrap();
        c.execute("CREATE TYPE mood AS ENUM ('happy', 'sad')", &[])
            .await
            .unwrap();
        c.execute(
            "CREATE FUNCTION fail_with(v text) RETURNS int LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'applicant % rejected', v; END $$",
            &[],
        )
        .await
        .unwrap();
        let canary = "canary-applicant@example.org";
        let numeric = c
            .execute(
                "INSERT INTO grants VALUES (1, $1::text::numeric, NULL)",
                &[&canary],
            )
            .await
            .unwrap_err();
        let enumeration = c
            .query("SELECT $1::text::mood", &[&canary])
            .await
            .unwrap_err();
        let raised = c
            .query("SELECT fail_with($1)", &[&canary])
            .await
            .unwrap_err();
        for (err, code) in [
            (&numeric, "22P02"),
            (&enumeration, "22P02"),
            (&raised, "P0001"),
        ] {
            assert_eq!(err.code(), Some(code), "{err}");
            let db = err.as_db_error().unwrap();
            assert!(db.message().contains("canary"), "the accessor keeps it");
            let shown = format!("{err} | {err:?} | {db} | {db:?}");
            assert!(!shown.contains("canary"), "{shown}");
            assert!(shown.contains(&format!("ERROR {code}")), "{shown}");
        }
        // Schema names stay in the output, since they are not data.
        c.execute("INSERT INTO grants VALUES (1, 1, NULL)", &[])
            .await
            .unwrap();
        let dup = c
            .execute("INSERT INTO grants VALUES (1, 2, NULL)", &[])
            .await
            .unwrap_err();
        let shown = format!("{dup} | {dup:?}");
        assert!(shown.contains("grants_pkey"), "{shown}");
        assert!(shown.contains("grants"), "{shown}");
    });
}

/// A Close queued for a stale statement must survive a later request whose
/// parameters fail to encode.
#[test]
fn review_pg_pending_close_lost() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        c.execute("CREATE TABLE t2 (s text)", &[]).await.unwrap();
        c.execute("INSERT INTO t2 (s) VALUES ($1)", &[&"ok"])
            .await
            .unwrap();
        c.query("SELECT * FROM t", &[]).await.unwrap();
        c.execute("ALTER TABLE t ADD COLUMN y int", &[])
            .await
            .unwrap();
        let e = c.query("SELECT * FROM t", &[]).await.unwrap_err();
        assert_eq!(e.code(), Some("0A000"));
        // The stale statement is queued for Close. The next statement is
        // cached and its parameter fails to encode.
        let e = c
            .execute("INSERT INTO t2 (s) VALUES ($1)", &[&"nul\0byte"])
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Encode, "{e}");
        assert!(!c.is_broken());
        c.query("SELECT * FROM t", &[]).await.unwrap();
        let names = c
            .query(
                "SELECT name FROM pg_prepared_statements WHERE statement = 'SELECT * FROM t'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(names.len(), 1, "a stale server-side statement leaked");
    });
}

/// A prepare that fails while encoding must not leave bytes behind for the
/// next transaction control statement.
#[test]
fn review_pg_run_control_dirty_wbuf() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        // A cache entry to evict, so the failed prepare also queues a Close.
        let cfg_small = cfg.clone().statement_cache_capacity(1);
        let mut small = Client::connect(rt(), &cfg_small).await.unwrap();
        small.query("SELECT 2", &[]).await.unwrap();
        for client in [&mut c, &mut small] {
            let e = client.query("SELECT 1\0", &[]).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config, "{e}");
            let mut tx = client.transaction().await.unwrap();
            let v: i32 = tx.query_one("SELECT 5", &[]).await.unwrap().get(0).unwrap();
            assert_eq!(v, 5);
            tx.commit().await.unwrap();
            assert!(!client.is_broken());
        }
        small.close().await.unwrap();
    });
}

/// A 0A000 read while draining an abandoned stream invalidates the cached
/// statement, so the next call prepares again instead of failing twice.
#[test]
fn review_pg_drain_skips_0a000_invalidation() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        c.execute("CREATE TABLE t (x int)", &[]).await.unwrap();
        c.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
        c.query("SELECT * FROM t", &[]).await.unwrap();
        c.execute("ALTER TABLE t ADD COLUMN y int", &[])
            .await
            .unwrap();
        // The stream is dropped before its first row, so drain() reads the
        // 0A000 error.
        drop(c.query_stream("SELECT * FROM t", &[]).await.unwrap());
        let v: i32 = c.query_one("SELECT 3", &[]).await.unwrap().get(0).unwrap();
        assert_eq!(v, 3);
        let rows = c.query("SELECT * FROM t", &[]).await.unwrap();
        assert_eq!(rows[0].len(), 2);
    });
}

/// `max_result_bytes` bounds the memory that `query` holds. Tiny rows cost
/// far more memory than their wire size, so they reach the limit sooner.
#[test]
fn review_pg_result_limit_underaccounts_memory() {
    let (_db, cfg) = fresh();
    let limit = 4usize << 20;
    let mut c = connect(&cfg.limits(Limits {
        max_result_bytes: limit,
        ..Limits::default()
    }));
    block_on(async {
        for sql in [
            "SELECT FROM generate_series(1, 2000000)",
            "SELECT g FROM generate_series(1, 400000) g",
        ] {
            let err = c.query(sql, &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ResultTooLarge, "{sql}: {err}");
            assert!(!c.is_broken());
        }
        // A result well inside the limit is still collected.
        let rows = c
            .query("SELECT g FROM generate_series(1, 10000) g", &[])
            .await
            .unwrap();
        assert_eq!(rows.len(), 10_000);
    });
}

/// PostgreSQL `json` keeps duplicate keys, which fstp-json rejects. Reading
/// such a value is a decode error; a cast to `jsonb` in SQL keeps the last
/// value and decodes.
#[test]
fn json_with_duplicate_keys_is_a_decode_error() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        let row = c
            .query_one(
                r#"SELECT '{"a":1,"a":2}'::json, '{"a":1,"a":2}'::json::jsonb"#,
                &[],
            )
            .await
            .unwrap();
        let err = row.get::<fstp_json::Value>(0).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decode, "{err}");
        let v = row.get::<fstp_json::Value>(1).unwrap();
        assert_eq!(v, fstp_json::parse(br#"{"a":2}"#).unwrap());
    });
}

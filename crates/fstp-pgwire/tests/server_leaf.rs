//! The server's verified leaf certificate, read from a live connection
//! (I-83, M3 design section 9.2). The cell and the vault derive the
//! cluster kind OU and the SPKI digest from it at start.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use common::{block_on, config_with, connect, fresh, rt};
use fstp_pgtest::{PgServer, tls as certs};
use fstp_pgwire::{Client, ClientTls, ErrorKind, ServerCheck};

/// The DER of the first certificate in `pem`.
fn first_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    fstp_pgwire::base64::decode(body.as_bytes()).unwrap()
}

/// The certificate the named server `server` was started with, as its
/// TLS directory holds it.
fn held_leaf(server: &PgServer) -> Vec<u8> {
    first_der(&std::fs::read(server.dir().join("tls").join("server.pem")).unwrap())
}

/// A client of a fresh database on the named server `server`, through a
/// role minted from its own cluster CA.
fn named_client(server: &'static PgServer) -> Client<fstp_rt::tokio::TokioRuntime> {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let role = format!("leaf_r{n}_{}", std::process::id());
    let db = format!("leaf_d{n}_{}", std::process::id());
    let login = server.create_login_role(&role).unwrap();
    server.create_database_for(&db, &[role.as_str()]).unwrap();
    let p = login.conn_params(server, &db);
    let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    block_on(Client::connect(rt(), &config_with(&p, tls))).unwrap()
}

/// I-83, design section 9.2: the client exposes the leaf certificate the
/// server presented, byte for byte, and it stays the same after
/// statements run on the connection.
#[test]
fn i83_client_exposes_the_verified_server_leaf() {
    let (_db, cfg) = fresh();
    let mut client = connect(&cfg);
    let want = first_der(certs::SERVER_CERT_PEM);
    assert_eq!(client.server_certificate_der(), want.as_slice());
    let one: i32 = block_on(client.query_one("SELECT 1::int4", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(one, 1);
    assert_eq!(client.server_certificate_der(), want.as_slice());
}

/// I-83, design section 9.2: on two named clusters, each with its own
/// cluster CA, each client exposes the certificate its own server holds,
/// and the two leaves differ.
#[test]
fn i83_each_cluster_connection_exposes_its_own_server_leaf() {
    let app = PgServer::shared_named("leaf_application", "application").unwrap();
    let vault = PgServer::shared_named("leaf_vault", "vault").unwrap();
    let a = named_client(app);
    let v = named_client(vault);
    assert_eq!(a.server_certificate_der(), held_leaf(app).as_slice());
    assert_eq!(v.server_certificate_der(), held_leaf(vault).as_slice());
    assert_ne!(a.server_certificate_der(), v.server_certificate_der());
}

/// A server check that records each leaf it sees and accepts the first
/// `accept` of them.
fn counting_check(accept: usize) -> (ServerCheck, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let check = ServerCheck::new(move |der: &[u8]| {
        let mut log = log.lock().unwrap();
        log.push(der.to_vec());
        log.len() <= accept
    });
    (check, seen)
}

/// I-83, design section 9.2: a server check of the configuration runs on
/// the verified leaf of every connection opened over the configuration
/// and its clones, so a pool that reconnects later runs it again.
#[test]
fn i83_server_check_runs_on_every_connection_of_a_config() {
    let (_db, cfg) = fresh();
    let (check, seen) = counting_check(usize::MAX);
    let cfg = cfg.server_check(check);
    let again = cfg.clone();
    let mut first = connect(&cfg);
    let mut second = connect(&again);
    let want = first_der(certs::SERVER_CERT_PEM);
    assert_eq!(*seen.lock().unwrap(), vec![want.clone(), want]);
    for c in [&mut first, &mut second] {
        let one: i32 = block_on(c.query_one("SELECT 1::int4", &[]))
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(one, 1);
    }
}

/// I-83, design section 9.2: a connection whose server a check refuses
/// fails with `ServerRefused`, and a later check never removes an
/// earlier one.
#[test]
fn i83_a_refused_server_fails_the_connection() {
    let (_db, cfg) = fresh();
    let refused = block_on(Client::connect(
        rt(),
        &cfg.clone().server_check(ServerCheck::new(|_: &[u8]| false)),
    ))
    .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::ServerRefused, "{refused}");
    let both = cfg
        .clone()
        .server_check(ServerCheck::new(|_: &[u8]| false))
        .server_check(ServerCheck::new(|_: &[u8]| true));
    assert_eq!(both.server_check_count(), 2);
    let refused = block_on(Client::connect(rt(), &both)).unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::ServerRefused, "{refused}");
    let accepted = cfg.server_check(ServerCheck::new(|_: &[u8]| true));
    drop(connect(&accepted));
}

/// I-83, design section 9.2: a check that accepts only the vault
/// cluster's held leaf connects to the vault cluster. The application
/// cluster, whose leaf chains to the roots its configuration trusts, is
/// refused.
#[test]
fn i83_a_server_check_tells_two_clusters_apart() {
    let app = PgServer::shared_named("leaf_application", "application").unwrap();
    let vault = PgServer::shared_named("leaf_vault", "vault").unwrap();
    let vault_leaf = held_leaf(vault);
    let only_vault = ServerCheck::new(move |der: &[u8]| der == vault_leaf.as_slice());
    for (server, accepted) in [(vault, true), (app, false)] {
        let role = format!("leaf_chk_{}_{}", accepted, std::process::id());
        let db = format!("leaf_chkdb_{}_{}", accepted, std::process::id());
        let login = server.create_login_role(&role).unwrap();
        server.create_database_for(&db, &[role.as_str()]).unwrap();
        let p = login.conn_params(server, &db);
        let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
        let cfg = config_with(&p, tls).server_check(only_vault.clone());
        let got = block_on(Client::connect(rt(), &cfg));
        match (accepted, got) {
            (true, Ok(_)) => {}
            (false, Err(e)) => assert_eq!(e.kind(), ErrorKind::ServerRefused, "{e}"),
            (want, got) => panic!("accepted {want}: {got:?}"),
        }
    }
}

/// I-83, design section 9.2: the cancel connection runs the server checks
/// too. A check that accepted the connection and then refuses the server
/// stops the CancelRequest before the key is sent.
#[test]
fn i83_the_cancel_connection_runs_the_server_checks() {
    let (_db, cfg) = fresh();
    let (check, seen) = counting_check(1);
    let client = connect(&cfg.server_check(check));
    let token = client.cancel_token();
    let refused = block_on(token.cancel(rt())).unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::ServerRefused, "{refused}");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

/// The `Debug` form of a configuration shows how many server checks it
/// runs and nothing of them.
#[test]
fn config_debug_counts_server_checks() {
    let (_db, cfg) = fresh();
    let cfg = cfg.server_check(ServerCheck::new(|_: &[u8]| true));
    let text = format!("{cfg:?}");
    assert!(text.contains("server_checks: 1"), "{text}");
    assert_eq!(
        format!("{:?}", ServerCheck::new(|_: &[u8]| true)),
        "ServerCheck(..)"
    );
}

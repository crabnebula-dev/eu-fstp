//! The vault's I-83 start check over real clusters (M3 design section
//! 9.2, lane m3i83). `fstp_vault::service::serve` reads the placement
//! marker, and takes the server certificate OU and the SPKI from the
//! leaf certificate its own `fstp_pgwire` connection verified. Nothing
//! about the server comes from the caller except the control plane's
//! registration of server keys.
//!
//! Two named servers from `fstp-pgtest` stand for an application cluster
//! and a vault cluster. Each has its own cluster CA, and its server
//! certificate carries its kind as the subject OU.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fstp_pgtest::{PgServer, RoleLogin, tls as fixtures};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::VaultError;
use fstp_vault::service::{
    AeadSealer, RegisteredSpki, VaultParts, is_vault_server, registered_role, serve,
    server_ou_role, server_spki_digest, vault_server_check,
};
use fstp_vault::start::ClusterRole;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// The refusal of a database that fails I-83.
const I83_REFUSAL: VaultError = VaultError::Malformed("not a vault database (I-83)");

/// The live server of `role`: OU `application` or `vault`.
fn cluster(role: ClusterRole) -> &'static PgServer {
    let (name, ou) = match role {
        ClusterRole::Application => ("vi83_application", "application"),
        ClusterRole::Vault => ("vi83_vault", "vault"),
        ClusterRole::Other => panic!("no live server of another kind"),
    };
    PgServer::shared_named(name, ou).unwrap_or_else(|e| panic!("{e}"))
}

/// The DER of the first certificate of `pem`.
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

/// The SHA-256 digest of the SPKI of the certificate `server` holds, as
/// `fstp-pgtest` wrote it to the server's TLS directory. This is what a
/// control plane registers for the cluster.
fn held_spki_digest(server: &PgServer) -> [u8; 32] {
    let pem = std::fs::read(server.dir().join("tls").join("server.pem")).unwrap();
    let der = first_der(&pem);
    fstp_crypto::sha256(fstp_witness::peer::read_cert(&der).unwrap().spki)
}

/// The registration a truthful control plane holds for the two live
/// servers.
fn truthful() -> Vec<RegisteredSpki> {
    vec![
        RegisteredSpki {
            digest: held_spki_digest(cluster(ClusterRole::Application)),
            role: ClusterRole::Application,
        },
        RegisteredSpki {
            digest: held_spki_digest(cluster(ClusterRole::Vault)),
            role: ClusterRole::Vault,
        },
    ]
}

fn config(server: &PgServer, dbname: &str, login: &RoleLogin) -> Config {
    let p = login.conn_params(server, dbname);
    let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)))
}

/// A migrated vault database `v_<cell>` on `server` with its placement
/// row of kind 2, the vault marker. The `v_<cell>_vault` role owns its
/// schemas. Returns the cell and the role's configuration.
fn vault_database(server: &'static PgServer) -> ([u8; 16], Config) {
    let cell = fstp_crypto::random_array::<16>().unwrap();
    let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
    let dbname = format!("v_{hex}");
    let role = format!("v_{hex}_vault");
    let login = server.create_login_role(&role).unwrap();
    server
        .create_database_for(&dbname, &[role.as_str()])
        .unwrap();
    server
        .psql(
            "postgres",
            &format!("GRANT CREATE ON DATABASE {dbname} TO {role}"),
        )
        .unwrap();
    let cfg = config(server, &dbname, &login);
    let mut client = block_on(Client::connect(rt(), &cfg)).unwrap();
    block_on(fstp_vault::store::migrate(&mut client)).unwrap();
    let cluster_id = vec![0x5a_u8; 16];
    let kind = 2i16;
    block_on(client.execute(
        "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ($1, $2, $3)",
        &[&cell.to_vec(), &cluster_id, &kind],
    ))
    .unwrap();
    block_on(client.close()).unwrap();
    (cell, cfg)
}

fn server_tls(client_roots: Option<&[u8]>) -> fstp_tls::ServerConfig {
    let b = fstp_tls::ServerConfig::builder(fixtures::SERVER_CERT_PEM, fixtures::SERVER_KEY_PEM);
    match client_roots {
        Some(r) => b.require_client_auth(r).build().unwrap(),
        None => b.build().unwrap(),
    }
}

/// Runs `serve` over the vault database of `cell` and `db` with the
/// registration `registered`. A vault that starts is shut down again.
fn serve_over(
    cell: [u8; 16],
    db: Config,
    registered: Vec<RegisteredSpki>,
) -> Result<(), VaultError> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let parts = VaultParts {
        cell,
        db,
        registered_servers: registered,
        sealer: Arc::new(AeadSealer::new(
            fstp_crypto::random_array::<16>().unwrap(),
            fstp_crypto::aead::Key::generate().unwrap(),
            fstp_crypto::random_array::<32>().unwrap(),
        )),
        ticket_keys: vec![
            fstp_crypto::sig::Ed25519SigningKey::generate()
                .unwrap()
                .public_key(),
        ],
        internal_tls: server_tls(Some(fixtures::CA_PEM)),
        tunnel_tls: Arc::new(server_tls(Some(fixtures::CA_PEM))),
        origin_tls: Arc::new(server_tls(None)),
        origin_host: "id.i83.cell.fstp.localhost".to_owned(),
        internal_listen: loopback,
        origin_listen: loopback,
        // No chain writer: these tests start the vault only (ADR-010 open
        // point 5, Q-C, lane F-VCHAIN).
        chain: None,
    };
    let handle = block_on(serve(rt().clone(), parts))?;
    block_on(handle.shutdown(Duration::from_secs(10)))
}

/// The DER of a server certificate with OU `ou` from a fresh cluster CA.
fn minted_server_leaf(ou: &str) -> Vec<u8> {
    let ca = fstp_pgtest::certs::ClusterCa::generate("vault i83 test CA").unwrap();
    first_der(&ca.issue_server(ou).unwrap().cert_pem)
}

/// I-83, design section 9.2: a vault refuses an application cluster even
/// when the database there carries the vault marker. The server's OU is
/// `application` and its key is registered for an application cluster,
/// so the migrated vault database with its kind 2 placement row is
/// refused.
#[test]
fn i83_vault_refuses_an_application_cluster_even_with_a_vault_marker() {
    let (cell, db) = vault_database(cluster(ClusterRole::Application));
    assert_eq!(serve_over(cell, db, truthful()), Err(I83_REFUSAL));
}

/// I-83, design section 9.2: a vault refuses a server whose OU is
/// `vault` when the control plane registered its key for an application
/// cluster.
#[test]
fn i83_vault_refuses_a_vault_ou_whose_key_is_registered_for_an_application_cluster() {
    let server = cluster(ClusterRole::Vault);
    let (cell, db) = vault_database(server);
    let registered = vec![RegisteredSpki {
        digest: held_spki_digest(server),
        role: ClusterRole::Application,
    }];
    assert_eq!(serve_over(cell, db, registered), Err(I83_REFUSAL));
}

/// I-83, design section 9.2: a vault refuses a server whose key the
/// control plane never registered, though its OU and marker are right.
#[test]
fn i83_vault_refuses_an_unregistered_server_key() {
    let (cell, db) = vault_database(cluster(ClusterRole::Vault));
    let only_app = vec![truthful()[0]];
    assert_eq!(serve_over(cell, db, only_app), Err(I83_REFUSAL));
}

/// I-83, design section 9.2: a vault refuses a server key registered for
/// both a vault and an application cluster.
#[test]
fn i83_vault_refuses_a_server_key_registered_for_both_kinds() {
    let server = cluster(ClusterRole::Vault);
    let (cell, db) = vault_database(server);
    let digest = held_spki_digest(server);
    let registered = vec![
        RegisteredSpki {
            digest,
            role: ClusterRole::Vault,
        },
        RegisteredSpki {
            digest,
            role: ClusterRole::Application,
        },
    ];
    assert_eq!(serve_over(cell, db, registered), Err(I83_REFUSAL));
}

/// I-83 control for the refusals above: the same vault database on a
/// vault cluster, whose key is registered for a vault cluster, starts
/// and shuts down.
#[test]
fn i83_vault_starts_on_a_vault_cluster_with_its_key_registered() {
    let (cell, db) = vault_database(cluster(ClusterRole::Vault));
    assert_eq!(serve_over(cell, db, truthful()), Ok(()));
}

/// I-83, design section 9.2: the vault reads the cluster kind from the
/// server certificate's OU. Only the exact markers name a kind. Another
/// cluster kind, a certificate without an OU whose CN is `vault`, and
/// bytes that are no certificate name none. Near-miss spellings of the
/// OU are covered in `fstp-celltest` (`i83_placement.rs`), which can
/// issue them.
#[test]
fn i83_vault_reads_the_cluster_kind_from_the_server_certificate_ou() {
    let cases = [
        ("application", ClusterRole::Application),
        ("vault", ClusterRole::Vault),
        ("control", ClusterRole::Other),
        ("witness", ClusterRole::Other),
    ];
    for (ou, want) in cases {
        assert_eq!(server_ou_role(&minted_server_leaf(ou)), want, "OU {ou:?}");
    }
    let ca = fstp_pgtest::certs::ClusterCa::generate("vault i83 test CA").unwrap();
    let cn_only = first_der(&ca.issue_role("vault").unwrap().cert_pem);
    assert_eq!(server_ou_role(&cn_only), ClusterRole::Other);
    let leaf = minted_server_leaf("vault");
    assert_eq!(server_ou_role(&leaf[1..]), ClusterRole::Other);
    assert_eq!(server_ou_role(b"vault"), ClusterRole::Other);
}

/// I-83, design section 9.2: a server key names a kind only when it is
/// registered, and every registration of it names that one kind.
#[test]
fn i83_vault_registered_kind_needs_one_agreeing_registration() {
    let leaf = minted_server_leaf("vault");
    let digest = server_spki_digest(&leaf).unwrap();
    let reg = |role| RegisteredSpki { digest, role };
    let elsewhere = RegisteredSpki {
        digest: server_spki_digest(&minted_server_leaf("vault")).unwrap(),
        role: ClusterRole::Vault,
    };
    assert_ne!(elsewhere.digest, digest);
    assert_eq!(registered_role(&leaf, &[]), ClusterRole::Other);
    assert_eq!(registered_role(&leaf, &[elsewhere]), ClusterRole::Other);
    assert_eq!(
        registered_role(&leaf, &[elsewhere, reg(ClusterRole::Vault)]),
        ClusterRole::Vault
    );
    assert_eq!(
        registered_role(&leaf, &[reg(ClusterRole::Vault), reg(ClusterRole::Vault)]),
        ClusterRole::Vault
    );
    assert_eq!(
        registered_role(
            &leaf,
            &[reg(ClusterRole::Vault), reg(ClusterRole::Application)]
        ),
        ClusterRole::Other
    );
    assert_eq!(
        registered_role(&leaf[..leaf.len() - 1], &[reg(ClusterRole::Vault)]),
        ClusterRole::Other
    );
}

/// Synthetic certificates whose subjects hold two OUs, from the
/// `fstp-pgwire` fuzz seeds: `OU=vault, OU=application`,
/// `OU=application, OU=vault`, and one multi-valued RDN
/// `OU=vault + CN=127.0.0.1 + OU=application`.
const TWO_OU_LEAVES: [&[u8]; 3] = [
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/two-ous"),
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/two-ous-application-first"),
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/multi-valued-rdn"),
];

/// The control for [`TWO_OU_LEAVES`]: the same kind of synthetic
/// certificate with the one subject OU `vault`.
const ONE_OU_LEAF: &[u8] = include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/one-ou");

/// I-83, design section 9.2: a server certificate whose subject holds
/// two OUs names no cluster kind, whichever OU comes first. So it is no
/// vault server even with its key registered for a vault cluster only.
/// The same certificate with one OU `vault` is one.
#[test]
fn i83_vault_refuses_a_server_certificate_with_two_ous() {
    let digest = server_spki_digest(ONE_OU_LEAF).unwrap();
    let vault = [RegisteredSpki {
        digest,
        role: ClusterRole::Vault,
    }];
    assert_eq!(server_ou_role(ONE_OU_LEAF), ClusterRole::Vault);
    assert!(is_vault_server(ONE_OU_LEAF, &vault));
    for leaf in TWO_OU_LEAVES {
        let reg = [RegisteredSpki {
            digest: server_spki_digest(leaf).unwrap(),
            role: ClusterRole::Vault,
        }];
        assert_eq!(server_ou_role(leaf), ClusterRole::Other);
        assert_eq!(registered_role(leaf, &reg), ClusterRole::Vault);
        assert!(!is_vault_server(leaf, &reg));
        assert!(!vault_server_check(&reg).accepts(leaf));
    }
}

/// I-83, design section 9.2: the vault's server check refuses every
/// connection to an application cluster with `ServerRefused`, before
/// the startup message, and accepts the vault cluster. It runs on each
/// connection over the configuration, not only the first.
#[test]
fn i83_vault_server_check_refuses_every_connection_to_an_application_cluster() {
    let check = vault_server_check(&truthful());
    let (_, app_db) = vault_database(cluster(ClusterRole::Application));
    let app_db = app_db.server_check(check.clone());
    for _ in 0..2 {
        let e = block_on(Client::connect(rt(), &app_db)).unwrap_err();
        assert_eq!(e.kind(), fstp_pgwire::ErrorKind::ServerRefused, "{e}");
    }
    let (_, vault_db) = vault_database(cluster(ClusterRole::Vault));
    let vault_db = vault_db.server_check(check);
    for _ in 0..2 {
        let c = block_on(Client::connect(rt(), &vault_db)).unwrap();
        block_on(c.close()).unwrap();
    }
}

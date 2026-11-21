//! `fstp_vault::run` over real clusters (ADR-026 and ADR-004 records of
//! lane L8, gap G12).
//!
//! Two named servers from `fstp-pgtest` stand for an application cluster
//! and a vault cluster, as in `i83_server_identity.rs`. Each test writes a
//! configuration and a credentials directory as an operator would, and
//! runs the start steps of `fstp_vault::run` over them. Custody is a stub
//! in this process that wraps under one AES key: the custody wire form is
//! covered by `fstp-keyd`, and the binaries by the celltest end-to-end
//! test `g12_vault_binary_answers_the_cell_binary`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use fstp_custody::{
    Aad, BackendId, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature, Refusal,
    RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};
use fstp_pgtest::{PgServer, RoleLogin, tls as fixtures};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::VaultError;
use fstp_vault::config::{VaultConfig, decode_config};
use fstp_vault::keystore::VaultKeys;
use fstp_vault::run::{self, Credentials};
use fstp_vault::start::ClusterRole;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// A custody stub: one AES-256-GCM key wraps every seal key, bound to its
/// AAD and handle. It counts its roots, so a test sees a second genesis.
#[derive(Clone)]
struct StubCustody {
    key: Arc<fstp_crypto::aead::Key>,
    roots: Arc<Mutex<u32>>,
}

impl StubCustody {
    fn new() -> StubCustody {
        StubCustody {
            key: Arc::new(fstp_crypto::aead::Key::generate().unwrap()),
            roots: Arc::new(Mutex::new(0)),
        }
    }

    fn roots(&self) -> u32 {
        *self.roots.lock().unwrap()
    }
}

fn bound(root: &RootRef, aad: &Aad) -> Vec<u8> {
    [&root.handle.0[..], &aad.0[..]].concat()
}

impl fstp_custody::Custody for StubCustody {
    async fn create_root(&self, label: RootLabel) -> Result<RootRef, CustodyError> {
        let mut n = self.roots.lock().unwrap();
        *n += 1;
        Ok(RootRef {
            backend: BackendId::Keyd,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(format!("stub-root-{n}").into_bytes()),
        })
    }

    async fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> Result<WrappedSealKey, CustodyError> {
        let s = fstp_crypto::aead::seal(&self.key, &bound(root, aad), key.expose())
            .map_err(|_| CustodyError::Refused(Refusal::Internal))?;
        Ok(WrappedSealKey([s.nonce.to_vec(), s.body].concat()))
    }

    async fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> Result<SealKey, CustodyError> {
        let refused = CustodyError::Refused(Refusal::UnwrapFailed);
        let (nonce, body) = w.0.split_at_checked(12).ok_or(refused)?;
        let plain = fstp_crypto::aead::open(
            &self.key,
            nonce.try_into().unwrap(),
            &bound(root, aad),
            body,
        )
        .map_err(|_| refused)?;
        SealKey::from_slice(&plain).map_err(|_| refused)
    }

    async fn destroy(&self, _: &RootRef) -> Result<DestroyReceipt, CustodyError> {
        Err(CustodyError::Refused(Refusal::Internal))
    }

    async fn sign(&self, _: &SignKeyRef, _: &[u8; 32]) -> Result<EcdsaSignature, CustodyError> {
        Err(CustodyError::Refused(Refusal::NoSignKey))
    }

    async fn usage_since(&self, _: &RootRef, _: UsageCursor) -> Result<UsagePage, CustodyError> {
        Err(CustodyError::Refused(Refusal::Internal))
    }
}

/// The refusal of a database that fails I-83.
const I83_REFUSAL: VaultError = VaultError::Malformed("not a vault database (I-83)");

fn cluster(role: ClusterRole) -> &'static PgServer {
    let (name, ou) = match role {
        ClusterRole::Application => ("vi83_application", "application"),
        ClusterRole::Vault => ("vi83_vault", "vault"),
        ClusterRole::Other => panic!("no live server of another kind"),
    };
    PgServer::shared_named(name, ou).unwrap_or_else(|e| panic!("{e}"))
}

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

fn held_spki_digest(server: &PgServer) -> [u8; 32] {
    let pem = std::fs::read(server.dir().join("tls").join("server.pem")).unwrap();
    let der = first_der(&pem);
    fstp_crypto::sha256(fstp_witness::peer::read_cert(&der).unwrap().spki)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn login_config(server: &PgServer, dbname: &str, login: &RoleLogin) -> Config {
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

/// A migrated vault database on `server`, with its kind 2 placement row,
/// the `_vault` role as owner and the `_keys` role granted every
/// `keystore` table. The configuration and credentials directory of an
/// operator point at it.
fn vault_on(server: &'static PgServer) -> (VaultConfig, PathBuf) {
    let cell = fstp_crypto::random_array::<16>().unwrap();
    let dbname = format!("v_{}", hex(&cell));
    let vault_role = format!("{dbname}_vault");
    let keys_role = format!("{dbname}_keys");
    let logins = server
        .create_login_roles(&[vault_role.as_str(), keys_role.as_str()])
        .unwrap();
    server
        .create_database_for(&dbname, &[vault_role.as_str(), keys_role.as_str()])
        .unwrap();
    server
        .psql(
            "postgres",
            &format!("GRANT CREATE ON DATABASE {dbname} TO {vault_role}"),
        )
        .unwrap();
    let mut client = block_on(Client::connect(
        rt(),
        &login_config(server, &dbname, &logins[0]),
    ))
    .unwrap();
    block_on(fstp_vault::store::migrate(&mut client)).unwrap();
    block_on(client.execute(
        "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ($1, $2, $3)",
        &[&cell.to_vec(), &vec![0x5a_u8; 16], &2i16],
    ))
    .unwrap();
    block_on(client.close()).unwrap();
    server
        .psql(
            &dbname,
            &format!(
                "GRANT USAGE ON SCHEMA keystore TO {keys_role}; \
                 GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA keystore TO {keys_role}"
            ),
        )
        .unwrap();
    let dir = std::env::temp_dir().join(format!("fstp-vault-run-{}", hex(&cell[..6])));
    let creds = dir.join("credentials");
    std::fs::create_dir_all(&creds).unwrap();
    let p = logins[0].conn_params(server, &dbname);
    let k = logins[1].conn_params(server, &dbname);
    let files: [(&str, &[u8]); 18] = [
        ("db-ca.pem", p.server_ca_pem),
        ("vault.pem", p.client_cert_pem),
        ("vault.key", p.client_key_pem),
        ("vault.password", p.password.as_bytes()),
        ("keys.pem", k.client_cert_pem),
        ("keys.key", k.client_key_pem),
        ("keys.password", k.password.as_bytes()),
        ("internal.pem", fixtures::SERVER_CERT_PEM),
        ("internal.key", fixtures::SERVER_KEY_PEM),
        ("cell-ca.pem", fixtures::CA_PEM),
        ("tunnel.pem", fixtures::SERVER_CERT_PEM),
        ("tunnel.key", fixtures::SERVER_KEY_PEM),
        ("tunnel-ca.pem", fixtures::CA_PEM),
        ("origin.pem", fixtures::SERVER_CERT_PEM),
        ("origin.key", fixtures::SERVER_KEY_PEM),
        ("witness.pem", fixtures::CLIENT_CERT_PEM),
        ("witness.key", fixtures::CLIENT_KEY_PEM),
        ("witness-ca.pem", fixtures::CA_PEM),
    ];
    for (name, bytes) in files {
        std::fs::write(creds.join(name), bytes).unwrap();
    }
    let registered = format!(
        "[{{\"kind\":\"application\",\"spki_sha256\":\"{}\"}},{{\"kind\":\"vault\",\"spki_sha256\":\"{}\"}}]",
        hex(&held_spki_digest(cluster(ClusterRole::Application))),
        hex(&held_spki_digest(cluster(ClusterRole::Vault))),
    );
    let text = format!(
        "{{\"cell\":\"{cell}\",\"credentials_dir\":\"{creds}\",\"database\":{{\"dbname\":\"{dbname}\",\"host\":\"{host}\",\"port\":{port}}},\"internal_listen\":\"127.0.0.1:0\",\"keyd_socket\":\"/nonexistent/vault.sock\",\"origin_host\":\"id.run.cell.fstp.localhost\",\"origin_listen\":\"127.0.0.1:0\",\"registered_servers\":{registered},\"ticket_keys\":[\"{t}\"],\"witness\":{{\"address\":\"127.0.0.1:1\",\"ca_spki_sha256\":\"{w}\",\"receipt_keys\":[\"{w}\"],\"server_name\":\"witness.fstp.localhost\"}}}}",
        cell = hex(&cell),
        creds = creds.display(),
        host = p.host,
        port = p.port,
        t = hex(&[3; 32]),
        w = hex(&[4; 32]),
    );
    (decode_config(text.as_bytes()).unwrap(), dir)
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// I-83, R-NG-01, ADR-009: the vault start refuses a cell cluster. A
/// configuration whose database lives on the application cluster is
/// refused by the start check over the vault login, before the keystore
/// or custody is touched, even with a vault marker in that database. The
/// same refusal stops `init-keys`, so no root is created.
#[test]
fn i83_vault_run_refuses_an_application_cluster() {
    let (cfg, dir) = vault_on(cluster(ClusterRole::Application));
    let creds = Credentials::read(&cfg.credentials_dir).unwrap();
    let custody = StubCustody::new();
    assert_eq!(
        block_on(run::start_with(rt().clone(), &cfg, &custody)).unwrap_err(),
        I83_REFUSAL
    );
    let keys = VaultKeys::generate().unwrap();
    assert_eq!(
        block_on(run::genesis_with(rt(), &cfg, &creds, &custody, &keys)).unwrap_err(),
        I83_REFUSAL
    );
    assert_eq!(custody.roots(), 0, "I-83: a root was created");
    cleanup(&dir);
}

/// ADR-004 record of lane L8, I-80, I-82: the vault keystore survives a
/// restart. Genesis writes the rows through the keys login, and two later
/// opens, each over a new connection as a new process makes, give the
/// same anchor key, data key id and keys. A second genesis is refused
/// before custody creates another root. A keystore without rows is
/// refused at start.
#[test]
fn adr004_vault_keystore_survives_a_restart() {
    let (cfg, dir) = vault_on(cluster(ClusterRole::Vault));
    let creds = Credentials::read(&cfg.credentials_dir).unwrap();
    let custody = StubCustody::new();
    assert_eq!(
        block_on(run::open_keystore(rt(), &cfg, &creds, &custody)).unwrap_err(),
        VaultError::Unavailable("the vault keystore: run fstp-vault init-keys")
    );
    let keys = VaultKeys::generate().unwrap();
    let anchor = block_on(run::genesis_with(rt(), &cfg, &creds, &custody, &keys)).unwrap();
    assert_eq!(anchor, keys.anchor_public());
    assert_eq!(custody.roots(), 1);
    let first = block_on(run::open_keystore(rt(), &cfg, &creds, &custody)).unwrap();
    let second = block_on(run::open_keystore(rt(), &cfg, &creds, &custody)).unwrap();
    for k in [&first, &second] {
        assert_eq!(k.anchor_public(), keys.anchor_public());
        assert_eq!(k.dek(), keys.dek());
        assert_eq!(
            k.query_digest_key().unwrap().expose(),
            keys.query_digest_key().unwrap().expose()
        );
    }
    // A value sealed before the restart opens after it.
    use fstp_vault::store::Sealer as _;
    let (_, before) = keys.into_service_keys().unwrap();
    let (_, after) = second.into_service_keys().unwrap();
    let v = before.seal(b"aad", b"fact").unwrap();
    assert_eq!(after.open(b"aad", &v.bytes).unwrap(), b"fact");
    // A second genesis is refused before custody runs.
    let again = VaultKeys::generate().unwrap();
    assert_eq!(
        block_on(run::genesis_with(rt(), &cfg, &creds, &custody, &again)).unwrap_err(),
        VaultError::Conflict("a vault keystore genesis")
    );
    assert_eq!(custody.roots(), 1);
    // Another custody root cannot open the rows.
    assert!(block_on(run::open_keystore(rt(), &cfg, &creds, &StubCustody::new())).is_err());
    drop(first);
    cleanup(&dir);
}

/// R-KY-02, ADR-004 record of lane L11 (row "Entry point"): the keystore
/// lock keeps `erase-identity` and a serving vault apart. While one keys
/// connection holds it, as the serving vault does, a second start and the
/// erase command are refused before custody runs. Once it is released,
/// the start takes it again. An idle keystore needs no witness.
#[test]
fn r_ky_02_vault_keystore_lock_refuses_a_second_process() {
    let (cfg, dir) = vault_on(cluster(ClusterRole::Vault));
    let creds = Credentials::read(&cfg.credentials_dir).unwrap();
    let custody = StubCustody::new();
    let keys = VaultKeys::generate().unwrap();
    block_on(run::genesis_with(rt(), &cfg, &creds, &custody, &keys)).unwrap();
    let (lease, opened) = block_on(run::resume_keystore(rt(), &cfg, &creds, &custody)).unwrap();
    assert_eq!(opened.anchor_public(), keys.anchor_public());
    let refused = VaultError::Conflict("the vault keystore lock: another vault process holds it");
    assert_eq!(
        block_on(run::resume_keystore(rt(), &cfg, &creds, &custody)).unwrap_err(),
        refused
    );
    assert_eq!(
        block_on(run::erase_identity_with(rt(), &cfg, &custody, 7)).unwrap_err(),
        refused
    );
    block_on(lease.into_client().close()).unwrap();
    let (again, _) = block_on(run::resume_keystore(rt(), &cfg, &creds, &custody)).unwrap();
    block_on(again.into_client().close()).unwrap();
    cleanup(&dir);
}

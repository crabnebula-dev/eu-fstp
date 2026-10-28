//! World builders of the isolation harness (M3 design sections 1.3, 4.1
//! and 14.1, "Real topology"; lane W1a). A world runs application, vault,
//! control and witness PostgreSQL servers through `fstp-pgtest`, each with
//! its own cluster CA. Role certificates are minted at test time.
//!
//! Logins here run a psql that the test configures itself, and the server
//! certificate is read from the file the server reports in `SHOW
//! ssl_cert_file`. Written test first: the cluster handles refuse until
//! lane W1a lands them. Minted certificates also need `fstp-pki` (lane
//! W1i) and the `fstp-crypto` signing module (lane W1h).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use fstp_celltest::world::{ClusterHandle, ClusterKind, DbMode, VaultLayout, World, WorldSpec};
use fstp_pgtest::{PgServer, RoleLogin};

/// Every cluster kind with the subject OU design section 1.3 gives it.
const KINDS: [(ClusterKind, &str); 4] = [
    (ClusterKind::Application, "application"),
    (ClusterKind::Vault, "vault"),
    (ClusterKind::Control, "control"),
    (ClusterKind::Witness, "witness"),
];

// ---------------------------------------------------------------------------
// psql with a configuration this test controls.

fn private_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("fstp-w1a-world-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

fn write_private(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(data).unwrap();
    path
}

/// Runs `SELECT current_user` in `dbname` with TLS verify-full against
/// `root_ca_pem`, the given password and client certificate.
fn login(
    server: &PgServer,
    root_ca_pem: &[u8],
    user: &str,
    password: &str,
    cert: (&[u8], &[u8]),
    dbname: &str,
) -> Result<String, String> {
    let home = private_dir();
    let root = write_private(&home, "root.pem", root_ca_pem);
    let out = Command::new(server.bindir().join("psql"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", &home)
        .env("PGPASSWORD", password)
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", &root)
        .env("PGSSLCERT", write_private(&home, "client.pem", cert.0))
        .env("PGSSLKEY", write_private(&home, "client-key.pem", cert.1))
        .env("PGCONNECT_TIMEOUT", "10")
        .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
        .args([
            "-h",
            server.host(),
            "-p",
            &server.port().to_string(),
            "-U",
            user,
        ])
        .args(["-d", dbname, "-c", "SELECT current_user"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    std::fs::remove_dir_all(&home).unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn ca_pem(cluster: &ClusterHandle) -> Vec<u8> {
    cluster
        .server()
        .cluster_ca()
        .expect("a world cluster has its own cluster CA")
        .cert_pem()
        .to_vec()
}

fn login_as(cluster: &ClusterHandle, who: &RoleLogin, dbname: &str) -> Result<String, String> {
    login(
        cluster.server(),
        &ca_pem(cluster),
        &who.role,
        &who.password,
        (&who.cert_pem, &who.key_pem),
        dbname,
    )
}

/// The contents of the file a server setting names.
fn setting_file(server: &PgServer, setting: &str) -> Vec<u8> {
    let path = server.psql("postgres", &format!("SHOW {setting}")).unwrap();
    std::fs::read(path).unwrap()
}

// ---------------------------------------------------------------------------
// PEM and DER, just enough to read a certificate's subject OU.

fn base64_decode(text: &[u8]) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {c:?}"),
        }
    };
    let chars: Vec<u8> = text
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut out = Vec::new();
    for group in chars.chunks(4) {
        let mut n = 0u32;
        for (i, c) in group.iter().enumerate() {
            n |= value(*c) << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..group.len() - 1]);
    }
    out
}

/// The DER of the first PEM block in `pem`.
fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(pem.to_vec()).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN "))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END "))
        .collect();
    base64_decode(body.as_bytes())
}

/// One DER element: tag, contents, and the rest after it.
fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = der[0];
    let (len, head) = if der[1] < 0x80 {
        (usize::from(der[1]), 2)
    } else {
        let n = usize::from(der[1] & 0x7f);
        let mut len = 0usize;
        for b in &der[2..2 + n] {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    (tag, &der[head..head + len], &der[head + len..])
}

/// Every OU value of the certificate's subject name.
fn subject_ous(cert_der: &[u8]) -> Vec<String> {
    let (_, cert, _) = tlv(cert_der);
    let (_, tbs, _) = tlv(cert);
    let mut rest = tbs;
    // [0] version, if present.
    if rest[0] == 0xa0 {
        rest = tlv(rest).2;
    }
    // serialNumber, signature, issuer, validity.
    for _ in 0..4 {
        rest = tlv(rest).2;
    }
    let (_, subject, _) = tlv(rest);
    let mut out = Vec::new();
    let mut rdns = subject;
    while !rdns.is_empty() {
        let (_, set, next) = tlv(rdns);
        rdns = next;
        let mut atvs = set;
        while !atvs.is_empty() {
            let (_, atv, next) = tlv(atvs);
            atvs = next;
            let (_, oid, value) = tlv(atv);
            if oid == [0x55, 0x04, 0x0b] {
                let (_, s, _) = tlv(value);
                out.push(String::from_utf8(s.to_vec()).unwrap());
            }
        }
    }
    out
}

/// A unique name for a test object on a shared cluster.
fn unique(tag: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!("w1a_{tag}_{}", N.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// One cluster of each kind starts.

fn starts(kind: ClusterKind) {
    let cluster = ClusterHandle::start(kind).unwrap();
    assert_eq!(cluster.kind(), kind);
    assert_eq!(cluster.server().psql("postgres", "SELECT 1").unwrap(), "1");
}

/// Design sections 4.1 and 14.1: an application cluster starts.
#[test]
fn w1a_world_application_cluster_starts() {
    starts(ClusterKind::Application);
}

/// Design sections 4.1 and 14.1: a vault cluster starts.
#[test]
fn w1a_world_vault_cluster_starts() {
    starts(ClusterKind::Vault);
}

/// Design sections 4.1 and 14.1: a control cluster starts.
#[test]
fn w1a_world_control_cluster_starts() {
    starts(ClusterKind::Control);
}

/// Design sections 4.1 and 14.1: a witness cluster starts.
#[test]
fn w1a_world_witness_cluster_starts() {
    starts(ClusterKind::Witness);
}

/// B1, design section 1.3: each cluster has its own cluster CA, and its
/// `ssl_ca_file` holds that CA only.
#[test]
fn w1a_b1_each_cluster_has_its_own_cluster_ca() {
    let clusters: Vec<ClusterHandle> = KINDS
        .iter()
        .map(|(k, _)| ClusterHandle::start(*k).unwrap())
        .collect();
    let cas: Vec<Vec<u8>> = clusters.iter().map(ca_pem).collect();
    for i in 0..cas.len() {
        for j in i + 1..cas.len() {
            assert_ne!(cas[i], cas[j], "clusters {i} and {j} share a CA");
        }
        assert_eq!(setting_file(clusters[i].server(), "ssl_ca_file"), cas[i]);
    }
}

/// Design section 1.3, I-83 kind marker: each cluster's server certificate
/// names its kind as the only subject OU.
#[test]
fn w1a_i83_server_certificate_names_the_cluster_kind_in_its_subject_ou() {
    for (kind, label) in KINDS {
        let cluster = ClusterHandle::start(kind).unwrap();
        let der = pem_to_der(&setting_file(cluster.server(), "ssl_cert_file"));
        assert_eq!(subject_ous(&der), vec![label.to_owned()], "{kind:?}");
    }
}

/// R-NF-09, ADR-005 D2, design section 1.3: on every cluster kind a role
/// logs in with a certificate minted at runtime by the cluster CA.
#[test]
fn w1a_r_nf_09_d2_every_cluster_admits_a_minted_role_certificate() {
    for (kind, _) in KINDS {
        let cluster = ClusterHandle::start(kind).unwrap();
        let role = unique("minted");
        let who = cluster.server().create_login_role(&role).unwrap();
        let db = unique("minted_db");
        cluster.server().create_database_for(&db, &[&role]).unwrap();
        assert_eq!(login_as(&cluster, &who, &db).unwrap(), role, "{kind:?}");
    }
}

/// B1, B7, R-NF-09: a certificate for the right role name from another
/// cluster's CA is refused. The vault cluster refuses one from the
/// application cluster's CA.
#[test]
fn w1a_b1_cluster_refuses_a_role_certificate_from_another_cluster_ca() {
    let app = ClusterHandle::start(ClusterKind::Application).unwrap();
    let vault = ClusterHandle::start(ClusterKind::Vault).unwrap();
    let role = unique("cross_ca");
    let who = vault.server().create_login_role(&role).unwrap();
    let db = unique("cross_ca_db");
    vault.server().create_database_for(&db, &[&role]).unwrap();
    // Control: the vault CA's certificate logs the role in.
    assert_eq!(login_as(&vault, &who, &db).unwrap(), role);
    let foreign = app
        .server()
        .cluster_ca()
        .expect("a world cluster has its own cluster CA")
        .issue_role(&role)
        .unwrap();
    let err = login(
        vault.server(),
        &ca_pem(&vault),
        &role,
        &who.password,
        (&foreign.cert_pem, &foreign.key_pem),
        &db,
    )
    .unwrap_err();
    assert!(
        !err.contains("password authentication failed"),
        "the foreign certificate passed the TLS handshake: {err}"
    );
}

/// B1, R-NF-09: a client that trusts another cluster's CA refuses the
/// server, so a cell cannot be pointed at the wrong cluster.
#[test]
fn w1a_b1_client_refuses_a_server_of_another_cluster_ca() {
    let app = ClusterHandle::start(ClusterKind::Application).unwrap();
    let vault = ClusterHandle::start(ClusterKind::Vault).unwrap();
    let role = unique("wrong_server");
    let who = vault.server().create_login_role(&role).unwrap();
    let db = unique("wrong_server_db");
    vault.server().create_database_for(&db, &[&role]).unwrap();
    // Control: with the vault CA as trust anchor the login works.
    assert_eq!(login_as(&vault, &who, &db).unwrap(), role);
    let err = login(
        vault.server(),
        &ca_pem(&app),
        &role,
        &who.password,
        (&who.cert_pem, &who.key_pem),
        &db,
    )
    .unwrap_err();
    assert!(err.contains("certificate verify failed"), "{err}");
}

// ---------------------------------------------------------------------------
// World shape.

fn spec(cells: u8, mode: DbMode) -> WorldSpec {
    WorldSpec {
        cells,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    }
}

/// Design sections 1.4 and 14.1: a SaaS world without cells runs one
/// cluster of each kind.
#[test]
fn w1a_world_without_cells_runs_one_cluster_of_each_kind() {
    let world = World::start(spec(0, DbMode::Shared)).unwrap();
    for (kind, _) in KINDS {
        let n = world.clusters().iter().filter(|c| c.kind() == kind).count();
        assert_eq!(n, 1, "{kind:?}");
    }
    assert_eq!(world.clusters().len(), KINDS.len());
}

/// B8, I-83, design section 1.4: the clusters of a world are separate
/// servers, so no vault database can share a server with an application
/// database.
#[test]
fn w1a_b8_i83_world_clusters_are_separate_servers() {
    let world = World::start(spec(0, DbMode::Shared)).unwrap();
    let ports: Vec<u16> = world.clusters().iter().map(|c| c.server().port()).collect();
    for i in 0..ports.len() {
        for j in i + 1..ports.len() {
            assert_ne!(ports[i], ports[j], "{ports:?}");
        }
    }
}

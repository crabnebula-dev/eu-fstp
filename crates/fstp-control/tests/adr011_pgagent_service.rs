//! ADR-011, I-82, I-83, R-NF-09: the `fstp-pgagent` service against a real
//! PostgreSQL 16 server, over its mutual TLS listener.
//!
//! `fstp-control`'s side of the link sends typed jobs through
//! `fstp_control::agent::send_job`, with a client certificate from a test
//! control-plane CA. The agent runs each job as `fstp_super` through
//! `fstp_pgwire::Client::execute_rendered_ddl`. The tests then read the
//! server's own catalogue and check it against `cell_role_plan`:
//!
//! - the jobs of design section 9.2 steps 4 and 7 grant exactly the
//!   plan's rows, run again without error, and `WriteHba` loads one line
//!   per planned role into `pg_hba_file_rules`;
//! - a job for the other cluster kind, a destructive job and a peer that
//!   is not `fstp-control` are refused before any SQL runs;
//! - an agent whose server presents another kind's OU refuses to work on
//!   it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::OnceLock;

use fstp_control::agent::{AgentParts, JobOutcome, JobRefusal, PgLogin, send_job, serve};
use fstp_control::approval::PinnedApprovers;
use fstp_control::pg::{CellDatabase, CellSubnet, cell_role_plan, database_name, role_name};
use fstp_control::pgagent::{DbIdent, PgagentJob};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement};
use fstp_control::provision::{database_jobs, grant_jobs};
use fstp_cp_proto::{CellId, RoleName};
use fstp_pgtest::certs::ClusterCa;
use fstp_pgtest::{PgServer, Role};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Listener, Runtime, Shutdown};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

/// The test control-plane CA, and the certificates it issues.
struct Pki {
    ca: ClusterCa,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| Pki {
        ca: ClusterCa::generate("fstp test control plane CA").unwrap(),
    })
}

/// The application server of these tests, with `application` as its OU.
fn server() -> &'static PgServer {
    PgServer::shared_named("agentapp", "application").unwrap_or_else(|e| panic!("{e}"))
}

/// The server's `pg_hba.conf` path, as it reports it.
fn hba_file(server: &PgServer) -> String {
    server.psql("postgres", "SHOW hba_file").unwrap()
}

/// Starts an agent of `kind` for `server` on a free loopback port, and
/// returns its address. The agent runs for the rest of the test binary.
fn start_agent(server: &'static PgServer, kind: ClusterKind) -> SocketAddr {
    start_agent_with(server, kind, None)
}

/// As `start_agent`, with the pinned approvers `approvals`.
fn start_agent_with(
    server: &'static PgServer,
    kind: ClusterKind,
    approvals: Option<PinnedApprovers>,
) -> SocketAddr {
    let login = server.fresh_database_as(Role::Superuser).unwrap();
    // The harness issues server certificates with a cluster kind OU only.
    let issued = pki().ca.issue_server("control").unwrap();
    let parts = AgentParts {
        cluster_kind: kind,
        cell_subnet: CellSubnet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).unwrap(),
        hba_file: hba_file(server),
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        control_ca_pem: pki().ca.cert_pem().to_vec(),
        cert_pem: issued.cert_pem,
        key_pem: issued.key_pem,
        pg: PgLogin {
            port: login.port,
            server_ca_pem: login.server_ca_pem.to_vec(),
            client_cert_pem: login.client_cert_pem.to_vec(),
            client_key_pem: login.client_key_pem.to_vec(),
            password: login.password.clone(),
        },
        approvals,
    };
    let listener = rt().block_on(rt().bind_tcp(parts.listen)).unwrap();
    let addr = listener.local_addr().unwrap();
    // The shutdown lives as long as the test binary, so the agent serves
    // until the process ends.
    let shutdown: &'static Shutdown = Box::leak(Box::new(Shutdown::new()));
    let signal = shutdown.signal();
    drop(rt().spawn(async move {
        serve(rt().clone(), &parts, listener, signal).await.unwrap();
    }));
    addr
}

/// Serialises the tests that create or drop databases on the shared
/// server: `CREATE DATABASE` copies `template1`, which `HardenCluster`
/// connects to, and two concurrent hardenings update the same rows.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn app_agent() -> SocketAddr {
    static ADDR: OnceLock<SocketAddr> = OnceLock::new();
    *ADDR.get_or_init(|| start_agent(server(), ClusterKind::Application))
}

/// The client TLS of `fstp-control` towards the agent: it trusts the
/// control-plane CA, which issued the agent's certificate, and presents a
/// certificate whose CN is `cn`, issued by `ca`.
fn control_tls(ca: &ClusterCa, cn: &str) -> fstp_tls::ClientConfig {
    let me = ca.issue_role(cn).unwrap();
    fstp_tls::ClientConfig::mutual(pki().ca.cert_pem(), &me.cert_pem, &me.key_pem).unwrap()
}

fn send(addr: SocketAddr, tls: &fstp_tls::ClientConfig, job: &PgagentJob) -> JobOutcome {
    rt().block_on(send_job(rt(), addr, "localhost", tls, job))
        .unwrap_or_else(|e| panic!("{job:?}: {e}"))
}

fn placement() -> Placement {
    Placement::new(
        &Cluster {
            id: ClusterId([1; 16]),
            kind: ClusterKind::Application,
        },
        &Cluster {
            id: ClusterId([2; 16]),
            kind: ClusterKind::Vault,
        },
    )
    .unwrap()
}

/// The `.sql` files of the application migration set, in order.
fn app_migrations() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fstp-pgstore/migrations/app");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no migrations in {}", dir.display());
    files
}

fn lines(server: &PgServer, db: &str, sql: &str) -> BTreeSet<String> {
    server
        .psql(db, sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Provisions the application database of `cell` through the agent: the
/// jobs of step 4, the migrations as the migrator (psql stands in for the
/// cell's migrator, only when `migrate` is set), the grants of step 7,
/// then `WriteHba`.
fn provision_app_through_agent(cell: CellId, migrate: bool) {
    let addr = app_agent();
    let tls = control_tls(&pki().ca, "fstp_control");
    let p = placement();
    let (app, _) = p.clusters();
    for (cluster, job) in database_jobs(cell, &p) {
        if cluster == app {
            assert_eq!(send(addr, &tls, &job), JobOutcome::Done, "{job:?}");
        }
    }
    let db = database_name(CellDatabase::App, cell);
    let migrator = role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap();
    for file in app_migrations().into_iter().filter(|_| migrate) {
        let sql = std::fs::read_to_string(&file).unwrap();
        server()
            .psql(&db, &format!("SET ROLE \"{migrator}\";\n{sql}"))
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    for (cluster, job) in grant_jobs(cell, &p) {
        if cluster == app {
            assert_eq!(send(addr, &tls, &job), JobOutcome::Done, "{job:?}");
        }
    }
    assert_eq!(send(addr, &tls, &PgagentJob::WriteHba), JobOutcome::Done);
}

/// I-82, ADR-011, design sections 4.1 and 9.2: jobs sent over the agent's
/// mutual TLS link leave the cell's table privileges, database privileges
/// and `pg_hba` lines exactly as `cell_role_plan` states them. PUBLIC
/// holds nothing on the database. Every job runs again without error.
#[test]
fn i82_pgagent_applies_the_role_plan_over_mutual_tls() {
    let _serial = serial();
    let cell = CellId([0xa7; 16]);
    provision_app_through_agent(cell, true);
    let server = server();
    let db = database_name(CellDatabase::App, cell);
    let plan = cell_role_plan(cell).unwrap();
    let hex = fstp_control::pg::cell_hex(cell);
    let migrator = role_name(CellDatabase::App, cell, RoleName::Migrator).unwrap();

    let want: BTreeSet<String> = plan
        .grants
        .iter()
        .filter(|g| g.database == CellDatabase::App)
        .flat_map(|g| {
            let role = role_name(CellDatabase::App, cell, g.role).unwrap();
            g.privileges
                .iter()
                .map(move |p| format!("{role}|{}|{}", g.object, p.keyword()))
        })
        .collect();
    let got = lines(
        server,
        &db,
        &format!(
            "SELECT r.rolname || '|' || n.nspname || '.' || c.relname || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee \
             WHERE r.rolname LIKE 'c\\_{hex}\\_%' AND r.rolname <> '{migrator}'"
        ),
    );
    assert_eq!(got, want, "table privileges differ from the plan");

    let want_db: BTreeSet<String> = plan
        .database_privileges
        .iter()
        .filter(|p| p.database == CellDatabase::App)
        .map(|p| {
            format!(
                "{}|{}",
                role_name(CellDatabase::App, cell, p.role).unwrap(),
                p.privilege.keyword()
            )
        })
        .collect();
    let got_db = lines(
        server,
        "postgres",
        &format!(
            "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END || '|' || a.privilege_type \
             FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE d.datname = '{db}' AND a.grantee <> d.datdba"
        ),
    );
    assert_eq!(got_db, want_db, "database privileges differ from the plan");

    let want_hba: BTreeSet<String> = plan
        .hba
        .iter()
        .filter(|h| h.database == CellDatabase::App)
        .map(|h| {
            format!(
                "{db}|{}|127.0.0.1|255.255.255.255|scram-sha-256|clientcert=verify-full",
                role_name(CellDatabase::App, cell, h.role).unwrap()
            )
        })
        .collect();
    let got_hba = lines(
        server,
        "postgres",
        &format!(
            "SELECT array_to_string(database, ',') || '|' || array_to_string(user_name, ',') \
             || '|' || address || '|' || netmask || '|' || auth_method || '|' \
             || array_to_string(options, ',') FROM pg_hba_file_rules \
             WHERE type = 'hostssl' AND '{db}' = ANY(database) AND error IS NULL"
        ),
    );
    assert_eq!(got_hba, want_hba, "pg_hba lines differ from the plan");
    let errors = server
        .psql(
            "postgres",
            "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
        )
        .unwrap();
    assert_eq!(errors, "0");

    // ADR-011: every job is idempotent.
    let before = got;
    provision_app_through_agent(cell, false);
    let again = lines(
        server,
        &db,
        &format!(
            "SELECT r.rolname || '|' || n.nspname || '.' || c.relname || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee \
             WHERE r.rolname LIKE 'c\\_{hex}\\_%' AND r.rolname <> '{migrator}'"
        ),
    );
    assert_eq!(again, before);
}

/// I-83, ADR-011: an agent on an application cluster refuses a vault
/// database job before any SQL runs, so the vault database never exists
/// there.
#[test]
fn i83_pgagent_refuses_a_vault_job_on_an_application_cluster() {
    let cell = CellId([0xb3; 16]);
    let tls = control_tls(&pki().ca, "fstp_control");
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::Vault, cell));
    assert_eq!(
        send(app_agent(), &tls, &job),
        JobOutcome::Refused(JobRefusal::ClusterKind)
    );
    let db = database_name(CellDatabase::Vault, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}

/// ADR-011 "Two-operator approval": destructive jobs are refused until the
/// two-operator check exists, and the audit job is refused as not built,
/// since its rows have no transport yet.
#[test]
fn adr011_pgagent_refuses_destructive_jobs() {
    let cell = CellId([0xc4; 16]);
    let tls = control_tls(&pki().ca, "fstp_control");
    let d = DbIdent::new(CellDatabase::App, cell);
    for job in [
        PgagentJob::DropCellDatabase(d),
        PgagentJob::DropRoles(d),
        PgagentJob::SetNoLogin(fstp_control::pgagent::RoleIdent::new(d, RoleName::App).unwrap()),
    ] {
        assert_eq!(
            send(app_agent(), &tls, &job),
            JobOutcome::Refused(JobRefusal::ApprovalRequired),
            "{job:?}"
        );
    }
    assert_eq!(
        send(app_agent(), &tls, &PgagentJob::PrivilegeAudit),
        JobOutcome::Refused(JobRefusal::NotBuilt)
    );
}

/// R-NF-09, ADR-011: the agent answers only `fstp-control`. A cell's
/// certificate from the same CA gets no reply, a certificate from another
/// CA fails the handshake, and a client without a certificate fails it
/// too. None of them runs a job.
#[test]
fn r_nf_09_pgagent_accepts_only_fstp_control_from_the_control_ca() {
    let addr = app_agent();
    let cell = CellId([0xd5; 16]);
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::App, cell));
    let as_cell = control_tls(&pki().ca, &format!("cell_{}", "d5".repeat(16)));
    let rogue_ca = ClusterCa::generate("rogue CA").unwrap();
    let rogue = control_tls(&rogue_ca, "fstp_control");
    let anonymous = fstp_tls::ClientConfig::new(pki().ca.cert_pem()).unwrap();
    for tls in [&as_cell, &rogue, &anonymous] {
        let r = rt().block_on(send_job(rt(), addr, "localhost", tls, &job));
        assert!(r.is_err(), "{r:?}");
    }
    let db = database_name(CellDatabase::App, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}

/// I-83, design section 1.3: an agent configured as a vault agent refuses
/// a server whose certificate OU says `application`, so it never creates a
/// vault database on an application cluster even when misconfigured.
#[test]
fn i83_pgagent_refuses_a_server_of_another_kind() {
    let addr = start_agent(server(), ClusterKind::Vault);
    let tls = control_tls(&pki().ca, "fstp_control");
    let cell = CellId([0xe6; 16]);
    let job = PgagentJob::CreateCellDatabase(DbIdent::new(CellDatabase::Vault, cell));
    assert_eq!(send(addr, &tls, &job), JobOutcome::Failed);
    let db = database_name(CellDatabase::Vault, cell);
    let found = server()
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_database WHERE datname = '{db}'"),
        )
        .unwrap();
    assert_eq!(found, "0");
}

/// Destructive jobs with two operators' approvals, which the agent checks
/// again itself (ADR-011 "Two-operator approval", R-SW-02 design section
/// 3.7 step 2). Lane m3/erase-cell-2.
mod approved {
    use super::*;
    use fstp_control::agent::{approved_frame, send_approved_job};
    use fstp_control::approval::{
        ApprovalEvidence, ApprovedJob, DestructiveJob, approval_challenge, job_digest,
    };
    use fstp_control::operator::{OperatorLogin, OperatorSession, Purpose, StaffCredential};
    use fstp_control::pgagent::{ApprovedFrame, encode_approved_job};
    use fstp_cp_proto::StaffRef;
    use fstp_crypto::sig::Ed25519SigningKey;
    use fstp_webauthn::{AssertionResponse, CoseKey};

    const HOST: &str = "control.example.test";

    /// The application cluster of `placement()`.
    const CLUSTER: ClusterId = ClusterId([1; 16]);

    /// A software passkey of one staff member.
    struct Passkey {
        staff: StaffRef,
        id: Vec<u8>,
        key: Ed25519SigningKey,
        count: u32,
    }

    impl Passkey {
        fn new(staff: u8, id: u8) -> Passkey {
            Passkey {
                staff: StaffRef([staff; 16]),
                id: vec![id; 16],
                key: Ed25519SigningKey::generate().unwrap(),
                count: 0,
            }
        }

        fn pinned(&self) -> StaffCredential {
            StaffCredential {
                staff: self.staff,
                credential_id: self.id.clone(),
                key: CoseKey::Ed25519 {
                    x: self.key.public_key(),
                },
            }
        }

        fn assert(&mut self, challenge: &[u8; 32]) -> AssertionResponse {
            self.count += 1;
            let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&self.count.to_be_bytes());
            let b64 = fstp_pgwire::base64::encode(challenge)
                .replace('+', "-")
                .replace('/', "_")
                .replace('=', "");
            let client = format!(
                "{{\"type\":\"webauthn.get\",\"challenge\":\"{b64}\",\"origin\":\"https://{HOST}\"}}"
            )
            .into_bytes();
            let mut message = auth.clone();
            message.extend_from_slice(&fstp_crypto::sha256(&client));
            AssertionResponse {
                credential_id: self.id.clone(),
                client_data_json: client,
                authenticator_data: auth,
                signature: self.key.sign(&message).unwrap().to_vec(),
            }
        }
    }

    fn now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// Two staff members logged in to one operator login.
    struct Operators {
        login: OperatorLogin,
        a: (Passkey, OperatorSession),
        b: (Passkey, OperatorSession),
    }

    impl Operators {
        fn new() -> Operators {
            let mut a = Passkey::new(1, 0xa1);
            let mut b = Passkey::new(2, 0xb2);
            let mut login = OperatorLogin::new(HOST, &[a.pinned(), b.pinned()]).unwrap();
            let mut session = |p: &mut Passkey| {
                let c = login.begin(Purpose::Login, now()).unwrap();
                login.finish_login(c, &p.assert(&c), now()).unwrap().0
            };
            let sa = session(&mut a);
            let sb = session(&mut b);
            Operators {
                login,
                a: (a, sa),
                b: (b, sb),
            }
        }

        fn pinned(&self) -> PinnedApprovers {
            PinnedApprovers {
                cluster: CLUSTER,
                operator_host: HOST.to_owned(),
                staff: vec![self.a.0.pinned(), self.b.0.pinned()],
            }
        }

        /// Both approve `job` on the application cluster, and the first
        /// asks for it.
        fn approved(&mut self, job: PgagentJob) -> ApprovedJob {
            let job = DestructiveJob::pgagent(CLUSTER, job).unwrap();
            for (p, s) in [&mut self.a, &mut self.b] {
                let c = self.login.begin_approval(*s, &job, now()).unwrap();
                let assertion = p.assert(&c);
                self.login
                    .finish_approval(*s, c, &assertion, now())
                    .unwrap();
            }
            self.login
                .authorise_destructive(self.a.1, &job, now())
                .unwrap()
        }
    }

    fn send_approved(addr: SocketAddr, approved: &ApprovedJob) -> JobOutcome {
        let tls = control_tls(&pki().ca, "fstp_control");
        rt().block_on(send_approved_job(rt(), addr, "localhost", &tls, approved))
            .unwrap()
    }

    fn send_frame(addr: SocketAddr, frame: &ApprovedFrame) -> JobOutcome {
        let tls = control_tls(&pki().ca, "fstp_control");
        let bytes = encode_approved_job(frame).unwrap();
        let reply = rt()
            .block_on(fstp_control::exchange::request(
                rt(),
                addr,
                "localhost",
                &tls,
                &bytes,
                fstp_control::agent::OUTCOME_LEN,
            ))
            .unwrap();
        fstp_control::agent::decode_job_outcome(&reply).unwrap()
    }

    /// Creates the application database of `cell` and its roles through
    /// the agent without approvers: design section 9.2 step 4.
    fn create_app(cell: CellId) {
        let tls = control_tls(&pki().ca, "fstp_control");
        let p = placement();
        let (app, _) = p.clusters();
        for (cluster, job) in database_jobs(cell, &p) {
            if cluster == app && job != PgagentJob::HardenCluster {
                assert_eq!(send(app_agent(), &tls, &job), JobOutcome::Done, "{job:?}");
            }
        }
        assert_eq!(
            send(app_agent(), &tls, &PgagentJob::WriteHba),
            JobOutcome::Done
        );
    }

    fn count(sql: &str) -> String {
        server().psql("postgres", sql).unwrap()
    }

    fn databases(cell: CellId) -> String {
        let db = database_name(CellDatabase::App, cell);
        count(&format!(
            "SELECT count(*) FROM pg_database WHERE datname = '{db}'"
        ))
    }

    fn roles(cell: CellId) -> String {
        let hex = fstp_control::pg::cell_hex(cell);
        count(&format!(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'c\\_{hex}\\_%'"
        ))
    }

    fn hba_lines(cell: CellId) -> String {
        let db = database_name(CellDatabase::App, cell);
        count(&format!(
            "SELECT count(*) FROM pg_hba_file_rules WHERE '{db}' = ANY(database)"
        ))
    }

    /// R-SW-02, design section 3.7 step 2, ADR-011: with two operators'
    /// approvals, which the agent verifies itself against its pinned
    /// staff passkeys, the agent drops the cell's database, then its
    /// roles, and `WriteHba` leaves no line of the cell. A role drop
    /// before the database drop fails and drops nothing. A spent frame
    /// sent again is refused. Each drop runs again without error.
    #[test]
    fn r_sw_02_pgagent_drops_a_cell_database_and_roles_on_verified_approvals() {
        let _serial = serial();
        let cell = CellId([0xf1; 16]);
        create_app(cell);
        assert_eq!(databases(cell), "1");
        let planned = cell_role_plan(cell)
            .unwrap()
            .roles
            .iter()
            .filter(|r| r.database == CellDatabase::App)
            .count()
            .to_string();
        assert_eq!(roles(cell), planned);
        assert_ne!(hba_lines(cell), "0");

        let mut ops = Operators::new();
        let agent = start_agent_with(server(), ClusterKind::Application, Some(ops.pinned()));
        let d = DbIdent::new(CellDatabase::App, cell);

        let early = ops.approved(PgagentJob::DropRoles(d));
        assert_eq!(send_approved(agent, &early), JobOutcome::Failed);
        assert_eq!(roles(cell), planned, "a role went before its database");

        let drop = ops.approved(PgagentJob::DropCellDatabase(d));
        assert_eq!(send_approved(agent, &drop), JobOutcome::Done);
        assert_eq!(databases(cell), "0");
        assert_eq!(
            send_approved(agent, &drop),
            JobOutcome::Refused(JobRefusal::ApprovalRequired),
            "a spent approval ran the job again"
        );
        let again = ops.approved(PgagentJob::DropCellDatabase(d));
        assert_eq!(send_approved(agent, &again), JobOutcome::Done);

        let roles_job = ops.approved(PgagentJob::DropRoles(d));
        assert_eq!(send_approved(agent, &roles_job), JobOutcome::Done);
        assert_eq!(roles(cell), "0");
        let again = ops.approved(PgagentJob::DropRoles(d));
        assert_eq!(send_approved(agent, &again), JobOutcome::Done);

        let tls = control_tls(&pki().ca, "fstp_control");
        assert_eq!(send(agent, &tls, &PgagentJob::WriteHba), JobOutcome::Done);
        assert_eq!(hba_lines(cell), "0");
    }

    /// ADR-011 "fstp-pgagent checks both approvals again itself": the
    /// agent refuses, before any SQL runs, an approved drop when it has no
    /// pinned approvers, when one staff member signed both approvals, when
    /// the approvals name another cluster, and when the job is sent as a
    /// plain frame. The database stays.
    #[test]
    fn adr011_pgagent_refuses_a_drop_without_two_verified_approvals() {
        let _serial = serial();
        let cell = CellId([0xf2; 16]);
        create_app(cell);
        let mut ops = Operators::new();
        let agent = start_agent_with(server(), ClusterKind::Application, Some(ops.pinned()));
        let d = DbIdent::new(CellDatabase::App, cell);
        let job = PgagentJob::DropCellDatabase(d);

        let approved = ops.approved(job.clone());
        assert_eq!(
            send_approved(app_agent(), &approved),
            JobOutcome::Refused(JobRefusal::ApprovalRequired),
            "an agent without pinned approvers ran a drop"
        );

        let digest = job_digest(&DestructiveJob::pgagent(CLUSTER, job.clone()).unwrap());
        let mut by_a = |n: u8| {
            let nonce = [n; 32];
            let issued_at = now();
            let c = approval_challenge(digest, issued_at, &nonce);
            ApprovalEvidence {
                issued_at,
                nonce,
                assertion: ops.a.0.assert(&c),
            }
        };
        let one_person = ApprovedFrame {
            job: job.clone(),
            approvals: [by_a(1), by_a(2)],
        };
        assert_eq!(
            send_frame(agent, &one_person),
            JobOutcome::Refused(JobRefusal::ApprovalRequired)
        );

        let other = DestructiveJob::pgagent(ClusterId([9; 16]), job.clone()).unwrap();
        let mut elsewhere = approved_frame(&ops.approved(job.clone())).unwrap();
        let other_digest = job_digest(&other);
        for (e, p) in elsewhere
            .approvals
            .iter_mut()
            .zip([&mut ops.a.0, &mut ops.b.0])
        {
            let c = approval_challenge(other_digest, e.issued_at, &e.nonce);
            e.assertion = p.assert(&c);
        }
        assert_eq!(
            send_frame(agent, &elsewhere),
            JobOutcome::Refused(JobRefusal::ApprovalRequired)
        );

        let tls = control_tls(&pki().ca, "fstp_control");
        assert_eq!(
            send(agent, &tls, &job),
            JobOutcome::Refused(JobRefusal::ApprovalRequired)
        );
        assert_eq!(databases(cell), "1");

        // The pair the control plane made still runs on the pinned agent.
        assert_eq!(send_approved(agent, &approved), JobOutcome::Done);
        assert_eq!(databases(cell), "0");
        let roles_job = ops.approved(PgagentJob::DropRoles(d));
        assert_eq!(send_approved(agent, &roles_job), JobOutcome::Done);
    }
}

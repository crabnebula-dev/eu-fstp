//! I-19: no tenant data crosses a cell boundary except through a tenant
//! export, a user-held profile bundle or a template the tenant published
//! (design section 14.4, T-ISO, B1 to B12, ADR-009).
//!
//! The canary sweep over whole worlds is `t_iso_i19_*` in `t_iso_i19.rs`.
//! `i19_cp_proto_fields_are_declared` lives in `w0_boundary_tables.rs`
//! (lane W0), with the reviewed field-class allowlist and register.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until the control plane and its codec (lane W2h), the edge (lane W2i)
//! and the cell runtime (lane W3a) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::egress::{Direction, Endpoint, Peer, Route};
use fstp_celltest::mc::auth_model::http::AuthClient;
use fstp_celltest::mc::place_model::db::{self, MigrationSet};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::scan::scan;
use fstp_celltest::world::{
    ClusterHandle, ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec,
};
use fstp_cp_proto::{CellToCp, CpToCell, ProtoError, decode_cell_to_cp, decode_cp_to_cell};
use fstp_domain_testkit::r#gen::roster::ADMIN;
use fstp_edge::{
    SniOutcome, TunnelHeader, decode_tunnel_header, encode_tunnel_header, parse_client_hello_sni,
};
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

fn world(cells: u8, process_mode: bool) -> World {
    World::start(WorldSpec {
        cells,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn set(name: &str) -> MigrationSet {
    db::migration_sets()
        .into_iter()
        .find(|s| s.set == name)
        .unwrap()
}

fn cycle(w: &World, i: u8) {
    let script = CycleScript {
        steps: vec![
            "login".to_owned(),
            "create-programme".to_owned(),
            "publish-call".to_owned(),
            "submit-proposal".to_owned(),
        ],
    };
    w.run_cycle(i, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
}

// ---------------------------------------------------------------------------
// Control-plane and witness columns (design section 4.4, ADR-009).

/// I-19, ADR-009 "Metadata register", design section 4.4: the cp and
/// witness migrations create exactly the columns of `fstp_control` and
/// `fstp_witness` catalogues, and each column has a declared class.
#[test]
fn i19_control_plane_columns_are_declared() {
    let mut failures = Vec::new();
    for s in [set("cp"), set("witness")] {
        for t in s.catalogue {
            for c in t.columns.iter().filter(|c| c.class.is_none()) {
                failures.push(format!(
                    "{}.{}.{} has no declared class (open point for Daniel)",
                    t.schema, t.name, c.name
                ));
            }
        }
        let cluster = ClusterHandle::start(s.kind).unwrap();
        match db::migrated(cluster.server(), &s) {
            Err(e) => failures.push(e),
            Ok(name) => {
                let tables = db::table_columns(cluster.server(), &name).unwrap();
                for d in db::catalogue_diff(&tables, &db::catalogue_columns(s.catalogue)) {
                    failures.push(format!("{}: {d}", s.set));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------
// The edge (design section 9.4, ADR-009 "Edge and tunnel").

fn u16_be(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap().to_be_bytes()
}

/// A TLS 1.3 ClientHello record for `host`, with a supported versions
/// extension before the server name extension.
fn client_hello(host: &str, random: &[u8; 32]) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = Vec::new();
    sni.extend([0x00, 0x00]);
    sni.extend(u16_be(name.len() + 5));
    sni.extend(u16_be(name.len() + 3));
    sni.push(0x00);
    sni.extend(u16_be(name.len()));
    sni.extend(name);
    let mut exts = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
    exts.extend(sni);
    let mut body = vec![0x03, 0x03];
    body.extend(random);
    body.push(32);
    body.extend([0x5a; 32]);
    body.extend([0x00, 0x02, 0x13, 0x01]);
    body.extend([0x01, 0x00]);
    body.extend(u16_be(exts.len()));
    body.extend(exts);
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut hs = vec![0x01, len[1], len[2], len[3]];
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend(u16_be(hs.len()));
    rec.extend(hs);
    rec
}

/// A routable host. The last label is never all digits, since the edge
/// refuses such a host as a numeric address (fstp-edge `HostName`).
fn host(g: &mut Gen) -> String {
    let mut labels = g.vec(2..=4, |g| {
        let n = g.usize_in(1..=12);
        (0..n)
            .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz0123456789")))
            .collect::<String>()
    });
    if let Some(last) = labels.last_mut()
        && last.bytes().all(|c| c.is_ascii_digit())
    {
        last.insert(0, 'a');
    }
    labels.join(".")
}

fn sni(buf: &[u8]) -> Result<SniOutcome, String> {
    parse_client_hello_sni(buf).map_err(|e| format!("parse_client_hello_sni: {e:?}"))
}

/// I-19, B5, ADR-009: the edge routes by the SNI of the ClientHello alone.
/// The parser names the host of a whole hello, asks for more bytes on every
/// strict prefix, and gives the same host whatever client bytes follow.
/// A tunnel header round trips. Reading, reported by lane W1f: the edge
/// stub has no splice entry point, so "bytes after the ClientHello
/// unchanged" is checked at the parser and the header (lane W2i).
#[test]
fn i19_edge_forwards_bytes_after_client_hello_unchanged() {
    fstp_prop::check(
        "i19_edge_forwards_bytes_after_client_hello_unchanged",
        |g: &mut Gen| {
            let h = host(g);
            let random: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let hello = client_hello(&h, &random);
            let tail = g.bytes(0..=64);
            let mut stream = hello.clone();
            stream.extend(&tail);
            let cut = g.usize_in(0..=hello.len() - 1);
            for (what, buf) in [("hello", &hello), ("hello and tail", &stream)] {
                match sni(buf)? {
                    SniOutcome::Host(got) => prop_assert_eq!(got.as_str(), h.as_str(), "{what}"),
                    other => return Err(format!("{what}: {other:?}")),
                }
            }
            prop_assert_eq!(sni(&hello[..cut])?, SniOutcome::NeedMore, "prefix of {cut}");
            let SniOutcome::Host(name) = sni(&hello)? else {
                return Err("no host".to_owned());
            };
            let header = TunnelHeader {
                host: name,
                client: g.bytes(16..=16).try_into().unwrap(),
                port: u16::from_be_bytes(g.bytes(2..=2).try_into().unwrap()),
            };
            let bytes = encode_tunnel_header(&header);
            let back = decode_tunnel_header(&bytes).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(&back, &header);
            Ok(())
        },
    );
}

/// I-19, ADR-009: a hello without SNI is no route, and bytes that are not
/// TLS are refused.
#[test]
fn i19_edge_refuses_hellos_without_a_server_name() {
    let mut no_sni = client_hello("a.example", &[7; 32]);
    // The server name extension type sits after the record (5) and
    // handshake (4) headers, the version (2), random (32), session id
    // (33), cipher suites (4), compression (2), extensions length (2) and
    // supported versions extension (7). Rewrite it into an unknown type.
    assert_eq!(no_sni[91..93], [0x00, 0x00]);
    no_sni[92] = 0x99;
    assert_eq!(sni(b"GET / HTTP/1.1\r\n\r\n").unwrap(), SniOutcome::NotTls);
    assert_eq!(sni(&no_sni).unwrap(), SniOutcome::NoSni);
}

// ---------------------------------------------------------------------------
// Certificates, sessions and processes.

fn ca_pem(c: &ClusterHandle) -> Vec<u8> {
    c.server().cluster_ca().unwrap().cert_pem().to_vec()
}

/// I-19, B1, B7, ADR-005: cell B's role certificates do not open cell A's
/// databases. A login as B's role into A's database is refused, and a
/// login as A's role with A's password and B's certificate is refused,
/// while A's own credential logs in.
///
/// Gap, reported by lane W1f: `CellHandle` exposes no vault endpoint, so
/// B's `cell-app` certificate against A's vault waits for lane W3a.
#[test]
fn i19_foreign_cell_certificates_are_refused() {
    let w = world(2, false);
    let mut checked = 0usize;
    for c in w
        .clusters()
        .iter()
        .filter(|c| matches!(c.kind(), ClusterKind::Application | ClusterKind::Vault))
    {
        let roles = db::cell_login_roles(c.server()).unwrap();
        let cells: std::collections::BTreeSet<&str> =
            roles.iter().filter_map(|r| db::cell_of(r)).collect();
        assert_eq!(cells.len(), 2, "{}: {cells:?}", c.name());
        let mut it = cells.iter();
        let (a, b) = (*it.next().unwrap(), *it.next().unwrap());
        let prefix = if c.kind() == ClusterKind::Vault {
            "v"
        } else {
            "c"
        };
        let suffix = if c.kind() == ClusterKind::Vault {
            "vault"
        } else {
            "app"
        };
        let (role_a, role_b) = (
            format!("{prefix}_{a}_{suffix}"),
            format!("{prefix}_{b}_{suffix}"),
        );
        let db_a = format!("{prefix}_{a}");
        let cred_a = db::take_over(c.server(), &role_a).unwrap();
        let cred_b = db::take_over(c.server(), &role_b).unwrap();
        let ca = ca_pem(c);
        assert!(
            db::run_as(c.server(), &ca, &cred_a, true, &db_a, "SELECT 1").is_ok(),
            "{role_a} cannot open {db_a}"
        );
        assert!(
            db::run_as(c.server(), &ca, &cred_b, true, &db_a, "SELECT 1").is_err(),
            "{role_b} opened {db_a}"
        );
        let mixed = db::Credential {
            cert_pem: cred_b.cert_pem.clone(),
            key_pem: cred_b.key_pem.clone(),
            ..cred_a.clone()
        };
        assert!(
            db::run_as(c.server(), &ca, &mixed, true, &db_a, "SELECT 1").is_err(),
            "{role_a} logged in with {role_b}'s certificate"
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
}

/// I-19, B11: a session cookie of cell A is refused by cell B, while cell
/// A admits it.
#[test]
fn i19_session_of_one_cell_is_refused_by_another() {
    let w = world(2, false);
    let (a, b) = (w.cell(0).unwrap(), w.cell(1).unwrap());
    let (ca, cb) = (AuthClient::new(a), AuthClient::new(b));
    assert!(ca.enrol(ADMIN).unwrap(), "cell A did not enrol the admin");
    assert!(cb.enrol(ADMIN).unwrap(), "cell B did not enrol the admin");
    let cookie = ca
        .login(ADMIN, RefMethod::Passkey)
        .unwrap()
        .expect("cell A refused the login");
    assert!(
        ca.admitted(&cookie).unwrap(),
        "cell A refused its own session"
    );
    assert!(
        !cb.admitted(&cookie).unwrap(),
        "cell B admitted cell A's session"
    );
}

/// I-19, B2, B7, design section 4.7: a cell process serves one cell. Its
/// configuration names one cell id, and in a two-cell world in process
/// mode no connection of any component of one cell reaches another cell.
#[test]
fn i19_cell_process_serves_one_cell() {
    let source =
        std::fs::read_to_string(db::workspace_root().join("crates/fstp-cell/src/config.rs"))
            .unwrap();
    let body = source
        .split("pub struct CellConfig {")
        .nth(1)
        .and_then(|s| s.split("\n}").next())
        .unwrap();
    let cell_fields = body.matches("CellId").count();
    assert_eq!(cell_fields, 1, "CellConfig names {cell_fields} cell ids");
    assert!(
        !body.contains("Vec<CellId>"),
        "CellConfig holds a list of cells"
    );
    let w = world(2, true);
    cycle(&w, 0);
    cycle(&w, 1);
    let captures = w.egress().captures();
    assert!(!captures.is_empty(), "no connection was recorded");
    let crossing: Vec<_> = captures
        .iter()
        .filter(|c| c.route.crosses_cells())
        .map(|c| c.route)
        .collect();
    assert!(crossing.is_empty(), "{crossing:?}");
}

// ---------------------------------------------------------------------------
// The metadata register (ADR-009, Q36 A).

/// The register class of a message from a cell: a register entry, or the
/// proposed `Infrastructure` class (ADR-009, interim, pending Daniel). The
/// match is exhaustive, so a new variant fails to compile until it is
/// classed.
fn class_of(m: &CellToCp) -> &'static str {
    match m {
        CellToCp::Heartbeat { .. } => "Heartbeat product version, Heartbeat health",
        CellToCp::Metering { .. } => "Metering counters",
        CellToCp::RoleCredential { .. } | CellToCp::CertRenewal { .. } => "Infrastructure",
    }
}

/// The class of a message to a cell: every variant is infrastructure.
fn class_of_reply(m: &CpToCell) -> &'static str {
    match m {
        CpToCell::Ack
        | CpToCell::Certificate(_)
        | CpToCell::OperatorTicket { .. }
        | CpToCell::BreakGlassRequest { .. }
        | CpToCell::EraseScheduled { .. } => "Infrastructure",
    }
}

/// I-19, ADR-009, Q36 A: after a cycle in each of two cells, every
/// capture between a cell and the control plane decodes as a `CellToCp`
/// or `CpToCell` message of a register entry or the infrastructure class.
/// At least one heartbeat crossed, so the check is not vacuous.
///
/// Reading, reported by lane W1f: the wire framing of `CellToCp` is not
/// designed yet, so each recorded write is read as one message.
#[test]
fn i19_only_registered_metadata_crosses() {
    let w = world(2, false);
    cycle(&w, 0);
    cycle(&w, 1);
    let mut heartbeats = 0usize;
    let mut failures = Vec::new();
    for c in w.egress().captures() {
        if c.route.to != Peer::ControlPlane {
            continue;
        }
        let class = match c.direction {
            Direction::Outbound => decode_cell_to_cp(&c.bytes).map(|m| {
                if matches!(m, CellToCp::Heartbeat { .. }) {
                    heartbeats += 1;
                }
                class_of(&m)
            }),
            Direction::Inbound => decode_cp_to_cell(&c.bytes).map(|m| class_of_reply(&m)),
        };
        if let Err(e) = class {
            failures.push(format!("{:?} {:?}: {e:?}", c.route, c.direction));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(heartbeats > 0, "no heartbeat crossed");
}

// ---------------------------------------------------------------------------
// Teeth.

/// I-19 teeth, design section 14.4: a test-only mutant client that sends a
/// heartbeat with a canary appended is caught twice. The egress scan finds
/// the canary in the capture to the control plane, and the closed
/// `CellToCp` decoder refuses the frame.
#[test]
fn i19_teeth_canary_in_heartbeat_is_caught() {
    let canary = Canary::generate(0, CanaryKind::Name).unwrap();
    let mut frame = b"heartbeat:".to_vec();
    frame.extend(canary.text().as_bytes());
    let log = fstp_celltest::egress::EgressLog::new();
    log.record(
        Route::new(Endpoint::cell(0), Peer::ControlPlane, None),
        Direction::Outbound,
        1,
        &frame,
    );
    let report = scan(&log.store_set(), std::slice::from_ref(&canary)).unwrap();
    assert!(
        report
            .hits
            .iter()
            .any(|(s, _)| s.starts_with("egress/cell-0/control-plane/")),
        "the canary in the heartbeat was missed: {:?}",
        report.hits
    );
    #[allow(unreachable_patterns, reason = "lane W2h adds decode errors")]
    match decode_cell_to_cp(&frame) {
        Ok(m) => panic!("the mutant frame decoded as {m:?}"),
        Err(ProtoError::NotImplemented(op)) => panic!("{op} is NotImplemented"),
        Err(_) => {}
    }
}

/// I-19 teeth: a canary of cell 1 seeded into a control-plane database is
/// found by a scan of the world's stores, under the control cluster.
#[test]
fn i19_teeth_seeded_leak_in_control_plane_is_caught() {
    let w = world(0, false);
    let control = w.cluster(ClusterKind::Control).unwrap();
    let canary = Canary::generate(1, CanaryKind::Email).unwrap();
    let name = db::fresh_database(control.server(), "w1f_leak").unwrap();
    control
        .server()
        .psql(
            &name,
            &format!(
                "CREATE TABLE leak (v text); INSERT INTO leak VALUES ('{}');",
                canary.email_address()
            ),
        )
        .unwrap();
    let report = scan(&w.stores().unwrap(), std::slice::from_ref(&canary)).unwrap();
    assert!(
        report
            .hits
            .iter()
            .any(|(s, _)| s.starts_with(&format!("{}/", control.name()))),
        "the seeded leak was missed: {:?}",
        report.hits
    );
}

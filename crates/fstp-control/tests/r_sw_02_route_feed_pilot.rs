//! The pilot `fstp-control` that serves only the signed route feed (lane
//! L15 `prod/route-feed`, ADR-009 "Pilot route feed", decided by Daniel on
//! 2026-11-21): its configuration, its feed signing key in `fstp-keyd`,
//! its persisted table, its checks before signing, and its operator
//! socket. The binaries end to end are
//! `crates/fstp-celltest/tests/i19_route_feed_e2e.rs`. Every value is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fstp_control::ControlError;
use fstp_control::config::decode_feed_config;
use fstp_control::route_change::{
    AUDIT_FILE, AuditLog, RouteChanges, change_digest, decode_audit_log,
};
use fstp_control::route_feed::{
    OperatorReply, OperatorRequest, OperatorStatus, bind_operator_socket, create_feed_key,
    decode_feed_key_file, decode_operator_reply, decode_operator_request, encode_feed_key_file,
    encode_operator_message, encode_operator_reply, open_feed_key, operator_request,
    serve_operator,
};
use fstp_control::routes::{EdgeId, RoutePublisher, next_version, sign_table};
use fstp_cp_proto::CellId;
use fstp_custody::KeydCustody;
use fstp_edge::{CellEndpoint, HostName, PinnedRoute, RouteEntry, verify_route_table};
use fstp_keyd::{ClientRole, ClientSocket, PassphraseSource};
use fstp_rt::future::block_on;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let tag = fstp_crypto::random_array::<4>().unwrap();
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("fstp-l15-{name}-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn route(cell: u8, host: &str) -> PinnedRoute {
    let ep = |port| CellEndpoint {
        cell: [cell; 16],
        address: SocketAddr::from(([10, 0, 5, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    };
    PinnedRoute {
        route: RouteEntry {
            host: HostName::parse(host.as_bytes()).unwrap(),
            app: ep(8443),
            vault: ep(9443),
        },
        app_pin: [cell; 32],
        vault_pin: [cell ^ 0x80; 32],
    }
}

const EDGE: &str = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";

const CONFIG: &str = r#"{"credentials_dir":"/etc/fstp/control","edges":["e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"],"feed_listen":"10.0.0.2:7350","keyd_socket":"/run/fstp-keyd/control.sock","operator_socket":"/run/fstp-control/routes.sock","state_dir":"/var/lib/fstp-control"}"#;

/// ADR-009 "Pilot route feed", row "Feed configuration": the route feed
/// configuration decodes its documented form, and refuses an unknown or
/// missing member, no edge, an edge twice, more than 16 edges, an edge id
/// out of grammar, a relative path and an address in a second spelling.
#[test]
fn adr009_l15_feed_config_refuses_bad_input() {
    let c = decode_feed_config(CONFIG.as_bytes()).unwrap();
    assert_eq!(c.edges, vec![EdgeId([0xe1; 16])]);
    assert_eq!(c.feed_listen, SocketAddr::from(([10, 0, 0, 2], 7350)));
    assert_eq!(c.operator_socket, "/run/fstp-control/routes.sock");
    let swap = |from: &str, to: &str| CONFIG.replacen(from, to, 1);
    let many: Vec<String> = (0..17u8)
        .map(|i| format!("\"{}\"", format!("{i:02x}").repeat(16)))
        .collect();
    for bad in [
        swap(
            r#""state_dir""#,
            r#""cell_listen":"10.0.0.2:1","state_dir""#,
        ),
        swap(r#","state_dir":"/var/lib/fstp-control""#, ""),
        swap(&format!("[\"{EDGE}\"]"), "[]"),
        swap(
            &format!("[\"{EDGE}\"]"),
            &format!("[\"{EDGE}\",\"{EDGE}\"]"),
        ),
        swap(&format!("[\"{EDGE}\"]"), &format!("[{}]", many.join(","))),
        swap(EDGE, &EDGE.to_uppercase()),
        swap(EDGE, &EDGE[2..]),
        swap("\"/var/lib/fstp-control\"", "\"var/lib\""),
        swap(
            "\"/run/fstp-control/routes.sock\"",
            "\"/run/../routes.sock\"",
        ),
        swap("10.0.0.2:7350", "010.0.0.2:7350"),
        swap("10.0.0.2:7350", "10.0.0.2:0"),
        "[]".to_owned(),
    ] {
        assert!(decode_feed_config(bad.as_bytes()).is_err(), "{bad}");
    }
}

/// A running `fstp-keyd` with a control socket and a cell socket.
fn keyd(dir: &Path) -> (KeydCustody, KeydCustody) {
    let volume = dir.join("volume");
    std::fs::create_dir_all(&volume).unwrap();
    let control = dir.join("control.sock");
    let cell = dir.join("cell.sock");
    {
        let sockets = vec![
            ClientSocket::owner_only(&control, ClientRole::Control),
            ClientSocket::owner_only(&cell, ClientRole::Cell),
        ];
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve_sockets(&sockets, &volume, PassphraseSource::Credential);
        });
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(control.exists() && cell.exists()) {
        assert!(Instant::now() < deadline, "fstp-keyd bound no sockets");
        std::thread::sleep(Duration::from_millis(10));
    }
    (
        KeydCustody::new(&control).unwrap(),
        KeydCustody::new(&cell).unwrap(),
    )
}

/// R-NF-08, I-80, ADR-009 "Pilot route feed", rows "Feed signing key" and
/// "`fstp-keyd` socket": the feed signing key is sealed under a seal key
/// that `fstp-keyd` wraps under a ControlPlane root, through the
/// `control` socket. It opens there to the same key. The cell socket
/// cannot create or unwrap a ControlPlane root. The key file holds no
/// open key, round-trips, and refuses a changed sealed byte, every cut
/// and a trailing byte.
#[test]
fn r_nf_08_feed_key_is_sealed_under_a_control_plane_root() {
    let dir = scratch("keyd");
    let (control, cell) = keyd(&dir.0);
    let key = fstp_crypto::composite::generate().unwrap();
    let file = block_on(create_feed_key(&control, &key)).unwrap();
    let secret = key.to_bytes().unwrap();
    assert!(
        !file.windows(secret.len()).any(|w| w == &secret[..]),
        "the key file holds the open key"
    );
    let opened = block_on(open_feed_key(&control, &file)).unwrap();
    assert_eq!(
        opened.public_key().to_bytes(),
        key.public_key().to_bytes(),
        "the key did not open to itself"
    );
    assert!(matches!(
        block_on(open_feed_key(&cell, &file)),
        Err(ControlError::Custody(_))
    ));
    assert!(matches!(
        block_on(create_feed_key(&cell, &key)),
        Err(ControlError::Custody(_))
    ));
    let decoded = decode_feed_key_file(&file).unwrap();
    assert_eq!(encode_feed_key_file(&decoded).unwrap(), file);
    let mut changed = file.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(block_on(open_feed_key(&control, &changed)).is_err());
    for cut in 0..file.len() {
        assert!(decode_feed_key_file(&file[..cut]).is_err(), "cut {cut}");
    }
    let mut longer = file.clone();
    longer.push(0);
    assert!(decode_feed_key_file(&longer).is_err());
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// R-SW-02, TH-48, ADR-009 "Pilot route feed", rows "Table state" and
/// "Versions": the pilot publisher writes each new table to its state
/// file before an edge can fetch it, and a restarted publisher resumes
/// that table and its version. Each version rises above the last and
/// above the clock in milliseconds. A state with a changed byte, or one
/// signed by another key, stops the start.
#[test]
fn r_sw_02_publisher_persists_and_resumes_its_table() {
    let dir = scratch("state");
    let path = dir.0.join("route-table.signed");
    let key = fstp_crypto::composite::generate().unwrap();
    let before = now_ms();
    let first = next_version(0).unwrap();
    assert!(first >= before);
    assert_eq!(next_version(u64::MAX - 1).unwrap(), u64::MAX);
    assert!(next_version(u64::MAX).is_err());
    std::fs::write(&path, sign_table(&key, first, &[]).unwrap()).unwrap();
    let edges = [EdgeId([0xe1; 16])];
    let resume = |key: &fstp_crypto::composite::CompositeSigningKey| {
        let bytes = std::fs::read(&path).unwrap();
        let k =
            fstp_crypto::composite::CompositeSigningKey::from_bytes(&key.to_bytes().unwrap()[..])
                .unwrap();
        RoutePublisher::resume(k, &edges, &bytes, path.clone())
    };
    let p = resume(&key).unwrap();
    assert_eq!(p.version(), first);
    let v1 = p.publish(route(1, "a.example")).unwrap();
    let v2 = p.publish(route(2, "b.example")).unwrap();
    let (removed, v3) = p.remove_cell(CellId([1; 16])).unwrap();
    assert_eq!(removed, 2);
    assert!(first < v1 && v1 < v2 && v2 < v3);
    // The state file holds the table the publisher serves.
    assert_eq!(std::fs::read(&path).unwrap(), p.signed_table());
    let pk = key.public_key().to_bytes().to_vec();
    let served = verify_route_table(&[pk], &p.signed_table()).unwrap();
    assert_eq!(served.version, v3);
    assert_eq!(served.routes, vec![route(2, "b.example")]);
    drop(p);
    // A restart resumes version and routes, and goes on above them.
    let again = resume(&key).unwrap();
    assert_eq!(again.version(), v3);
    assert_eq!(again.routes(), vec![route(2, "b.example")]);
    let v4 = again.publish(route(3, "c.example")).unwrap();
    assert!(v4 > v3);
    drop(again);
    // A changed state and a foreign key stop the start.
    let good = std::fs::read(&path).unwrap();
    let mut changed = good.clone();
    let at = changed.windows(9).position(|w| w == b"c.example").unwrap();
    changed[at] = b'd';
    std::fs::write(&path, &changed).unwrap();
    assert_eq!(
        resume(&key).err(),
        Some(ControlError::Config("route table state"))
    );
    std::fs::write(&path, &good).unwrap();
    let stranger = fstp_crypto::composite::generate().unwrap();
    assert_eq!(
        resume(&stranger).err(),
        Some(ControlError::Config("route table state"))
    );
    assert!(resume(&key).is_ok());
}

/// I-19, TH-48, ADR-009 "Pilot route feed", row "Checks before signing":
/// the publisher builds each table through the edge's own checks before
/// it signs. A host held by another cell, a shared tunnel address and a
/// pin of two endpoints are refused, and the version, the signed table
/// and the state file stay as they were. A new pin for a cell's route
/// replaces the old one.
#[test]
fn i19_publisher_never_signs_a_table_the_edge_refuses() {
    let dir = scratch("checks");
    let path = dir.0.join("route-table.signed");
    let key = fstp_crypto::composite::generate().unwrap();
    std::fs::write(
        &path,
        sign_table(&key, next_version(0).unwrap(), &[]).unwrap(),
    )
    .unwrap();
    let p = RoutePublisher::resume(
        key,
        &[EdgeId([1; 16])],
        &std::fs::read(&path).unwrap(),
        path.clone(),
    )
    .unwrap();
    p.publish(route(1, "a.example")).unwrap();
    let (version, signed) = (p.version(), p.signed_table());
    let mut other_host = route(2, "a.example");
    other_host.app_pin = [0x22; 32];
    let mut shared_address = route(2, "b.example");
    shared_address.route.app.address = route(1, "a.example").route.app.address;
    let mut shared_pin = route(2, "b.example");
    shared_pin.app_pin = route(1, "a.example").vault_pin;
    let mut vault_host = route(2, "id.a.example");
    vault_host.app_pin = [0x23; 32];
    for bad in [other_host, shared_address, shared_pin, vault_host] {
        assert!(
            matches!(p.publish(bad.clone()), Err(ControlError::Request(_))),
            "{bad:?}"
        );
        assert_eq!(p.version(), version);
        assert_eq!(p.signed_table(), signed);
        assert_eq!(std::fs::read(&path).unwrap(), signed);
    }
    let mut renewed = route(1, "a.example");
    renewed.app_pin = [0x77; 32];
    p.publish(renewed.clone()).unwrap();
    assert_eq!(p.routes(), vec![renewed]);
}

/// A pilot behind its operator socket: a persisted table and audit log.
struct Socketed {
    dir: Scratch,
    socket: PathBuf,
    changes: Arc<RouteChanges>,
}

fn socketed(name: &str) -> Socketed {
    let dir = scratch(name);
    let socket = dir.0.join("routes.sock");
    let state = dir.0.join("route-table.signed");
    let key = fstp_crypto::composite::generate().unwrap();
    std::fs::write(
        &state,
        sign_table(&key, next_version(0).unwrap(), &[]).unwrap(),
    )
    .unwrap();
    let publisher = RoutePublisher::resume(
        key,
        &[EdgeId([1; 16])],
        &std::fs::read(&state).unwrap(),
        state,
    )
    .unwrap();
    let audit = AuditLog::open(&dir.0.join(AUDIT_FILE)).unwrap();
    let changes = Arc::new(RouteChanges::new(Arc::new(publisher), audit));
    let listener = bind_operator_socket(&socket).unwrap();
    let served = Arc::clone(&changes);
    std::thread::spawn(move || serve_operator(&listener, &served));
    Socketed {
        dir,
        socket,
        changes,
    }
}

/// ADR-009 "Pilot route feed", rows "Route changes on the host" and
/// "Operator bytes" (Daniel, 2026-11-21: plain route changes on the host,
/// logged): the operator socket is bound with mode 0600. An add and a
/// removal apply at once, each answered with the version that serves it.
/// A route the edge would refuse is answered as refused, bytes that are
/// no request change nothing, and a list answers the served table.
/// Request and reply have one spelling.
#[test]
fn adr009_l15_operator_socket_applies_changes_at_once() {
    use std::os::unix::fs::PermissionsExt as _;
    let p = socketed("operator");
    let mode = std::fs::metadata(&p.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let start = p.changes.publisher().version();
    let add = OperatorRequest::Add(Box::new(route(1, "a.example")));
    let (added, _) = operator_request(&p.socket, "alice", &add).unwrap();
    assert_eq!(added.status, OperatorStatus::Stored);
    assert!(added.version > start);
    assert_eq!(p.changes.publisher().routes(), vec![route(1, "a.example")]);
    let mut clash = route(2, "b.example");
    clash.route.vault.address = route(1, "a.example").route.app.address;
    let (refused, _) =
        operator_request(&p.socket, "", &OperatorRequest::Add(Box::new(clash))).unwrap();
    assert_eq!(refused.status, OperatorStatus::Refused);
    assert_eq!(refused.version, added.version);
    let (listed, table) = operator_request(&p.socket, "", &OperatorRequest::List).unwrap();
    assert_eq!(listed.status, OperatorStatus::Stored);
    assert_eq!(table, p.changes.publisher().signed_table());
    let (removed, _) =
        operator_request(&p.socket, "bob", &OperatorRequest::Remove([1; 16])).unwrap();
    assert_eq!(removed.status, OperatorStatus::Stored);
    assert!(removed.version > added.version);
    assert!(p.changes.publisher().routes().is_empty());
    // Bytes that are no request.
    {
        use std::io::{Read as _, Write as _};
        let mut s = std::os::unix::net::UnixStream::connect(&p.socket).unwrap();
        s.write_all(b"FRO1\x00\x09").unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        let reply = decode_operator_reply(&reply).unwrap();
        assert_eq!(reply.status, OperatorStatus::Refused);
        assert_eq!(reply.version, removed.version);
    }
    // One spelling, with and without a user. A user outside the grammar
    // is refused.
    for (user, r) in [
        (
            "carol",
            OperatorRequest::Add(Box::new(route(3, "c.example"))),
        ),
        ("", OperatorRequest::Remove([3; 16])),
        ("_svc-1", OperatorRequest::List),
    ] {
        let bytes = encode_operator_message(user, &r).unwrap();
        assert_eq!(
            decode_operator_request(&bytes).unwrap(),
            (user.to_owned(), r)
        );
        for cut in 0..bytes.len() {
            assert!(decode_operator_request(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_operator_request(&longer).is_err());
    }
    for user in ["Root", "a b", "9x", &"a".repeat(33)] {
        assert!(encode_operator_message(user, &OperatorRequest::List).is_err());
    }
    let reply = OperatorReply {
        status: OperatorStatus::Failed,
        version: 7,
    };
    assert_eq!(
        decode_operator_reply(&encode_operator_reply(&reply)),
        Ok(reply)
    );
}

/// ADR-009 "Pilot route feed", row "Audit" (Daniel, 2026-11-21: plain
/// route changes, logged): each applied change appends one record before
/// its table is stored: the time, the operation, the cell, the version,
/// the change digest and the OS user when known. A refused change and a
/// list log nothing. The records form a hash chain: a changed byte or a
/// cut breaks it, and a log with a broken chain does not open, so
/// `fstp-control` refuses to start on it.
#[test]
fn adr009_l15_route_changes_are_logged_in_a_hash_chain() {
    let p = socketed("audit");
    let add = OperatorRequest::Add(Box::new(route(1, "a.example")));
    let (a, _) = operator_request(&p.socket, "alice", &add).unwrap();
    let mut clash = route(2, "b.example");
    clash.route.app.address = route(1, "a.example").route.app.address;
    let (r, _) =
        operator_request(&p.socket, "alice", &OperatorRequest::Add(Box::new(clash))).unwrap();
    assert_eq!(r.status, OperatorStatus::Refused);
    let _ = operator_request(&p.socket, "", &OperatorRequest::List).unwrap();
    let (b, _) = operator_request(&p.socket, "", &OperatorRequest::Remove([1; 16])).unwrap();
    let path = p.dir.0.join(AUDIT_FILE);
    let bytes = std::fs::read(&path).unwrap();
    let (records, _) = decode_audit_log(&bytes).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        (
            records[0].op,
            records[0].cell,
            records[0].version,
            records[0].user.as_str()
        ),
        (1, [1; 16], a.version, "alice")
    );
    assert_eq!(records[0].digest, change_digest(&add).unwrap());
    assert_eq!(
        (
            records[1].op,
            records[1].cell,
            records[1].version,
            records[1].user.as_str()
        ),
        (2, [1; 16], b.version, "")
    );
    let mut changed = bytes.clone();
    changed[12] ^= 1;
    assert!(decode_audit_log(&changed).is_err());
    for cut in [1, 10, bytes.len() - 1] {
        assert!(decode_audit_log(&bytes[..cut]).is_err(), "cut {cut}");
    }
    std::fs::write(&path, &changed).unwrap();
    assert!(AuditLog::open(&path).is_err());
}

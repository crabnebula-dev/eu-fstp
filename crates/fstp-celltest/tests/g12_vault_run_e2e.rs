//! Gap G12 of `docs/handoff/production-mcp-design.md` (lane L8): the
//! production `fstp-vault` binary runs from its configuration file beside
//! the production `fstp-cell` binary, and a vault answer reaches the cell.
//!
//! The world provisions the clusters, the witness, the relays and the edge
//! (`World::start_external`). The cell runs as `fstp-cell` from
//! `cell.json`, and the vault as `fstp-vault` from `vault.json`
//! (`fstp_celltest::external_vault`). Three `fstp-custody-sim --serve`
//! processes stand for the cell's App chain entry, the cell key file entry
//! and the vault's own entry. Every value is synthetic.
//!
//! The binaries must be built first: `cargo build -p fstp-cell --bin
//! fstp-cell -p fstp-vault --bin fstp-vault`. The CI part that runs this
//! test builds them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::smtp_sink::{SINK_SERVER_NAME, SinkConfig, SmtpSink};
use fstp_celltest::external_cell::{ExternalRelay, ExternalSpec};
use fstp_celltest::external_vault::{ExternalVaultSpec, start_world};
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, ClusterKind, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_domain_testkit::r#gen::roster::ADMIN_2;
use fstp_json::Value;
use fstp_vault_core::fact::Fact;
use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProgramme, WriteKind};

/// The CA of the test SMTP sink's certificate, which the cell pins for
/// its platform relay.
const SINK_CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");

/// A call of the web API in the session `cookie`, as `web/src/core/api.ts`
/// sends it. On `step_up_required` the passkey ceremony of the challenge
/// runs with the software authenticator, and the request is sent once
/// more (`withStepUp`, I-78).
fn web(
    client: &AuthClient<'_>,
    method: &str,
    path: &str,
    cookie: &Cookie,
    body: &str,
) -> HttpReply {
    let cell = client.cell();
    let send = || {
        let mut r = HttpRequest::new(method, path)
            .header("host", cell.host())
            .header("cookie", cookie.0.clone())
            .header("accept", "application/json");
        if method != "GET" {
            r = r
                .header("origin", format!("https://{}", cell.host()))
                .header("x-fstp-request", "1")
                .header("content-type", "application/json")
                .body(body.as_bytes().to_vec());
        }
        cell.request(&r).unwrap_or_else(|e| panic!("{e}"))
    };
    let first = send();
    let v = fstp_json::parse(&first.body).unwrap_or(Value::Null);
    if v.get("code").and_then(Value::as_str) != Some("step_up_required") {
        return first;
    }
    let ch = v.get("challenge").unwrap();
    let id = ch.get("challenge_id").and_then(Value::as_str).unwrap();
    let bytes = ch
        .get("public_key")
        .and_then(|p| p.get("challenge"))
        .and_then(Value::as_str)
        .unwrap();
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(
        client.prove_api_step_up(cookie, id, challenge).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    send()
}

/// The link token of the newest admin invitation mail to `to` that the
/// sink holds, read from its text part's `/auth/invite#<token>` link as
/// the invitee reads it.
fn admin_invitation_token(sink: &SmtpSink, to: &str) -> Option<Vec<u8>> {
    let begun = std::time::Instant::now();
    let mine = || {
        sink.messages()
            .into_iter()
            .filter(|m| m.to.iter().any(|t| t == to))
            .collect::<Vec<_>>()
    };
    while mine().is_empty() && begun.elapsed() < std::time::Duration::from_secs(20) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let m = mine().pop()?;
    let parsed = fstp_mail::parse(&m.data).ok()?;
    let text = parsed
        .parts
        .iter()
        .find(|p| p.content_type == "text/plain")
        .map(|p| String::from_utf8_lossy(&p.decoded).into_owned())?;
    let at = text.find("/auth/invite#")? + "/auth/invite#".len();
    let hex = text.get(at..at + 64)?;
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

fn now_us() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

/// A `country_stated` write for `account` under a ticket signed with the
/// cell's `Ticket` key, posted to the vault origin through the edge as the
/// vault origin's page posts it. The status of the vault's reply.
fn origin_write(cell: &CellHandle, account: u128, country: u16) -> u16 {
    let account = WireAccount(account);
    let programme = WireProgramme(1);
    let now = now_us();
    let claims = TicketClaims {
        kind: TicketKind::Write(WriteKind::CountryStated),
        cell: cell.id(),
        account,
        proposal: None,
        scope: fstp_vault_proto::country_scope(programme),
        issued_at: now - 1_000_000,
        expires_at: now + 60_000_000,
        nonce: fstp_crypto::random_array::<16>().unwrap(),
    };
    let ticket = cell.sign_ticket(&claims).unwrap();
    let fact = Fact::CountryStated {
        account,
        programme,
        country,
    };
    let body = fact
        .body_value()
        .and_then(|v| fstp_vault_proto::json::to_canonical(&v))
        .unwrap();
    let frame =
        fstp_vault::codec::encode_origin_write(&fstp_vault::codec::OriginWrite { ticket, body })
            .unwrap();
    let host = cell.vault_host();
    let req = HttpRequest::new("POST", "/w")
        .header("host", host.as_str())
        .header("origin", format!("https://{host}"))
        .header("content-type", "application/json")
        .body(frame);
    cell.vault_origin_request(&req).unwrap().status
}

fn vault_sql(world: &World, cell: &CellHandle, sql: &str) -> String {
    world
        .cluster(ClusterKind::Vault)
        .unwrap()
        .server()
        .psql(&cell.vault_database(), sql)
        .unwrap()
}

/// G12, R-NG-01, I-83, I-24, ADR-004 record of lane L8: both binaries run
/// from their configuration files, and a vault answer reaches the cell.
///
/// 1. The vault binary starts from `vault.json`, opens its keystore through
///    its own custody entry, verifies its chain at the witness and listens.
///    It runs in a process of its own, apart from the cell (R-NG-01).
/// 2. A ticket write through the edge to the vault origin is answered 204.
///    It opens vault epoch 1, sealed under the keystore's data key and
///    anchored at the witness under the keystore's anchor key (I-24).
/// 3. The vault binary drains at SIGTERM and starts again from the same
///    file. Its keystore survives the restart: its chain verifies at
///    start, and a second write is answered 204.
/// 4. The world ran `fstp-cell first-admin` and started the cell binary
///    before step 2. The first admin enrols, invites a second admin
///    through the API core with a step-up, and the second admin enrols
///    from the mailed link, which accepts the invitation. Each is a cell
///    command, so the cell binary asks the vault binary its epoch, asks
///    `ChangedSince`, and acknowledges epoch 2 (NOTE 4). The acknowledgement in `vault.epoch` and the logged
///    query in `vault.query_log` show that the answer reached the cell.
/// 5. The cell binary drains at SIGTERM, and the vault binary after it.
#[test]
fn g12_vault_binary_answers_the_cell_binary() {
    let cell_binary = bin_path("fstp-cell").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-cell --bin fstp-cell` before this test")
    });
    let vault_binary = bin_path("fstp-vault").unwrap_or_else(|e| {
        panic!("{e}: run `cargo build -p fstp-vault --bin fstp-vault` before this test")
    });
    let tag = fstp_crypto::random_array::<6>().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "fstp-l8-{}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let custody = SimProcess::spawn(0, &dir).unwrap_or_else(|e| panic!("{e}"));
    let key_file_custody = SimProcess::spawn(1, &dir).unwrap_or_else(|e| panic!("{e}"));
    let vault_custody = SimProcess::spawn(2, &dir).unwrap_or_else(|e| panic!("{e}"));
    // The platform relay (D3): the test SMTP sink, which carries the
    // second admin's invitation mail. It must outlive the cell.
    let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1).unwrap();
    let sink_cfg = SinkConfig::default();
    let sink = rt.block_on(SmtpSink::start(&rt, sink_cfg.clone())).unwrap();
    let handle = sink.handle().clone();
    let relay = ExternalRelay {
        address: sink.addr(),
        relay: SINK_SERVER_NAME.to_owned(),
        username: sink_cfg.username,
        password: sink_cfg.password,
        ca_pem: SINK_CA.to_vec(),
        messages: std::sync::Arc::new(move || {
            handle
                .messages()
                .into_iter()
                .filter_map(|m| Some((m.to.first()?.clone(), m.data)))
                .collect()
        }),
    };
    let spec = ExternalSpec {
        binary: cell_binary,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
        relay: Some(relay),
        shell: None,
    };
    let (world, vault) = start_world(
        WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        custody.socket().to_path_buf(),
        &spec,
        ExternalVaultSpec {
            binary: vault_binary,
            dir: dir.clone(),
            keyd_socket: vault_custody.socket().to_path_buf(),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let external = cell.external().unwrap();

    // Step 1: the vault is a process of its own (R-NG-01).
    let vault_pid = vault.pid().unwrap();
    assert_ne!(vault_pid, std::process::id());
    assert!(external.pid().is_some(), "the cell binary serves");
    assert_ne!(external.pid(), Some(vault_pid), "R-NG-01: one process");
    assert_eq!(
        vault_sql(&world, cell, "SELECT count(*) FROM keystore.root"),
        "1",
        "the keystore has its one root"
    );

    // Step 2: a ticket write through the edge opens epoch 1.
    assert_eq!(origin_write(cell, 7_001, 250), 204, "the first write");
    assert_eq!(
        vault_sql(&world, cell, "SELECT max(epoch) FROM vault.epoch"),
        "1"
    );
    let rows_before: u64 = vault_sql(
        &world,
        cell,
        "SELECT count(*) FROM vault_audit.chain WHERE kind = 1",
    )
    .parse()
    .unwrap();
    assert!(rows_before >= 1, "I-24: the write left no vault chain row");

    // Step 3: a restart keeps the keystore and the chain.
    vault.stop().unwrap_or_else(|e| panic!("{e}"));
    vault.start().unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(vault.pid(), Some(vault_pid), "the vault did not restart");
    assert_eq!(
        origin_write(cell, 7_002, 276),
        204,
        "the write after restart"
    );
    assert_eq!(
        vault_sql(&world, cell, "SELECT max(epoch) FROM vault.epoch"),
        "2"
    );

    // Step 4: the cell binary asks the vault binary and acknowledges.
    assert_eq!(
        vault_sql(
            &world,
            cell,
            "SELECT count(*) FROM vault.epoch WHERE ack_seq IS NOT NULL"
        ),
        "0"
    );
    // The second admin joins as a production client adds one: the
    // `tenant.invite_admin` operation of the API core with its step-up,
    // the mailed link, and the enrolment that accepts the invitation
    // (SoD-07, J0). The raw command route of a production build serves
    // break-glass approval only (ADR-026 D8 as amended 2026-11-23).
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin1 = client.admin_session().expect("the first admin's session");
    let email = cell.login_email(ADMIN_2);
    let invited = web(
        &client,
        "POST",
        "/api/v1/admin/admins",
        &admin1,
        &format!(r#"{{"email":"{email}"}}"#),
    );
    assert_eq!(
        invited.status,
        200,
        "SoD-07: the admin invitation: {}",
        String::from_utf8_lossy(&invited.body)
    );
    let token = admin_invitation_token(&sink, &email).expect("SoD-07: no admin invitation mail");
    let a2 = client
        .enrol_by_link(ADMIN_2, &token)
        .unwrap()
        .expect("SoD-07: the second admin enrols from the mailed link");
    let admin2 = client
        .login(ADMIN_2, RefMethod::Passkey)
        .unwrap()
        .expect("the second admin's session");
    let admins = web(&client, "GET", "/api/v1/admin/admins", &admin2, "");
    assert_eq!(admins.status, 200);
    assert!(
        String::from_utf8_lossy(&admins.body).contains(&a2.raw().to_string()),
        "the second admin is a tenant admin"
    );
    assert_eq!(
        vault_sql(
            &world,
            cell,
            "SELECT count(*) FROM vault.epoch WHERE epoch = 2 AND ack_seq IS NOT NULL"
        ),
        "1",
        "NOTE 4: the cell binary did not acknowledge the vault's epoch"
    );
    let asked: u64 = vault_sql(&world, cell, "SELECT count(*) FROM vault.query_log")
        .parse()
        .unwrap();
    assert!(asked >= 1, "the cell binary asked the vault binary nothing");

    // Step 5: both drain.
    external.stop().unwrap_or_else(|e| panic!("{e}"));
    vault.stop().unwrap_or_else(|e| panic!("{e}"));
    drop(world);
    drop(vault);
    drop((custody, key_file_custody, vault_custody));
    let _ = std::fs::remove_dir_all(&dir);
}

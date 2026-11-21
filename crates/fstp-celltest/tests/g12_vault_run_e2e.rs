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

use fstp_celltest::external_cell::ExternalSpec;
use fstp_celltest::external_vault::{ExternalVaultSpec, start_world};
use fstp_celltest::mc::auth_model::RosterChange;
use fstp_celltest::mc::auth_model::http::{AuthClient, FIRST_ADMIN};
use fstp_celltest::world::{
    CellHandle, ClusterKind, DbMode, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_domain_testkit::r#gen::roster::ADMIN_2;
use fstp_vault_core::fact::Fact;
use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProgramme, WriteKind};

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
///    before step 2. The first admin and a second admin enrol, and the
///    first grants the second the tenant admin role. Each is a cell
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
    let spec = ExternalSpec {
        binary: cell_binary,
        dir: dir.clone(),
        key_file_custody: key_file_custody.socket().to_path_buf(),
        assets_dir: None,
        relay: None,
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
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    assert!(client.enrol(ADMIN_2).unwrap(), "the second admin enrols");
    let admin1 = client.admin_session().expect("the first admin's session");
    assert!(
        client
            .roster(&admin1, RosterChange::GrantAdmin { account: ADMIN_2 })
            .unwrap(),
        "the tenant admin grant to the second admin"
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

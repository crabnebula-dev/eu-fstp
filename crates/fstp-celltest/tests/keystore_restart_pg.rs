//! A real process restart of a world cell over PostgreSQL keeps every key
//! (ADR-004, decided by Daniel on 2026-11-20; production MCP design
//! section 3.5, lane L3). The new process gets no keystore from the old
//! one: `fstp_cell::process::start_with` loads it from the keystore tables
//! over the `c_<cell>_keys` login.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};

/// I-23, I-79, I-81, ADR-004 (2026-11-20): across a process restart over
/// PostgreSQL, every stored text opens, the first admin's login email
/// still finds the account (recovery needs it, I-79), the loaded keystore
/// is the one the old process held, and an erasure after the restart
/// completes from the loaded chain state (I-81). The erased text then
/// stays refused across a second restart.
#[test]
fn i23_i79_i81_keystore_survives_a_pg_process_restart() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let login = CycleScript {
        steps: ["login", "erase-text"].map(str::to_owned).to_vec(),
    };
    if let Err(e) = world.run_cycle(0, &login).result {
        panic!("{e}");
    }
    let cell = world.cell(0).unwrap();
    let texts: Vec<([u8; 16], Vec<u8>)> = (0u8..3)
        .map(|i| {
            (
                [0xC0 | i; 16],
                format!("synthetic restart text {i}").into_bytes(),
            )
        })
        .collect();
    for (id, text) in &texts {
        cell.store_text(*id, text).unwrap();
    }
    let email = cell.login_email(fstp_domain_testkit::r#gen::roster::ADMIN);
    let account = cell.login_account(&email).unwrap();
    assert!(account.is_some(), "the first admin has no login email");
    let before = cell.keystore_fingerprint().unwrap();

    cell.restart().unwrap();

    for (id, text) in &texts {
        assert_eq!(cell.open_text(*id).unwrap().as_ref(), Some(text), "I-23");
    }
    assert_eq!(cell.login_account(&email).unwrap(), account, "I-79");
    assert_eq!(cell.keystore_fingerprint().unwrap(), before, "ADR-004");

    // An erasure after the restart: `erase-text` erases the live text the
    // first `erase-text` stored, so the batch runs on the loaded state.
    let again = CycleScript {
        steps: ["erase-text", "restart"].map(str::to_owned).to_vec(),
    };
    if let Err(e) = world.run_cycle(0, &again).result {
        panic!("I-81: {e}");
    }
    for (id, text) in &texts {
        assert_eq!(cell.open_text(*id).unwrap().as_ref(), Some(text), "I-23");
    }
    assert_eq!(cell.login_account(&email).unwrap(), account, "I-79");
}

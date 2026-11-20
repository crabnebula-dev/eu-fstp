//! The production cell's `ApiCore` over PostgreSQL (ADR-026, lane L1):
//! the exactly-once confirmation of a pending action (I-85) and the audit
//! event of every API call (I-24, R-AU-01), on a world cell.
//!
//! Lane L1 wrote these before the composition was mounted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;

use fstp_cell::engine::EngineError;
use fstp_cell_core::driver::ExecError;
use fstp_cell_core::gate::{self, Action, LoginPolicy};
use fstp_cell_core::text::{TextCommand, TextOwner};
use fstp_cell_core::{ApiEffects, CellCommand, CellRefusal};
use fstp_celltest::cycle::Cycle;
use fstp_celltest::world::{DbMode, HttpRequest, VaultLayout, World, WorldSpec};
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;

fn spec() -> WorldSpec {
    WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    }
}

/// I-85, ADR-026 "Pending actions": two transactions that confirm one
/// pending action race, and exactly one appends. The other is refused
/// with I-85 and appends nothing: its `api.pending_confirmed` row would
/// violate the primary key, so its whole append aborts.
#[test]
fn i85_concurrent_confirmations_execute_once() {
    let world = World::start(spec()).unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let mut cycle = Cycle::new(cell);
    cycle.step("login").unwrap_or_else(|e| panic!("{e}"));
    let engine = cell.cell_engine().unwrap();
    let state = engine.state();
    let admin = state
        .tenant()
        .admins()
        .into_iter()
        .next()
        .expect("the first admin");
    let now = Timestamp::from_micros(engine.now());
    // A pending action of the admin's agent, as the API core stores it.
    let pending: [u8; 16] = fstp_crypto::random_array().unwrap();
    cell.with_running(async |c| {
        let key = fstp_crypto::aead::Key::from_bytes(&[3; 32]).unwrap();
        let keys = fstp_pgstore::LedgerKeys::new(fstp_pgstore::LedgerKey::new(
            7,
            fstp_keys::DekId([7; 16]),
            key,
        ));
        let store = fstp_pgstore::ApiStore::new(c.app_pool().clone(), Arc::new(keys)).unwrap();
        store
            .insert_pending(&fstp_pgstore::PendingRow {
                id: pending,
                account: admin.raw().to_be_bytes(),
                client: [0xC1; 16],
                op: "programme.prepare_draft".to_owned(),
                request: b"{}".to_vec(),
                digest: [0xD1; 32],
                created: now.micros(),
                expires: now.micros() + 86_400_000_000,
                status: fstp_pgstore::StoredPendingStatus::Open,
                closed: None,
                confirmed: None,
            })
            .await
            .unwrap();
    })
    .unwrap();
    // Two confirmations of the same action: two commands, each admitted
    // through the gate in a passkey session of the admin, each naming the
    // action in its side effects.
    let session = fstp_auth::SessionView {
        id: [0x5E; 16],
        account: admin,
        method: fstp_auth::Method::Passkey,
        started: Timestamp::from_micros(now.micros() - 60_000_000),
        last_used: now,
    };
    let policy = LoginPolicy {
        stepup_freshness_us: fstp_cell_core::tenant::P71_DEFAULT_US,
    };
    let admit = |n: u8| {
        let text: [u8; 16] = [n; 16];
        let id: [u8; 16] = fstp_crypto::random_array().unwrap();
        gate::admit_api_command(
            &state,
            &session,
            Action::Command(CellCommand::Text(TextCommand::PutOwnedText {
                id: text,
                owner: TextOwner::Account(admin),
                len: 8,
            })),
            id,
            [0xD1; 32],
            None,
            now,
            &policy,
        )
        .unwrap()
        .with_api(ApiEffects {
            pending: Some(pending),
            events: vec![b"{\"kind\":\"api_call\"}".to_vec()],
        })
    };
    let (a, b) = (admit(0x71), admit(0x72));
    let head = state.head();
    let results = cell
        .with_running(async |c| {
            let e = c.engine();
            let (x, y) = fstp_rt::future::join(e.execute(a), e.execute(b)).await;
            vec![x, y]
        })
        .unwrap();
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "I-85: {results:?}");
    let refused = results.iter().find(|r| r.is_err()).unwrap();
    match refused {
        Err(EngineError::Exec(ExecError::Refused(CellRefusal::Domain(r)))) => {
            assert_eq!(r.rule, RuleRef::I85, "{r:?}");
        }
        other => panic!("I-85: the second confirmation gave {other:?}"),
    }
    // One batch appended: its text record and nothing of the other.
    let after = engine.state().head();
    assert!(after > head);
    let ledger = cell.ledger().unwrap();
    let texts = ledger
        .iter()
        .filter(|e| {
            matches!(
                &e.record,
                fstp_cell_core::CellRecord::Text(
                    fstp_cell_core::text::TextRecord::OwnedTextPut { .. }
                )
            )
        })
        .count();
    assert_eq!(texts, 1, "I-85: both batches appended");
}

/// I-24, R-AU-01, ADR-010 amendment of 2026-11-20: every call through the
/// cell's `ApiCore` leaves one kind 2 event on the App chain before it is
/// answered, accepted or refused, web and MCP.
#[test]
fn i24_every_api_call_leaves_one_chain_event() {
    let world = World::start_with_api(spec()).unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let mut cycle = Cycle::new(cell);
    cycle.step("login").unwrap_or_else(|e| panic!("{e}"));
    let cookie = cycle.admin_session().expect("the admin session").0;
    let events = || {
        cell.chain_kinds()
            .unwrap()
            .iter()
            .filter(|k| **k == 2)
            .count()
    };
    // An accepted web read.
    let before = events();
    let r = cell
        .request(
            &HttpRequest::new("GET", "/api/v1/me/pending-actions")
                .header("host", cell.host())
                .header("cookie", cookie.clone()),
        )
        .unwrap();
    assert_eq!(r.status, 200, "{:?}", String::from_utf8_lossy(&r.body));
    assert_eq!(events(), before + 1, "I-24: the accepted read");
    // A refused web read: no session.
    let before = events();
    let r = cell
        .request(&HttpRequest::new("GET", "/api/v1/me/pending-actions").header("host", cell.host()))
        .unwrap();
    assert_eq!(r.status, 401, "{:?}", String::from_utf8_lossy(&r.body));
    assert_eq!(events(), before + 1, "I-24: the refused read");
    // The journey UI shell is the web adapter's, behind its page gate.
    let r = cell
        .request(
            &HttpRequest::new("GET", "/app/")
                .header("host", cell.host())
                .header("cookie", cookie),
        )
        .unwrap();
    assert_eq!(r.status, 200, "the /app shell");
}

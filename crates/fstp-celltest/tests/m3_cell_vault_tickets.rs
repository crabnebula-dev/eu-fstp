//! The cell's own `POST /api/v1/vault-tickets` signs the ticket of the
//! issue record it commits, and the vault origin admits it (I-17,
//! R-AU-01, ADR-004 purpose `Ticket`, ADR-009 "Tickets", design section
//! 6.5; lane m3/cell-routes).
//!
//! Each test starts the production front over the in-memory backend
//! (`fstp_cell::routes::memory::LocalCell`) on a ledger that production
//! `decide` built through the M2 domain (`ProdCell` over
//! `driver_model::paths`). The seeded tenant admin of the local cell asks
//! for the ticket. The vault is the production `fstp_vault::Vault` with
//! the cell's ticket key pinned. Every account is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_cell::routes::Backend;
use fstp_cell::routes::memory::{LOCAL_ADMIN, LocalCell};
use fstp_cell_core::CellRecord;
use fstp_cell_core::release::ReleaseRecord;
use fstp_celltest::mc::auth_model::ProdCell;
use fstp_celltest::mc::driver_model::paths;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, PR1};
use fstp_domain_testkit::r#gen::roster::{ADMIN, P1, T0};
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_ledger::Entry;
use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProposal};

const CELL: [u8; 16] = [0xCB; 16];
const HOST: &str = "tenant-t.fstp.test";

/// The ledger of PR1 brought to `state` through production `decide`.
fn ledger_at(state: StateTag) -> Vec<Entry<CellRecord>> {
    let path = paths::to(state).unwrap();
    let mut cell = ProdCell::genesis(paths::truth(true)).unwrap();
    cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0).unwrap();
    for p in &path {
        cell.exec_step(&p.step, p.at).unwrap();
    }
    cell.entries()
}

fn post(path: &str, cookie: &[u8], body: &[u8]) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap()
        .try_with_header("cookie", cookie.to_vec())
        .unwrap();
    req.body = body.to_vec();
    req
}

fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn member(r: &Response, key: &str) -> String {
    let t = text(r);
    let (_, rest) = t
        .split_once(&format!("\"{key}\":\""))
        .unwrap_or_else(|| panic!("no {key} in {t}"));
    rest.split_once('"').unwrap().0.to_owned()
}

fn release_body(command_id: u8, proposal: u128) -> Vec<u8> {
    format!(
        "{{\"command_id\":\"{}\",\"kind\":\"release\",\"proposal\":\"{proposal}\"}}",
        format!("{command_id:02x}").repeat(16)
    )
    .into_bytes()
}

fn release_records(c: &LocalCell) -> Vec<ReleaseRecord> {
    c.backend()
        .records()
        .into_iter()
        .filter_map(|r| match r {
            CellRecord::Release(r) => Some(r),
            _ => None,
        })
        .collect()
}

/// I-17, R-AU-01, design section 6.5: a tenant admin's release ticket for
/// a proposal in NEGOTIATION commits `IdentityReleaseIssued` and answers
/// the ticket signed with the cell's `Ticket` key. Its claims name the
/// proposal's lead, the proposal and its programme, with the record's id
/// as the nonce. The link opens the vault origin's release page, and the
/// vault with the cell's key pinned releases it once, given its own
/// negotiation fact.
#[test]
fn i17_r_au_01_cell_release_ticket_opens_on_the_vault() {
    let c = LocalCell::start_after(CELL, HOST, &ledger_at(StateTag::Negotiation)).unwrap();
    let cookie = c.admin_session().unwrap();
    let r = c.serve(post(
        "/api/v1/vault-tickets",
        &cookie,
        &release_body(0x71, PR1.raw()),
    ));
    assert_eq!(r.status.as_u16(), 200, "{}", text(&r));
    let issued: Vec<[u8; 16]> = release_records(&c)
        .into_iter()
        .filter_map(|r| match r {
            ReleaseRecord::IdentityReleaseIssued { id, proposal, by }
                if proposal == PR1.raw() && by == LOCAL_ADMIN =>
            {
                Some(id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(issued.len(), 1, "the issue is one ledger record");
    let hex = member(&r, "ticket");
    let url = member(&r, "url");
    assert_eq!(url, format!("https://id.{HOST}/r#{hex}"));
    assert_eq!(member(&r, "kind"), "release");
    let bytes = fstp_cell::http::body::hex_vec(&hex, fstp_vault_proto::MAX_TICKET_LEN).unwrap();
    let ticket = fstp_vault_proto::decode_ticket(&bytes).unwrap();
    let key = c.backend().ticket_public_key().unwrap();
    fstp_crypto::sig::ed25519_verify(&key, ticket.body(), ticket.signature()).unwrap();
    let claims = TicketClaims::parse(ticket.body()).unwrap();
    assert_eq!(claims.kind, TicketKind::Release);
    assert_eq!(claims.cell, CELL);
    assert_eq!(claims.account, WireAccount(L1.raw()));
    assert_eq!(claims.proposal, Some(WireProposal(PR1.raw())));
    assert_eq!(
        claims.scope,
        fstp_vault_proto::country_scope(fstp_vault_proto::WireProgramme(P1.raw()))
    );
    assert_eq!(claims.nonce, issued[0]);
    assert!(claims.expires_at > claims.issued_at);

    let mut vault = fstp_vault::Vault::new(CELL, &[key]).unwrap();
    let now = c.backend().now().micros();
    assert!(
        vault.post_release(&bytes, now).is_err(),
        "the vault releases nothing without its negotiation fact"
    );
    vault
        .negotiation_opened(
            WireProposal(PR1.raw()),
            &BTreeSet::from([WireAccount(L1.raw())]),
            1,
        )
        .unwrap();
    vault.post_release(&bytes, now).unwrap();
    assert!(
        vault.post_release(&bytes, now).is_err(),
        "a ticket is single use"
    );
}

/// I-17: before NEGOTIATION no release ticket is issued. The route
/// answers the engine's refusal, and nothing is recorded or signed.
#[test]
fn i17_cell_refuses_a_release_ticket_before_negotiation() {
    let c = LocalCell::start_after(CELL, HOST, &ledger_at(StateTag::Ranked)).unwrap();
    let cookie = c.admin_session().unwrap();
    let r = c.serve(post(
        "/api/v1/vault-tickets",
        &cookie,
        &release_body(0x72, PR1.raw()),
    ));
    assert_eq!(r.status.as_u16(), 403, "{}", text(&r));
    assert!(!text(&r).contains("ticket"), "{}", text(&r));
    assert!(release_records(&c).is_empty());
}

/// I-17, ADR-007: a retry under the same command id commits no second
/// issue record, and its ticket carries the same nonce, so the vault
/// still admits one use of the issue.
#[test]
fn i17_cell_release_ticket_retry_keeps_one_issue() {
    let c = LocalCell::start_after(CELL, HOST, &ledger_at(StateTag::Negotiation)).unwrap();
    let cookie = c.admin_session().unwrap();
    let body = release_body(0x73, PR1.raw());
    let first = c.serve(post("/api/v1/vault-tickets", &cookie, &body));
    assert_eq!(first.status.as_u16(), 200, "{}", text(&first));
    let again = c.serve(post("/api/v1/vault-tickets", &cookie, &body));
    assert_eq!(again.status.as_u16(), 200, "{}", text(&again));
    assert_eq!(release_records(&c).len(), 1);
    let nonce = |r: &Response| {
        let bytes =
            fstp_cell::http::body::hex_vec(&member(r, "ticket"), fstp_vault_proto::MAX_TICKET_LEN)
                .unwrap();
        let t = fstp_vault_proto::decode_ticket(&bytes).unwrap();
        TicketClaims::parse(t.body()).unwrap().nonce
    };
    assert_eq!(nonce(&first), nonce(&again));
}

/// I-78, ADR-008: a download is the high-risk `IdentityDownload`, so
/// without a step-up it is refused, and the vault has no download ticket
/// kind yet, so with every check passed it still records nothing.
#[test]
fn i78_cell_download_ticket_needs_a_step_up_and_records_nothing() {
    let c = LocalCell::start_after(CELL, HOST, &ledger_at(StateTag::Negotiation)).unwrap();
    let cookie = c.admin_session().unwrap();
    let body = format!(
        "{{\"command_id\":\"{}\",\"kind\":\"download\",\"proposal\":\"{}\"}}",
        "74".repeat(16),
        PR1.raw()
    );
    let r = c.serve(post("/api/v1/vault-tickets", &cookie, body.as_bytes()));
    assert_eq!(r.status.as_u16(), 403, "{}", text(&r));
    assert!(release_records(&c).is_empty());
}

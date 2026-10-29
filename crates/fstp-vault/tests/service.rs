//! The vault service's internal API, route tables and configuration
//! (design sections 6.1, 6.2 and 6.9, ADR-009 "Vault origin", NOTE 2,
//! NOTE 4, I-18).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::origin_write;
use common::vc::wire::{RQuery, RTicket, hex};
use common::vc::{Signer, fact};
use fstp_vault::config::{CONFIG_MEMBERS, decode_config};
use fstp_vault::origin::{INTERNAL_ROUTES, ORIGIN_ROUTES};
use fstp_vault::{JournalEntry, Vault};
use fstp_vault_proto::{
    RelationshipKind, VaultRefusal, VaultRequest, VaultResponse, WireAccount, WireProgramme,
    WireProposal, decode_response, encode_request,
};

const CELL: [u8; 16] = [0xCE; 16];
const NOW: i64 = 10_001_000_000;

fn vault() -> (Signer, Vault) {
    let key = Signer::new(1);
    let v = Vault::new(CELL, &[key.public()]).unwrap();
    (key, v)
}

fn call(v: &mut Vault, req: &VaultRequest) -> VaultResponse {
    decode_response(&v.internal_bytes(&encode_request(req).unwrap(), NOW)).unwrap()
}

/// NOTE 4, design section 6.2: the internal API runs the commit protocol.
/// A relationship opens epoch 1, a query about its accounts is pending
/// until the acknowledgement, and the reaction ask sees it.
#[test]
fn i06_note4_internal_api_runs_the_commit_protocol() {
    let (_, mut v) = vault();
    assert_eq!(call(&mut v, &VaultRequest::Epoch), VaultResponse::Epoch(0));
    let rel = VaultRequest::RecordRelationship {
        a: WireAccount(1),
        b: WireAccount(2),
        kind: RelationshipKind::Conflict,
        programme: WireProgramme(1),
        ledger_seq: 5,
    };
    assert_eq!(call(&mut v, &rel), VaultResponse::Acked);
    assert_eq!(call(&mut v, &VaultRequest::Epoch), VaultResponse::Epoch(1));
    let q = RQuery::HasConflict {
        reviewer: 1,
        team: [2].into_iter().collect(),
    }
    .wire();
    let ask = |reaction_for| VaultRequest::Ask {
        at: 1,
        reaction_for,
        queries: vec![q.clone()],
    };
    assert_eq!(
        call(&mut v, &ask(None)),
        VaultResponse::Refused(VaultRefusal::Pending { epoch: 1 })
    );
    match call(&mut v, &ask(Some(1))) {
        VaultResponse::Answers(a) => assert!(a[0].holds && a[0].epoch == 1, "{a:?}"),
        other => panic!("the reaction was refused: {other:?}"),
    }
    let ack = VaultRequest::Ack {
        epoch: 1,
        ledger_seq: 6,
        link: [9; 32],
    };
    assert_eq!(call(&mut v, &ack), VaultResponse::Acked);
    assert_eq!(
        call(&mut v, &ack),
        VaultResponse::Acked,
        "a repeat is accepted"
    );
    match call(&mut v, &ask(None)) {
        VaultResponse::Answers(a) => assert!(a[0].holds && a[0].epoch == 1, "{a:?}"),
        other => panic!("refused after the ack: {other:?}"),
    }
    let link = v.state().log().last().and_then(|e| e.ack_link).unwrap();
    assert_eq!(link, [9; 32], "the vault keeps the reaction's link");
}

/// NOTE 2: a request that does not decode is refused as malformed, and
/// changes nothing.
#[test]
fn note2_internal_api_refuses_undecodable_requests() {
    let (_, mut v) = vault();
    for bytes in [
        b"".as_slice(),
        b"{\"type\":\"seal\"}",
        b"{\"type\": \"epoch\"}",
        b"{\"epoch\":1,\"ledger_seq\":1,\"link\":\"00\",\"type\":\"ack\"}",
    ] {
        let got = decode_response(&v.internal_bytes(bytes, NOW)).unwrap();
        assert_eq!(got, VaultResponse::Refused(VaultRefusal::Malformed));
    }
    assert!(v.take_journal().is_empty());
}

/// Design section 6.5, I-17: the negotiation fact the cell pushes and
/// closes over the internal API is the release guard the origin reads. A
/// re-entry into NEGOTIATION carries a newer ledger sequence (seq 9).
#[test]
fn i17_internal_negotiation_fact_guards_releases() {
    let (key, mut v) = vault();
    let t = RTicket {
        kind: "release".to_owned(),
        cell: CELL,
        account: 501,
        proposal: Some(3),
        scope: "identity".to_owned(),
        issued_at: NOW - 1,
        expires_at: NOW + 100,
        nonce: [4; 16],
    };
    let ticket = key.sign(&t);
    assert!(v.post_release(&ticket, NOW).is_err());
    let open = VaultRequest::NegotiationOpened {
        proposal: WireProposal(3),
        accounts: vec![WireAccount(501)],
        ledger_seq: 7,
    };
    assert_eq!(call(&mut v, &open), VaultResponse::Acked);
    let close = VaultRequest::NegotiationClosed {
        proposal: WireProposal(3),
        ledger_seq: 8,
    };
    assert_eq!(call(&mut v, &close), VaultResponse::Acked);
    assert!(v.post_release(&ticket, NOW).is_err(), "closed");
    let reopen = VaultRequest::NegotiationOpened {
        proposal: WireProposal(3),
        accounts: vec![WireAccount(501)],
        ledger_seq: 9,
    };
    assert_eq!(call(&mut v, &reopen), VaultResponse::Acked);
    let reply = v.post_release(&ticket, NOW).unwrap();
    assert_eq!(reply.status, 200);
    let journal = v.take_journal();
    assert!(journal.contains(&JournalEntry::TicketUsed {
        nonce: [4; 16],
        at: NOW
    }));
}

/// ADR-009 "It serves three route groups only", design section 6.9: the
/// origin answers only `POST /w` and `POST /r`. Any other path is 404,
/// and another method on a known path is 405. Neither table names a seed
/// route.
#[test]
fn i18_vault_route_tables_are_closed_and_name_no_seed_route() {
    let (key, mut v) = vault();
    for (method, path, status) in [
        ("GET", "/w", 405),
        ("PUT", "/r", 405),
        ("POST", "/admin", 404),
        ("POST", "/v1/epoch", 404),
        ("GET", "/", 404),
        ("POST", "/w/", 404),
    ] {
        let reply = v.origin(method, path, b"", NOW);
        assert_eq!(reply.status, status, "{method} {path}");
        assert!(reply.headers.iter().all(|(n, _)| *n != "set-cookie"));
    }
    for r in ORIGIN_ROUTES.iter().chain(INTERNAL_ROUTES.iter()) {
        assert!(!r.path.to_lowercase().contains("seed"), "{}", r.path);
    }
    let t = RTicket {
        kind: "write:country_stated".to_owned(),
        cell: CELL,
        account: 501,
        proposal: None,
        scope: "programme:1".to_owned(),
        issued_at: NOW - 1,
        expires_at: NOW + 100,
        nonce: [1; 16],
    };
    let body = String::from_utf8(fact::country(501, 1, 250).body).unwrap();
    let reply = v.origin("POST", "/w", &origin_write(&key.sign(&t), &body), NOW);
    assert_eq!(reply.status, 204);
    let again = v.origin("POST", "/w", &origin_write(&key.sign(&t), &body), NOW);
    assert_eq!(again.status, 409, "a replay");
    let release = v.origin("POST", "/r", hex(b"not a ticket").as_bytes(), NOW);
    assert_eq!(release.status, 400);
}

fn config_text(extra: &str) -> String {
    format!(
        "{{\"cell\":\"{}\",\"credentials_dir\":\"/etc/fstp/vault\",\"database\":{{\"dbname\":\"v_c1\",\"host\":\"db.internal\",\"port\":5432,\"role\":\"v_c1_app\"}},\"internal_listen\":\"127.0.0.1:7001\",\"origin_listen\":\"127.0.0.1:7002\"{extra},\"ticket_keys\":[\"{}\"]}}",
        hex(&CELL),
        hex(&[3; 32])
    )
}

/// Design section 6.9, I-18: the configuration has a closed member set.
/// A seed member, or any other unknown member, is refused.
#[test]
fn i18_vault_configuration_refuses_a_seed_member() {
    let c = decode_config(config_text("").as_bytes()).unwrap();
    assert_eq!(c.cell, CELL);
    assert_eq!(c.ticket_keys, vec![[3; 32]]);
    assert!(CONFIG_MEMBERS.iter().all(|m| !m.contains("seed")));
    for extra in [",\"seed\":\"facts.json\"", ",\"source\":\"x\"", ",\"zz\":0"] {
        assert!(
            decode_config(config_text(extra).as_bytes()).is_err(),
            "{extra}"
        );
    }
}

/// I-17, design section 6.5: a negotiation fact at or below the highest
/// ledger sequence the vault saw for its proposal is a retry or a stale
/// message. A stale `NegotiationOpened` (seq 7) after the close (seq 8)
/// is acknowledged and reopens nothing, so the release stays refused.
#[test]
fn i17_stale_negotiation_opened_never_reopens_a_closed_negotiation() {
    let (key, mut v) = vault();
    let t = RTicket {
        kind: "release".to_owned(),
        cell: CELL,
        account: 501,
        proposal: Some(3),
        scope: "identity".to_owned(),
        issued_at: NOW - 1,
        expires_at: NOW + 100,
        nonce: [5; 16],
    };
    let ticket = key.sign(&t);
    let open = VaultRequest::NegotiationOpened {
        proposal: WireProposal(3),
        accounts: vec![WireAccount(501)],
        ledger_seq: 7,
    };
    let close = VaultRequest::NegotiationClosed {
        proposal: WireProposal(3),
        ledger_seq: 8,
    };
    // Reordered: the close arrives before the open it follows.
    assert_eq!(call(&mut v, &close), VaultResponse::Acked);
    assert_eq!(call(&mut v, &open), VaultResponse::Acked);
    assert!(v.post_release(&ticket, NOW).is_err(), "reordered open");
    // Retried: the open is sent again after its close.
    let (_, mut w) = vault();
    assert_eq!(call(&mut w, &open), VaultResponse::Acked);
    assert_eq!(call(&mut w, &close), VaultResponse::Acked);
    let _ = w.take_journal();
    assert_eq!(call(&mut w, &open), VaultResponse::Acked);
    assert!(w.post_release(&ticket, NOW).is_err(), "retried open");
    assert!(w.take_journal().is_empty(), "a stale open journals nothing");
}

/// Design section 6.4, Q17, R-ID-02: a verification's identity comes from
/// its match key, never from a request member. One match key resolves to
/// one identity, another key to another, and each new identity is
/// journaled for `vault.identity`.
#[test]
fn i20_verification_identity_comes_from_the_match_key() {
    use fstp_vault_core::{Check, DocumentType, Fact, VerificationMethod, VerificationRecord};
    let (_, mut v) = vault();
    let k1 = fstp_vault::match_key(&[0xA1; 32], b"synthetic|manual|passport|0001");
    let k2 = fstp_vault::match_key(&[0xA1; 32], b"synthetic|manual|passport|0002");
    let record = VerificationRecord {
        method: VerificationMethod::Manual,
        document_type: DocumentType::Passport,
        checks: [Check::DocumentAuthentic].into_iter().collect(),
        at: NOW,
        verifier: WireAccount(900),
    };
    let f1 = v
        .verification_fact(WireAccount(900), WireAccount(501), record.clone(), k1)
        .unwrap();
    let f2 = v
        .verification_fact(WireAccount(900), WireAccount(502), record.clone(), k1)
        .unwrap();
    let f3 = v
        .verification_fact(WireAccount(900), WireAccount(503), record, k2)
        .unwrap();
    let person = |f: &Fact| match f {
        Fact::VerificationRecorded { person, .. } => *person,
        other => panic!("not a verification: {other:?}"),
    };
    assert_eq!(person(&f1), person(&f2), "one match key, one identity");
    assert_ne!(person(&f1), person(&f3), "another key, another identity");
    let assigned: Vec<_> = v
        .take_journal()
        .into_iter()
        .filter(|e| matches!(e, JournalEntry::IdentityAssigned { .. }))
        .collect();
    assert_eq!(assigned.len(), 2, "each new identity is journaled once");
}

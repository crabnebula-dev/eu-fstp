//! I-17 as amended 2026-11-15 (ADR-023 readings 7 to 10): the vault side
//! of the coordinator unmask.
//!
//! - An `unmask` ticket releases on the release route without a
//!   negotiation fact, since the cell decided the coordinator's right and
//!   recorded the unmask first. A `release` ticket for the same subject
//!   still needs the fact.
//! - Every other ticket check holds: an unmask ticket is single use, and
//!   it is no write ticket.
//! - The use is journalled, so the vault chain records it as a release.
//! - The document shows the scope's programme only, and the guardian's
//!   consent record when the ticket names the proposal (I-18).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::vc::wire::RTicket;
use common::vc::{Signer, fact};
use common::{Origin, Refusal, origin_write, refusal};
use fstp_vault::JournalEntry;
use fstp_vault_proto::{TicketKind, VaultRequest, VaultResponse};

const CELL: [u8; 16] = [0xCE; 16];
const APPLICANT: u128 = 501;
const PR: u128 = 1;
const ISSUED: i64 = 10_000_000_000;
const NOW: i64 = ISSUED + 1_000_000;

fn ticket(kind: &str, proposal: Option<u128>, scope: &str, nonce: u8) -> RTicket {
    RTicket {
        kind: kind.to_owned(),
        cell: CELL,
        account: APPLICANT,
        proposal,
        scope: scope.to_owned(),
        issued_at: ISSUED,
        expires_at: ISSUED + 300_000_000,
        nonce: [nonce; 16],
    }
}

fn state_country(o: &mut Origin, key: &Signer, programme: u128, country: u16, nonce: u8) {
    let t = ticket(
        "write:country_stated",
        None,
        &format!("programme:{programme}"),
        nonce,
    );
    let body = String::from_utf8(fact::country(APPLICANT, programme, country).body).unwrap();
    let w = o
        .post_write(&origin_write(&key.sign(&t), &body), NOW)
        .unwrap();
    let epoch = w.epoch.unwrap();
    let ack = VaultRequest::Ack {
        epoch,
        ledger_seq: epoch,
        link: [7; 32],
    };
    assert_eq!(o.vault.internal(&ack, NOW), VaultResponse::Acked);
}

/// ADR-023: the ticket kind `unmask` round-trips its label.
#[test]
fn i17_adr023_unmask_ticket_label_round_trips() {
    assert_eq!(TicketKind::Unmask.label(), "unmask");
    assert_eq!(TicketKind::from_label("unmask"), Some(TicketKind::Unmask));
    assert_eq!(TicketKind::from_label("unmasks"), None);
}

/// I-17 (ADR-023 reading 8): an unmask ticket releases the subject with
/// no negotiation fact, while a release ticket for the same subject is
/// still refused for the missing fact.
#[test]
fn i17_adr023_unmask_releases_without_a_negotiation_fact() {
    let key = Signer::new(1);
    let mut o = Origin::new(CELL, &[key.public()]).unwrap();
    state_country(&mut o, &key, 1, 250, 1);
    state_country(&mut o, &key, 2, 276, 2);
    let release = ticket("release", Some(PR), "programme:1", 3);
    assert_eq!(
        refusal(o.post_release(&key.sign(&release), NOW)).unwrap(),
        Refusal::NoNegotiationFact,
        "I-17: a release still needs the negotiation fact"
    );
    let unmask = ticket("unmask", None, "programme:1", 4);
    let r = o.post_release(&key.sign(&unmask), NOW).unwrap();
    assert_eq!(r.status, 200);
    let text = String::from_utf8(r.body).unwrap();
    assert!(text.contains(&APPLICANT.to_string()), "{text}");
    assert!(text.contains("250"), "the country for programme 1: {text}");
    assert!(
        !text.contains("276"),
        "I-17: the unmask shows another programme's country: {text}"
    );
    assert!(!text.contains("<script"), "the document runs no script");
    assert!(
        r.headers
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "default-src 'none'")
    );
}

/// I-17 (ADR-023 reading 8): the other ticket checks hold. An unmask
/// ticket is used once, and it admits no write.
#[test]
fn i17_adr023_unmask_ticket_is_single_use_and_no_write() {
    let key = Signer::new(1);
    let mut o = Origin::new(CELL, &[key.public()]).unwrap();
    let t = key.sign(&ticket("unmask", None, "programme:1", 5));
    o.post_release(&t, NOW).unwrap();
    assert_eq!(
        refusal(o.post_release(&t, NOW)).unwrap(),
        Refusal::Replayed,
        "single use"
    );
    let w = key.sign(&ticket("unmask", None, "programme:1", 6));
    let body = String::from_utf8(fact::country(APPLICANT, 1, 250).body).unwrap();
    assert!(
        o.post_write(&origin_write(&w, &body), NOW).is_err(),
        "an unmask ticket admitted a write"
    );
}

/// I-17, R-AU-01 (ADR-023 reading 9): the vault journals the use of the
/// unmask ticket, which the vault chain records as a release row.
#[test]
fn r_au_01_adr023_unmask_is_journalled_in_the_vault() {
    let key = Signer::new(1);
    let mut o = Origin::new(CELL, &[key.public()]).unwrap();
    let _ = o.vault.take_journal();
    o.post_release(&key.sign(&ticket("unmask", None, "programme:1", 7)), NOW)
        .unwrap();
    let journal = o.vault.take_journal();
    assert!(
        journal
            .iter()
            .any(|e| matches!(e, JournalEntry::TicketUsed { nonce, .. } if *nonce == [7; 16])),
        "R-AU-01: the unmask is not journalled: {journal:?}"
    );
}

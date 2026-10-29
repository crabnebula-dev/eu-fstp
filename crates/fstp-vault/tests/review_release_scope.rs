//! Review reproducer (I-17, design section 6.5, ADR-009 "Releases"): a
//! release ticket is issued for one proposal, to an Operations role holder
//! of that proposal's programme. The release must not show what the
//! subject stated for another programme.

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
use common::{Origin, origin_write};
use fstp_vault_proto::{VaultRequest, VaultResponse};

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

/// I-17, design section 6.5: a release for proposal PR (programme 1)
/// releases nothing the subject stated for programme 2. The country 276
/// was stated only for programme 2.
#[test]
fn review_release_shows_no_country_of_another_programme() {
    let key = Signer::new(1);
    let mut o = Origin::new(CELL, &[key.public()]).unwrap();
    state_country(&mut o, &key, 1, 250, 1);
    state_country(&mut o, &key, 2, 276, 2);
    o.negotiation_opened(PR, &[APPLICANT]).unwrap();
    let t = ticket("release", Some(PR), "programme:1", 3);
    let r = o.post_release(&key.sign(&t), NOW).unwrap();
    let text = String::from_utf8(r.body).unwrap();
    assert!(
        !text.contains("276"),
        "I-17: the release for PR shows the country stated for programme 2: {text}"
    );
}

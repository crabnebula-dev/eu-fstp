//! The vault origin (I-17, I-20, ADR-009 "Vault origin", "Tickets",
//! "Write kinds" and "Releases", design sections 6.4 and 6.5).
//!
//! - Writes on `POST /w` and releases on `POST /r` need a signed,
//!   single-use ticket. The signature is checked before any other field
//!   is used.
//! - A write ticket admits one write of one kind, by its writer, for the
//!   proposal or programme it names (W1c `origin_binding`).
//! - Release responses render server-side with
//!   `Content-Security-Policy: default-src 'none'` and
//!   `Cache-Control: no-store`, and the document runs no script.
//! - The origin sets no cookie and keeps no session.
//!
//! The tests call the service through `common::Origin`. The W0 stub has
//! no origin handler, so each test is red on `common::ORIGIN_SEAM` until
//! lane W2d lands one.

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
use common::{Fail, Origin, Refusal, match_key, origin_write, refusal};
use fstp_prop::{Gen, prop_assert_eq};

const CELL: [u8; 16] = [0xCE; 16];
const APPLICANT: u128 = 501;
const GUARDIAN: u128 = 401;
const PR: u128 = 1;
const PROGRAMME: u128 = 1;
const ISSUED: i64 = 10_000_000_000;
const NOW: i64 = ISSUED + 1_000_000;

fn ticket(kind: &str, account: u128, proposal: Option<u128>, scope: &str, nonce: u8) -> RTicket {
    RTicket {
        kind: kind.to_owned(),
        cell: CELL,
        account,
        proposal,
        scope: scope.to_owned(),
        issued_at: ISSUED,
        expires_at: ISSUED + 300_000_000,
        nonce: [nonce; 16],
    }
}

fn country_ticket(nonce: u8) -> RTicket {
    ticket(
        "write:country_stated",
        APPLICANT,
        None,
        &format!("programme:{PROGRAMME}"),
        nonce,
    )
}

fn country_body(programme: u128) -> String {
    String::from_utf8(fact::country(APPLICANT, programme, 250).body).unwrap()
}

fn origin(key: &Signer) -> Result<Origin, Fail> {
    Origin::new(CELL, &[key.public()])
}

/// I-17, ADR-009 "The ticket signature is checked before any other field
/// is used": a ticket no pinned key signed is refused for its signature,
/// whatever the ticket body and the write body hold.
#[test]
fn i17_origin_checks_the_signature_before_any_field() {
    fstp_prop::check(
        "i17_origin_checks_the_signature_before_any_field",
        |g: &mut Gen| {
            let key = Signer::new(1);
            let mut o = origin(&key).map_err(|f| format!("{f:?}"))?;
            let ticket_bytes = if g.bool() {
                Signer::new(2).sign(&country_ticket(g.u8()))
            } else {
                g.bytes(65..=300)
            };
            let body = if g.bool() {
                country_body(PROGRAMME)
            } else {
                format!("{{\"zz\":\"{}\"}}", g.u64())
            };
            let got = o.post_write(&origin_write(&ticket_bytes, &body), NOW);
            prop_assert_eq!(
                refusal(got).map_err(|f| format!("{f:?}"))?,
                Refusal::BadSignature
            );
            Ok(())
        },
    );
}

/// I-17, ADR-009 "Single use": a ticket admits one write. The second use
/// is refused as replayed.
#[test]
fn i17_origin_refuses_a_replayed_write_ticket() -> Result<(), Fail> {
    let key = Signer::new(1);
    let mut o = origin(&key)?;
    let bytes = origin_write(&key.sign(&country_ticket(1)), &country_body(PROGRAMME));
    let first = o.post_write(&bytes, NOW)?;
    assert_eq!(first.epoch, Some(1));
    assert_eq!(refusal(o.post_write(&bytes, NOW))?, Refusal::Replayed);
    Ok(())
}

/// I-17, ADR-009 "Write kinds": a write ticket binds its kind, its writer
/// and the programme or proposal it names. A write outside that binding
/// is refused as the wrong kind.
#[test]
fn i17_origin_write_ticket_binds_kind_writer_and_scope() -> Result<(), Fail> {
    let key = Signer::new(1);
    let mut o = origin(&key)?;
    let cases = [
        (
            "another programme",
            country_ticket(2),
            country_body(PROGRAMME + 1),
        ),
        (
            "another writer",
            ticket(
                "write:country_stated",
                APPLICANT + 1,
                None,
                &format!("programme:{PROGRAMME}"),
                3,
            ),
            country_body(PROGRAMME),
        ),
        (
            "a consent for another proposal",
            ticket("write:guardian_consent", GUARDIAN, Some(PR + 1), "", 5),
            String::from_utf8(fact::consent(PR, GUARDIAN).body).unwrap(),
        ),
        (
            "a release ticket on the write route",
            ticket("release", APPLICANT, Some(PR), "identity", 6),
            country_body(PROGRAMME),
        ),
    ];
    for (what, t, body) in cases {
        let got = o.post_write(&origin_write(&key.sign(&t), &body), NOW);
        assert_eq!(refusal(got)?, Refusal::WrongKind, "{what}");
    }
    let lawful = origin_write(&key.sign(&country_ticket(7)), &country_body(PROGRAMME));
    o.post_write(&lawful, NOW)?;
    Ok(())
}

/// I-17, ADR-009 "Release responses" (`i17_release_response_document_runs_no_script`,
/// an ADR-009 test name): the release page is rendered server-side with
/// `default-src 'none'` and `no-store`, holds no script, and sets no
/// cookie.
#[test]
fn i17_release_response_document_runs_no_script() -> Result<(), Fail> {
    let key = Signer::new(1);
    let mut o = origin(&key)?;
    o.negotiation_opened(PR, &[APPLICANT])?;
    let t = ticket("release", APPLICANT, Some(PR), "identity", 8);
    let r = o.post_release(&key.sign(&t), NOW)?;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("content-security-policy"),
        vec!["default-src 'none'"]
    );
    assert_eq!(r.header("cache-control"), vec!["no-store"]);
    assert!(r.header("set-cookie").is_empty());
    let body = String::from_utf8_lossy(&r.body).to_lowercase();
    assert!(
        !body.contains("<script"),
        "the release document runs no script"
    );
    assert!(!body.contains("javascript:"), "no script URL");
    Ok(())
}

/// I-17, design section 6.5 "Second guard": the origin refuses a release
/// unless the vault's own negotiation fact lists the subject.
#[test]
fn i17_origin_refuses_release_without_negotiation_fact() -> Result<(), Fail> {
    let key = Signer::new(1);
    let mut o = origin(&key)?;
    let t = ticket("release", APPLICANT, Some(PR), "identity", 9);
    assert_eq!(
        refusal(o.post_release(&key.sign(&t), NOW))?,
        Refusal::NoNegotiationFact
    );
    o.negotiation_opened(PR, &[APPLICANT])?;
    o.post_release(&key.sign(&t), NOW)?;
    Ok(())
}

/// I-20, Q17: the identity match key is a keyed hash under each cell's
/// own Match key, so the same attribute tuple gives unrelated keys in two
/// cells, and the same key in one cell.
#[test]
fn i20_vault_match_keys_differ_across_cells() -> Result<(), Fail> {
    let tuple = b"synthetic|method:manual|doc:passport|attrs:0001";
    let a = match_key(&[0xA1; 32], tuple)?;
    let b = match_key(&[0xB2; 32], tuple)?;
    assert_ne!(a, b);
    assert_eq!(a, match_key(&[0xA1; 32], tuple)?);
    assert_ne!(a, match_key(&[0xA1; 32], b"synthetic|other")?);
    Ok(())
}

/// Writes the country `country` of `APPLICANT` for `programme` through
/// the origin, and acknowledges its epoch.
fn state_country(o: &mut Origin, key: &Signer, programme: u128, country: u16, nonce: u8) {
    let t = ticket(
        "write:country_stated",
        APPLICANT,
        None,
        &format!("programme:{programme}"),
        nonce,
    );
    let body = String::from_utf8(fact::country(APPLICANT, programme, country).body).unwrap();
    let epoch = o
        .post_write(&origin_write(&key.sign(&t), &body), NOW)
        .unwrap()
        .epoch
        .unwrap();
    let ack = fstp_vault_proto::VaultRequest::Ack {
        epoch,
        ledger_seq: epoch,
        link: [7; 32],
    };
    assert_eq!(
        o.vault.internal(&ack, NOW),
        fstp_vault_proto::VaultResponse::Acked
    );
}

/// I-17, design section 6.5: a release shows the country stated for the
/// programme its ticket names as `programme:<id>`, and no other. A ticket
/// that names no programme shows no country at all.
#[test]
fn i17_release_shows_only_the_country_of_the_ticket_programme() -> Result<(), Fail> {
    let key = Signer::new(1);
    let mut o = origin(&key)?;
    state_country(&mut o, &key, 1, 250, 11);
    state_country(&mut o, &key, 2, 276, 12);
    o.negotiation_opened(PR, &[APPLICANT])?;
    let shown = |o: &mut Origin, scope: &str, nonce: u8| -> String {
        let t = ticket("release", APPLICANT, Some(PR), scope, nonce);
        String::from_utf8(o.post_release(&key.sign(&t), NOW).unwrap().body).unwrap()
    };
    let one = shown(&mut o, "programme:1", 13);
    assert!(one.contains(">250<") && !one.contains("276"), "{one}");
    let two = shown(&mut o, "programme:2", 14);
    assert!(two.contains(">276<") && !two.contains("250"), "{two}");
    for (scope, nonce) in [("identity", 15), ("programme:01", 16), ("programme:", 17)] {
        let none = shown(&mut o, scope, nonce);
        assert!(
            !none.contains("250") && !none.contains("276"),
            "{scope}: {none}"
        );
    }
    Ok(())
}

/// ADR-009 "Each route has a body limit per ticket kind": `POST /r` takes
/// at most the longest ticket in hex. One byte more is refused as too
/// large before it is decoded, and the longest body is decoded.
#[test]
fn adr009_release_route_body_limit_is_the_longest_ticket() {
    let key = Signer::new(1);
    let mut v = fstp_vault::Vault::new(CELL, &[key.public()]).unwrap();
    let limit = fstp_vault::origin::MAX_RELEASE_LEN;
    assert_eq!(limit, 2 * fstp_vault_proto::MAX_TICKET_LEN);
    let over = v.origin("POST", "/r", &vec![b'0'; limit + 1], NOW);
    assert_eq!(over.status, 413);
    let at = v.origin("POST", "/r", &vec![b'0'; limit], NOW);
    assert_ne!(at.status, 413, "a body at the limit is read");
}

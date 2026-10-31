//! Review reproducers for lane W2d (robustness and test strength). Each
//! test fails against the current code and passes once its defect is
//! fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::vc::Signer;
use common::vc::wire::RQuery;
use fstp_vault::{OriginRefusal, Vault};
use fstp_vault_proto::{
    MAX_TICKET_LEN, RelationshipKind, VaultRequest, VaultResponse, WireAccount, WireProgramme,
    decode_response, encode_request,
};

const CELL: [u8; 16] = [0xCE; 16];
const NOW: i64 = 10_001_000_000;

fn vault() -> Vault {
    Vault::new(CELL, &[Signer::new(1).public()]).unwrap()
}

/// NOTE 2, NOTE 5, design section 6.2: every response the vault's
/// internal API emits decodes with the shared `decode_response`, so the
/// cell can read it. A `ChangedSince` answer that lists more than the
/// decoder's 10 000 elements per container is encoded anyway, and the
/// cell's decoder then refuses the vault's own reply.
#[test]
fn review_changed_since_reply_decodes_at_the_cell() {
    let mut v = vault();
    for i in 0..5_001u128 {
        let rel = VaultRequest::RecordRelationship {
            a: WireAccount(2 * i + 1),
            b: WireAccount(2 * i + 2),
            kind: RelationshipKind::Conflict,
            programme: WireProgramme(1),
            ledger_seq: 1,
        };
        assert_eq!(v.internal(&rel, NOW), VaultResponse::Acked);
        let epoch = u64::try_from(i + 1).unwrap();
        let ack = VaultRequest::Ack {
            epoch,
            ledger_seq: epoch,
            link: [7; 32],
        };
        assert_eq!(v.internal(&ack, NOW), VaultResponse::Acked);
    }
    let _ = v.take_journal();
    let ask = VaultRequest::Ask {
        at: 1,
        reaction_for: None,
        queries: vec![RQuery::ChangedSince { epoch: 0 }.wire()],
    };
    let reply = v.internal_bytes(&encode_request(&ask).unwrap(), NOW);
    assert!(
        decode_response(&reply).is_ok(),
        "the cell cannot decode the vault's ChangedSince reply ({} bytes)",
        reply.len()
    );
}

/// ADR-009 "Each route has a body limit per ticket kind", design section
/// 6.5: `POST /r` carries only a release ticket in hex, so a body longer
/// than the longest ticket is refused as too large before it is decoded.
/// `POST /w` does this; `POST /r` decodes any length of hex first.
#[test]
fn review_release_route_has_a_body_limit() {
    let mut v = vault();
    let body = vec![b'0'; 2 * MAX_TICKET_LEN + 2];
    let reply = v.origin("POST", "/r", &body, NOW);
    assert_eq!(reply.status, OriginRefusal::TooLarge.status());
}

/// R-ID-02, design section 6.4, Q17, ADR-008: a verification's identity
/// and verifier never come from a browser body. The vault origin does not
/// decode a kind 6 body under any write ticket, so it is malformed there,
/// even under a `write:verification_recorded` ticket whose account is the
/// body's verifier.
#[test]
fn review_r_id_02_origin_never_decodes_a_verification_body() {
    use common::origin_write;
    use common::vc::wire::RTicket;
    use fstp_vault_core::{Check, DocumentType, Fact, Person, VerificationMethod};
    use fstp_vault_core::{VerificationRecord, ticket::fact_kinds_of};
    use fstp_vault_proto::{TicketKind, WriteKind};

    const VERIFIER: u128 = 900;
    let body = Fact::VerificationRecorded {
        account: WireAccount(501),
        person: Person(1),
        record: VerificationRecord {
            method: VerificationMethod::Manual,
            document_type: DocumentType::Passport,
            checks: [Check::DocumentAuthentic].into_iter().collect(),
            at: NOW,
            verifier: WireAccount(VERIFIER),
        },
    }
    .body()
    .unwrap();
    let body = String::from_utf8(body).unwrap();
    let key = Signer::new(1);
    let mut v = vault();
    for (i, kind) in WriteKind::ALL.into_iter().enumerate() {
        assert!(
            !fact_kinds_of(kind).contains(&fstp_vault_core::fact::kind::VERIFICATION_RECORDED),
            "R-ID-02: a {kind:?} ticket carries a verification body"
        );
        let t = RTicket {
            kind: TicketKind::Write(kind).label(),
            cell: CELL,
            account: VERIFIER,
            proposal: None,
            scope: String::new(),
            issued_at: NOW - 1_000_000,
            expires_at: NOW + 1_000_000,
            nonce: [u8::try_from(i).unwrap() + 1; 16],
        };
        let got = v.post_write(&origin_write(&key.sign(&t), &body), NOW);
        assert_eq!(
            got,
            Err(OriginRefusal::Malformed),
            "R-ID-02: the origin decoded a verification body under a {kind:?} ticket"
        );
    }
    assert!(v.take_journal().is_empty(), "nothing was written");
}

/// R-ID-02, ADR-008: the verifier of a verification fact is the recorder
/// the vault names, never the one a record from the request holds.
#[test]
fn review_r_id_02_verification_verifier_is_the_recorder() {
    use fstp_vault_core::{Check, DocumentType, Fact, VerificationMethod, VerificationRecord};
    let mut v = vault();
    let k = fstp_vault::match_key(&[0xA1; 32], b"synthetic|manual|passport|0001");
    let record = VerificationRecord {
        method: VerificationMethod::Manual,
        document_type: DocumentType::Passport,
        checks: [Check::DocumentAuthentic].into_iter().collect(),
        at: NOW,
        verifier: WireAccount(777),
    };
    let f = v
        .verification_fact(WireAccount(900), WireAccount(501), record, k)
        .unwrap();
    match f {
        Fact::VerificationRecorded { record, .. } => {
            assert_eq!(record.verifier, WireAccount(900), "R-ID-02");
        }
        other => panic!("not a verification: {other:?}"),
    }
}

/// I-54, NOTE 4, design section 6.2: a retried `RecordRelationship`, in
/// either account order, is acknowledged and writes nothing. It opens no
/// second epoch, whether the first write is provisional, queued or
/// effective.
#[test]
fn review_i54_relationship_retry_opens_no_epoch() {
    let mut v = vault();
    let rel = |a, b, seq| VaultRequest::RecordRelationship {
        a: WireAccount(a),
        b: WireAccount(b),
        kind: RelationshipKind::Conflict,
        programme: WireProgramme(1),
        ledger_seq: seq,
    };
    assert_eq!(v.internal(&rel(1, 2, 1), NOW), VaultResponse::Acked);
    assert_eq!(v.internal(&rel(3, 4, 2), NOW), VaultResponse::Acked);
    let _ = v.take_journal();
    // The first is provisional, the second queued.
    for retry in [rel(1, 2, 1), rel(2, 1, 1), rel(3, 4, 2), rel(4, 3, 2)] {
        assert_eq!(v.internal(&retry, NOW), VaultResponse::Acked);
    }
    assert_eq!(v.state().current(), 1, "a retry opened an epoch");
    assert_eq!(v.state().queued(), 1, "a retry queued a write");
    assert!(v.take_journal().is_empty(), "a retry journaled a write");
    for epoch in 1..=2 {
        let ack = VaultRequest::Ack {
            epoch,
            ledger_seq: epoch,
            link: [7; 32],
        };
        assert_eq!(v.internal(&ack, NOW), VaultResponse::Acked);
    }
    let _ = v.take_journal();
    // Both are effective now.
    assert_eq!(v.internal(&rel(1, 2, 1), NOW), VaultResponse::Acked);
    assert_eq!(v.state().current(), 2, "a retry opened an epoch");
    assert!(v.take_journal().is_empty(), "a retry journaled a write");
}

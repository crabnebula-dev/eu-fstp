//! Review reproducers for the W1c reference vault (design sections 6.5,
//! 6.6 and 6.8, ADR-009 "Tickets" and "Write kinds", I-04, I-18).
//! Written by the independent reviewer. Each test fails against the
//! current reference and passes once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::vault::{
    Org, Person, RefTicket, RefVault, RefWrite, RouteKind, TicketCheck, TicketKind, WriteKind,
    sign_ticket, ticket_public_key,
};
use fstp_domain::id::{AccountId, ClassId, ProposalId};
use fstp_domain::time::Timestamp;

const CELL: [u8; 16] = [0xCE; 16];
const KEY: [u8; 32] = [0x11; 32];
const NOW: Timestamp = Timestamp::from_micros(10_000_000_000);
const GUARDIAN: AccountId = AccountId::from_raw(401);
const STAFF: AccountId = AccountId::from_raw(501);
const P1: ProposalId = ProposalId::from_raw(1);
const P2: ProposalId = ProposalId::from_raw(2);
const K1: ClassId = ClassId::from_raw(1);

fn ticket(kind: WriteKind, account: AccountId, proposal: Option<ProposalId>, n: u8) -> Vec<u8> {
    let t = RefTicket {
        kind: TicketKind::Write(kind),
        cell: CELL,
        account,
        proposal,
        scope: "write".to_owned(),
        issued_at: Timestamp::from_micros(NOW.micros() - 1),
        expires_at: Timestamp::from_micros(NOW.micros() + 60_000_000),
        nonce: [n; 16],
    };
    sign_ticket(&t, &KEY).unwrap()
}

fn effective(v: &mut RefVault, w: RefWrite) {
    v.write(w);
    let e = v.current();
    v.ack(e, e, [0; 32]).unwrap();
}

/// I-18, ADR-009 "Tickets": a guardian consent ticket names its proposal.
/// The vault must refuse a consent written under it for another proposal.
/// Otherwise the verified guardian of P1 records a consent that makes
/// `HasGuardianConsent` answer yes for P2, whose guardian it is not.
#[test]
fn review_i18_guardian_ticket_is_bound_to_its_proposal() {
    let keys = [ticket_public_key(&KEY).unwrap()];
    let check = TicketCheck {
        pinned: &keys,
        cell: CELL,
        route: RouteKind::Write,
        now: NOW,
    };
    let mut v = RefVault::default();
    effective(
        &mut v,
        RefWrite::VerificationRecorded {
            account: GUARDIAN,
            person: Person(401),
        },
    );
    let bytes = ticket(WriteKind::GuardianConsent, GUARDIAN, Some(P1), 1);
    let got = v.origin_write(
        &bytes,
        RefWrite::GuardianConsent {
            proposal: P2,
            guardian: GUARDIAN,
        },
        &check,
    );
    assert!(
        got.is_err(),
        "I-18: a guardian ticket for {P1:?} admitted a consent for {P2:?}: {got:?}"
    );
}

/// I-18, design section 14.4 ("Consents recorded, withdrawn"), and the
/// reference's own reading that a withdrawal travels under the kind of
/// the fact it withdraws: the guardian who consented withdraws the consent
/// with a guardian consent ticket for the same proposal.
#[test]
fn review_i18_guardian_can_withdraw_consent_on_the_origin() {
    let keys = [ticket_public_key(&KEY).unwrap()];
    let check = TicketCheck {
        pinned: &keys,
        cell: CELL,
        route: RouteKind::Write,
        now: NOW,
    };
    let mut v = RefVault::default();
    effective(
        &mut v,
        RefWrite::VerificationRecorded {
            account: GUARDIAN,
            person: Person(401),
        },
    );
    let first = ticket(WriteKind::GuardianConsent, GUARDIAN, Some(P1), 1);
    v.origin_write(
        &first,
        RefWrite::GuardianConsent {
            proposal: P1,
            guardian: GUARDIAN,
        },
        &check,
    )
    .unwrap();
    let e = v.current();
    v.ack(e, e, [0; 32]).unwrap();
    let second = ticket(WriteKind::GuardianConsent, GUARDIAN, Some(P1), 2);
    let got = v.origin_write(&second, RefWrite::ConsentWithdrawn { proposal: P1 }, &check);
    assert!(
        got.is_ok(),
        "I-18: the consenting guardian could not withdraw the consent: {got:?}"
    );
}

/// I-04, ADR-009 "Write kinds" ("A write ticket admits one write of one
/// kind"): ending a partner staff affiliation, which carries an excluded
/// class, needs a partner staff ticket. An ordinary affiliation ticket must
/// not remove the exclusion.
#[test]
fn review_i04_affiliation_ticket_cannot_end_partner_staff_exclusion() {
    let keys = [ticket_public_key(&KEY).unwrap()];
    let check = TicketCheck {
        pinned: &keys,
        cell: CELL,
        route: RouteKind::Write,
        now: NOW,
    };
    let mut v = RefVault::default();
    effective(
        &mut v,
        RefWrite::AffiliationDeclared {
            account: STAFF,
            org: Org(7),
            class: Some(K1),
        },
    );
    let bytes = ticket(WriteKind::AffiliationDeclared, STAFF, None, 1);
    let got = v.origin_write(
        &bytes,
        RefWrite::AffiliationEnded {
            account: STAFF,
            org: Org(7),
        },
        &check,
    );
    assert!(
        got.is_err(),
        "I-04: an affiliation ticket ended a partner staff affiliation in class {K1:?}: {got:?}"
    );
}

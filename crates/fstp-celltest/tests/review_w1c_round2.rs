//! Review reproducers for the W1c reference vault, round 2 (ADR-009
//! "Write kinds", design section 6.8, I-04). Written by the independent
//! reviewer. Each test fails against the current reference and passes
//! once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::reference::vault::{
    Org, RefTicket, RefVault, RefWrite, RouteKind, TicketCheck, TicketKind, WriteKind, sign_ticket,
    ticket_public_key,
};
use fstp_domain::id::{AccountId, ClassId, ProgrammeId};
use fstp_domain::oracle::Query;
use fstp_domain::policy::ExclusionClasses;
use fstp_domain::time::Timestamp;

const CELL: [u8; 16] = [0xCE; 16];
const KEY: [u8; 32] = [0x11; 32];
const NOW: Timestamp = Timestamp::from_micros(10_000_000_000);
const STAFF: AccountId = AccountId::from_raw(501);
const K1: ClassId = ClassId::from_raw(1);
const ORG: Org = Org(7);

fn ticket(kind: WriteKind, account: AccountId, n: u8) -> Vec<u8> {
    let t = RefTicket {
        kind: TicketKind::Write(kind),
        cell: CELL,
        account,
        proposal: None,
        scope: "write".to_owned(),
        issued_at: Timestamp::from_micros(NOW.micros() - 1),
        expires_at: Timestamp::from_micros(NOW.micros() + 60_000_000),
        nonce: [n; 16],
    };
    sign_ticket(&t, &KEY).unwrap()
}

fn ack_current(v: &mut RefVault) {
    let e = v.current();
    v.ack(e, e, [0; 32]).unwrap();
}

/// I-04, ADR-009 "Write kinds" ("A write ticket admits one write of one
/// kind"): the fix of round 1 makes ending a partner staff affiliation
/// need a partner staff ticket. Re-declaring the same affiliation with no
/// class under an ordinary affiliation ticket replaces the classed row, so
/// it clears the exclusion just as an end would. The vault must refuse
/// that write, or keep the class, so `InExcludedClass` still answers yes.
#[test]
fn review_i04_affiliation_ticket_cannot_redeclare_partner_staff_without_class() {
    let keys = [ticket_public_key(&KEY).unwrap()];
    let check = TicketCheck {
        pinned: &keys,
        cell: CELL,
        route: RouteKind::Write,
        now: NOW,
    };
    let mut v = RefVault::default();
    v.origin_write(
        &ticket(WriteKind::PartnerStaffDeclared, STAFF, 1),
        RefWrite::AffiliationDeclared {
            account: STAFF,
            org: ORG,
            class: Some(K1),
        },
        &check,
    )
    .unwrap();
    ack_current(&mut v);
    let excluded = Query::InExcludedClass {
        account: STAFF,
        programme: ProgrammeId::from_raw(1),
        classes: ExclusionClasses(BTreeSet::from([K1])),
    };
    assert!(v.facts().holds(&excluded), "setup: STAFF is excluded");

    let got = v.origin_write(
        &ticket(WriteKind::AffiliationDeclared, STAFF, 2),
        RefWrite::AffiliationDeclared {
            account: STAFF,
            org: ORG,
            class: None,
        },
        &check,
    );
    if got.is_ok() {
        ack_current(&mut v);
    }
    assert!(
        v.facts().holds(&excluded),
        "I-04: an ordinary affiliation ticket cleared the partner staff class {K1:?} by re-declaring the affiliation ({got:?})"
    );
}

//! The email to the recorders of a verification request (ADR-026 record
//! of lane L24, lead reading of 2026-11-22; I-25, I-27, R-NG-01).
//!
//! Each open request, once visible to the recorders, is one event of kind
//! `VERIFICATION_REQUEST`, sourced by the account and the request's
//! ordinal. It fires once. With a mail relay it sends one email of the
//! template `id-check-waiting` to each tenant admin who may record, with
//! a link to Members and nothing else. A staff request is visible at
//! once; an applicant's only once the proposal is in NEGOTIATION or later.
//! `TODO(legal)`: the wording is a draft.

#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeSet;

use common::Cell;
use fstp_cell_core::CellRecord;
use fstp_cell_core::release::ReleaseRecord;
use fstp_cell_core::timeline::{EventStatus, Recipient};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::L1;
use fstp_mail::{LinkTarget, Slot, TemplateId, Value};
use fstp_timeline::{kind, verification_request_drafts, verification_request_visible};

/// A staff account: no Receiving binding.
const STAFF: AccountId = AccountId::from_raw(0x77);
const DAY: i64 = 86_400_000_000;

fn ask(c: &mut Cell, at: i64, n: u8, account: AccountId) {
    c.append(
        at,
        [0xA0 + n; 16],
        vec![CellRecord::Release(ReleaseRecord::VerificationRequested {
            account,
        })],
    );
}

fn close(c: &mut Cell, at: i64, n: u8, account: AccountId) {
    c.append(
        at,
        [0xB0 + n; 16],
        vec![CellRecord::Release(
            ReleaseRecord::VerificationRequestClosed { account },
        )],
    );
}

fn events(c: &Cell) -> Vec<(Vec<u8>, EventStatus)> {
    c.state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::VERIFICATION_REQUEST)
        .map(|(_, e)| (e.source.clone(), e.status))
        .collect()
}

fn source(account: AccountId, ordinal: u64) -> Vec<u8> {
    let mut s = account.raw().to_be_bytes().to_vec();
    s.extend_from_slice(&ordinal.to_be_bytes());
    s
}

/// I-25, ADR-026 record of lane L24, row "Email": a staff request derives
/// one event, fired by the same tick, and a repeat tick or a repeated
/// press adds none. After the vault's confirmation closed it, a new
/// request is a new event with the next ordinal.
#[test]
fn adr008_staff_request_fires_one_event_once() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let at = c.state.now_floor().micros() + DAY;
    assert!(verification_request_visible(&c.state, STAFF));
    ask(&mut c, at, 1, STAFF);
    c.tick(Timestamp::from_micros(at + 1)).unwrap();
    let ev = events(&c);
    assert_eq!(ev, vec![(source(STAFF, 1), EventStatus::Fired)]);
    ask(&mut c, at + 2, 2, STAFF);
    c.tick(Timestamp::from_micros(at + 3)).unwrap();
    assert_eq!(events(&c).len(), 1, "a repeat press sent a second email");
    close(&mut c, at + 4, 1, STAFF);
    ask(&mut c, at + 5, 3, STAFF);
    c.tick(Timestamp::from_micros(at + 6)).unwrap();
    let ev = events(&c);
    assert_eq!(ev.len(), 2);
    assert!(ev.contains(&(source(STAFF, 2), EventStatus::Fired)));
}

/// R-NG-01, ADR-026 record of lane L24, rows "Email" and "Earlier list":
/// the request of an applicant whose proposal is not yet in NEGOTIATION
/// derives no event and is not visible.
#[test]
fn adr008_applicant_request_waits_for_negotiation() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let at = c.state.now_floor().micros() + DAY;
    assert!(!verification_request_visible(&c.state, L1));
    ask(&mut c, at, 1, L1);
    c.tick(Timestamp::from_micros(at + 1)).unwrap();
    assert!(
        events(&c).is_empty(),
        "R-NG-01: an applicant's request emailed before NEGOTIATION"
    );
}

/// I-27, ADR-026 record of lane L24, row "Email": with a relay, one email
/// of `id-check-waiting` goes to each recorder's account, with the one slot
/// `Link` set to Members. Without a relay, none.
#[test]
fn adr008_i27_email_names_no_person_and_links_to_members() {
    let recorders: BTreeSet<AccountId> = [AccountId::from_raw(1), AccountId::from_raw(2)].into();
    let drafts = verification_request_drafts(&recorders, true);
    assert_eq!(drafts.len(), 2);
    for (to, template, bindings) in &drafts {
        assert!(matches!(to, Recipient::Account(a) if recorders.contains(a)));
        assert_eq!(*template, TemplateId::IdCheckWaiting);
        let slots: Vec<Slot> = bindings.slots().collect();
        assert_eq!(slots, vec![Slot::Link]);
        assert_eq!(
            bindings.get(Slot::Link),
            Some(&Value::Link(LinkTarget::Members))
        );
    }
    assert!(verification_request_drafts(&recorders, false).is_empty());
    assert_eq!(LinkTarget::Members.path(), "/app/admin/members");
    let t = fstp_mail::Template::latest(TemplateId::IdCheckWaiting, fstp_mail::Locale::En).unwrap();
    assert_eq!(t.slots().len(), 1);
}

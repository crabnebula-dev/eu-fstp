//! Issue 6 L10 follow-up, ADR-008 "Decided by Daniel, 2026-11-19", I-25,
//! I-27: each `CredentialSuspect` record is one flagging event, which the
//! timeline turns into one event of kind `PASSKEY_DISABLED`. With a mail
//! relay it fires one email of the pinned template `passkey-disabled` to the
//! holder's account, holding a link to the platform home and nothing else.
//! Without a relay it fires with no message. A repeat adds no event.
//! `TODO(legal)`: the wording is a draft.

#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_auth::AuthRecord;
use fstp_cell_core::CellRecord;
use fstp_cell_core::timeline::{EventStatus, Recipient};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_mail::{LinkTarget, Slot, TemplateId, Value};
use fstp_timeline::message::MessageSpec;
use fstp_timeline::{kind, passkey_disabled_drafts};
use fstp_webauthn::CoseKey;

const HOLDER: AccountId = AccountId::from_raw(0x71);
const DAY: i64 = 86_400_000_000;

fn register(c: &mut Cell, at: i64, n: u8) {
    c.append(
        at,
        [0xD0 + n; 16],
        vec![CellRecord::Auth(AuthRecord::CredentialRegistered {
            account: HOLDER,
            credential: vec![0xCC, n],
            key: CoseKey::Ed25519 { x: [n; 32] },
            user_verified: true,
        })],
    );
}

fn flag(c: &mut Cell, at: i64, n: u8) {
    c.append(
        at,
        [0xE0 + n; 16],
        vec![CellRecord::Auth(AuthRecord::CredentialSuspect {
            account: HOLDER,
            credential: vec![0xCC, n],
        })],
    );
}

fn events(c: &Cell) -> Vec<(Vec<u8>, EventStatus)> {
    c.state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::PASSKEY_DISABLED)
        .map(|(_, e)| (e.source.clone(), e.status))
        .collect()
}

/// ADR-008, I-25: a flagged passkey schedules one event, numbered by its
/// ordinal, and a second flag a second event. A repeated tick adds none.
/// A tenant with no relay fires with no message and no body.
#[test]
fn issue6_l10_adr008_flag_derives_one_event_and_no_relay_sends_no_email() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let at = c.state.now_floor().micros() + DAY;
    register(&mut c, at, 1);
    register(&mut c, at, 2);
    assert!(events(&c).is_empty(), "no flag, no event");
    flag(&mut c, at + 1, 1);
    c.tick(Timestamp::from_micros(at + 2)).unwrap();
    let ev = events(&c);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0].0, 1u64.to_be_bytes().to_vec());
    assert_eq!(ev[0].1, EventStatus::Fired, "fired by the same tick");
    assert!(c.bodies.is_empty(), "I-25: no relay, no email");
    c.tick(Timestamp::from_micros(at + 3)).unwrap();
    assert_eq!(events(&c).len(), 1, "a repeat tick adds none");
    flag(&mut c, at + 4, 2);
    c.tick(Timestamp::from_micros(at + 5)).unwrap();
    assert_eq!(events(&c).len(), 2);
}

/// ADR-008, I-25, I-27: with a relay, the event's one message goes to the
/// holder's account from the template `passkey-disabled`, with the one
/// slot `Link` set to the platform home. No time, id or address.
#[test]
fn issue6_l10_adr008_i25_i27_email_goes_to_the_holder_with_a_link_only() {
    let drafts = passkey_disabled_drafts(HOLDER, true);
    assert_eq!(drafts.len(), 1);
    let (to, template, bindings) = &drafts[0];
    assert_eq!(*to, Recipient::Account(HOLDER));
    assert_eq!(*template, TemplateId::PasskeyDisabled);
    let slots: Vec<Slot> = bindings.slots().collect();
    assert_eq!(slots, vec![Slot::Link]);
    assert_eq!(
        bindings.get(Slot::Link),
        Some(&Value::Link(LinkTarget::Home))
    );
    assert!(passkey_disabled_drafts(HOLDER, false).is_empty());
    // The rendered text holds no id and no time.
    let t =
        fstp_mail::Template::latest(TemplateId::PasskeyDisabled, fstp_mail::Locale::En).unwrap();
    assert_eq!(t.slots().len(), 1);
    let spec_ok = MessageSpec::decode(
        &MessageSpec {
            template: TemplateId::PasskeyDisabled,
            version: t.version(),
            locale: fstp_mail::Locale::En,
            event: [1; 32],
            idem: [2; 32],
            to: Recipient::Account(HOLDER),
            date: Timestamp::from_micros(0),
            bindings: bindings.clone(),
        }
        .encode()
        .unwrap(),
    );
    assert!(spec_ok.is_ok(), "the body round-trips with the home link");
}

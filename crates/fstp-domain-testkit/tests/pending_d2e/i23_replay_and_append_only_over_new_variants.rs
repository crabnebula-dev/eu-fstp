//! I-23, I-10, ADR-007: replay and append-only over the M4 envelope variants (M4 design section 4.2).
//!
//! NOT YET COMPILED. Cargo does not discover files in `tests/pending_d2e/`.
//! This file is written against the API of design sections 3.4 and 4.2.
//! Move it to `tests/` once these exist:
//!
//! - `fstp_engine::Record::{Creator, Import, Tenant}` and
//!   `fstp_engine::EnvelopeKind::{Creator, Import, Tenant}` (W2e, D2e);
//! - the stored member names `creator`, `import` and `tenant`. The design
//!   names the variants only. The lower-case member follows the M2
//!   `core` and `finding` members, and is a reading;
//! - `fstp_domain_testkit::activation::activate(scenario, programme,
//!   approver)` switched to `Command::Creator(ApproveActivation)` (D8 step 2);
//! - a `fstp-creator` dependency of `fstp-domain-testkit`, which the
//!   switched `activate` needs.
//!
//! Every new variant follows ADR-007: a canonical RFC 8785 body, a schema
//! version per entry, insert-only storage, structural replay, and
//! `verify_append_only` over the whole envelope.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::VaultEpoch;
use fstp_domain_testkit::activation::activate;
use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, SodSetup, T0, sod_truth};
use fstp_domain_testkit::harness::prop::{append_only, replay_matches};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::{
    EnvelopeKind, Record, envelope_from_json, envelope_to_json, record_from_json_at,
};
use fstp_json::{FromJson, ToJson, Value, parse};
use fstp_ledger::Entry;

/// The M4 sides and their stored member names.
const NEW_SIDES: [(EnvelopeKind, &str); 3] = [
    (EnvelopeKind::Creator, "creator"),
    (EnvelopeKind::Import, "import"),
    (EnvelopeKind::Tenant, "tenant"),
];

/// The side `record` is stored on.
fn side(record: &Record) -> EnvelopeKind {
    match record {
        Record::Core(_) => EnvelopeKind::Core,
        Record::Finding(_) => EnvelopeKind::Finding,
        Record::Creator(_) => EnvelopeKind::Creator,
        Record::Import(_) => EnvelopeKind::Import,
        Record::Tenant(_) => EnvelopeKind::Tenant,
        Record::Contract(_) => EnvelopeKind::Contract,
        Record::Report(_) => EnvelopeKind::Report,
    }
}

/// I-23, ADR-007: each new side has its own member, distinct from every
/// other side's, and the envelope splits back onto the side it was
/// stored on.
#[test]
fn i23_new_envelope_sides_split_onto_their_side() {
    let mut members = vec![EnvelopeKind::Core.member(), EnvelopeKind::Finding.member()];
    for (kind, member) in NEW_SIDES {
        assert_eq!(kind.member(), member, "the stored member of {kind:?}");
        assert!(!members.contains(&member), "two sides share {member}");
        members.push(member);
        let stored = envelope_to_json(kind, Value::Null);
        let (back, inner) = envelope_from_json(&stored).unwrap();
        assert_eq!(back, kind);
        assert!(inner.identical(&Value::Null));
    }
}

/// I-10, I-23: a core record's body stored under a new side's member is
/// refused. A record never decodes on another side than its own.
#[test]
fn i23_core_body_under_a_new_member_is_refused() {
    let core = fstp_domain::Record::VaultEpochProcessed {
        epoch: VaultEpoch::from_raw(9),
    };
    for (kind, _) in NEW_SIDES {
        let stored = envelope_to_json(kind, core.to_json());
        assert!(
            Record::from_json(&stored).is_err(),
            "I-10: a core body decoded on the {kind:?} side"
        );
    }
}

/// A draft P1 from genesis, with the programme manager and drafter
/// granted (the grants a draft admits, D3).
fn draft() -> Scenario {
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    for step in SodSetup::one(0, &[])
        .steps()
        .unwrap_or_else(|e| panic!("{e}"))
    {
        run_on(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("setup step {:?}: {e:?}", step.cmd.kind()));
    }
    s
}

/// Checks that each entry's canonical text decodes to the same entry, on
/// the side its record is on.
fn round_trips(entries: &[Entry<Record>]) {
    for entry in entries {
        let text = entry.canonical_text().unwrap();
        let raw = Entry::<Value>::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
        let back = raw
            .clone()
            .try_map_record(|schema, r| record_from_json_at(schema, &r))
            .unwrap_or_else(|e| panic!("I-23: entry {:?} does not decode: {e}", entry.seq));
        assert_eq!(&back, entry, "I-23: entry {:?} changed", entry.seq);
        let (kind, _) = envelope_from_json(&raw.record).unwrap();
        assert_eq!(
            kind,
            side(&entry.record),
            "I-10: entry {:?} changed side",
            entry.seq
        );
    }
}

/// I-23, I-66, D2e: the activation through the creator appends creator
/// records and the core `ProgrammeActivated` in one entry. The ledger
/// before it is a prefix of the ledger after it, the ledger replays to the
/// state, and every entry round-trips through its canonical bytes.
#[test]
fn i23_activation_ledger_replays_and_is_append_only() {
    let mut s = draft();
    let before = s.entries().unwrap();
    activate(&mut s, P1, ADMIN_2).unwrap_or_else(|e| panic!("activate: {e:?}"));
    let after = s.entries().unwrap();
    append_only(&before, &after).unwrap_or_else(|e| panic!("I-23: {e}"));
    replay_matches(&after, s.state()).unwrap_or_else(|e| panic!("I-23: {e}"));
    round_trips(&after);

    let added = &after[before.len()..];
    let activated: Vec<&Entry<Record>> = added
        .iter()
        .filter(|e| {
            matches!(
                &e.record,
                Record::Core(fstp_domain::Record::ProgrammeActivated { .. })
            )
        })
        .collect();
    assert_eq!(activated.len(), 1, "D2e: one ProgrammeActivated");
    let command = activated[0].command;
    assert!(
        added
            .iter()
            .any(|e| e.command == command && matches!(e.record, Record::Creator(_))),
        "D2e: the activation entry holds a creator record beside ProgrammeActivated"
    );
    assert!(
        added
            .iter()
            .filter(|e| e.command == command)
            .all(|e| !matches!(
                &e.record,
                Record::Core(fstp_domain::Record::PolicyVersionRecorded { .. })
            )),
        "R-PC-03: the activation entry records no policy version"
    );
}

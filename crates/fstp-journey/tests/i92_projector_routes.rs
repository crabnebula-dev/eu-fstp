//! I-92, R-JV-01, `SPEC/12-journey-ui.md` sections 7.1 and 11: what the
//! projector folds. Each proposal's completed legs and current node
//! follow its `Transitioned` records, each transition is one state
//! transition entry, and every row is well formed: 16-byte ids that
//! never repeat, sequence numbers of real ledger entries, the time of
//! the source entry, and text and correction rows that name an entry.
//!
//! The journey crate also names no command, driver or store write, so it
//! holds no authority and writes no ledger entry (I-92, ADR-015).
//!
//! Lane j2 test author. The property tests are red until the implementer
//! writes the projector. The source scan is green and guards the fold.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain_testkit::reference::projection::{self, Leg, Place};
use fstp_journey::projector::{EntryRow, Subject};
use fstp_journey::visibility::EntryKind;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use j2::{at_seq, ledger, ledger_config, rows_of};

/// I-92, R-JV-01: each proposal's legs, in route order, are its
/// `Transitioned` records with their states, entry times and sequence
/// numbers.
#[test]
fn i92_legs_follow_the_transition_records() {
    fstp_prop::check_with(
        "i92_legs_follow_the_transition_records",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let want = projection::legs(&l);
            prop_assert!(!want.is_empty(), "the generated ledger has no transition");
            let mut got: BTreeMap<_, Vec<(u32, Leg)>> = BTreeMap::new();
            for leg in &rows.legs {
                got.entry(leg.proposal).or_default().push((
                    leg.ord,
                    Leg {
                        from: leg.from,
                        to: leg.to,
                        at: leg.at,
                        seq: leg.source_seq,
                    },
                ));
            }
            let mut ordered: BTreeMap<_, Vec<Leg>> = BTreeMap::new();
            for (p, mut legs) in got {
                legs.sort_by_key(|(ord, _)| *ord);
                let ords: Vec<u32> = legs.iter().map(|(o, _)| *o).collect();
                let want_ords: Vec<u32> = (0u32..).take(ords.len()).collect();
                prop_assert_eq!(&ords, &want_ords, "I-92: leg order of {p:?}");
                ordered.insert(p, legs.into_iter().map(|(_, leg)| leg).collect());
            }
            prop_assert_eq!(ordered, want, "I-92: the legs differ from the transitions");
            Ok(())
        },
    );
}

/// I-92, R-JV-01: each proposal's current position is the state of its
/// last transition, or DRAFT from its creation, with the time and
/// sequence number of that record.
#[test]
fn i92_positions_follow_the_last_transition() {
    fstp_prop::check_with(
        "i92_positions_follow_the_last_transition",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let want = projection::positions(&l);
            prop_assert!(!want.is_empty(), "the generated ledger has no proposal");
            for (p, place) in &want {
                let got = rows.position(*p).map(|pos| Place {
                    node: pos.node,
                    since: pos.since,
                    seq: pos.source_seq,
                });
                prop_assert_eq!(got, Some(*place), "I-92: position of {p:?}");
            }
            Ok(())
        },
    );
}

/// I-92, section 7.2 "State transition": each `Transitioned` record is
/// exactly one state transition entry of its proposal, at its own
/// sequence number and time, and no other record is one.
#[test]
fn i92_every_transition_has_one_state_transition_entry() {
    fstp_prop::check_with(
        "i92_every_transition_has_one_state_transition_entry",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let want = projection::transition_seqs(&l);
            let got: Vec<&EntryRow> = rows
                .entries
                .iter()
                .filter(|r| r.kind == EntryKind::StateTransition)
                .collect();
            let mut seen: BTreeMap<u64, Subject> = BTreeMap::new();
            for r in &got {
                let entry = at_seq(&l, r.source_seq)
                    .ok_or_else(|| format!("I-92: no ledger entry {}", r.source_seq))?;
                prop_assert_eq!(r.occurred_at, entry.at, "I-92: time of {r:?}");
                let before = seen.insert(r.source_seq, r.subject);
                prop_assert!(before.is_none(), "I-92: two entries for {}", r.source_seq);
            }
            let want: BTreeMap<u64, Subject> = want
                .into_iter()
                .map(|(seq, p)| (seq, Subject::Proposal(p)))
                .collect();
            prop_assert_eq!(seen, want, "I-92: state transition entries");
            Ok(())
        },
    );
}

/// I-92, section 11: every row is well formed. Entry ids never repeat.
/// Each entry names a ledger entry and carries its time. Each text row
/// names an entry, with an `ord` unique within it. Each correction names
/// an earlier entry. The cursor names the last ledger entry.
#[test]
fn i92_rows_are_well_formed() {
    fstp_prop::check_with(
        "i92_rows_are_well_formed",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let mut ids: BTreeMap<[u8; 16], u64> = BTreeMap::new();
            for r in &rows.entries {
                prop_assert!(r.source_seq >= 1, "I-92: {r:?}");
                let entry = at_seq(&l, r.source_seq)
                    .ok_or_else(|| format!("I-92: no ledger entry {} for {r:?}", r.source_seq))?;
                prop_assert_eq!(r.occurred_at, entry.at, "I-92: time of {r:?}");
                let before = ids.insert(r.entry_id, r.source_seq);
                prop_assert!(before.is_none(), "I-92: entry id repeats: {r:?}");
            }
            for r in &rows.entries {
                if let Some(s) = r.supersedes {
                    let target = ids.get(&s).copied();
                    prop_assert!(
                        target.is_some_and(|seq| seq < r.source_seq),
                        "I-92, I-23: {r:?} corrects no earlier entry"
                    );
                }
            }
            let mut keys: BTreeSet<([u8; 16], u16)> = BTreeSet::new();
            for t in &rows.texts {
                prop_assert!(ids.contains_key(&t.entry_id), "I-92: {t:?} names no entry");
                prop_assert!(keys.insert((t.entry_id, t.ord)), "I-92: {t:?} repeats");
            }
            let last = l.last().map_or(0, |e| e.seq.raw());
            prop_assert_eq!(rows.last_seq(), last, "I-92: the cursor");
            prop_assert!(
                rows.cursor.iter().any(|c| c.last_ledger_seq == last),
                "I-92: no cursor row names entry {last}: {:?}",
                rows.cursor
            );
            Ok(())
        },
    );
}

/// The library sources of the journey crate.
fn sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("the source directory reads") {
            let p = e.expect("a directory entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).expect("a source file reads");
                out.push((p.display().to_string(), text));
            }
        }
    }
    out
}

/// I-92, ADR-015: the journey layer holds no authority and writes no
/// ledger entry. Its sources name no command, no engine driver, no
/// scenario and no store write.
#[test]
fn i92_journey_sources_name_no_command_or_ledger_write() {
    let forbidden = [
        "Command",
        "Engine",
        "Driver",
        "execute",
        "append",
        "MemStore",
        "AsyncStore",
        "fstp_engine::driver",
        "fstp_ledger::store",
    ];
    let mut hits = Vec::new();
    for (path, text) in sources() {
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for word in forbidden {
                if code.contains(word) {
                    hits.push(format!("{path}:{}: {word}", n.saturating_add(1)));
                }
            }
        }
    }
    assert!(hits.is_empty(), "I-92: the journey crate names {hits:#?}");
}

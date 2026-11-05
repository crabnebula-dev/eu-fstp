//! I-97, R-JV-11, R-NF-08, I-81, ADR-007, `SPEC/12-journey-ui.md`
//! sections 7.1, 7.3 and 11: a journey row or diary item never holds free
//! text from a ledger record. It holds `TextRef` values only: an id and
//! its salted digest. An erased text reads as the erasure-log
//! placeholder, never as text.
//!
//! A canary text is seeded into every free-text field a ledger record can
//! hold: the opaque policy values, the pinned model names and the
//! deadline zones. It never appears in the rows, their bytes or the
//! diary items.
//!
//! Lane j2 test author. Red until the implementer writes the projector
//! and the diary read. The canary teeth test is green: it checks the
//! seeding itself.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{TextId, TextRef};
use fstp_domain_testkit::mc::ledger_model::stored_json;
use fstp_domain_testkit::reference::projection::{self, CANARY_MARK, holds_canary};
use fstp_journey::diary::{Erasure, TextSlot, items};
use fstp_journey::projector::EntryRow;
use fstp_journey::visibility::EntryKind;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use j2::{ledger, ledger_config, rows_of};

/// I-97, R-JV-11: every text row of an entry is a reference its source
/// record holds. No row invents a reference or copies one from another
/// record.
#[test]
fn i97_text_rows_hold_only_references_of_their_source_record() {
    fstp_prop::check_with(
        "i97_text_rows_hold_only_references_of_their_source_record",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let by_seq = projection::text_refs_by_seq(&l);
            let entries: BTreeMap<[u8; 16], &EntryRow> =
                rows.entries.iter().map(|r| (r.entry_id, r)).collect();
            for t in &rows.texts {
                let e = entries
                    .get(&t.entry_id)
                    .ok_or_else(|| format!("I-97: {t:?} names no entry"))?;
                let held = by_seq.get(&e.source_seq).cloned().unwrap_or_default();
                prop_assert!(
                    held.contains(&t.text),
                    "I-97: {t:?} is no reference of ledger entry {}",
                    e.source_seq
                );
            }
            Ok(())
        },
    );
}

/// I-97, section 7.2 "Clarification question and answer": each stage 2
/// question and answer record is a clarification entry of its proposal
/// that references exactly the record's text.
#[test]
fn i97_clarification_entries_reference_their_text() {
    fstp_prop::check_with(
        "i97_clarification_entries_reference_their_text",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            for (seq, (proposal, text)) in projection::clarification_texts(&l) {
                let entry = rows
                    .entries
                    .iter()
                    .find(|r| r.source_seq == seq && r.kind == EntryKind::Clarification)
                    .ok_or_else(|| {
                        format!("I-97: no clarification entry for ledger entry {seq}")
                    })?;
                prop_assert_eq!(
                    entry.subject,
                    fstp_journey::projector::Subject::Proposal(proposal),
                    "I-97: subject of entry {seq}"
                );
                let refs: Vec<TextRef> = rows
                    .texts
                    .iter()
                    .filter(|t| t.entry_id == entry.entry_id)
                    .map(|t| t.text)
                    .collect();
                prop_assert_eq!(refs, vec![text], "I-97: text of entry {seq}");
            }
            Ok(())
        },
    );
}

/// I-97 teeth: the seeding writes the canary into the ledger. The stored
/// form of the seeded ledger holds it, so a projector that copied any
/// seeded field would be caught.
#[test]
fn i97_teeth_the_canary_is_seeded_into_the_ledger() {
    fstp_prop::check_with(
        "i97_teeth_the_canary_is_seeded_into_the_ledger",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let (seeded, fields) = projection::seed_canary(&l)?;
            prop_assert!(fields > 0, "no free-text field was seeded");
            let stored = seeded
                .iter()
                .filter_map(|e| stored_json(&e.record))
                .any(|v| holds_canary(v.to_compact().as_bytes()));
            prop_assert!(stored, "the seeded ledger does not hold {CANARY_MARK}");
            Ok(())
        },
    );
}

/// I-97, R-NF-08: with the canary in every free-text field of the
/// ledger, no journey row holds it, in its values or its stored bytes.
#[test]
fn i97_canary_in_ledger_records_never_reaches_journey_rows() {
    fstp_prop::check_with(
        "i97_canary_in_ledger_records_never_reaches_journey_rows",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let (seeded, _) = projection::seed_canary(&l)?;
            let rows = rows_of(&seeded)?;
            prop_assert!(
                !rows.entries.is_empty(),
                "I-97: the seeded ledger projects no entry"
            );
            prop_assert!(
                !holds_canary(&rows.encode()),
                "I-97: the stored row bytes hold the canary"
            );
            prop_assert!(
                !holds_canary(format!("{rows:?}").as_bytes()),
                "I-97: a row value holds the canary"
            );
            Ok(())
        },
    );
}

/// I-97: with the canary in every free-text field of the ledger, no
/// diary item holds it. Sentences are built from catalogue keys and
/// typed parameters only.
#[test]
fn i97_canary_never_reaches_diary_items() {
    fstp_prop::check_with(
        "i97_canary_never_reaches_diary_items",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let (seeded, _) = projection::seed_canary(&l)?;
            let rows = rows_of(&seeded)?;
            let got = items(&rows, &seeded, &BTreeMap::new())
                .map_err(|e| format!("I-97: the diary read refused: {e}"))?;
            prop_assert_eq!(got.len(), rows.entries.len(), "I-97: one item per entry");
            prop_assert!(
                !holds_canary(format!("{got:?}").as_bytes()),
                "I-97: a diary item holds the canary"
            );
            Ok(())
        },
    );
}

/// I-97, I-81, section 7.3: a text in the erasure log reads as its
/// placeholder, with the erasure's date and cause, and never as a
/// reference. A live text reads as its reference only, in `ord` order.
#[test]
fn i97_erased_text_reads_as_the_erasure_placeholder() {
    fstp_prop::check_with(
        "i97_erased_text_reads_as_the_erasure_placeholder",
        ledger_config(),
        |g: &mut Gen| {
            // R-AC-01 (review J2-R2): call drafts give no entry, so a
            // generated ledger may hold no text row. The witness ledger
            // holds stage 2 question and answer texts.
            let generated = ledger(g)?;
            let l = if rows_of(&generated)?.texts.is_empty() {
                projection::witness_ledger()?
            } else {
                generated
            };
            let rows = rows_of(&l)?;
            let ids: BTreeSet<TextId> = rows.texts.iter().map(|t| t.text.id()).collect();
            prop_assert!(!ids.is_empty(), "I-97: the projection holds no text row");
            let mut erasures: BTreeMap<TextId, Erasure> = BTreeMap::new();
            for id in &ids {
                if g.bool() {
                    let e = Erasure {
                        on: g.i64_in(1..=4_000_000_000_000_000),
                        cause: g.u16_in(1..=9),
                    };
                    erasures.insert(*id, e);
                }
            }
            let got = items(&rows, &l, &erasures)
                .map_err(|e| format!("I-97: the diary read refused: {e}"))?;
            for item in &got {
                let mut want: Vec<(u16, TextRef)> = rows
                    .texts
                    .iter()
                    .filter(|t| t.entry_id == item.entry_id)
                    .map(|t| (t.ord, t.text))
                    .collect();
                want.sort_by_key(|(ord, _)| *ord);
                let want: Vec<TextSlot> = want
                    .into_iter()
                    .map(|(_, r)| match erasures.get(&r.id()) {
                        Some(e) => TextSlot::Erased(*e),
                        None => TextSlot::Live(r),
                    })
                    .collect();
                prop_assert_eq!(&item.texts, &want, "I-97: texts of {:?}", item.entry_id);
            }
            Ok(())
        },
    );
}

/// I-97, section 7.2 "Clarification question and answer", on the scripted
/// witness ledger, which records a stage 2 question and its answer: each
/// is a clarification entry that references exactly its text.
#[test]
fn i97_witness_clarifications_reference_their_text() {
    let l = projection::witness_ledger().unwrap_or_else(|e| panic!("{e}"));
    let want = projection::clarification_texts(&l);
    assert!(
        want.len() >= 2,
        "the witness holds a question and an answer: {want:?}"
    );
    let rows = rows_of(&l).unwrap_or_else(|e| panic!("{e}"));
    for (seq, (_, text)) in want {
        let refs: Vec<TextRef> = rows
            .entries
            .iter()
            .filter(|r| r.source_seq == seq && r.kind == EntryKind::Clarification)
            .flat_map(|r| rows.texts.iter().filter(move |t| t.entry_id == r.entry_id))
            .map(|t| t.text)
            .collect();
        assert_eq!(
            refs,
            vec![text],
            "I-97: clarification of ledger entry {seq}"
        );
    }
}

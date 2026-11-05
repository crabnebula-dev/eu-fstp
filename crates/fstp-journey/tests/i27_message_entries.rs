//! I-27, ADR-015 "Visibility", `SPEC/12-journey-ui.md` section 7.2 "Hard
//! rules": no message on any channel carries proposal content, scores,
//! deliberation or identity attributes. A diary entry derived from a
//! message record, an outbox event, is never a score entry and its
//! sentence carries no score parameter.
//!
//! Lane j2 test author. Red until the implementer writes the projector
//! and the diary read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain_testkit::reference::projection;
use fstp_journey::diary::{Param, items};
use fstp_journey::visibility::EntryKind;
use fstp_prop::{Gen, prop_assert};
use j2::{ledger, ledger_config, rows_of};

/// I-27: no entry derived from an outbox record is a reviewer score or
/// comment entry.
#[test]
fn i27_message_derived_rows_are_never_score_entries() {
    fstp_prop::check_with(
        "i27_message_derived_rows_are_never_score_entries",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let messages: BTreeSet<u64> = projection::message_seqs(&l).into_iter().collect();
            for r in &rows.entries {
                if messages.contains(&r.source_seq) {
                    prop_assert!(
                        r.kind != EntryKind::ReviewerScore,
                        "I-27: message entry {} is a score entry: {r:?}",
                        r.source_seq
                    );
                }
            }
            Ok(())
        },
    );
}

/// I-27: no diary item derived from an outbox record carries a score
/// parameter, whatever the proposal's state.
#[test]
fn i27_message_derived_items_carry_no_score() {
    fstp_prop::check_with(
        "i27_message_derived_items_carry_no_score",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let rows = rows_of(&l)?;
            let messages: BTreeSet<u64> = projection::message_seqs(&l).into_iter().collect();
            let got = items(&rows, &l, &BTreeMap::new())
                .map_err(|e| format!("I-27: the diary read refused: {e}"))?;
            for item in &got {
                if messages.contains(&item.source_seq) {
                    prop_assert!(
                        !item.params.iter().any(|p| matches!(p, Param::Score(_))),
                        "I-27: message item {} carries a score: {item:?}",
                        item.source_seq
                    );
                }
            }
            Ok(())
        },
    );
}

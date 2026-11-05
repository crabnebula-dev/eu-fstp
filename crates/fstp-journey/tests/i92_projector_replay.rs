//! I-92, ADR-015 "Read model only", `SPEC/12-journey-ui.md` sections 3.2
//! and 13 ("Replay test", "Checkpoint test"): the projector is a pure
//! fold of the ledger. Deleting every journey row and replaying gives
//! byte-identical rows, and a checkpoint plus the remaining entries
//! equals a full replay.
//!
//! Every property folds ledgers the I-23 machine of the domain testkit
//! drew over the full engine from genesis.
//!
//! Lane j2 test author. Red until the implementer writes the projector:
//! the stub refuses every fold with `ProjectError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain_testkit::reference::projection;
use fstp_journey::projector::{ProjectError, Projector};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use j2::{ledger, ledger_config, rows_of};

/// I-92: two replays of the same ledger give the same bytes, as a rebuild
/// after deleting every journey row must.
#[test]
fn i92_rebuild_from_the_ledger_is_byte_identical() {
    fstp_prop::check_with(
        "i92_rebuild_from_the_ledger_is_byte_identical",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let first = rows_of(&l)?;
            let rebuilt = rows_of(&l.clone())?;
            prop_assert_eq!(&first, &rebuilt, "I-92: the rebuilt rows differ");
            prop_assert_eq!(
                first.encode(),
                rebuilt.encode(),
                "I-92: the rebuilt bytes differ"
            );
            Ok(())
        },
    );
}

/// I-92, ADR-007: a rebuild reads the ledger from its stored bytes. The
/// rows of the decoded entries are byte for byte the rows of the
/// entries the engine appended.
#[test]
fn i92_rebuild_from_the_stored_entries_is_byte_identical() {
    fstp_prop::check_with(
        "i92_rebuild_from_the_stored_entries_is_byte_identical",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let stored = projection::stored_copy(&l)?;
            let live = rows_of(&l)?;
            let rebuilt = rows_of(&stored)?;
            prop_assert_eq!(
                live.encode(),
                rebuilt.encode(),
                "I-92: rows from the stored entries differ"
            );
            Ok(())
        },
    );
}

/// I-92, section 3.2 "Projection checkpoints are allowed. A test compares
/// each checkpoint with a full replay": the rows of a prefix, resumed as
/// a restarted projector reads them back, then the remaining entries,
/// equal the full replay byte for byte.
#[test]
fn i92_checkpoint_plus_tail_equals_full_replay() {
    fstp_prop::check_with(
        "i92_checkpoint_plus_tail_equals_full_replay",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let k = g.usize_in(0..=l.len());
            let (head, tail) = l.split_at(k);
            g.note("checkpoint after", &k);
            let checkpoint = rows_of(head)?;
            let mut p = Projector::resume(checkpoint.clone())
                .map_err(|e| format!("I-92: resume after {k} entries refused: {e}"))?;
            for e in tail {
                p.fold(e).map_err(|err| {
                    format!(
                        "I-92: fold of entry {} after the checkpoint: {err}",
                        e.seq.raw()
                    )
                })?;
            }
            let full = rows_of(&l)?;
            prop_assert_eq!(
                p.rows().encode(),
                full.encode(),
                "I-92: checkpoint after {k} entries plus tail differs from the full replay"
            );
            Ok(())
        },
    );
}

/// I-92: folding one entry at a time gives, after each entry, the rows
/// of a full replay of the prefix so far.
#[test]
fn i92_incremental_fold_equals_full_replay_after_every_entry() {
    fstp_prop::check_with(
        "i92_incremental_fold_equals_full_replay_after_every_entry",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let mut p = Projector::new();
            for (i, e) in l.iter().enumerate() {
                p.fold(e)
                    .map_err(|err| format!("I-92: fold of entry {}: {err}", e.seq.raw()))?;
                let prefix = l.get(..=i).unwrap_or_default();
                let full = rows_of(prefix)?;
                prop_assert_eq!(
                    p.rows().encode(),
                    full.encode(),
                    "I-92: after entry {} the incremental rows differ",
                    e.seq.raw()
                );
            }
            Ok(())
        },
    );
}

/// I-92: the cursor names the last folded entry, so a resumed projector
/// refuses a tail that skips an entry or repeats one. A checkpoint can
/// never silently miss or double a record.
#[test]
fn i92_resume_refuses_a_tail_that_skips_or_repeats_an_entry() {
    fstp_prop::check_with(
        "i92_resume_refuses_a_tail_that_skips_or_repeats_an_entry",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            prop_assert!(l.len() >= 3, "the generated ledger has {} entries", l.len());
            let k = g.usize_in(1..=l.len().saturating_sub(2));
            let checkpoint = rows_of(l.get(..k).unwrap_or_default())?;
            prop_assert_eq!(
                checkpoint.last_seq(),
                l.get(k.saturating_sub(1)).map_or(0, |e| e.seq.raw()),
                "I-92: the cursor does not name the last folded entry"
            );
            let resumed = Projector::resume(checkpoint)
                .map_err(|e| format!("I-92: resume after {k} entries refused: {e}"))?;
            let skipped = l.get(k.saturating_add(1)).ok_or("no entry to skip to")?;
            let repeated = l.get(k.saturating_sub(1)).ok_or("no entry to repeat")?;
            for (what, e) in [("skips an entry", skipped), ("repeats an entry", repeated)] {
                let mut p = resumed.clone();
                match p.fold(e) {
                    Err(ProjectError::OutOfOrder { .. }) => {}
                    other => {
                        return Err(format!(
                            "I-92: a tail that {what} (entry {} after {k}) gave {other:?}",
                            e.seq.raw()
                        ));
                    }
                }
            }
            Ok(())
        },
    );
}

/// I-92 teeth: the bytes tell a ledger from its proper prefix whenever
/// the tail holds a state transition, so byte identity is not vacuous.
#[test]
fn i92_teeth_bytes_tell_a_ledger_from_its_prefix() {
    fstp_prop::check_with(
        "i92_teeth_bytes_tell_a_ledger_from_its_prefix",
        ledger_config(),
        |g: &mut Gen| {
            let l = ledger(g)?;
            let seqs = projection::transition_seqs(&l);
            let Some(last) = seqs.keys().next_back().copied() else {
                return Err("the generated ledger holds no transition".to_owned());
            };
            let cut = l
                .iter()
                .position(|e| e.seq.raw() == last)
                .ok_or("the last transition is not in the ledger")?;
            let prefix = rows_of(l.get(..cut).unwrap_or_default())?;
            let full = rows_of(&l)?;
            prop_assert!(
                prefix.encode() != full.encode(),
                "I-92: the bytes before and after transition {last} are equal"
            );
            Ok(())
        },
    );
}

//! fstp-prop adapters for state machine tests (design section 6.1).
//!
//! - [`two_way`] compares accept and refuse with an independent reference
//!   in both directions. It catches over-denial as well as over-permission.
//! - [`two_way_exec`] does the same over a driver result. Only
//!   `ExecError::Refused` counts as a refusal. Every other error fails the
//!   check, so a fold or store failure never hides inside a refusal.
//! - [`replay_matches`] checks `replay(ledger) == state` (I-23).
//! - [`append_only`] checks that a later read of the ledger extends an
//!   earlier one (I-23).
//! - [`ledger_step`] runs both ledger checks, as every machine step must.
//!
//! Each returns `Result<(), String>`, so it composes with `?` inside an
//! fstp-prop property or postcondition.
//!
//! Records have no canonical encoding until lane L-CODEC lands. Until then
//! [`append_only`] compares entries by equality, field by field. Once
//! records implement `fstp_ledger::Canonical`, it moves to
//! `fstp_ledger::verify_append_only`, which compares canonical bytes.

use core::fmt::Debug;

use fstp_domain::refusal::Refusal;
use fstp_engine::{EngineState, ExecError, Record, replay};
use fstp_ledger::{Entry, Seq};

/// Checks that `actual` agrees with the reference in both directions.
///
/// `reference_accepts` is the verdict of the independent reference.
/// Accepting what the reference refuses is over-permission. Refusing what
/// the reference accepts is over-denial. The message names `context`.
pub fn two_way<T: Debug>(
    context: &str,
    reference_accepts: bool,
    actual: &Result<T, Refusal>,
) -> Result<(), String> {
    match (reference_accepts, actual) {
        (true, Ok(_)) | (false, Err(_)) => Ok(()),
        (false, Ok(v)) => Err(format!(
            "{context}: over-permission, the engine accepted ({v:?}) what the reference refuses"
        )),
        (true, Err(r)) => Err(format!(
            "{context}: over-denial, the engine refused ({r}) what the reference accepts"
        )),
    }
}

/// Checks a driver result against the reference in both directions.
///
/// `Ok` is an accept and `ExecError::Refused` a refusal, compared as
/// [`two_way`] does. Any other error fails the check whatever the
/// reference says, because it is neither an accept nor a refusal. A fold
/// error is an I-23 defect, and a duplicate or contended run means the
/// test did not drive the command it meant to. The message names `context`.
///
/// A refusal of the `VaultChanged` that the driver processed first also
/// arrives as `Refused`. A test that changes the vault in the same step
/// runs `Scenario::change_vault` or `Engine::sync_vault` before the
/// command, so the two refusals stay apart.
pub fn two_way_exec(
    context: &str,
    reference_accepts: bool,
    actual: &Result<Seq, ExecError>,
) -> Result<(), String> {
    let decided: Result<Seq, Refusal> = match actual {
        Ok(seq) => Ok(*seq),
        Err(ExecError::Refused(r)) => Err(*r),
        Err(e) => {
            return Err(format!(
                "{context}: the driver failed with {e:?}, which is neither an accept nor a refusal"
            ));
        }
    };
    two_way(context, reference_accepts, &decided)
}

/// Checks that `state` is the replay of `entries` from genesis (I-23).
pub fn replay_matches(entries: &[Entry<Record>], state: &EngineState) -> Result<(), String> {
    match replay(entries) {
        Ok(replayed) if replayed == *state => Ok(()),
        Ok(replayed) => Err(format!(
            "I-23: the state differs from the replay of {} entries\n  state: {state:?}\nreplay: {replayed:?}",
            entries.len()
        )),
        Err(e) => Err(format!(
            "I-23: the replay of {} entries failed: {e}",
            entries.len()
        )),
    }
}

/// Checks that `current` extends `previous` without changing, dropping,
/// inserting or reordering any entry, and that `current` numbers its
/// entries from 1 without gaps (I-23).
pub fn append_only(previous: &[Entry<Record>], current: &[Entry<Record>]) -> Result<(), String> {
    if current.len() < previous.len() {
        return Err(format!(
            "I-23: the ledger shrank from {} to {} entries",
            previous.len(),
            current.len()
        ));
    }
    let mut expected: u64 = 0;
    let mut earlier = previous.iter();
    for e in current {
        expected = expected.saturating_add(1);
        if let Some(old) = earlier.next()
            && old != e
        {
            return Err(format!(
                "I-23: entry {expected} changed\n  was: {old:?}\n  now: {e:?}"
            ));
        }
        if e.seq.raw() != expected {
            return Err(format!(
                "I-23: entry {expected} has sequence number {}",
                e.seq.raw()
            ));
        }
    }
    Ok(())
}

/// The ledger checks of one machine step: `current` extends `previous`,
/// and `state` is the replay of `current` (I-23).
pub fn ledger_step(
    previous: &[Entry<Record>],
    current: &[Entry<Record>],
    state: &EngineState,
) -> Result<(), String> {
    append_only(previous, current)?;
    replay_matches(current, state)
}

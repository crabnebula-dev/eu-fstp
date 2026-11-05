//! Shared helpers for the lane j2 tests (I-92, I-93, I-97, I-27, O-54,
//! O-57, O-58, O-60, R-JV-07).
//!
//! The tests are written before the production code, against this API of
//! the journey crate:
//!
//! - `fstp_journey::projector::{project, Projector, Rows, EntryRow,
//!   EntryTextRow, LegRow, CursorRow, Position, Subject, ProjectError}`;
//! - `fstp_journey::diary::{items, DiaryItem, Param, TextSlot, Erasure}`;
//! - `fstp_journey::visibility::{visible, route_strip, state_counts,
//!   EntryKind, Relation, Viewer, EntryFacts}`;
//! - `fstp_journey::overlay::{compute, Overlay, OverlayInputs,
//!   IrcConcern, WORDING_PARAMS}`.
//!
//! The references are `fstp_domain_testkit::reference::{diary,
//! projection}`, written from the spec text. Only tests use these helpers.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::reference::diary::{Facts, Kind};
use fstp_domain_testkit::reference::projection;
use fstp_engine::Record;
use fstp_journey::projector::{Rows, project};
use fstp_journey::visibility::{EntryFacts, EntryKind, Relation, Viewer, visible};
use fstp_ledger::Entry;
use fstp_prop::{Config, Gen};

/// Commands the ledger machine draws per generated ledger.
pub(crate) const COMMANDS: usize = 60;

/// Cases of each property over generated ledgers. Each case runs the
/// full engine from genesis, so the count stays small.
pub(crate) const LEDGER_CASES: u32 = 24;

/// The configuration of a property over generated ledgers.
pub(crate) fn ledger_config() -> Config {
    Config::default().with_cases(LEDGER_CASES)
}

/// A generated ledger from the domain testkit.
pub(crate) fn ledger(g: &mut Gen) -> Result<Vec<Entry<Record>>, String> {
    projection::generated_ledger(g, COMMANDS)
}

/// The rows of a full replay, or the projector's refusal as a message.
pub(crate) fn rows_of(ledger: &[Entry<Record>]) -> Result<Rows, String> {
    project(ledger).map_err(|e| {
        format!(
            "I-92: the projector refused a ledger of {} entries: {e}",
            ledger.len()
        )
    })
}

/// The production kind of a reference kind.
pub(crate) fn kind(k: Kind) -> EntryKind {
    match k {
        Kind::StateTransition => EntryKind::StateTransition,
        Kind::DeadlineSet => EntryKind::DeadlineSet,
        Kind::NoticeSent => EntryKind::NoticeSent,
        Kind::Clarification => EntryKind::Clarification,
        Kind::ReviewerScore => EntryKind::ReviewerScore,
        Kind::Conflict => EntryKind::Conflict,
        Kind::VaultOutcome => EntryKind::VaultOutcome,
        Kind::Contract => EntryKind::Contract,
        Kind::MilestonePayment => EntryKind::MilestonePayment,
        Kind::Complaint => EntryKind::Complaint,
        Kind::AgentAction => EntryKind::AgentAction,
        Kind::GuardianStep => EntryKind::GuardianStep,
    }
}

/// The production viewer of reference facts.
pub(crate) fn viewer(f: &Facts) -> Viewer {
    Viewer {
        role: f.role,
        programme: f.viewer_programme,
        relation: Relation {
            team: f.team,
            guardian_of: f.guardian_of,
            assigned: f.assigned,
            declared_no_conflict: f.declared_no_conflict,
            conflicted: f.conflicted,
            own: f.own,
            complaint_reviewer: f.complaint_reviewer,
            sod13_barred: f.sod13_barred,
        },
    }
}

/// The production entry facts of reference facts.
pub(crate) fn entry(f: &Facts) -> EntryFacts {
    EntryFacts {
        kind: kind(f.kind),
        programme: f.entry_programme,
        path: f.path.clone(),
        transition: f.transition,
    }
}

/// The production verdict on reference facts.
pub(crate) fn production_visible(f: &Facts) -> bool {
    visible(&viewer(f), f.p10, &entry(f))
}

/// The ledger entry with sequence number `seq`.
pub(crate) fn at_seq(ledger: &[Entry<Record>], seq: u64) -> Option<&Entry<Record>> {
    ledger.iter().find(|e| e.seq.raw() == seq)
}

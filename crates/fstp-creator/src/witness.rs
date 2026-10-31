//! The witnesses of activation (I-66, I-67, M4 design section 3.2).
//!
//! - [`CleanReport`]: no failure, and every warning acknowledged at the
//!   report's revision. Only [`clean`] builds it.
//! - [`ActivationClearance`]: the approver is a tenant admin outside the
//!   builder set, verified, and shares no verified identity with a
//!   builder. Only [`clear_activation`] builds it, from a `CleanReport`.
//! - [`ActivationApproved`]: the creator record of an approval. Outside
//!   the record decoder only [`ActivationApproved::new`] builds it.
//!
//! None of the three has public fields, `Default` or a JSON decoder. The
//! twins in `twins.rs` check this.

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{AccountId, DecisionId, ProgrammeId};
use fstp_domain::state::State;
use fstp_ledger::Seq;

use crate::check::{CheckId, Severity, WarningKey};
use crate::decide::{CreatorRefusal, approver_checks};
use crate::inputs::CreatorInputs;
use crate::model::{DraftRevision, ReportDigest};
use crate::state::CreatorState;
use crate::validate::ValidationReport;

/// The live acknowledgements of one draft at its head revision.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AckSet {
    programme: ProgrammeId,
    revision: DraftRevision,
    keys: BTreeSet<WarningKey>,
}

impl AckSet {
    /// The acknowledgements of `programme` that no edit has voided
    /// (reading R1, interim, pending Daniel). Empty for an unknown draft.
    pub fn live(creator: &CreatorState, programme: ProgrammeId) -> AckSet {
        match creator.draft(programme) {
            Some(d) => AckSet {
                programme,
                revision: d.head(),
                keys: d.live_acks(),
            },
            None => AckSet {
                programme,
                revision: DraftRevision::new(0, Seq::ZERO),
                keys: BTreeSet::new(),
            },
        }
    }

    /// The programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The head revision the set was read at.
    pub fn revision(&self) -> DraftRevision {
        self.revision
    }

    /// The live keys.
    pub fn keys(&self) -> &BTreeSet<WarningKey> {
        &self.keys
    }
}

/// Why a report does not clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Uncleared {
    /// The report shows this failure. The first failure in catalogue
    /// order is named.
    Failure(CheckId),
    /// This warning has no live acknowledgement. The first such warning
    /// in catalogue order is named.
    Unacknowledged(CheckId),
    /// The acknowledgements were read at another revision or programme
    /// than the report.
    Stale,
}

/// I-66 witness: no failure, and every warning acknowledged at the
/// report's revision.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CleanReport {
    programme: ProgrammeId,
    revision: DraftRevision,
    digest: ReportDigest,
}

impl CleanReport {
    /// The programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The revision the report was computed at.
    pub fn revision(&self) -> DraftRevision {
        self.revision
    }

    /// The report's fingerprint.
    pub fn digest(&self) -> &ReportDigest {
        &self.digest
    }
}

/// Turns `report` into a [`CleanReport`] when it shows no failure and
/// every warning has a live acknowledgement in `acks`.
pub fn clean(report: &ValidationReport, acks: &AckSet) -> Result<CleanReport, Uncleared> {
    if acks.programme != report.programme() || acks.revision != report.revision() {
        return Err(Uncleared::Stale);
    }
    if let Some(f) = report.failures().next() {
        return Err(Uncleared::Failure(f.check));
    }
    if let Some(w) = report
        .results()
        .iter()
        .find(|r| r.severity == Severity::Warning && !acks.keys.contains(&r.key()))
    {
        return Err(Uncleared::Unacknowledged(w.check));
    }
    Ok(CleanReport {
        programme: report.programme(),
        revision: report.revision(),
        digest: report.digest(),
    })
}

/// I-67 witness: the approver is a tenant admin outside the builder set,
/// verified, and shares no verified identity with any builder. Every
/// builder is verified too (Q2, interim, pending Daniel).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActivationClearance {
    report: CleanReport,
    approver: AccountId,
    builders: BTreeSet<AccountId>,
    decision: DecisionId,
}

impl ActivationClearance {
    /// The clean report.
    pub fn report(&self) -> &CleanReport {
        &self.report
    }

    /// The approver.
    pub fn approver(&self) -> AccountId {
        self.approver
    }

    /// The builder set the approver was checked against.
    pub fn builders(&self) -> &BTreeSet<AccountId> {
        &self.builders
    }

    /// The decision id of the approval.
    pub fn decision(&self) -> DecisionId {
        self.decision
    }
}

/// Clears the approval of `programme` by the actor of `ctx`.
///
/// It checks again what the approval needs: the draft is open, the clean
/// report is at the head revision, the actor is a tenant admin outside the
/// builder set, the vault verified the actor and every builder, the actor
/// shares no verified identity with a builder, and an activation request
/// is live.
///
/// Interim, pending Daniel: the design's signature has no decision id.
/// The approval record carries one for the core `ActivateProgramme`, so
/// it is passed here.
pub fn clear_activation(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    report: CleanReport,
    ctx: &Ctx,
    inputs: &CreatorInputs,
    decision: DecisionId,
) -> Result<ActivationClearance, CreatorRefusal> {
    let _ = core;
    if report.programme != programme {
        return Err(CreatorRefusal::UnknownDraft);
    }
    let (approver, builders) = approver_checks(creator, programme, report.revision, ctx, inputs)?;
    let Actor::Account(actor) = ctx.actor else {
        return Err(CreatorRefusal::NotAnAccount);
    };
    if actor != approver {
        return Err(CreatorRefusal::NotAnAccount);
    }
    if builders
        .iter()
        .any(|b| inputs.vault.is_verified.get(b) != Some(&true))
    {
        return Err(CreatorRefusal::BuilderUnverified);
    }
    Ok(ActivationClearance {
        report,
        approver,
        builders,
        decision,
    })
}

/// The creator record of an approved activation. The engine composes the
/// core `ActivateProgramme` from it in the same entry, and its fold
/// refuses a `ProgrammeActivated` without this record (D2e).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActivationApproved {
    programme: ProgrammeId,
    revision: DraftRevision,
    report: ReportDigest,
    decision: DecisionId,
    approver: AccountId,
    builders: BTreeSet<AccountId>,
}

impl ActivationApproved {
    /// The record of the cleared approval `clearance`.
    pub fn new(clearance: &ActivationClearance) -> ActivationApproved {
        ActivationApproved {
            programme: clearance.report.programme,
            revision: clearance.report.revision,
            report: clearance.report.digest.clone(),
            decision: clearance.decision,
            approver: clearance.approver,
            builders: clearance.builders.clone(),
        }
    }

    /// The record as the decoder read it. Decoding is structural and runs
    /// no check, as for every stored record.
    pub(crate) fn decoded(
        programme: ProgrammeId,
        revision: DraftRevision,
        report: ReportDigest,
        decision: DecisionId,
        approver: AccountId,
        builders: BTreeSet<AccountId>,
    ) -> ActivationApproved {
        ActivationApproved {
            programme,
            revision,
            report,
            decision,
            approver,
            builders,
        }
    }

    /// The programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The revision approved.
    pub fn revision(&self) -> DraftRevision {
        self.revision
    }

    /// The fingerprint of the clean report.
    pub fn report(&self) -> &ReportDigest {
        &self.report
    }

    /// The decision id.
    pub fn decision(&self) -> DecisionId {
        self.decision
    }

    /// The approver.
    pub fn approver(&self) -> AccountId {
        self.approver
    }

    /// The builder set the approver was checked against: the
    /// `creator_builders` of the core `ActivateProgramme` (D2).
    pub fn builders(&self) -> &BTreeSet<AccountId> {
        &self.builders
    }
}
